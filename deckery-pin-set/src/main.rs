use anyhow::{bail, Context, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2, Params, Version,
};
use std::fs;
use std::io::{self, BufRead};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Where the PIN hash is stored. Root-only readable — pam_deckery runs as
/// root (invoked from the PAM stack) so this is fine.
const PIN_HASH_PATH: &str = "/etc/deckery/pin.hash";

/// Root-only auth socket — daemon's address.
const AUTH_SOCKET_PATH: &str = "/run/deckery/auth.sock";

/// Argon2id parameters. This check happens rarely (interactive auth, not an
/// API endpoint) and locally, so we can afford to go well above the OWASP
/// minimums without any noticeable UX cost.
///
/// m_cost in KiB — 65536 = 64 MiB
const ARGON2_M_COST: u32 = 65536;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;

fn main() -> Result<()> {
    if !running_as_root() {
        bail!("deckery-pin-set must be run as root (use sudo)");
    }

    // --stdin: non-interactive mode for automated testing (deploy.sh smoke test).
    // Reads the raw PIN from stdin — no TTY, no daemon, no UI required.
    // Do not use in production; the PIN is visible to anyone who can inspect
    // the process's stdin (e.g. via /proc), which is acceptable only because
    // the caller already has root.
    if std::env::args().any(|a| a == "--stdin") {
        return stdin_mode();
    }

    // --keyboard: fallback for environments without a controller or display
    // client (e.g. headless servers, recovery scenarios).
    if std::env::args().any(|a| a == "--keyboard") {
        return keyboard_mode();
    }

    // Default: controller mode — delegate PIN collection to the daemon.
    // The daemon opens the controller, shows the set-PIN UI, collects the PIN
    // twice, and writes the hash.  Requires deckery-auth-daemon + deckery-auth-ui.
    controller_mode()
}

fn running_as_root() -> bool {
    // SAFETY: geteuid() has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

fn hash_pin(pin: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, None)
        .map_err(|e| anyhow::anyhow!("invalid argon2 params: {e}"))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);
    let hash = argon2
        .hash_password(pin.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("failed to hash PIN: {e}"))?;
    Ok(hash.to_string())
}

fn write_hash(hash: &str) -> Result<()> {
    let dir = Path::new(PIN_HASH_PATH)
        .parent()
        .expect("PIN_HASH_PATH has a parent");
    fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;

    fs::write(PIN_HASH_PATH, hash).with_context(|| format!("failed to write {PIN_HASH_PATH}"))?;

    // root:root, rw for owner only — pam_deckery runs as root when invoked
    // from the PAM stack and is the only reader of this file.
    fs::set_permissions(PIN_HASH_PATH, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to set permissions on {PIN_HASH_PATH}"))?;

    Ok(())
}

fn stdin_mode() -> Result<()> {
    let mut line = String::new();
    io::stdin()
        .lock()
        .read_line(&mut line)
        .context("failed to read PIN from stdin")?;
    let pin = line.trim_end_matches('\n').trim_end_matches('\r');
    if pin.trim().is_empty() { bail!("PIN must not be empty"); }
    if pin.len() < 4 { bail!("PIN must be at least 4 characters"); }
    let hash = hash_pin(pin)?;
    write_hash(&hash)?;
    Ok(())
}

fn keyboard_mode() -> Result<()> {
    println!("Deckery — controller PIN setup (keyboard fallback)");
    println!("This PIN is used to authenticate sudo, polkit, and the lock screen");
    println!("via pam_deckery. It is independent of your login password.\n");

    let pin = rpassword::prompt_password("Enter new PIN: ").context("failed to read PIN")?;
    let confirm = rpassword::prompt_password("Confirm PIN: ").context("failed to read PIN")?;

    if pin != confirm {
        bail!("PINs did not match — aborting");
    }
    if pin.trim().is_empty() { bail!("PIN must not be empty"); }
    if pin.len() < 4 { bail!("PIN must be at least 4 characters"); }

    let hash = hash_pin(&pin)?;
    write_hash(&hash)?;
    println!("\nPIN set. Stored (hashed) at {PIN_HASH_PATH}");
    Ok(())
}

/// Default mode: delegate PIN collection to the daemon (uses the physical
/// controller + UI overlay).  The daemon verifies SO_PEERCRED independently.
fn controller_mode() -> Result<()> {
    use std::io::Write;

    println!("Deckery — controller PIN setup");
    println!("The daemon will show the PIN entry UI on the connected display.");
    println!("Enter your new PIN twice using the controller.\n");

    let mut stream = std::os::unix::net::UnixStream::connect(AUTH_SOCKET_PATH)
        .context("cannot connect to deckery-auth-daemon — is it running?")?;

    writeln!(stream, "SET_PIN").context("send SET_PIN")?;

    // Block until the daemon responds — the user is entering the PIN now.
    let mut response = String::new();
    std::io::BufReader::new(&stream)
        .read_line(&mut response)
        .context("read daemon response")?;

    match response.trim() {
        "PIN_SET" => {
            println!("PIN set successfully.");
            Ok(())
        }
        "CANCEL" => bail!("PIN setup cancelled."),
        s if s.starts_with("ERROR:") => {
            bail!("{}", s.strip_prefix("ERROR:").unwrap_or(s))
        }
        other => bail!("unexpected daemon response: {other}"),
    }
}
