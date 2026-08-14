use anyhow::{bail, Context, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2, Params, Version,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Where the PIN hash is stored. Root-only readable — pam_deckery runs as
/// root (invoked from the PAM stack) so this is fine.
const PIN_HASH_PATH: &str = "/etc/deckery/pin.hash";

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

    println!("Deckery — controller PIN setup");
    println!("This PIN is used to authenticate sudo, polkit, and the lock screen");
    println!("via pam_deckery. It is independent of your login password.\n");

    let pin = rpassword::prompt_password("Enter new PIN: ").context("failed to read PIN")?;
    let confirm = rpassword::prompt_password("Confirm PIN: ").context("failed to read PIN")?;

    if pin != confirm {
        bail!("PINs did not match — aborting");
    }
    if pin.trim().is_empty() {
        bail!("PIN must not be empty");
    }
    if pin.len() < 4 {
        bail!("PIN must be at least 4 characters");
    }

    let hash = hash_pin(&pin)?;
    write_hash(&hash)?;

    println!("\nPIN set. Stored (hashed) at {PIN_HASH_PATH}");
    Ok(())
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
