//! `pam_deckery.so` — PAM module authenticating against the Deckery controller
//! PIN via the running `deckery-auth-daemon`.
//!
//! # Responsibility
//!
//! This module has exactly one job: collect a PIN from the controller via the
//! daemon and verify it against the stored argon2id hash.
//!
//! It does **not** implement a keyboard fallback. Keyboard fallback is handled
//! by `pam_unix.so` at the PAM stack level:
//!
//! ```text
//! auth  sufficient  pam_deckery.so  source=sudo   # Controller PIN (this module)
//! auth  sufficient  pam_unix.so                   # Keyboard password (PAM stack fallback)
//! auth  required    pam_deny.so
//! ```
//!
//! With `sufficient`, when this module returns `AUTHINFO_UNAVAIL` or `AUTH_ERR`,
//! PAM moves on to `pam_unix.so` — which provides the keyboard prompt.
//!
//! # Return codes
//!
//! | Situation | Return code | PAM behaviour |
//! |---|---|---|
//! | Correct PIN | `SUCCESS` | Auth succeeds immediately |
//! | No PIN hash stored | `AUTHINFO_UNAVAIL` | Skip → pam_unix |
//! | Daemon not running | `AUTHINFO_UNAVAIL` | Skip → pam_unix |
//! | User cancelled on controller | `MAXTRIES` | sudo/polkit give up, no retry |
//! | Wrong PIN | `AUTH_ERR` | Skip → pam_unix |
//!
//! # Source name
//!
//! Pass `source=<name>` as a module argument in `/etc/pam.d/`. The daemon owns
//! the priority table — callers only declare their identity.
//!
//! Known source names: `greeter`, `screenlock`, `polkit`, `sudo`, `su`, `login`.

use argon2::{password_hash::PasswordHash, Argon2, PasswordVerifier};
use pamsm::{Pam, PamError, PamFlags, PamServiceModule};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// Stored PIN hash path — written by `deckery-pin-set`, read here.
const PIN_HASH_PATH: &str = "/etc/deckery/pin.hash";

/// Auth daemon socket. Mode 0600, root-only; created by `deckery-auth-daemon`.
const DAEMON_SOCKET: &str = "/run/deckery/auth.sock";

struct PamDeckery;

impl PamServiceModule for PamDeckery {
    fn authenticate(_pamh: Pam, _flags: PamFlags, args: Vec<String>) -> PamError {
        // No PIN configured → skip this module, fall through to pam_unix.
        let stored_hash = match fs::read_to_string(PIN_HASH_PATH) {
            Ok(h) => h,
            Err(_) => return PamError::AUTHINFO_UNAVAIL,
        };

        let source = parse_source(&args);
        let pin = match collect_pin_from_daemon(&source) {
            Ok(p)  => p,
            Err(e) => return e,
        };

        match verify_pin(&pin, &stored_hash) {
            Ok(true)  => PamError::SUCCESS,
            Ok(false) => PamError::AUTH_ERR,
            Err(_)    => PamError::AUTH_ERR,
        }
    }

    /// Called by PAM right after a successful `authenticate`. We have no
    /// credentials to establish, so this is a deliberate no-op.
    fn setcred(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    /// Account management — we have no opinion, so we ignore unconditionally.
    /// Returning IGNORE prevents this module from short-circuiting an `account`
    /// stack it was accidentally placed in.
    fn acct_mgmt(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        PamError::IGNORE
    }
}

// ── PIN acquisition ───────────────────────────────────────────────────────────

/// Extract the `source=<name>` module argument. Defaults to `"unknown"`.
fn parse_source(args: &[String]) -> String {
    args.iter()
        .find_map(|a| a.strip_prefix("source="))
        .unwrap_or("unknown")
        .to_string()
}

/// Connect to `deckery-auth-daemon` and wait for it to collect a PIN from the
/// controller.
///
/// Returns:
/// - `Ok(pin)` — daemon collected a PIN; caller should verify it.
/// - `Err(AUTHINFO_UNAVAIL)` — daemon socket unreachable (daemon not running).
///   PAM will skip this module and try the next one (`pam_unix.so`).
/// - `Err(MAXTRIES)` — user explicitly cancelled on the controller or via the UI.
///   `sudo` and `polkit` treat MAXTRIES as "stop retrying" rather than "try again".
/// - `Err(AUTH_ERR)` — daemon returned an error or the connection was lost.
///   PAM skips this module and tries the next one (pam_unix keyboard fallback).
///
/// PIN entry timeout: 5 minutes. If the user hasn't confirmed a PIN within
/// this window, PAM returns AUTHINFO_UNAVAIL and the stack falls through to
/// pam_unix.so (keyboard password). The user can always cancel earlier via
/// the UI or controller.
const PIN_TIMEOUT: Duration = Duration::from_secs(300);

fn collect_pin_from_daemon(source: &str) -> Result<String, PamError> {
    // Connect fails → daemon not running → AUTHINFO_UNAVAIL so PAM tries pam_unix.
    let mut stream = UnixStream::connect(DAEMON_SOCKET)
        .map_err(|_| PamError::AUTHINFO_UNAVAIL)?;

    // Read timeout: if the daemon never responds (hang, no input), fall through
    // to pam_unix after 5 minutes rather than blocking forever.
    stream.set_read_timeout(Some(PIN_TIMEOUT))
        .map_err(|_| PamError::AUTH_ERR)?;

    // Send source name so the daemon can assign the right priority.
    stream.write_all(format!("{source}\n").as_bytes())
        .map_err(|_| PamError::AUTH_ERR)?;

    // Block until daemon responds, connection closes, or timeout fires.
    let mut line = String::new();
    match BufReader::new(stream).read_line(&mut line) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
               || e.kind() == std::io::ErrorKind::TimedOut => {
            // Timeout → treat as unavailable, let pam_unix handle it.
            return Err(PamError::AUTHINFO_UNAVAIL);
        }
        Err(_) => return Err(PamError::AUTH_ERR),
    }

    let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');

    if trimmed == "CANCEL" {
        // Hard cancel (QAM button / ✕): abort the entire PAM transaction.
        // PAM_ABORT prevents pam_unix from running — no keyboard dialog appears.
        return Err(PamError::ABORT);
    }
    if trimmed == "SWITCH_KB" {
        // Soft cancel ("Switch to Password"): fall through to pam_unix so the
        // keyboard password dialog appears.
        return Err(PamError::AUTH_ERR);
    }
    if trimmed.starts_with("ERROR:") || trimmed.is_empty() {
        return Err(PamError::AUTH_ERR);
    }

    Ok(trimmed.to_string())
}

// ── Hash verification ─────────────────────────────────────────────────────────

fn verify_pin(pin: &str, stored_hash: &str) -> anyhow::Result<bool> {
    let parsed_hash = PasswordHash::new(stored_hash.trim())
        .map_err(|e| anyhow::anyhow!("stored PIN hash is malformed: {e}"))?;
    Ok(Argon2::default()
        .verify_password(pin.as_bytes(), &parsed_hash)
        .is_ok())
}

pamsm::pam_module!(PamDeckery);
