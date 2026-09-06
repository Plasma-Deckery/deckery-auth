//! `pam_deckery.so` — PAM module that authenticates via the running
//! `deckery-auth-daemon`.
//!
//! # What this module does
//!
//! It drives a **multi-turn** dialogue with the daemon over the auth socket:
//!
//! 1. Connect → send `source\n`.
//! 2. Daemon sends an attempt: `PIN:<encoded>\n` or `KBD:<password>\n`.
//! 3. This module verifies and replies `CORRECT\n` or `WRONG\n`.
//! 4. On WRONG the daemon relays the failure to the UI (which shows ✗ and
//!    lets the user retry); on CORRECT the session ends successfully.
//! 5. `CANCEL\n` from the daemon aborts the entire PAM transaction.
//!
//! All verification happens here:
//! - Controller PIN  → argon2id against `/etc/deckery/pin.hash`
//! - Keyboard password → shadow/crypt against `/etc/shadow`
//!
//! # PAM stack
//!
//! ```text
//! auth  sufficient  pam_deckery.so  source=sudo
//! auth  sufficient  pam_unix.so                   # fallback when daemon unreachable
//! auth  required    pam_deny.so
//! ```
//!
//! # Return codes
//!
//! | Situation                           | Code               | PAM behaviour        |
//! |-------------------------------------|--------------------|----------------------|
//! | Correct PIN or password             | `SUCCESS`          | Auth succeeds        |
//! | Daemon not running / timeout        | `AUTHINFO_UNAVAIL` | Skip → pam_unix      |
//! | User cancelled (controller / UI ✕)  | `ABORT`            | No keyboard fallback |
//! | Unexpected error                    | `AUTH_ERR`         | Skip → pam_unix      |

use argon2::{password_hash::PasswordHash, Argon2, PasswordVerifier};
use pamsm::{Pam, PamError, PamFlags, PamLibExt, PamServiceModule};
use std::ffi::CString;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

// crypt(3) is in libxcrypt on modern Fedora/Bazzite. Not always re-exported by
// the `libc` crate, so we declare it explicitly. Linked via build.rs (-lcrypt).
extern "C" {
    fn crypt(key: *const libc::c_char, salt: *const libc::c_char) -> *mut libc::c_char;
}

/// Stored controller PIN hash — written by `deckery-pin-set`.
const PIN_HASH_PATH: &str = "/etc/deckery/pin.hash";

/// Auth daemon socket — mode 0600 (root-only).
const DAEMON_SOCKET: &str = "/run/deckery/auth.sock";

/// Per-attempt read timeout. After this long with no input from the user,
/// we fall through to `pam_unix.so`.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(300);

struct PamDeckery;

impl PamServiceModule for PamDeckery {
    fn authenticate(pamh: Pam, _flags: PamFlags, args: Vec<String>) -> PamError {
        // Load the stored PIN hash (empty string = no PIN configured; keyboard
        // password mode still works via shadow verification).
        let stored_hash = fs::read_to_string(PIN_HASH_PATH)
            .map(|s| s.trim().to_string())
            .unwrap_or_default();

        // Username is needed for shadow verification.
        let username = match pamh.get_user(None) {
            Ok(Some(u)) => u.to_string_lossy().to_string(),
            _           => return PamError::AUTH_ERR,
        };

        let source = parse_source(&args);

        match run_auth_session(&source, &username, &stored_hash) {
            Ok(())  => PamError::SUCCESS,
            Err(e)  => e,
        }
    }

    fn setcred(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    fn acct_mgmt(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        PamError::IGNORE
    }
}

// ── Source parsing ────────────────────────────────────────────────────────────

fn parse_source(args: &[String]) -> String {
    args.iter()
        .find_map(|a| a.strip_prefix("source="))
        .unwrap_or("unknown")
        .to_string()
}

// ── Auth session ──────────────────────────────────────────────────────────────

/// Connect to the daemon and run the multi-turn verification loop.
///
/// Protocol (one iteration per attempt):
/// ```text
/// → source\n
/// ← PIN:<encoded>\n   → verify argon2 → CORRECT\n or WRONG\n
/// ← KBD:<password>\n  → verify shadow → CORRECT\n or WRONG\n
/// ← CANCEL\n          → return PAM_ABORT
/// ← ERROR:<msg>\n     → return PAM_AUTH_ERR
/// ```
fn run_auth_session(
    source:      &str,
    username:    &str,
    stored_hash: &str,
) -> Result<(), PamError> {
    let mut stream = UnixStream::connect(DAEMON_SOCKET)
        .map_err(|_| PamError::AUTHINFO_UNAVAIL)?;

    // Per-attempt timeout: if the daemon sends nothing for 5 minutes,
    // fall through to pam_unix.
    stream.set_read_timeout(Some(ATTEMPT_TIMEOUT))
        .map_err(|_| PamError::AUTH_ERR)?;

    // Send source name.
    stream.write_all(format!("{source}\n").as_bytes())
        .map_err(|_| PamError::AUTH_ERR)?;

    let mut reader = BufReader::new(
        stream.try_clone().map_err(|_| PamError::AUTH_ERR)?,
    );

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => return Err(PamError::AUTH_ERR),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                   || e.kind() == std::io::ErrorKind::TimedOut
                => return Err(PamError::AUTHINFO_UNAVAIL),
            Err(_) => return Err(PamError::AUTH_ERR),
            Ok(_)  => {}
        }

        let msg = line.trim_end_matches(['\n', '\r']);

        if msg == "CANCEL" {
            return Err(PamError::ABORT);
        }
        if msg.starts_with("ERROR:") || msg.is_empty() {
            return Err(PamError::AUTH_ERR);
        }

        let correct = if let Some(encoded) = msg.strip_prefix("PIN:") {
            if stored_hash.is_empty() {
                false  // No PIN configured
            } else {
                verify_pin(encoded, stored_hash).unwrap_or(false)
            }
        } else if let Some(password) = msg.strip_prefix("KBD:") {
            verify_password(username, password)
        } else {
            return Err(PamError::AUTH_ERR);
        };

        let reply: &[u8] = if correct { b"CORRECT\n" } else { b"WRONG\n" };
        stream.write_all(reply).map_err(|_| PamError::AUTH_ERR)?;

        if correct {
            return Ok(());
        }
        // WRONG → daemon sends WrongPassword to overlay; loop for next attempt.
    }
}

// ── Verification helpers ──────────────────────────────────────────────────────

fn verify_pin(pin: &str, stored_hash: &str) -> anyhow::Result<bool> {
    let parsed = PasswordHash::new(stored_hash)
        .map_err(|e| anyhow::anyhow!("malformed PIN hash: {e}"))?;
    Ok(Argon2::default().verify_password(pin.as_bytes(), &parsed).is_ok())
}

/// Verify `password` against the system shadow database for `username`.
///
/// Uses `getspnam(3)` + `crypt(3)`. Both require root, which is guaranteed
/// in a PAM `authenticate` call.
fn verify_password(username: &str, password: &str) -> bool {
    let uname = match CString::new(username) {
        Ok(s)  => s,
        Err(_) => return false,
    };
    let pwd = match CString::new(password) {
        Ok(s)  => s,
        Err(_) => return false,
    };

    unsafe {
        let sp = libc::getspnam(uname.as_ptr());
        if sp.is_null() {
            return false;
        }
        let hash_ptr = (*sp).sp_pwdp;
        if hash_ptr.is_null() {
            return false;
        }
        let result = crypt(pwd.as_ptr(), hash_ptr);
        if result.is_null() {
            return false;
        }
        // crypt(password, stored_hash) == stored_hash  ↔  correct password
        libc::strcmp(result, hash_ptr) == 0
    }
}

pamsm::pam_module!(PamDeckery);
