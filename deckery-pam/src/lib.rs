//! `pam_deckery.so` — PAM module authenticating against the Deckery controller
//! PIN, independent of the user's login password.
//!
//! ## Step 1 (current)
//!
//! No daemon, no popup, no controller input yet. The PIN is requested via the
//! standard PAM conversation function (`PAM_PROMPT_ECHO_OFF`) — on a terminal
//! this reads from stdin same as a password prompt would. This proves out the
//! PAM stack wiring (registration, ordering, hash verification) before the
//! Layer Shell daemon and controller input reader are added in later steps.
//! See https://github.com/Plasma-Deckery/deckery/issues/19.
//!
//! ## Stack placement
//!
//! Must be listed *before* `pam_unix.so` as `sufficient` so it is tried
//! first — see the Step 1 write-up on deckery#19 for the reasoning:
//!
//! ```text
//! auth  sufficient  pam_deckery.so
//! auth  sufficient  pam_unix.so
//! auth  required    pam_deny.so
//! ```

use argon2::{password_hash::PasswordHash, Argon2, PasswordVerifier};
use pamsm::{Pam, PamError, PamFlags, PamLibExt, PamMsgStyle, PamServiceModule};
use std::fs;

/// Same path written by `deckery-pin-set`.
const PIN_HASH_PATH: &str = "/etc/deckery/pin.hash";

struct PamDeckery;

impl PamServiceModule for PamDeckery {
    fn authenticate(pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        let stored_hash = match fs::read_to_string(PIN_HASH_PATH) {
            Ok(h) => h,
            // No PIN configured yet — not an error, just skip this module
            // and let the stack fall through to pam_unix.
            Err(_) => return PamError::AUTHINFO_UNAVAIL,
        };

        let pin = match pamh.conv(Some("Deckery PIN: "), PamMsgStyle::PROMPT_ECHO_OFF) {
            Ok(Some(pin)) => pin,
            Ok(None) => return PamError::AUTH_ERR,
            Err(e) => return e,
        };

        let pin = match pin.to_str() {
            Ok(s) => s,
            Err(_) => return PamError::AUTH_ERR,
        };

        match verify_pin(pin, &stored_hash) {
            Ok(true) => PamError::SUCCESS,
            Ok(false) => PamError::AUTH_ERR,
            Err(_) => PamError::AUTH_ERR,
        }
    }

    /// Required, not decorative: `setcred` belongs to the same PAM group as
    /// `authenticate` ("auth"). Applications like sudo call `pam_setcred()`
    /// automatically right after a successful `pam_authenticate()`, as part
    /// of the standard PAM flow. pamsm's default (unimplemented) behavior
    /// for every trait method is `PamError::SERVICE_ERR` — so leaving this
    /// out would make sudo fail *after* a correct PIN, once it tries to set
    /// up credentials. We have no credentials to establish, so SUCCESS
    /// (a no-op "nothing to do here") is the correct response.
    fn setcred(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        PamError::SUCCESS
    }

    /// Belongs to PAM's "account" group, not "auth" — since `pam_deckery.so`
    /// is only registered under `auth` in /etc/pam.d/, this is never
    /// actually invoked by our current stack config.
    ///
    /// Deliberately returns IGNORE, not SUCCESS. Unlike `setcred` (which runs
    /// only after identity is already verified), account management *is* a
    /// real security decision — expired accounts, locked accounts, forced
    /// password changes. We have no opinion on any of that; returning
    /// unconditional SUCCESS here would silently wave through those checks
    /// if this module ever ended up in an `account` stack by mistake.
    /// IGNORE tells PAM to disregard this module's verdict entirely,
    /// regardless of whether it's `required`, `sufficient`, or `optional` —
    /// it cannot short-circuit a stack the way SUCCESS could.
    fn acct_mgmt(_pamh: Pam, _flags: PamFlags, _args: Vec<String>) -> PamError {
        PamError::IGNORE
    }
}

fn verify_pin(pin: &str, stored_hash: &str) -> anyhow::Result<bool> {
    let parsed_hash = PasswordHash::new(stored_hash.trim())
        .map_err(|e| anyhow::anyhow!("stored PIN hash is malformed: {e}"))?;
    Ok(Argon2::default()
        .verify_password(pin.as_bytes(), &parsed_hash)
        .is_ok())
}

pamsm::pam_module!(PamDeckery);
