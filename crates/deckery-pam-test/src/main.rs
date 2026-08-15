//! `deckery-pam-test` — PAM smoke-test for dev and CI.
//!
//! Calls `pam_authenticate` against a named PAM service and reports success
//! or failure. Used by `deploy.sh` to verify that `pam_deckery.so` is wired
//! up correctly without touching `/etc/pam.d/sudo`.
//!
//! **Not installed in production.** The RPM spec excludes this binary.
//!
//! Usage:
//!   sudo deckery-pam-test <service> <user> <pin>
//!
//! Exit code: 0 = PAM_SUCCESS, 1 = authentication failed or error.

use anyhow::{bail, Result};
use std::ffi::{CStr, CString};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        bail!("Usage: {} <service> <user> <pin>", args[0]);
    }
    let service = CString::new(args[1].as_str())?;
    let user = CString::new(args[2].as_str())?;
    let pin = CString::new(args[3].as_str())?;

    let (code, msg) = run_pam_auth(&service, &user, &pin)?;
    println!("{msg}");
    // Exit based on the PAM return code, not the localised string —
    // pam_strerror differs between implementations ("Success" on glibc/Fedora,
    // "Authentication successful" on Arch, etc.).
    std::process::exit(if code == PAM_SUCCESS { 0 } else { 1 });
}

// ── Raw PAM FFI ───────────────────────────────────────────────────────────────
// We only need three calls: pam_start, pam_authenticate, pam_end.
// libpam is linked via build.rs (`cargo:rustc-link-lib=pam`).

#[repr(C)]
struct PamHandle {
    _opaque: [u8; 0],
}

#[repr(C)]
struct PamMessage {
    msg_style: libc::c_int,
    msg: *const libc::c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut libc::c_char,
    resp_retcode: libc::c_int,
}

#[repr(C)]
struct PamConv {
    conv: unsafe extern "C" fn(
        num_msg: libc::c_int,
        msg: *mut *const PamMessage,
        resp: *mut *mut PamResponse,
        appdata_ptr: *mut libc::c_void,
    ) -> libc::c_int,
    appdata_ptr: *mut libc::c_void,
}

extern "C" {
    fn pam_start(
        service_name: *const libc::c_char,
        user: *const libc::c_char,
        pam_conversation: *const PamConv,
        pamh: *mut *mut PamHandle,
    ) -> libc::c_int;
    fn pam_authenticate(pamh: *mut PamHandle, flags: libc::c_int) -> libc::c_int;
    fn pam_strerror(pamh: *mut PamHandle, errnum: libc::c_int) -> *const libc::c_char;
    fn pam_end(pamh: *mut PamHandle, pam_status: libc::c_int) -> libc::c_int;
}

const PAM_SUCCESS: libc::c_int = 0;
const PAM_PROMPT_ECHO_OFF: libc::c_int = 1;
const PAM_PROMPT_ECHO_ON: libc::c_int = 2;

/// Conversation callback: responds to any echo-off or echo-on prompt with
/// the PIN supplied via appdata_ptr.
unsafe extern "C" fn conv_fn(
    num_msg: libc::c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut libc::c_void,
) -> libc::c_int {
    let pin = appdata_ptr as *const libc::c_char;
    let n = num_msg as usize;

    // Allocate response array with calloc so PAM can free it.
    let responses =
        libc::calloc(n, std::mem::size_of::<PamResponse>()) as *mut PamResponse;
    if responses.is_null() {
        return 1; // PAM_BUF_ERR
    }

    for i in 0..n {
        let m = &**msg.add(i);
        if m.msg_style == PAM_PROMPT_ECHO_OFF || m.msg_style == PAM_PROMPT_ECHO_ON {
            // strdup so PAM can call free() on it.
            (*responses.add(i)).resp = libc::strdup(pin);
        }
    }

    *resp = responses;
    PAM_SUCCESS
}

fn run_pam_auth(service: &CStr, user: &CStr, pin: &CStr) -> Result<(libc::c_int, String)> {
    let conv = PamConv {
        conv: conv_fn,
        appdata_ptr: pin.as_ptr() as *mut libc::c_void,
    };

    let mut pamh: *mut PamHandle = std::ptr::null_mut();

    unsafe {
        let ret = pam_start(service.as_ptr(), user.as_ptr(), &conv, &mut pamh);
        if ret != PAM_SUCCESS {
            let msg = CStr::from_ptr(pam_strerror(pamh, ret)).to_string_lossy().into_owned();
            pam_end(pamh, ret);
            bail!("pam_start: {msg}");
        }

        let ret = pam_authenticate(pamh, 0);
        let msg = CStr::from_ptr(pam_strerror(pamh, ret)).to_string_lossy().into_owned();
        pam_end(pamh, ret);
        Ok((ret, msg))
    }
}
