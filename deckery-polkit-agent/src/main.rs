//! `deckery-polkit-agent` — thin polkit authentication agent.
//!
//! Registers with polkitd on D-Bus and forwards every `BeginAuthentication`
//! request to the running `deckery-auth-daemon` over the auth socket.
//! The daemon (running as root) handles all user interaction via
//! `deckery-auth-ui` and verifies the credential internally — no PAM in
//! this process.
//!
//! # Protocol
//!
//! ```text
//! agent → daemon: "polkit-1:<username>\n"
//! daemon → agent: "OK\n"     — auth succeeded
//!              or "CANCEL\n" — user cancelled
//!              or "ERROR:<msg>\n" — controller unavailable or other error
//! ```
//!
//! No GUI lives in this binary — it is a pure relay.

use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tracing::{info, warn};
use zbus::{connection, interface, proxy};
use zbus::zvariant::{OwnedValue, Value};

// ── polkitd proxy ─────────────────────────────────────────────────────────────

#[proxy(
    interface = "org.freedesktop.PolicyKit1.Authority",
    default_service = "org.freedesktop.PolicyKit1",
    default_path = "/org/freedesktop/PolicyKit1/Authority"
)]
trait Authority {
    fn register_authentication_agent_with_options(
        &self,
        subject: (String, HashMap<String, OwnedValue>),
        locale: &str,
        object_path: &str,
        options: HashMap<String, OwnedValue>,
    ) -> zbus::Result<()>;

    fn authentication_agent_response2(
        &self,
        uid: u32,
        cookie: &str,
        identity: (String, HashMap<String, OwnedValue>),
    ) -> zbus::Result<()>;
}

// ── cancel map ────────────────────────────────────────────────────────────────

type CancelMap = Arc<Mutex<HashMap<String, oneshot::Sender<()>>>>;

// ── agent interface ───────────────────────────────────────────────────────────

struct DeckeryAgent {
    conn: zbus::Connection,
    pending: CancelMap,
}

#[interface(name = "org.freedesktop.PolicyKit1.AuthenticationAgent")]
impl DeckeryAgent {
    async fn begin_authentication(
        &self,
        action_id: String,
        _message: String,
        _icon_name: String,
        _details: HashMap<String, String>,
        cookie: String,
        identities: Vec<(String, HashMap<String, OwnedValue>)>,
    ) {
        let (uid, username) = match extract_unix_user(&identities) {
            Some(v) => v,
            None => {
                warn!("begin_authentication: no unix-user identity found");
                return;
            }
        };

        info!("polkit auth: action={action_id} user={username}");

        let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
        self.pending.lock().unwrap().insert(cookie.clone(), cancel_tx);

        let conn    = self.conn.clone();
        let pending = self.pending.clone();
        let identity = identities.into_iter().next().unwrap();

        tokio::spawn(async move {
            let result = tokio::select! {
                r = daemon_auth(&username) => r,
                _ = cancel_rx => {
                    info!("auth for {username} cancelled by polkit");
                    Ok(false)
                }
            };

            pending.lock().unwrap().remove(&cookie);

            match result {
                Ok(true) => {
                    info!("auth for {username}: daemon OK, reporting success");
                    if let Err(e) = report_success(&conn, uid, &cookie, identity).await {
                        warn!("auth for {username}: AuthenticationAgentResponse2 failed: {e:#?}");
                    } else {
                        info!("auth for {username}: AuthenticationAgentResponse2 accepted");
                    }
                }
                Ok(false) => {
                    info!("auth for {username}: cancelled or failed");
                }
                Err(e) => {
                    warn!("auth for {username}: daemon error: {e:#}");
                }
            }
        });
    }

    async fn cancel_authentication(&self, cookie: String) {
        if let Some(tx) = self.pending.lock().unwrap().remove(&cookie) {
            let _ = tx.send(());
        }
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn extract_unix_user(
    identities: &[(String, HashMap<String, OwnedValue>)],
) -> Option<(u32, String)> {
    for (kind, props) in identities {
        if kind == "unix-user" {
            if let Some(val) = props.get("uid") {
                if let Value::U32(uid) = val.deref() {
                    let username = uid_to_name(*uid).unwrap_or_else(|| uid.to_string());
                    return Some((*uid, username));
                }
            }
        }
    }
    None
}

fn uid_to_name(uid: u32) -> Option<String> {
    let mut buf = vec![0i8; 1024];
    let mut result = std::ptr::null_mut();
    let mut pwd = unsafe { std::mem::zeroed::<libc::passwd>() };
    let ret = unsafe {
        libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result)
    };
    if ret != 0 || result.is_null() {
        return None;
    }
    let name = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) };
    Some(name.to_string_lossy().into_owned())
}

// ── daemon communication ──────────────────────────────────────────────────────

const AUTH_SOCKET: &str = "/run/deckery/polkit.sock";
/// Maximum time to wait for the daemon to complete authentication.
const AUTH_TIMEOUT: Duration = Duration::from_secs(300);

/// Connect to the auth daemon, send the polkit-1 request, and wait for the
/// result.  Returns `Ok(true)` if auth succeeded, `Ok(false)` if cancelled,
/// `Err` if the daemon is unreachable or responds unexpectedly.
async fn daemon_auth(username: &str) -> Result<bool> {
    let mut stream = tokio::time::timeout(
        Duration::from_secs(5),
        UnixStream::connect(AUTH_SOCKET),
    )
    .await
    .context("connect timeout")?
    .context("connect to auth socket")?;

    stream
        .write_all(format!("polkit-1:{username}\n").as_bytes())
        .await
        .context("write source")?;

    let mut line = String::new();
    tokio::time::timeout(
        AUTH_TIMEOUT,
        BufReader::new(&mut stream).read_line(&mut line),
    )
    .await
    .context("auth timeout")?
    .context("read result")?;

    match line.trim() {
        "OK"     => Ok(true),
        "CANCEL" => Ok(false),
        other    => {
            // ERROR:<msg> or unexpected — not fatal, just auth didn't succeed.
            info!("daemon response: {other}");
            Ok(false)
        }
    }
}

async fn report_success(
    conn: &zbus::Connection,
    uid: u32,
    cookie: &str,
    identity: (String, HashMap<String, OwnedValue>),
) -> Result<()> {
    let proxy = AuthorityProxy::new(conn).await?;
    proxy
        .authentication_agent_response2(uid, cookie, identity)
        .await
        .context("AuthenticationAgentResponse2 failed")?;
    Ok(())
}

fn session_subject() -> Result<(String, HashMap<String, OwnedValue>)> {
    let session_id = std::env::var("XDG_SESSION_ID")
        .context("XDG_SESSION_ID not set")?;

    let mut props: HashMap<String, OwnedValue> = HashMap::new();
    props.insert(
        "session-id".into(),
        OwnedValue::try_from(Value::Str(session_id.as_str().into()))?,
    );

    Ok(("unix-session".into(), props))
}

// ── main ──────────────────────────────────────────────────────────────────────

const OBJECT_PATH: &str = "/org/deckery/PolicyKit1/AuthenticationAgent";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let pending: CancelMap = Arc::new(Mutex::new(HashMap::new()));

    let conn = connection::Builder::system()?
        .build()
        .await
        .context("failed to connect to system bus")?;

    let agent = DeckeryAgent {
        conn: conn.clone(),
        pending,
    };
    conn.object_server()
        .at(OBJECT_PATH, agent)
        .await
        .context("failed to register agent object")?;

    let subject = session_subject().context("failed to build session subject")?;
    let proxy = AuthorityProxy::new(&conn).await?;
    proxy
        .register_authentication_agent_with_options(
            subject,
            "en_US",
            OBJECT_PATH,
            HashMap::new(),
        )
        .await
        .context("failed to register with polkitd")?;

    info!("deckery-polkit-agent registered at {OBJECT_PATH}");

    std::future::pending::<()>().await;
    Ok(())
}
