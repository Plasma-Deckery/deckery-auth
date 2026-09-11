//! `deckery-polkit-agent` — thin polkit authentication agent.
//!
//! Registers with polkitd on D-Bus and forwards every `BeginAuthentication`
//! request to the running `deckery-auth-daemon` via `pam_authenticate(3)`.
//! pam_deckery.so (in the polkit-1 PAM stack) connects to the daemon socket;
//! the existing `deckery-auth-ui` overlay handles all user interaction.
//!
//! No GUI lives in this binary — it is a pure relay.

use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use pam_client2::{Context as PamContext, Flag};
use pam_client2::conv_null::Conversation as NullConv;
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

        let (cancel_tx, mut cancel_rx) = oneshot::channel::<()>();
        self.pending.lock().unwrap().insert(cookie.clone(), cancel_tx);

        let conn = self.conn.clone();
        let pending = self.pending.clone();
        let identity = identities.into_iter().next().unwrap();

        tokio::task::spawn_blocking(move || {
            // Blocks until pam_deckery.so + daemon finish auth.
            let pam_result = run_pam_auth("polkit-1", &username);

            pending.lock().unwrap().remove(&cookie);

            if cancel_rx.try_recv().is_ok() {
                info!("auth for {username} cancelled");
                return;
            }

            match pam_result {
                Ok(()) => {
                    let rt = tokio::runtime::Handle::current();
                    let _ = rt.block_on(async {
                        report_success(&conn, uid, &cookie, identity).await
                    });
                }
                Err(e) => {
                    info!("auth for {username} failed: {e}");
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

/// Call pam_authenticate for polkit-1. pam_deckery.so handles the actual
/// interaction via the daemon — NullConversation is intentional (no prompts
/// expected from pam_deckery.so; if daemon is down, auth fails cleanly).
fn run_pam_auth(service: &str, username: &str) -> Result<()> {
    let conv = NullConv::new();
    let mut ctx = PamContext::new(service, Some(username), conv)
        .context("pam_start failed")?;
    ctx.authenticate(Flag::NONE).context("pam_authenticate failed")?;
    Ok(())
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
    let pid = std::process::id();
    let stat = std::fs::read_to_string("/proc/self/stat")?;
    let start_time: u64 = stat
        .split_whitespace()
        .nth(21)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let mut props: HashMap<String, OwnedValue> = HashMap::new();
    props.insert("pid".into(), OwnedValue::try_from(Value::U32(pid))?);
    props.insert("start-time".into(), OwnedValue::try_from(Value::U64(start_time))?);

    Ok(("unix-process".into(), props))
}

// ── main ──────────────────────────────────────────────────────────────────────

const OBJECT_PATH: &str = "/org/deckery/PolicyKit1/AuthenticationAgent";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let pending: CancelMap = Arc::new(Mutex::new(HashMap::new()));

    let conn = connection::Builder::session()?
        .build()
        .await
        .context("failed to connect to session bus")?;

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
