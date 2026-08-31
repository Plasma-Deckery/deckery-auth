//! `deckery-auth-daemon` — controller PIN authentication daemon.
//!
//! Runs as root (systemd service). Owns the Steam Deck controller exclusively
//! during a PIN entry session and exposes a root-only Unix socket so that
//! `pam_deckery.so` can request PIN collection without needing direct device
//! access itself.
//!
//! # Architecture
//!
//! ```text
//!  pam_deckery.so (root, within PAM stack)
//!       │  connect /run/deckery/auth.sock
//!       │  send "<source>\n"   e.g. "sudo", "screenlock", "greeter"
//!       │  blocking read until response (no timeout)
//!       ▼
//!  deckery-auth-daemon (root, systemd service)
//!       │  assigns priority from source name (table lives here — one place)
//!       │  queues request; serves highest-priority first, FIFO within tier
//!       │  when at head of queue:
//!       │    TokenReader::open() → exclusive evdev grab + Lizard Mode
//!       │    reads tokens until Confirm / Cancel / IO error
//!       │    writes one response line, closes connection
//!       │
//!       │  Display events → D-Bus signals (org.deckery.AuthDisplay1)
//!       │    deckery-auth-ui subscribes as a D-Bus client on the system bus
//!       │    UI-Cancel → UiCancel() D-Bus method call → cancel channel
//!       ▼
//!  pam_deckery receives encoded PIN (or CANCEL / ERROR:…)
//!  → verifies against /etc/deckery/pin.hash
//! ```
//!
//! # Socket protocol (auth.sock — PAM side)
//!
//! One round-trip per connection, newline-delimited ASCII.
//!
//! **Client → daemon (one line, sent before blocking):**
//! ```text
//! sudo\n
//! screenlock\n
//! greeter\n
//! ```
//!
//! **Daemon → client:**
//! | Response | Meaning |
//! |---|---|
//! | `<encoded_pin>\n` | Confirm pressed |
//! | `CANCEL\n` | Cancel pressed |
//! | `ERROR:<msg>\n` | Controller unavailable or IO error |
//!
//! # D-Bus interface (display — UI side)
//!
//! Interface `org.deckery.AuthDisplay1` on the **system bus**.
//! Object path `/org/deckery/AuthDisplay`.
//! Policy file: `/usr/share/dbus-1/system.d/org.deckery.AuthDisplay1.conf`.
//!
//! **Signals (daemon → UI):**
//! | Signal | Arguments | Meaning |
//! |---|---|---|
//! | `SessionStart` | `source: s, session_id: t` | New auth session |
//! | `Token` | `token: s` | Chord token added |
//! | `Backspace` | — | Last token removed |
//! | `Confirm` | `session_id: t` | Confirmed, auth succeeding |
//! | `Cancel` | `session_id: t` | Cancelled |
//! | `SessionEnd` | `session_id: t` | Session closed |
//!
//! **Methods (UI → daemon):**
//! | Method | Arguments | Meaning |
//! |---|---|---|
//! | `UiCancel` | `session_id: t` | On-screen Cancel button pressed |
//!
//! # Priority queue
//!
//! Lower number = served sooner.
//!
//! | Source | Priority |
//! |---|---|
//! | `greeter` | 0 |
//! | `screenlock` | 1 |
//! | `polkit` | 2 |
//! | `sudo` / `su` | 3 |
//! | `login` | 4 |
//! | everything else | 10 |

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, oneshot, Mutex, Notify};
use zbus::object_server::SignalContext;

use deckery_input::{ControlAction, Token, TokenReader, encode_sequence};

/// Root-only socket path for PAM connections. Mode 0600 enforced after bind.
const SOCKET_PATH: &str = "/run/deckery/auth.sock";

// ── Display events ────────────────────────────────────────────────────────────

/// Events emitted as D-Bus signals over `org.deckery.AuthDisplay1`.
#[derive(Debug, Clone)]
enum DisplayEvent {
    SessionStart(String, u64),
    Token(String),
    Backspace,
    Confirm(u64),
    Cancel(u64),
    SessionEnd(u64),
}

// ── D-Bus interface ───────────────────────────────────────────────────────────

/// Implementation of `org.deckery.AuthDisplay1`.
///
/// Holds the sender end of the UI-cancel broadcast so the `UiCancel` method
/// can forward the request to the active `collect_pin` call.
struct AuthDisplayIface {
    ui_cancel_tx: broadcast::Sender<u64>,
}

#[zbus::interface(name = "org.deckery.AuthDisplay1")]
impl AuthDisplayIface {
    /// Called by the UI when the on-screen Cancel button is pressed.
    /// The session ID guards against stale cancels from a previous session.
    async fn ui_cancel(&self, session_id: u64) {
        eprintln!("deckery-auth-daemon: UI cancel via D-Bus (session {session_id})");
        // Ignore send error: no active session means there is nothing to cancel.
        let _ = self.ui_cancel_tx.send(session_id);
    }

    // ── Signals ───────────────────────────────────────────────────────────────
    // Signal declarations: the daemon emits these; the UI subscribes.

    #[zbus(signal)]
    async fn session_start(ctx: &SignalContext<'_>, source: &str, session_id: u64) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn token(ctx: &SignalContext<'_>, token: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn backspace(ctx: &SignalContext<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn confirm(ctx: &SignalContext<'_>, session_id: u64) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn cancel(ctx: &SignalContext<'_>, session_id: u64) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn session_end(ctx: &SignalContext<'_>, session_id: u64) -> zbus::Result<()>;
}

// ── Priority table ────────────────────────────────────────────────────────────

fn priority_for_source(source: &str) -> u8 {
    match source {
        "greeter"    => 0,
        "screenlock" => 1,
        "polkit"     => 2,
        "sudo" | "su" => 3,
        "login"      => 4,
        _            => 10,
    }
}

// ── Queue entry ───────────────────────────────────────────────────────────────

struct QueueEntry {
    priority: u8,
    sequence: u64,
    source:   String,
    response: oneshot::Sender<Response>,
}

impl Ord for QueueEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other.priority.cmp(&self.priority)
            .then(other.sequence.cmp(&self.sequence))
    }
}
impl PartialOrd for QueueEntry { fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) } }
impl PartialEq  for QueueEntry { fn eq(&self, other: &Self) -> bool { self.priority == other.priority && self.sequence == other.sequence } }
impl Eq for QueueEntry {}

// ── Shared queue ──────────────────────────────────────────────────────────────

struct Queue {
    heap:     BinaryHeap<QueueEntry>,
    sequence: u64,
}

impl Queue {
    fn new() -> Self { Self { heap: BinaryHeap::new(), sequence: 0 } }

    fn push(&mut self, source: String, response: oneshot::Sender<Response>) {
        let priority = priority_for_source(&source);
        let sequence = self.sequence;
        self.sequence += 1;
        self.heap.push(QueueEntry { priority, sequence, source, response });
    }

    fn pop(&mut self) -> Option<QueueEntry> { self.heap.pop() }
    fn len(&self) -> usize { self.heap.len() }
}

// ── Response type ─────────────────────────────────────────────────────────────

enum Response {
    Pin(String),
    Cancel,
    Error(String),
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!("deckery-auth-daemon must run as root");
    }

    tokio::fs::create_dir_all("/run/deckery")
        .await
        .context("create /run/deckery")?;
    let _ = tokio::fs::remove_file(SOCKET_PATH).await;

    let listener = UnixListener::bind(SOCKET_PATH)
        .with_context(|| format!("bind {SOCKET_PATH}"))?;
    std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 600 {SOCKET_PATH}"))?;

    println!("deckery-auth-daemon: listening on {SOCKET_PATH}");

    let queue  = Arc::new(Mutex::new(Queue::new()));
    let notify = Arc::new(Notify::new());

    // Internal broadcast for display events (capacity 64).
    let (display_tx, _) = broadcast::channel::<DisplayEvent>(64);

    // UI-cancel broadcast (carries session ID).
    let (ui_cancel_tx, _) = broadcast::channel::<u64>(4);

    tokio::spawn(worker_loop(queue.clone(), notify.clone(), display_tx.clone(), ui_cancel_tx.clone()));
    tokio::spawn(dbus_display_loop(display_tx, ui_cancel_tx));
    accept_loop(listener, queue, notify).await;

    Ok(())
}

// ── D-Bus display loop ────────────────────────────────────────────────────────

/// Owns the `org.deckery.AuthDisplay1` D-Bus name, forwards internal broadcast
/// events as D-Bus signals, and receives `UiCancel` method calls from the UI.
///
/// If D-Bus setup fails (e.g. policy file not yet installed), the daemon logs
/// the error and continues without UI display. The PAM auth flow is unaffected.
async fn dbus_display_loop(
    display_tx:   broadcast::Sender<DisplayEvent>,
    ui_cancel_tx: broadcast::Sender<u64>,
) {
    if let Err(e) = run_dbus_display(display_tx, ui_cancel_tx).await {
        eprintln!("deckery-auth-daemon: D-Bus display service failed: {e}");
        eprintln!("  hint: install org.deckery.AuthDisplay1.conf to /usr/share/dbus-1/system.d/");
    }
}

async fn run_dbus_display(
    display_tx:   broadcast::Sender<DisplayEvent>,
    ui_cancel_tx: broadcast::Sender<u64>,
) -> Result<()> {
    let iface = AuthDisplayIface { ui_cancel_tx };

    let conn = zbus::connection::Builder::system()
        .context("D-Bus system bus connect")?
        .name("org.deckery.AuthDisplay1")
        .context("D-Bus name request")?
        .serve_at("/org/deckery/AuthDisplay", iface)
        .context("D-Bus serve_at")?
        .build()
        .await
        .context("D-Bus connection build")?;

    let ctx = SignalContext::new(&conn, "/org/deckery/AuthDisplay")
        .context("D-Bus signal context")?;

    eprintln!("deckery-auth-daemon: D-Bus service ready (org.deckery.AuthDisplay1)");

    let mut rx = display_tx.subscribe();
    loop {
        match rx.recv().await {
            Ok(ev) => {
                let result = match &ev {
                    DisplayEvent::SessionStart(src, id) =>
                        AuthDisplayIface::session_start(&ctx, src, *id).await,
                    DisplayEvent::Token(t) =>
                        AuthDisplayIface::token(&ctx, t).await,
                    DisplayEvent::Backspace =>
                        AuthDisplayIface::backspace(&ctx).await,
                    DisplayEvent::Confirm(id) =>
                        AuthDisplayIface::confirm(&ctx, *id).await,
                    DisplayEvent::Cancel(id) =>
                        AuthDisplayIface::cancel(&ctx, *id).await,
                    DisplayEvent::SessionEnd(id) =>
                        AuthDisplayIface::session_end(&ctx, *id).await,
                };
                if let Err(e) = result {
                    eprintln!("deckery-auth-daemon: D-Bus signal error: {e}");
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                eprintln!("deckery-auth-daemon: D-Bus display lagged ({n} events dropped)");
            }
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }

    Ok(())
}

// ── PAM acceptor ─────────────────────────────────────────────────────────────

async fn accept_loop(
    listener: UnixListener,
    queue:    Arc<Mutex<Queue>>,
    notify:   Arc<Notify>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let queue  = queue.clone();
                let notify = notify.clone();
                tokio::spawn(handle_incoming(stream, queue, notify));
            }
            Err(e) => eprintln!("deckery-auth-daemon: accept error: {e}"),
        }
    }
}

async fn handle_incoming(
    mut stream: UnixStream,
    queue:      Arc<Mutex<Queue>>,
    notify:     Arc<Notify>,
) {
    let source = {
        let mut reader = BufReader::new(&mut stream);
        let mut line = String::new();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => {
                let _ = stream.write_all(b"ERROR:read source\n").await;
                return;
            }
            Ok(_) => line.trim().to_string(),
        }
    };

    let priority = priority_for_source(&source);

    let (response_tx, response_rx) = oneshot::channel::<Response>();
    let queue_len = {
        let mut q = queue.lock().await;
        q.push(source.clone(), response_tx);
        q.len()
    };
    notify.notify_one();

    eprintln!(
        "deckery-auth-daemon: queued '{}' (priority {}) — {} request(s) in queue",
        source, priority, queue_len
    );

    let response = match response_rx.await {
        Ok(r)  => r,
        Err(_) => Response::Error("worker crashed".into()),
    };

    match response {
        Response::Pin(p)   => { let _ = stream.write_all(format!("{p}\n").as_bytes()).await; }
        Response::Cancel   => { let _ = stream.write_all(b"CANCEL\n").await; }
        Response::Error(e) => { let _ = stream.write_all(format!("ERROR:{e}\n").as_bytes()).await; }
    }
}

// ── Worker ────────────────────────────────────────────────────────────────────

async fn worker_loop(
    queue:        Arc<Mutex<Queue>>,
    notify:       Arc<Notify>,
    display_tx:   broadcast::Sender<DisplayEvent>,
    ui_cancel_tx: broadcast::Sender<u64>,
) {
    let mut next_session_id: u64 = 0;
    loop {
        let entry = { let mut q = queue.lock().await; q.pop() };

        match entry {
            None => { notify.notified().await; }
            Some(entry) => {
                if entry.response.is_closed() {
                    eprintln!(
                        "deckery-auth-daemon: '{}' request abandoned (client disconnected)",
                        entry.source
                    );
                    continue;
                }

                eprintln!(
                    "deckery-auth-daemon: serving '{}' (priority {})",
                    entry.source, entry.priority
                );

                let session_id = next_session_id;
                next_session_id += 1;
                let response = match collect_pin(&entry.source, &display_tx, &ui_cancel_tx, session_id).await {
                    Ok(Some(pin)) => Response::Pin(pin),
                    Ok(None)      => Response::Cancel,
                    Err(e)        => {
                        let _ = display_tx.send(DisplayEvent::SessionEnd(session_id));
                        Response::Error(e.to_string())
                    }
                };

                let _ = entry.response.send(response);
            }
        }
    }
}

// ── PIN collection ────────────────────────────────────────────────────────────

async fn collect_pin(
    source:       &str,
    display_tx:   &broadcast::Sender<DisplayEvent>,
    ui_cancel_tx: &broadcast::Sender<u64>,
    session_id:   u64,
) -> Result<Option<String>> {
    let mut ui_cancel_rx = ui_cancel_tx.subscribe();

    let mut reader = TokenReader::open()
        .await
        .context("open controller")?;

    eprintln!(
        "deckery-auth-daemon: PIN collection started on {}",
        reader.path().display()
    );

    let _ = display_tx.send(DisplayEvent::SessionStart(source.to_string(), session_id));

    let mut tokens: Vec<Token> = Vec::new();

    loop {
        tokio::select! {
            token_result = reader.next_token() => {
                let token = token_result.context("read controller event")?;
                match token {
                    Token::Control(ControlAction::Confirm) => {
                        eprintln!("deckery-auth-daemon: Confirm — {} token(s)", tokens.len());
                        let _ = display_tx.send(DisplayEvent::Confirm(session_id));
                        let _ = display_tx.send(DisplayEvent::SessionEnd(session_id));
                        return Ok(Some(encode_sequence(&tokens)));
                    }
                    Token::Control(ControlAction::Backspace) => {
                        tokens.pop();
                        eprintln!("deckery-auth-daemon: Backspace — {} remaining", tokens.len());
                        let _ = display_tx.send(DisplayEvent::Backspace);
                    }
                    Token::Control(ControlAction::Cancel) => {
                        eprintln!("deckery-auth-daemon: Cancel (controller)");
                        let _ = display_tx.send(DisplayEvent::Cancel(session_id));
                        let _ = display_tx.send(DisplayEvent::SessionEnd(session_id));
                        return Ok(None);
                    }
                    Token::Release(_) => {}
                    t @ Token::Chord(_) => {
                        let encoded = t.encode();
                        let _ = display_tx.send(DisplayEvent::Token(encoded));
                        tokens.push(t);
                        eprintln!("deckery-auth-daemon: chord — {} total", tokens.len());
                    }
                }
            }

            Ok(id) = ui_cancel_rx.recv() => {
                if id == session_id {
                    eprintln!("deckery-auth-daemon: Cancel (UI button, session {session_id})");
                    let _ = display_tx.send(DisplayEvent::Cancel(session_id));
                    let _ = display_tx.send(DisplayEvent::SessionEnd(session_id));
                    return Ok(None);
                }
            }
        }
    }
}
