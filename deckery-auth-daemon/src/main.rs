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
//!       ▼
//!  pam_deckery receives encoded PIN (or CANCEL / ERROR:…)
//!  → verifies against /etc/deckery/pin.hash
//! ```
//!
//! # Socket protocol
//!
//! One round-trip per connection, newline-delimited ASCII.
//!
//! **Client → daemon (one line, sent before blocking):**
//!
//! The client sends its source name as declared in `/etc/pam.d/`:
//! ```text
//! sudo\n
//! screenlock\n
//! greeter\n
//! ```
//!
//! **Daemon → client (one response line when it's this request's turn):**
//!
//! | Response | Meaning |
//! |---|---|
//! | `<encoded_pin>\n` | Confirm pressed; PIN as token sequence |
//! | `CANCEL\n` | Cancel pressed (BTN_MODE / Steam button) |
//! | `ERROR:<msg>\n` | Controller unavailable or IO error |
//!
//! # Priority queue
//!
//! The daemon assigns numeric priority entirely based on the source name —
//! **callers declare identity, not priority**. Adding a new priority tier
//! only requires updating [`priority_for_source`] in this file; the protocol
//! and the PAM module stay unchanged.
//!
//! Current ordering (lower number = served sooner):
//!
//! | Source | Priority | Rationale |
//! |---|---|---|
//! | `greeter` | 0 | Login screen — system is inaccessible until resolved |
//! | `screenlock` | 1 | Screen locked — user is stuck |
//! | `polkit` | 2 | System-level privilege escalation |
//! | `sudo` / `su` | 3 | User-level interactive shell |
//! | `login` | 4 | TTY login |
//! | everything else | 10 | Conservative default |
//!
//! Requests within the same priority tier are served FIFO. A waiting request
//! that is abandoned (client disconnects) is silently skipped when it reaches
//! the head of the queue.
//!
//! # Controller grab conflict
//!
//! `TokenReader::open()` calls `EVIOCGRAB`. If another process (e.g. makima)
//! already holds the grab, the request receives `ERROR:…` and pam_deckery
//! falls back to the PAM text-prompt conversation.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, oneshot, Mutex, Notify};

use deckery_input::{ControlAction, Token, TokenReader, encode_sequence};

/// Root-only socket path. Mode 0600 enforced after bind.
const SOCKET_PATH: &str = "/run/deckery/auth.sock";

/// Display socket — streams real-time token events to the visual frontend.
/// Mode 0666: the frontend runs as the user; tokens are shown on-screen anyway.
const DISPLAY_SOCKET_PATH: &str = "/run/deckery/display.sock";

// ── Display events ────────────────────────────────────────────────────────────

/// Events sent over the display socket to the visual frontend.
///
/// The frontend receives the actual tokens so it can show them exactly
/// as entered — the same way a terminal shows typed characters.
/// Security model: same as any other auth UI (kscreenlocker, polkit-kde-agent-1).
#[derive(Debug, Clone)]
enum DisplayEvent {
    /// A new auth session has started.
    /// Payload: (source name, session ID). The session ID is a monotonically
    /// increasing counter used by the UI to tag its UI_CANCEL commands so the
    /// daemon can ignore cancels that belong to a different or already-ended session.
    SessionStart(String, u64),
    /// A chord was registered. Payload: encoded token (e.g. "↓+A").
    Token(String),
    /// The last token was removed (Backspace).
    Backspace,
    /// User confirmed — auth succeeding.
    Confirm,
    /// User cancelled — auth aborted.
    Cancel,
    /// Session ended (follows Confirm, Cancel, or error).
    SessionEnd,
}

impl DisplayEvent {
    fn to_line(&self) -> String {
        match self {
            DisplayEvent::SessionStart(src, id) => format!("SESSION_START:{src}:{id}\n"),
            DisplayEvent::Token(t)          => format!("TOKEN:{t}\n"),
            DisplayEvent::Backspace         => "BACKSPACE\n".to_string(),
            DisplayEvent::Confirm           => "CONFIRM\n".to_string(),
            DisplayEvent::Cancel            => "CANCEL\n".to_string(),
            DisplayEvent::SessionEnd        => "SESSION_END\n".to_string(),
        }
    }
}

// ── Priority table ────────────────────────────────────────────────────────────

/// Assign a numeric priority to a source name.
///
/// **Lower number = served sooner.**
///
/// The daemon owns this table. Callers declare their source name; the daemon
/// decides what that means for ordering. To reprioritise a source or add a new
/// one, update this function — no protocol or PAM-config changes needed.
fn priority_for_source(source: &str) -> u8 {
    match source {
        "greeter"    => 0,   // login screen — nothing works until resolved
        "screenlock" => 1,   // locked desktop — user is stuck
        "polkit"     => 2,   // system-level privilege escalation
        "sudo" | "su" => 3,  // interactive user shell elevation
        "login"      => 4,   // TTY login
        _            => 10,  // unknown sources get lowest urgency
    }
}

// ── Queue entry ───────────────────────────────────────────────────────────────

struct QueueEntry {
    priority: u8,
    /// Monotonic counter for FIFO ordering within the same priority tier.
    sequence: u64,
    source:   String,
    response: oneshot::Sender<Response>,
}

/// BinaryHeap is a max-heap; we want the *lowest* priority number first.
/// Tie-break on sequence: earlier arrival wins (lower sequence number).
impl Ord for QueueEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other.priority.cmp(&self.priority)           // invert: lower wins
            .then(other.sequence.cmp(&self.sequence)) // invert: earlier wins
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
    fn new() -> Self {
        Self { heap: BinaryHeap::new(), sequence: 0 }
    }

    fn push(&mut self, source: String, response: oneshot::Sender<Response>) {
        let priority = priority_for_source(&source);
        let sequence = self.sequence;
        self.sequence += 1;
        self.heap.push(QueueEntry { priority, sequence, source, response });
    }

    fn pop(&mut self) -> Option<QueueEntry> {
        self.heap.pop()
    }

    fn len(&self) -> usize {
        self.heap.len()
    }
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

    // Broadcast channel for display events. Capacity 64 — more than enough
    // for a PIN session. Lagged receivers (slow frontends) simply drop events.
    let (display_tx, _) = broadcast::channel::<DisplayEvent>(64);

    // UI-initiated cancel commands (e.g. on-screen Cancel button).
    // Carries the session ID so the daemon can ignore stale cancels.
    let (ui_cancel_tx, _) = broadcast::channel::<u64>(4);

    tokio::spawn(worker_loop(queue.clone(), notify.clone(), display_tx.clone(), ui_cancel_tx.clone()));
    tokio::spawn(display_accept_loop(display_tx, ui_cancel_tx));
    accept_loop(listener, queue, notify).await;

    Ok(())
}

// ── Display socket ────────────────────────────────────────────────────────────

/// Accepts frontend connections on the display socket and forwards all
/// broadcast events to each connected client.
async fn display_accept_loop(
    display_tx:   broadcast::Sender<DisplayEvent>,
    ui_cancel_tx: broadcast::Sender<u64>,
) {
    let _ = tokio::fs::remove_file(DISPLAY_SOCKET_PATH).await;
    let listener = match UnixListener::bind(DISPLAY_SOCKET_PATH) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("deckery-auth-daemon: failed to bind display socket: {e}");
            return;
        }
    };
    // 0666 — frontend runs as user; tokens are shown on-screen regardless.
    let _ = std::fs::set_permissions(
        DISPLAY_SOCKET_PATH,
        std::fs::Permissions::from_mode(0o666),
    );
    eprintln!("deckery-auth-daemon: display socket at {DISPLAY_SOCKET_PATH}");

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let rx = display_tx.subscribe();
                tokio::spawn(handle_display_connection(stream, rx, ui_cancel_tx.clone()));
            }
            Err(e) => eprintln!("deckery-auth-daemon: display accept error: {e}"),
        }
    }
}

/// Forwards display events to a single connected frontend over the socket and
/// reads back UI-initiated commands (e.g. "UI_CANCEL\n" from the Cancel button).
///
/// The socket is used bidirectionally:
///   daemon → frontend : newline-terminated event lines (SESSION_START, TOKEN, …)
///   frontend → daemon : "UI_CANCEL\n" to abort the active auth session
async fn handle_display_connection(
    stream:       UnixStream,
    mut rx:       broadcast::Receiver<DisplayEvent>,
    ui_cancel_tx: broadcast::Sender<u64>,
) {
    let (read_half, mut write_half) = stream.into_split();
    let mut incoming = BufReader::new(read_half).lines();

    loop {
        tokio::select! {
            // ── outgoing events → frontend ────────────────────────────────────
            event = rx.recv() => {
                match event {
                    Ok(ev) => {
                        if write_half.write_all(ev.to_line().as_bytes()).await.is_err() {
                            break; // frontend disconnected
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        eprintln!("deckery-auth-daemon: display client lagged ({n} events dropped)");
                        // Continue — best-effort delivery, don't disconnect
                    }
                }
            }

            // ── incoming commands ← frontend ──────────────────────────────────
            line = incoming.next_line() => {
                match line {
                    Ok(Some(l)) if l.trim().starts_with("UI_CANCEL:") => {
                        let id_str = l.trim().strip_prefix("UI_CANCEL:").unwrap_or("");
                        if let Ok(id) = id_str.parse::<u64>() {
                            eprintln!("deckery-auth-daemon: UI cancel requested (session {id})");
                            // Harmless if no session is active or ID doesn't match —
                            // the subscriber in collect_pin will check the ID.
                            let _ = ui_cancel_tx.send(id);
                        }
                    }
                    Ok(Some(_)) => {} // unknown command — ignore
                    _ => break,       // frontend disconnected or IO error
                }
            }
        }
    }
}

// ── Acceptor ──────────────────────────────────────────────────────────────────

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

/// Read the source name from the client, enqueue the request, then block
/// until the worker responds.
async fn handle_incoming(
    mut stream: UnixStream,
    queue:      Arc<Mutex<Queue>>,
    notify:     Arc<Notify>,
) {
    // ── Read source name ──────────────────────────────────────────────────────
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
    }; // BufReader dropped — stream usable again

    let priority = priority_for_source(&source);

    // ── Enqueue ───────────────────────────────────────────────────────────────
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

    // ── Wait for the worker ───────────────────────────────────────────────────
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

/// Serves one request at a time. After each session, immediately checks for
/// more queued requests before sleeping on `notify`. This avoids lost wakeups
/// when multiple requests arrive while a session is in progress.
async fn worker_loop(
    queue:        Arc<Mutex<Queue>>,
    notify:       Arc<Notify>,
    display_tx:   broadcast::Sender<DisplayEvent>,
    ui_cancel_tx: broadcast::Sender<u64>,
) {
    let mut next_session_id: u64 = 0;
    loop {
        let entry = {
            let mut q = queue.lock().await;
            q.pop()
        };

        match entry {
            None => {
                // Queue empty — wait until a new request arrives.
                notify.notified().await;
                // Go back to top immediately; the new entry might not be
                // the only one (multiple concurrent arrivals).
            }
            Some(entry) => {
                // Skip if the client already disconnected while waiting.
                if entry.response.is_closed() {
                    eprintln!(
                        "deckery-auth-daemon: '{}' request abandoned (client disconnected)",
                        entry.source
                    );
                    continue; // Check for more entries without sleeping
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
                        let _ = display_tx.send(DisplayEvent::SessionEnd);
                        Response::Error(e.to_string())
                    }
                };

                // Ignore send error — client disconnected between the
                // is_closed() check and now. Harmless.
                let _ = entry.response.send(response);
                // Loop back immediately to serve next queued entry.
            }
        }
    }
}

// ── PIN collection ────────────────────────────────────────────────────────────

async fn collect_pin(
    source:        &str,
    display_tx:    &broadcast::Sender<DisplayEvent>,
    ui_cancel_tx:  &broadcast::Sender<u64>,
    session_id:    u64,
) -> Result<Option<String>> {
    // Subscribe before we start — any UI_CANCEL arriving during the session
    // will be received.  Cancels for a different session ID are ignored.
    // Cancels arriving between sessions have no subscriber and are harmlessly
    // dropped by the broadcast channel.
    let mut ui_cancel_rx = ui_cancel_tx.subscribe();

    let mut reader = TokenReader::open()
        .await
        .context("open controller")?;

    eprintln!(
        "deckery-auth-daemon: PIN collection started on {}",
        reader.path().display()
    );

    // Notify any connected frontend that a session is starting.
    let _ = display_tx.send(DisplayEvent::SessionStart(source.to_string(), session_id));

    let mut tokens: Vec<Token> = Vec::new();

    loop {
        tokio::select! {
            // ── Controller input ──────────────────────────────────────────────
            token_result = reader.next_token() => {
                let token = token_result.context("read controller event")?;
                match token {
                    Token::Control(ControlAction::Confirm) => {
                        eprintln!("deckery-auth-daemon: Confirm — {} token(s)", tokens.len());
                        let _ = display_tx.send(DisplayEvent::Confirm);
                        let _ = display_tx.send(DisplayEvent::SessionEnd);
                        return Ok(Some(encode_sequence(&tokens)));
                    }
                    Token::Control(ControlAction::Backspace) => {
                        tokens.pop();
                        eprintln!("deckery-auth-daemon: Backspace — {} remaining", tokens.len());
                        let _ = display_tx.send(DisplayEvent::Backspace);
                    }
                    Token::Control(ControlAction::Cancel) => {
                        eprintln!("deckery-auth-daemon: Cancel (controller)");
                        let _ = display_tx.send(DisplayEvent::Cancel);
                        let _ = display_tx.send(DisplayEvent::SessionEnd);
                        return Ok(None);
                    }
                    Token::Release(_) => {
                        // Visualization-only — not part of the PIN credential.
                    }
                    t @ Token::Chord(_) => {
                        let encoded = t.encode();
                        let _ = display_tx.send(DisplayEvent::Token(encoded));
                        tokens.push(t);
                        eprintln!("deckery-auth-daemon: chord — {} total", tokens.len());
                    }
                }
            }

            // ── UI-initiated cancel (on-screen button) ────────────────────────
            Ok(id) = ui_cancel_rx.recv() => {
                if id == session_id {
                    eprintln!("deckery-auth-daemon: Cancel (UI button, session {session_id})");
                    let _ = display_tx.send(DisplayEvent::Cancel);
                    let _ = display_tx.send(DisplayEvent::SessionEnd);
                    return Ok(None);
                }
                // Wrong session ID (stale cancel from a previous session) — ignore.
            }
        }
    }
}
