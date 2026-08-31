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
//!       │  connect /run/deckery/auth.sock   (mode 0600 — root only)
//!       │  send "<source>\n"
//!       │  blocking read until response
//!       ▼
//!  deckery-auth-daemon (root, systemd service)
//!       │  priority queue, serves highest-priority first
//!       │  TokenReader → exclusive evdev grab + Lizard Mode
//!       │  reads tokens until Confirm / Cancel / IO error
//!       │
//!       │  display.sock (mode 0666, but exe-verified)
//!       │    on connect: SO_PEERCRED → PID → /proc/<pid>/exe
//!       │    only DISPLAY_EXE_ALLOWLIST binaries are accepted
//!       │    accepted clients receive event stream (bidirectional)
//!       │    UI_CANCEL:<id> → cancel active session if IDs match
//!       ▼
//!  pam_deckery receives encoded PIN (or CANCEL / ERROR:…)
//! ```
//!
//! # Auth socket protocol (auth.sock)
//!
//! **Client → daemon:** `<source>\n`  e.g. `sudo`, `screenlock`
//!
//! **Daemon → client:**
//! | Response | Meaning |
//! |---|---|
//! | `<encoded_pin>\n` | Confirm pressed |
//! | `CANCEL\n` | Cancel pressed |
//! | `ERROR:<msg>\n` | Controller unavailable or IO error |
//!
//! # Display socket protocol (display.sock)
//!
//! **Daemon → UI (event lines):**
//! ```text
//! SESSION_START:<source>:<session_id>\n
//! TOKEN:<encoded>\n
//! BACKSPACE\n
//! CONFIRM:<session_id>\n
//! CANCEL:<session_id>\n
//! SESSION_END:<session_id>\n
//! ```
//!
//! **UI → Daemon (command lines):**
//! ```text
//! UI_CANCEL:<session_id>\n
//! ```
//!
//! # Display peer verification
//!
//! The display socket is world-readable (0666) so `deckery-auth-ui` (running
//! as user) can connect. The daemon immediately reads `SO_PEERCRED` on every
//! incoming connection and resolves `/proc/<pid>/exe` to verify the binary.
//! Only paths listed in `DISPLAY_EXE_ALLOWLIST` are accepted; all others are
//! closed without receiving any data.
//!
//! This provides process-level isolation: not just UID-level but binary-level.
//! Root can read any process's `/proc/<pid>/exe`; the symlink is set by the
//! kernel and cannot be faked by the connecting process.
//!
//! # Priority queue
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
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, oneshot, Mutex, Notify};

use deckery_input::{ControlAction, Token, TokenReader, encode_sequence};

/// Root-only socket. PAM module connects here.
const AUTH_SOCKET_PATH: &str = "/run/deckery/auth.sock";

/// Display socket. World-readable but peer-verified (see [`verify_display_peer`]).
const DISPLAY_SOCKET_PATH: &str = "/run/deckery/display.sock";

/// Only these binaries may receive display events.
/// Checked via SO_PEERCRED → /proc/<pid>/exe (resolved by root, not faked by peer).
const DISPLAY_EXE_ALLOWLIST: &[&str] = &[
    "/usr/local/bin/deckery-auth-ui",
];

// ── Display events ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum DisplayEvent {
    SessionStart(String, u64),
    Token(String),
    Backspace,
    Confirm(u64),
    Cancel(u64),
    SessionEnd(u64),
}

impl DisplayEvent {
    fn to_line(&self) -> String {
        match self {
            DisplayEvent::SessionStart(src, id) => format!("SESSION_START:{src}:{id}\n"),
            DisplayEvent::Token(t)              => format!("TOKEN:{t}\n"),
            DisplayEvent::Backspace             => "BACKSPACE\n".to_string(),
            DisplayEvent::Confirm(id)           => format!("CONFIRM:{id}\n"),
            DisplayEvent::Cancel(id)            => format!("CANCEL:{id}\n"),
            DisplayEvent::SessionEnd(id)        => format!("SESSION_END:{id}\n"),
        }
    }
}

// ── Display peer verification ─────────────────────────────────────────────────

/// Returns `true` iff the peer of `stream` is running a binary in
/// [`DISPLAY_EXE_ALLOWLIST`].
///
/// Reads `SO_PEERCRED` to obtain the peer PID (kernel-set, unforgeable), then
/// resolves `/proc/<pid>/exe` as root. A `(deleted)` suffix is stripped — it
/// appears when the binary is updated on disk while the process is still running,
/// which is a normal occurrence during `deploy.sh`.
fn verify_display_peer(stream: &tokio::net::UnixStream) -> bool {
    let fd = stream.as_raw_fd();

    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        eprintln!("deckery-auth-daemon: SO_PEERCRED failed on display connect");
        return false;
    }

    let pid = cred.pid;
    let exe_link = format!("/proc/{pid}/exe");

    match std::fs::read_link(&exe_link) {
        Err(e) => {
            eprintln!("deckery-auth-daemon: display rejected: cannot read {exe_link}: {e}");
            false
        }
        Ok(path) => {
            let path_str = path.to_string_lossy();
            // Strip kernel-appended " (deleted)" — appears when the binary is
            // updated on disk (e.g. during deploy) while the process still runs.
            let exe = path_str.trim_end_matches(" (deleted)");

            // /proc/<pid>/exe is always the *canonical* (symlink-resolved) path.
            // Allowlist entries may contain symlinks (e.g. /usr/local → /var/usrlocal
            // on Bazzite/Fedora Atomic). Canonicalise each allowlist entry before
            // comparing so both sides are symlink-free real paths.
            let allowed = DISPLAY_EXE_ALLOWLIST.iter().any(|&entry| {
                if exe == entry {
                    return true; // fast path: already matches verbatim
                }
                std::fs::canonicalize(entry)
                    .map(|c| c.to_string_lossy() == exe)
                    .unwrap_or(false)
            });

            if allowed {
                eprintln!("deckery-auth-daemon: display accepted: {exe} (pid {pid})");
                true
            } else {
                eprintln!("deckery-auth-daemon: display rejected: {exe} (pid {pid}) not in allowlist");
                false
            }
        }
    }
}

// ── Priority table ────────────────────────────────────────────────────────────

fn priority_for_source(source: &str) -> u8 {
    match source {
        "greeter"     => 0,
        "screenlock"  => 1,
        "polkit"      => 2,
        "sudo" | "su" => 3,
        "login"       => 4,
        _             => 10,
    }
}

// ── Queue ─────────────────────────────────────────────────────────────────────

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
impl PartialOrd for QueueEntry { fn partial_cmp(&self, o: &Self) -> Option<Ordering> { Some(self.cmp(o)) } }
impl PartialEq  for QueueEntry { fn eq(&self, o: &Self) -> bool { self.priority == o.priority && self.sequence == o.sequence } }
impl Eq for QueueEntry {}

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

enum Response { Pin(String), Cancel, Error(String) }

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!("deckery-auth-daemon must run as root");
    }

    tokio::fs::create_dir_all("/run/deckery").await.context("create /run/deckery")?;

    let _ = tokio::fs::remove_file(AUTH_SOCKET_PATH).await;
    let listener = UnixListener::bind(AUTH_SOCKET_PATH)
        .with_context(|| format!("bind {AUTH_SOCKET_PATH}"))?;
    std::fs::set_permissions(AUTH_SOCKET_PATH, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 600 {AUTH_SOCKET_PATH}"))?;

    println!("deckery-auth-daemon: listening on {AUTH_SOCKET_PATH}");

    let queue  = Arc::new(Mutex::new(Queue::new()));
    let notify = Arc::new(Notify::new());

    let (display_tx, _) = broadcast::channel::<DisplayEvent>(64);
    let (ui_cancel_tx, _) = broadcast::channel::<u64>(4);

    tokio::spawn(worker_loop(queue.clone(), notify.clone(), display_tx.clone(), ui_cancel_tx.clone()));
    tokio::spawn(display_accept_loop(display_tx, ui_cancel_tx));
    auth_accept_loop(listener, queue, notify).await;

    Ok(())
}

// ── Display socket ────────────────────────────────────────────────────────────

async fn display_accept_loop(
    display_tx:   broadcast::Sender<DisplayEvent>,
    ui_cancel_tx: broadcast::Sender<u64>,
) {
    let _ = tokio::fs::remove_file(DISPLAY_SOCKET_PATH).await;
    let listener = match UnixListener::bind(DISPLAY_SOCKET_PATH) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("deckery-auth-daemon: cannot bind display socket: {e}");
            return;
        }
    };
    // 0666: the user-space UI needs to connect.
    // Actual access control is done by verify_display_peer().
    let _ = std::fs::set_permissions(
        DISPLAY_SOCKET_PATH,
        std::fs::Permissions::from_mode(0o666),
    );
    eprintln!("deckery-auth-daemon: display socket at {DISPLAY_SOCKET_PATH} (exe-verified)");

    loop {
        match listener.accept().await {
            Err(e) => eprintln!("deckery-auth-daemon: display accept error: {e}"),
            Ok((stream, _)) => {
                // Verify binary identity before handing off.
                if !verify_display_peer(&stream) {
                    // Connection is dropped here; peer receives EOF.
                    continue;
                }
                let rx = display_tx.subscribe();
                tokio::spawn(handle_display_connection(stream, rx, ui_cancel_tx.clone()));
            }
        }
    }
}

/// Forwards display events to a verified frontend and reads back UI_CANCEL commands.
async fn handle_display_connection(
    stream:       UnixStream,
    mut rx:       broadcast::Receiver<DisplayEvent>,
    ui_cancel_tx: broadcast::Sender<u64>,
) {
    let (read_half, mut write_half) = stream.into_split();
    let mut incoming = BufReader::new(read_half).lines();

    loop {
        tokio::select! {
            event = rx.recv() => {
                match event {
                    Ok(ev) => {
                        if write_half.write_all(ev.to_line().as_bytes()).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        eprintln!("deckery-auth-daemon: display client lagged ({n} events dropped)");
                    }
                }
            }
            line = incoming.next_line() => {
                match line {
                    Ok(Some(l)) if l.trim().starts_with("UI_CANCEL:") => {
                        let id_str = l.trim().strip_prefix("UI_CANCEL:").unwrap_or("");
                        if let Ok(id) = id_str.parse::<u64>() {
                            eprintln!("deckery-auth-daemon: UI cancel (session {id})");
                            let _ = ui_cancel_tx.send(id);
                        }
                    }
                    Ok(Some(_)) => {}
                    _ => break,
                }
            }
        }
    }
}

// ── Auth acceptor ─────────────────────────────────────────────────────────────

async fn auth_accept_loop(
    listener: UnixListener,
    queue:    Arc<Mutex<Queue>>,
    notify:   Arc<Notify>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => tokio::spawn(handle_incoming(stream, queue.clone(), notify.clone())),
            Err(e)          => { eprintln!("deckery-auth-daemon: accept error: {e}"); continue; }
        };
    }
}

async fn handle_incoming(mut stream: UnixStream, queue: Arc<Mutex<Queue>>, notify: Arc<Notify>) {
    let source = {
        let mut reader = BufReader::new(&mut stream);
        let mut line = String::new();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => { let _ = stream.write_all(b"ERROR:read source\n").await; return; }
            Ok(_)          => line.trim().to_string(),
        }
    };

    let priority = priority_for_source(&source);
    let (response_tx, response_rx) = oneshot::channel::<Response>();
    let queue_len = { let mut q = queue.lock().await; q.push(source.clone(), response_tx); q.len() };
    notify.notify_one();

    eprintln!("deckery-auth-daemon: queued '{source}' (priority {priority}) — {queue_len} request(s)");

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
                    eprintln!("deckery-auth-daemon: '{}' abandoned (client disconnected)", entry.source);
                    continue;
                }
                eprintln!("deckery-auth-daemon: serving '{}' (priority {})", entry.source, entry.priority);
                let session_id = next_session_id;
                next_session_id += 1;
                let response = match collect_pin(&entry.source, &display_tx, &ui_cancel_tx, session_id).await {
                    Ok(Some(pin)) => Response::Pin(pin),
                    Ok(None)      => Response::Cancel,
                    Err(e)        => { let _ = display_tx.send(DisplayEvent::SessionEnd(session_id)); Response::Error(e.to_string()) }
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
    let mut reader = TokenReader::open().await.context("open controller")?;

    eprintln!("deckery-auth-daemon: PIN collection on {}", reader.path().display());
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
                    eprintln!("deckery-auth-daemon: Cancel (UI, session {session_id})");
                    let _ = display_tx.send(DisplayEvent::Cancel(session_id));
                    let _ = display_tx.send(DisplayEvent::SessionEnd(session_id));
                    return Ok(None);
                }
            }
        }
    }
}
