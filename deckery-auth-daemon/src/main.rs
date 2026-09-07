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
//!       │  multi-turn: recv PIN:/KBD: → send CORRECT/WRONG
//!       ▼
//!  deckery-auth-daemon (root, systemd service)
//!       │  priority queue, serves highest-priority first
//!       │  TokenReader → exclusive evdev grab + Lizard Mode
//!       │  reads tokens until Confirm / Cancel / IO error
//!       │  per-attempt: sends attempt to pam_deckery, awaits CORRECT/WRONG
//!       │  on WRONG: sends WrongPassword display event, retries
//!       │
//!       │  display.sock (mode 0666, but exe-verified)
//!       │    on connect: SO_PEERCRED → PID → /proc/<pid>/exe
//!       │    only DISPLAY_EXE_ALLOWLIST binaries are accepted
//!       │    accepted clients receive event stream (bidirectional)
//!       │    UI_CANCEL:<id>          → cancel active session if IDs match
//!       │    UI_PASSWORD:<id>:<pwd>  → keyboard password attempt
//!       ▼
//!  pam_deckery receives CORRECT (returns SUCCESS) or CANCEL (returns ABORT)
//! ```
//!
//! # Auth socket protocol (auth.sock) — multi-turn
//!
//! **Client → daemon:** `<source>\n`  e.g. `sudo`, `screenlock`
//!
//! **Daemon → client (one message per attempt):**
//! | Message | Meaning |
//! |---|---|
//! | `PIN:<encoded>\n` | Encoded controller PIN sequence |
//! | `KBD:<password>\n` | Keyboard password typed in overlay |
//! | `CANCEL\n` | User cancelled — pam_deckery returns PAM_ABORT |
//! | `ERROR:<msg>\n` | Controller unavailable or IO error |
//!
//! **Client → daemon (per attempt):**
//! | Message | Meaning |
//! |---|---|
//! | `CORRECT\n` | Verification succeeded |
//! | `WRONG\n` | Verification failed — daemon shows ✗ and waits for retry |
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
//! WRONG_PASSWORD:<session_id>\n
//! SESSION_END:<session_id>\n
//! ```
//!
//! **UI → Daemon (command lines):**
//! ```text
//! UI_CANCEL:<session_id>\n
//! UI_PASSWORD:<session_id>:<password>\n
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
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2, Params, Version,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc, Mutex, Notify};

use deckery_input::{ControlAction, Token, TokenReader, encode_sequence};

// ── PIN hash constants (shared with deckery-pin-set) ─────────────────────────

/// Where the PIN hash lives. Root-only (0600) — pam_deckery runs as root.
const PIN_HASH_PATH: &str = "/etc/deckery/pin.hash";

// Argon2id parameters — affordable on idle hardware, well above OWASP minimums.
const ARGON2_M_COST: u32 = 65536; // 64 MiB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;

// ── Makima pause / resume ─────────────────────────────────────────────────────

/// RAII guard that sends `pause` to Makima's IPC socket on creation and
/// `resume` in `Drop` — ensuring Makima is always resumed even if the session
/// exits early or panics.
///
/// If Makima is not running (socket absent or refused), creation is a no-op.
/// The auth session proceeds regardless.
struct MakimaPause;

impl MakimaPause {
    fn pause() -> Self {
        ipc_send("pause");
        Self
    }
}

impl Drop for MakimaPause {
    fn drop(&mut self) {
        ipc_send("resume");
    }
}

/// Find all Makima IPC sockets across all logged-in users.
///
/// Makima binds in `$XDG_RUNTIME_DIR` (= `/run/user/<uid>/makima-control.sock`).
/// On a multi-user system there may be more than one; we collect all of them so
/// every running Makima instance is paused / resumed.  Returns an empty Vec if
/// no socket is found (Makima not running) — callers treat that as a no-op.
fn find_makima_sockets() -> Vec<std::path::PathBuf> {
    let Ok(read_dir) = std::fs::read_dir("/run/user") else { return vec![] };
    let mut sockets = Vec::new();
    for entry in read_dir {
        let Ok(entry) = entry else { continue };
        let candidate = entry.path().join("makima-control.sock");
        if candidate.exists() {
            sockets.push(candidate);
        }
    }
    sockets
}

/// Send a single-line command to every running Makima instance. Silently
/// ignores a missing socket (Makima not running is not fatal for the daemon).
fn ipc_send(cmd: &str) {
    use std::io::Write;
    for path in find_makima_sockets() {
        match std::os::unix::net::UnixStream::connect(&path) {
            Ok(mut s) => {
                if let Err(e) = writeln!(s, "{cmd}") {
                    eprintln!("deckery-auth-daemon: makima IPC write ({path:?}): {e}");
                } else {
                    eprintln!("deckery-auth-daemon: makima IPC → {cmd}");
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                // Stale socket — Makima exited without cleanup. Skip silently.
            }
            Err(e) => eprintln!("deckery-auth-daemon: makima IPC connect ({path:?}): {e}"),
        }
    }
}

/// Root-only socket. PAM module connects here.
const AUTH_SOCKET_PATH: &str = "/run/deckery/auth.sock";

/// Display socket. World-readable but peer-verified (see [`verify_display_peer`]).
const DISPLAY_SOCKET_PATH: &str = "/run/deckery/display.sock";

/// Only these binaries may receive display events.
const DISPLAY_EXE_ALLOWLIST: &[&str] = &[
    "/usr/local/bin/deckery-auth-ui",
];

// ── Attempt / verify channel types ───────────────────────────────────────────

/// Worker → handle_incoming: "here is something to verify."
enum AttemptMsg {
    /// Encoded controller PIN sequence. Client verifies argon2.
    Pin(String),
    /// Keyboard password typed in overlay. Client verifies shadow/crypt.
    Password(String),
    /// User cancelled — send CANCEL to client and close.
    Cancel,
    /// Error (e.g. controller unavailable) — send ERROR to client and close.
    Error(String),
}

/// handle_incoming → worker: "the client said..."
#[derive(Debug, Clone, Copy)]
enum VerifyMsg {
    Correct,
    Wrong,
}

// ── Display events ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum DisplayEvent {
    // ── Normal auth events ────────────────────────────────────────────────────
    SessionStart(String, u64),
    Token(String),
    Backspace,
    Confirm(u64),
    Cancel(u64),
    /// Verification failed — overlay shows ✗ briefly and stays open for retry.
    WrongPassword(u64),
    SessionEnd(u64),
    // ── Set-PIN events ────────────────────────────────────────────────────────
    /// Phase 1: enter new PIN.
    SetPinStart,
    /// Phase 2: re-enter PIN to confirm.
    SetPinPhase2,
    /// The two entries did not match — UI shows ✗ and restarts phase 1.
    SetPinMismatch,
    /// PIN saved successfully — UI shows ✓ briefly then closes.
    SetPinDone,
    /// User pressed Cancel during set-PIN — UI closes.
    SetPinCancel,
    /// Unrecoverable error during set-PIN (e.g. controller unavailable).
    SetPinError(String),
}

impl DisplayEvent {
    fn to_line(&self) -> String {
        match self {
            DisplayEvent::SessionStart(src, id) => format!("SESSION_START:{src}:{id}\n"),
            DisplayEvent::Token(t)              => format!("TOKEN:{t}\n"),
            DisplayEvent::Backspace             => "BACKSPACE\n".to_string(),
            DisplayEvent::Confirm(id)           => format!("CONFIRM:{id}\n"),
            DisplayEvent::Cancel(id)            => format!("CANCEL:{id}\n"),
            DisplayEvent::WrongPassword(id)     => format!("WRONG_PASSWORD:{id}\n"),
            DisplayEvent::SessionEnd(id)        => format!("SESSION_END:{id}\n"),
            DisplayEvent::SetPinStart           => "SET_PIN_START\n".to_string(),
            DisplayEvent::SetPinPhase2          => "SET_PIN_PHASE2\n".to_string(),
            DisplayEvent::SetPinMismatch        => "SET_PIN_MISMATCH\n".to_string(),
            DisplayEvent::SetPinDone            => "SET_PIN_DONE\n".to_string(),
            DisplayEvent::SetPinCancel          => "SET_PIN_CANCEL\n".to_string(),
            DisplayEvent::SetPinError(e)        => format!("SET_PIN_ERROR:{e}\n"),
        }
    }
}

// ── Display peer verification ─────────────────────────────────────────────────

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
            let exe = path_str.trim_end_matches(" (deleted)");

            let allowed = DISPLAY_EXE_ALLOWLIST.iter().any(|&entry| {
                if exe == entry { return true; }
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
    priority:   u8,
    sequence:   u64,
    source:     String,
    /// Worker sends attempts (PIN/Password/Cancel/Error) through this channel.
    /// `handle_incoming` reads from the paired receiver and writes to the socket.
    attempt_tx: mpsc::UnboundedSender<AttemptMsg>,
    /// `handle_incoming` sends verify results (Correct/Wrong) through this channel.
    /// Worker reads from the paired receiver to decide whether to retry or finish.
    verify_rx:  mpsc::UnboundedReceiver<VerifyMsg>,
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

    /// Push a new entry. Returns the (attempt_tx, verify_rx) pair for the worker.
    /// The caller (`handle_incoming`) keeps (attempt_rx, verify_tx).
    fn push(
        &mut self,
        source:     String,
        attempt_tx: mpsc::UnboundedSender<AttemptMsg>,
        verify_rx:  mpsc::UnboundedReceiver<VerifyMsg>,
    ) {
        let priority = priority_for_source(&source);
        let sequence = self.sequence;
        self.sequence += 1;
        self.heap.push(QueueEntry { priority, sequence, source, attempt_tx, verify_rx });
    }

    fn pop(&mut self) -> Option<QueueEntry> { self.heap.pop() }
    fn len(&self) -> usize { self.heap.len() }
}

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

    let (display_tx, _)     = broadcast::channel::<DisplayEvent>(64);
    let (ui_cancel_tx, _)   = broadcast::channel::<u64>(4);
    let (ui_password_tx, _) = broadcast::channel::<(u64, String)>(4);

    let active_session: Arc<Mutex<Option<(String, u64)>>> = Arc::new(Mutex::new(None));

    tokio::spawn(worker_loop(
        queue.clone(), notify.clone(),
        display_tx.clone(), ui_cancel_tx.clone(), ui_password_tx.clone(),
        active_session.clone(),
    ));
    tokio::spawn(display_accept_loop(
        display_tx.clone(), ui_cancel_tx, ui_password_tx, active_session,
    ));
    auth_accept_loop(listener, queue, notify, display_tx).await;

    Ok(())
}

// ── Display socket ────────────────────────────────────────────────────────────

async fn display_accept_loop(
    display_tx:      broadcast::Sender<DisplayEvent>,
    ui_cancel_tx:    broadcast::Sender<u64>,
    ui_password_tx:  broadcast::Sender<(u64, String)>,
    active_session:  Arc<Mutex<Option<(String, u64)>>>,
) {
    let _ = tokio::fs::remove_file(DISPLAY_SOCKET_PATH).await;
    let listener = match UnixListener::bind(DISPLAY_SOCKET_PATH) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("deckery-auth-daemon: cannot bind display socket: {e}");
            return;
        }
    };
    let _ = std::fs::set_permissions(
        DISPLAY_SOCKET_PATH,
        std::fs::Permissions::from_mode(0o666),
    );
    eprintln!("deckery-auth-daemon: display socket at {DISPLAY_SOCKET_PATH} (exe-verified)");

    loop {
        match listener.accept().await {
            Err(e) => eprintln!("deckery-auth-daemon: display accept error: {e}"),
            Ok((stream, _)) => {
                if !verify_display_peer(&stream) { continue; }
                let rx     = display_tx.subscribe();
                let replay = { active_session.lock().await.clone() };
                tokio::spawn(handle_display_connection(
                    stream, rx, ui_cancel_tx.clone(), ui_password_tx.clone(), replay,
                ));
            }
        }
    }
}

async fn handle_display_connection(
    stream:         UnixStream,
    mut rx:         broadcast::Receiver<DisplayEvent>,
    ui_cancel_tx:   broadcast::Sender<u64>,
    ui_password_tx: broadcast::Sender<(u64, String)>,
    replay:         Option<(String, u64)>,
) {
    let (read_half, mut write_half) = stream.into_split();
    let mut incoming = BufReader::new(read_half).lines();

    if let Some((source, id)) = replay {
        eprintln!("deckery-auth-daemon: replaying SESSION_START:{source}:{id} to reconnected display client");
        let line = DisplayEvent::SessionStart(source, id).to_line();
        if write_half.write_all(line.as_bytes()).await.is_err() { return; }
    }

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
                    Ok(Some(l)) if l.trim().starts_with("UI_PASSWORD:") => {
                        let rest = l.trim().strip_prefix("UI_PASSWORD:").unwrap_or("");
                        if let Some((id_str, password)) = rest.split_once(':') {
                            if let Ok(id) = id_str.parse::<u64>() {
                                eprintln!("deckery-auth-daemon: UI keyboard password (session {id})");
                                let _ = ui_password_tx.send((id, password.to_owned()));
                            }
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
    listener:   UnixListener,
    queue:      Arc<Mutex<Queue>>,
    notify:     Arc<Notify>,
    display_tx: broadcast::Sender<DisplayEvent>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => tokio::spawn(handle_incoming(
                stream, queue.clone(), notify.clone(), display_tx.clone(),
            )),
            Err(e) => { eprintln!("deckery-auth-daemon: accept error: {e}"); continue; }
        };
    }
}

/// Handles one connection on `auth.sock`.
///
/// Reads the first line to determine the request type:
/// - `"SET_PIN"` → [`handle_set_pin`] (root-only, controller-based PIN setup)
/// - anything else → treated as PAM source name and added to the auth queue
///
/// For the normal PAM flow the function mediates the multi-turn protocol
/// between the socket (pam_deckery) and the worker (`collect_pin`):
///
/// ```text
/// worker ──AttemptMsg──► handle_incoming ──PIN:/KBD:/CANCEL/ERROR──► pam_deckery
/// worker ◄──VerifyMsg─── handle_incoming ◄──────CORRECT/WRONG──────── pam_deckery
/// ```
async fn handle_incoming(
    mut stream: UnixStream,
    queue:      Arc<Mutex<Queue>>,
    notify:     Arc<Notify>,
    display_tx: broadcast::Sender<DisplayEvent>,
) {
    // Read first line — determines the request type.
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

    // SET_PIN is a privileged out-of-band command — not an auth session.
    if source == "SET_PIN" {
        handle_set_pin(stream, display_tx).await;
        return;
    }

    let priority = priority_for_source(&source);

    // Create the two channels that connect this handler with the worker.
    // handle_incoming keeps:  attempt_rx (reads attempts) + verify_tx (sends results)
    // QueueEntry keeps:       attempt_tx (sends attempts) + verify_rx (reads results)
    let (attempt_tx, mut attempt_rx) = mpsc::unbounded_channel::<AttemptMsg>();
    let (verify_tx,      verify_rx ) = mpsc::unbounded_channel::<VerifyMsg>();

    let queue_len = {
        let mut q = queue.lock().await;
        q.push(source.clone(), attempt_tx, verify_rx);
        q.len()
    };
    notify.notify_one();

    eprintln!("deckery-auth-daemon: queued '{source}' (priority {priority}) — {queue_len} request(s)");

    // Split into owned halves so we can write and read concurrently without
    // borrow conflicts.
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    let mut idle_buf = String::new();
    loop {
        // Wait for the next attempt from collect_pin, OR detect that pam_deckery
        // closed the connection (EOF/error on the read half while we're idle).
        // In the idle state pam_deckery sends nothing, so any read result means
        // the peer disconnected — drop channels so collect_pin can clean up.
        let msg = tokio::select! {
            msg = attempt_rx.recv() => match msg {
                None      => break,   // collect_pin dropped sender — session over
                Some(msg) => msg,
            },
            result = reader.read_line(&mut idle_buf) => {
                // Ok(0) = EOF (pam_deckery died/timed out), Err = broken pipe.
                // Either way: peer is gone. Dropping verify_tx here will cause
                // collect_pin's verify_rx.recv() to return None → clean exit.
                let _ = result;
                eprintln!("deckery-auth-daemon: pam_deckery disconnected mid-session — cleaning up");
                break;
            }
        };

        match msg {
            AttemptMsg::Cancel => {
                let _ = write_half.write_all(b"CANCEL\n").await;
                break;
            }
            AttemptMsg::Error(e) => {
                let _ = write_half.write_all(format!("ERROR:{e}\n").as_bytes()).await;
                break;
            }
            AttemptMsg::Pin(encoded) => {
                if write_half.write_all(format!("PIN:{encoded}\n").as_bytes()).await.is_err() {
                    break;
                }
            }
            AttemptMsg::Password(pwd) => {
                if write_half.write_all(format!("KBD:{pwd}\n").as_bytes()).await.is_err() {
                    break;
                }
            }
        }

        // Read CORRECT or WRONG from pam_deckery.
        let mut line = String::new();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let response = line.trim_end_matches(['\n', '\r']);
        let result = if response == "CORRECT" { VerifyMsg::Correct } else { VerifyMsg::Wrong };
        let _ = verify_tx.send(result);

        if matches!(result, VerifyMsg::Correct) {
            break;  // Done — worker will send Confirm+SessionEnd display events.
        }
        // Wrong → loop: wait for worker to send next AttemptMsg.
    }
}

// ── SET_PIN handler ───────────────────────────────────────────────────────────

/// Handle a `SET_PIN` command from `auth.sock`.
///
/// Security invariants:
/// - The caller's UID is verified via `SO_PEERCRED` — only root (UID 0) is
///   allowed.  `auth.sock` is 0600 so non-root cannot even connect, but
///   `SO_PEERCRED` adds a defence-in-depth layer that is unforgeable.
/// - At least one display client must be connected — otherwise the user would
///   have no way to see the token display or enter the PIN.
async fn handle_set_pin(
    mut stream: UnixStream,
    display_tx: broadcast::Sender<DisplayEvent>,
) {
    // Verify caller is root via SO_PEERCRED.
    match stream.peer_cred() {
        Err(e) => {
            eprintln!("deckery-auth-daemon: SET_PIN peer_cred failed: {e}");
            let _ = stream.write_all(b"ERROR:internal\n").await;
            return;
        }
        Ok(cred) if cred.uid() != 0 => {
            eprintln!("deckery-auth-daemon: SET_PIN rejected — caller uid={}", cred.uid());
            let _ = stream.write_all(b"ERROR:permission denied\n").await;
            return;
        }
        Ok(_) => {}
    }

    // Require an active display client (user needs to see the UI).
    if display_tx.receiver_count() == 0 {
        eprintln!("deckery-auth-daemon: SET_PIN rejected — no display client connected");
        let _ = stream.write_all(b"ERROR:no display client connected\n").await;
        return;
    }

    eprintln!("deckery-auth-daemon: entering SET_PIN mode");
    let _makima_pause = MakimaPause::pause();

    match collect_pin_set(&display_tx).await {
        Ok(()) => {
            eprintln!("deckery-auth-daemon: SET_PIN complete");
            let _ = stream.write_all(b"PIN_SET\n").await;
        }
        Err(SetPinError::Cancel) => {
            eprintln!("deckery-auth-daemon: SET_PIN cancelled by user");
            let _ = stream.write_all(b"CANCEL\n").await;
        }
        Err(SetPinError::Controller(e)) => {
            eprintln!("deckery-auth-daemon: SET_PIN controller error: {e:#}");
            let _ = display_tx.send(DisplayEvent::SetPinError(e.to_string()));
            let _ = stream.write_all(format!("ERROR:{e}\n").as_bytes()).await;
        }
        Err(SetPinError::Write(e)) => {
            eprintln!("deckery-auth-daemon: SET_PIN write error: {e:#}");
            let _ = display_tx.send(DisplayEvent::SetPinError(e.to_string()));
            let _ = stream.write_all(format!("ERROR:{e}\n").as_bytes()).await;
        }
    }
}

enum SetPinError {
    Cancel,
    Controller(anyhow::Error),
    Write(anyhow::Error),
}

impl From<anyhow::Error> for SetPinError {
    fn from(e: anyhow::Error) -> Self { SetPinError::Controller(e) }
}

/// Collect the PIN twice from the controller, compare, and write the hash.
///
/// Loops on mismatch — the user can try again without re-running the command.
/// Returns `Err(Cancel)` if the user presses Cancel at any point.
async fn collect_pin_set(
    display_tx: &broadcast::Sender<DisplayEvent>,
) -> Result<(), SetPinError> {
    let mut reader = TokenReader::open().await
        .map_err(|e| SetPinError::Controller(e.into()))?;

    eprintln!("deckery-auth-daemon: SET_PIN controller on {}", reader.path().display());

    loop {
        // Phase 1 — enter new PIN.
        let _ = display_tx.send(DisplayEvent::SetPinStart);
        let first = collect_one_pin_set(&mut reader, display_tx).await?;

        // Phase 2 — confirm.
        let _ = display_tx.send(DisplayEvent::SetPinPhase2);
        let second = collect_one_pin_set(&mut reader, display_tx).await?;

        if first == second {
            // Hash and write.
            let hash = hash_pin_for_set(&first)
                .map_err(SetPinError::Write)?;
            write_pin_hash(&hash)
                .map_err(SetPinError::Write)?;
            let _ = display_tx.send(DisplayEvent::SetPinDone);
            return Ok(());
        } else {
            // Mismatch — show error and restart phase 1.
            eprintln!("deckery-auth-daemon: SET_PIN mismatch — restarting");
            let _ = display_tx.send(DisplayEvent::SetPinMismatch);
            tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        }
    }
}

/// Collect tokens until Confirm or Cancel.  Returns encoded sequence on
/// Confirm, or `Err(Cancel)` when the user presses Cancel.
async fn collect_one_pin_set(
    reader:     &mut TokenReader,
    display_tx: &broadcast::Sender<DisplayEvent>,
) -> Result<String, SetPinError> {
    let mut tokens: Vec<Token> = Vec::new();
    loop {
        let token = reader.next_token().await
            .map_err(|e| SetPinError::Controller(e.into()))?;
        match token {
            Token::Control(ControlAction::Confirm) => {
                return Ok(encode_sequence(&tokens));
            }
            Token::Control(ControlAction::Cancel) => {
                let _ = display_tx.send(DisplayEvent::SetPinCancel);
                return Err(SetPinError::Cancel);
            }
            Token::Control(ControlAction::Backspace) => {
                tokens.pop();
                let _ = display_tx.send(DisplayEvent::Backspace);
            }
            Token::Release(_) => {}
            t @ Token::Chord(_) => {
                let encoded = t.encode();
                let _ = display_tx.send(DisplayEvent::Token(encoded));
                tokens.push(t);
            }
        }
    }
}

fn hash_pin_for_set(encoded: &str) -> Result<String> {
    let salt   = SaltString::generate(&mut OsRng);
    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, None)
        .map_err(|e| anyhow::anyhow!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);
    let hash   = argon2
        .hash_password(encoded.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2 hash: {e}"))?;
    Ok(hash.to_string())
}

fn write_pin_hash(hash: &str) -> Result<()> {
    use std::fs;
    let dir = std::path::Path::new(PIN_HASH_PATH)
        .parent()
        .expect("PIN_HASH_PATH has parent");
    fs::create_dir_all(dir)
        .with_context(|| format!("create {}", dir.display()))?;
    fs::write(PIN_HASH_PATH, hash)
        .with_context(|| format!("write {PIN_HASH_PATH}"))?;
    fs::set_permissions(PIN_HASH_PATH, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 600 {PIN_HASH_PATH}"))?;
    eprintln!("deckery-auth-daemon: PIN hash written to {PIN_HASH_PATH}");
    Ok(())
}

// ── Worker ────────────────────────────────────────────────────────────────────

async fn worker_loop(
    queue:          Arc<Mutex<Queue>>,
    notify:         Arc<Notify>,
    display_tx:     broadcast::Sender<DisplayEvent>,
    ui_cancel_tx:   broadcast::Sender<u64>,
    ui_password_tx: broadcast::Sender<(u64, String)>,
    active_session: Arc<Mutex<Option<(String, u64)>>>,
) {
    let mut next_session_id: u64 = 0;
    loop {
        let entry = { let mut q = queue.lock().await; q.pop() };
        match entry {
            None => { notify.notified().await; }
            Some(entry) => {
                // Detect abandoned connections (pam_deckery disconnected before
                // being served). attempt_tx is closed when handle_incoming exits.
                if entry.attempt_tx.is_closed() {
                    eprintln!("deckery-auth-daemon: '{}' abandoned (client disconnected)", entry.source);
                    continue;
                }
                eprintln!("deckery-auth-daemon: serving '{}' (priority {})", entry.source, entry.priority);
                let session_id = next_session_id;
                next_session_id += 1;
                *active_session.lock().await = Some((entry.source.clone(), session_id));

                // Pause Makima for the duration of the session so it doesn't
                // process the same controller input we're consuming.
                // The guard sends SIGCONT automatically when dropped.
                let _makima_pause = MakimaPause::pause();

                collect_pin(
                    entry.attempt_tx,
                    entry.verify_rx,
                    &entry.source,
                    &display_tx,
                    &ui_cancel_tx,
                    &ui_password_tx,
                    session_id,
                ).await;

                drop(_makima_pause); // resume Makima before clearing active session
                *active_session.lock().await = None;
            }
        }
    }
}

// ── PIN collection ────────────────────────────────────────────────────────────

async fn collect_pin(
    attempt_tx:     mpsc::UnboundedSender<AttemptMsg>,
    mut verify_rx:  mpsc::UnboundedReceiver<VerifyMsg>,
    source:         &str,
    display_tx:     &broadcast::Sender<DisplayEvent>,
    ui_cancel_tx:   &broadcast::Sender<u64>,
    ui_password_tx: &broadcast::Sender<(u64, String)>,
    session_id:     u64,
) {
    let mut reader = match TokenReader::open().await {
        Ok(r)  => r,
        Err(e) => {
            eprintln!("deckery-auth-daemon: cannot open controller (session {session_id}): {e:#}");
            let _ = attempt_tx.send(AttemptMsg::Error(e.to_string()));
            let _ = display_tx.send(DisplayEvent::SessionEnd(session_id));
            return;
        }
    };

    eprintln!("deckery-auth-daemon: PIN collection on {} (session {session_id})", reader.path().display());
    let _ = display_tx.send(DisplayEvent::SessionStart(source.to_string(), session_id));

    let mut ui_cancel_rx   = ui_cancel_tx.subscribe();
    let mut ui_password_rx = ui_password_tx.subscribe();
    let mut tokens: Vec<Token> = Vec::new();

    loop {
        tokio::select! {
            token_result = reader.next_token() => {
                let token = match token_result {
                    Ok(t)  => t,
                    Err(e) => {
                        eprintln!("deckery-auth-daemon: controller error (session {session_id}): {e:#}");
                        let _ = attempt_tx.send(AttemptMsg::Error(e.to_string()));
                        let _ = display_tx.send(DisplayEvent::SessionEnd(session_id));
                        return;
                    }
                };
                match token {
                    Token::Control(ControlAction::Confirm) => {
                        let encoded = encode_sequence(&tokens);
                        eprintln!("deckery-auth-daemon: Confirm — sending PIN (session {session_id})");
                        if attempt_tx.send(AttemptMsg::Pin(encoded)).is_err() { return; }

                        match verify_rx.recv().await {
                            None => {
                                // handle_incoming dropped verify_tx — pam_deckery gone.
                                eprintln!("deckery-auth-daemon: pam_deckery gone after PIN (session {session_id})");
                                let _ = display_tx.send(DisplayEvent::SessionEnd(session_id));
                                return;
                            }
                            Some(VerifyMsg::Correct) => {
                                eprintln!("deckery-auth-daemon: PIN correct (session {session_id})");
                                let _ = display_tx.send(DisplayEvent::Confirm(session_id));
                                let _ = display_tx.send(DisplayEvent::SessionEnd(session_id));
                                return;
                            }
                            Some(VerifyMsg::Wrong) => {
                                eprintln!("deckery-auth-daemon: PIN wrong (session {session_id})");
                                tokens.clear();
                                let _ = display_tx.send(DisplayEvent::WrongPassword(session_id));
                                // Continue — user can retry.
                            }
                        }
                    }
                    Token::Control(ControlAction::Backspace) => {
                        tokens.pop();
                        eprintln!("deckery-auth-daemon: Backspace (session {session_id})");
                        let _ = display_tx.send(DisplayEvent::Backspace);
                    }
                    Token::Control(ControlAction::Cancel) => {
                        eprintln!("deckery-auth-daemon: Cancel (controller, session {session_id})");
                        let _ = attempt_tx.send(AttemptMsg::Cancel);
                        let _ = display_tx.send(DisplayEvent::Cancel(session_id));
                        let _ = display_tx.send(DisplayEvent::SessionEnd(session_id));
                        return;
                    }
                    Token::Release(_) => {}
                    t @ Token::Chord(_) => {
                        let encoded = t.encode();
                        let _ = display_tx.send(DisplayEvent::Token(encoded));
                        tokens.push(t);
                    }
                }
            }

            Ok(id) = ui_cancel_rx.recv() => {
                if id == session_id {
                    eprintln!("deckery-auth-daemon: Cancel (UI, session {session_id})");
                    let _ = attempt_tx.send(AttemptMsg::Cancel);
                    let _ = display_tx.send(DisplayEvent::Cancel(session_id));
                    let _ = display_tx.send(DisplayEvent::SessionEnd(session_id));
                    return;
                }
            }

            Ok((id, pwd)) = ui_password_rx.recv() => {
                if id == session_id {
                    eprintln!("deckery-auth-daemon: keyboard password (session {session_id})");
                    if attempt_tx.send(AttemptMsg::Password(pwd)).is_err() { return; }

                    match verify_rx.recv().await {
                        None => {
                            eprintln!("deckery-auth-daemon: pam_deckery gone after password (session {session_id})");
                            let _ = display_tx.send(DisplayEvent::SessionEnd(session_id));
                            return;
                        }
                        Some(VerifyMsg::Correct) => {
                            eprintln!("deckery-auth-daemon: password correct (session {session_id})");
                            let _ = display_tx.send(DisplayEvent::Confirm(session_id));
                            let _ = display_tx.send(DisplayEvent::SessionEnd(session_id));
                            return;
                        }
                        Some(VerifyMsg::Wrong) => {
                            eprintln!("deckery-auth-daemon: password wrong (session {session_id})");
                            tokens.clear();
                            let _ = display_tx.send(DisplayEvent::WrongPassword(session_id));
                            // Continue — user can retry (password field was cleared by QML on submit).
                        }
                    }
                }
            }
        }
    }
}
