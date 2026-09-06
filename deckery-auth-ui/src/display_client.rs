//! `DisplayClient` — cxx-qt QObject that subscribes to the auth daemon's
//! display socket and makes events accessible to QML.
//!
//! Threading model
//! ───────────────
//! A background tokio thread connects to `/run/deckery/display.sock` and
//! pushes `Event` values into a `Mutex<VecDeque>`. QML calls `poll()` every
//! 50 ms via a `Timer`; `poll()` drains the queue and emits Qt signals on
//! the main thread.
//!
//! The daemon verifies the connecting binary via SO_PEERCRED + /proc/<pid>/exe
//! before accepting the connection. Only `/usr/local/bin/deckery-auth-ui`
//! (and any other entries in the daemon's DISPLAY_EXE_ALLOWLIST) can receive
//! display events or send UI_CANCEL commands.
//!
//! UI-Cancel
//! ─────────
//! `send_ui_cancel()` is synchronous (Qt main thread safe). It sends the
//! session ID to the background thread via an `UnboundedSender`; the thread
//! writes `UI_CANCEL:<id>\n` to the socket without blocking Qt.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc::UnboundedSender;

// ── Event type ────────────────────────────────────────────────────────────────

#[derive(Debug)]
enum Event {
    /// Source name + session ID.
    SessionStart(String, u64),
    Token(String),
    Backspace,
    /// Session ID — only the owning UI reacts.
    Confirm(u64),
    /// Session ID — only the owning UI reacts.
    Cancel(u64),
    /// Verification failed — overlay shows ✗ briefly and stays open for retry.
    WrongPassword(u64),
    /// Session ID — only the owning UI reacts.
    SessionEnd(u64),
}

fn parse_line(line: &str) -> Option<Event> {
    if let Some(rest) = line.strip_prefix("SESSION_START:") {
        let (src, id_str) = rest.rsplit_once(':')?;
        let id = id_str.parse::<u64>().ok()?;
        Some(Event::SessionStart(src.to_owned(), id))
    } else if let Some(tok) = line.strip_prefix("TOKEN:") {
        Some(Event::Token(tok.to_owned()))
    } else if line == "BACKSPACE" {
        Some(Event::Backspace)
    } else if let Some(id_str) = line.strip_prefix("CONFIRM:") {
        Some(Event::Confirm(id_str.parse().ok()?))
    } else if let Some(id_str) = line.strip_prefix("CANCEL:") {
        Some(Event::Cancel(id_str.parse().ok()?))
    } else if let Some(id_str) = line.strip_prefix("WRONG_PASSWORD:") {
        Some(Event::WrongPassword(id_str.parse().ok()?))
    } else if let Some(id_str) = line.strip_prefix("SESSION_END:") {
        Some(Event::SessionEnd(id_str.parse().ok()?))
    } else {
        None
    }
}

// ── Rust-side state ───────────────────────────────────────────────────────────

pub struct DisplayClientRust {
    queue:              Arc<Mutex<VecDeque<Event>>>,
    started:            bool,
    /// Session ID of the active auth session. Used to tag UI_CANCEL so the
    /// daemon can ignore cancels that belong to a different session.
    current_session_id: u64,
    /// Sends UI_CANCEL:<id>\n strings to the background writer task.
    /// Set when connected, cleared on disconnect.
    cmd_tx:             Arc<Mutex<Option<UnboundedSender<String>>>>,
}

impl Default for DisplayClientRust {
    fn default() -> Self {
        Self {
            queue:              Arc::new(Mutex::new(VecDeque::new())),
            started:            false,
            current_session_id: 0,
            cmd_tx:             Arc::new(Mutex::new(None)),
        }
    }
}

// ── cxx-qt bridge ─────────────────────────────────────────────────────────────

#[cxx_qt::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("cxx-qt-lib/qstring.h");
        type QString = cxx_qt_lib::QString;
    }

    unsafe extern "RustQt" {
        #[qobject]
        #[qml_element]
        type DisplayClient = super::DisplayClientRust;

        #[qsignal]
        fn session_started(self: Pin<&mut DisplayClient>, source: QString);

        #[qsignal]
        fn token_added(self: Pin<&mut DisplayClient>, token: QString);

        #[qsignal]
        fn backspace_pressed(self: Pin<&mut DisplayClient>);

        #[qsignal]
        fn confirmed(self: Pin<&mut DisplayClient>);

        #[qsignal]
        fn cancelled(self: Pin<&mut DisplayClient>);

        /// Emitted when the daemon reports a wrong PIN or password.
        /// The overlay shows ✗ briefly and stays open so the user can retry.
        #[qsignal]
        fn wrong_password(self: Pin<&mut DisplayClient>);

        #[qsignal]
        fn session_ended(self: Pin<&mut DisplayClient>);

        #[qinvokable]
        fn start_listening(self: Pin<&mut DisplayClient>);

        #[qinvokable]
        fn poll(self: Pin<&mut DisplayClient>);

        /// Hard cancel — aborts the entire auth session (no keyboard fallback).
        #[qinvokable]
        fn send_ui_cancel(self: Pin<&mut DisplayClient>);

        /// Send a password typed in the overlay's keyboard-input mode.
        /// The daemon passes it to pam_deckery as `KBD_AUTH:<pwd>`, which sets
        /// PAM_AUTHTOK and returns AUTH_ERR so pam_unix (try_first_pass) verifies
        /// it against the system password without prompting.
        #[qinvokable]
        fn send_ui_password(self: Pin<&mut DisplayClient>, password: QString);
    }
}

use core::pin::Pin;
use cxx_qt::CxxQtType;
use cxx_qt_lib::QString;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

const DISPLAY_SOCKET: &str = "/run/deckery/display.sock";

impl ffi::DisplayClient {
    fn start_listening(mut self: Pin<&mut Self>) {
        if self.rust().started {
            return;
        }
        let queue  = self.rust().queue.clone();
        let cmd_tx = self.rust().cmd_tx.clone();
        self.as_mut().rust_mut().started = true;

        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime")
                .block_on(reader_loop(queue, cmd_tx));
        });
    }

    fn poll(mut self: Pin<&mut Self>) {
        let events: Vec<Event> = {
            let mut q = self.rust().queue.lock().unwrap();
            q.drain(..).collect()
        };

        for event in events {
            match event {
                Event::SessionStart(src, id) => {
                    eprintln!("deckery-auth-ui: poll: SESSION_START src={src} id={id}");
                    self.as_mut().rust_mut().current_session_id = id;
                    self.as_mut().session_started(QString::from(&src));
                }
                Event::Token(t)   => self.as_mut().token_added(QString::from(&t)),
                Event::Backspace  => self.as_mut().backspace_pressed(),
                Event::Confirm(id) if id == self.rust().current_session_id
                    => self.as_mut().confirmed(),
                Event::Cancel(id) if id == self.rust().current_session_id
                    => self.as_mut().cancelled(),
                Event::WrongPassword(id) if id == self.rust().current_session_id
                    => self.as_mut().wrong_password(),
                Event::SessionEnd(id) if id == self.rust().current_session_id
                    => self.as_mut().session_ended(),
                Event::Confirm(_) | Event::Cancel(_) | Event::WrongPassword(_)
                | Event::SessionEnd(_) => {}
            }
        }
    }

    fn send_ui_cancel(self: Pin<&mut Self>) {
        let id    = self.rust().current_session_id;
        let guard = self.rust().cmd_tx.lock().unwrap();
        if let Some(tx) = guard.as_ref() {
            let _ = tx.send(format!("UI_CANCEL:{id}\n"));
        }
    }

    fn send_ui_password(self: Pin<&mut Self>, password: QString) {
        let id       = self.rust().current_session_id;
        let pwd_str  = password.to_string();
        let guard    = self.rust().cmd_tx.lock().unwrap();
        if let Some(tx) = guard.as_ref() {
            let _ = tx.send(format!("UI_PASSWORD:{id}:{pwd_str}\n"));
        }
    }
}

// ── Background reader ─────────────────────────────────────────────────────────

async fn reader_loop(
    queue:  Arc<Mutex<VecDeque<Event>>>,
    cmd_tx: Arc<Mutex<Option<UnboundedSender<String>>>>,
) {
    loop {
        match UnixStream::connect(DISPLAY_SOCKET).await {
            Err(e) => {
                eprintln!("deckery-auth-ui: {DISPLAY_SOCKET} unavailable ({e}), retrying in 2s");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            Ok(stream) => {
                eprintln!("deckery-auth-ui: connected to {DISPLAY_SOCKET}");

                // Note: the daemon verifies our /proc/<pid>/exe on accept.
                // If we're rejected, the socket closes immediately and we retry.

                let (read_half, mut write_half) = stream.into_split();
                let (tx, mut rx) = mpsc::unbounded_channel::<String>();
                *cmd_tx.lock().unwrap() = Some(tx);

                // Forward outgoing commands (UI_CANCEL) to the socket.
                tokio::spawn(async move {
                    while let Some(cmd) = rx.recv().await {
                        if write_half.write_all(cmd.as_bytes()).await.is_err() {
                            break;
                        }
                    }
                });

                // Read incoming event lines from the daemon.
                let mut lines = BufReader::new(read_half).lines();
                loop {
                    match lines.next_line().await {
                        Ok(Some(line)) => {
                            eprintln!("deckery-auth-ui: recv: {line}");
                            if let Some(event) = parse_line(&line) {
                                queue.lock().unwrap().push_back(event);
                            }
                        }
                        _ => break,
                    }
                }

                *cmd_tx.lock().unwrap() = None;
                eprintln!("deckery-auth-ui: disconnected, reconnecting…");
            }
        }
    }
}
