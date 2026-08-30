//! `DisplayClient` — cxx-qt QObject that subscribes to the auth daemon's
//! display socket and makes events accessible to QML.
//!
//! Threading model
//! ───────────────
//! A background tokio thread reads lines from `display.sock` and pushes
//! `Event` values into a `Mutex<VecDeque>`. QML calls `poll()` every 50 ms
//! via a `Timer`; `poll()` drains the queue and emits the appropriate Qt
//! signals on the main thread.
//!
//! The socket is bidirectional: the daemon pushes events down and the UI
//! can push "UI_CANCEL\n" back up (e.g. from the on-screen Cancel button).
//! `send_ui_cancel()` is a synchronous invokable — it just calls
//! `UnboundedSender::send`, which does not need a tokio runtime on the
//! calling thread.

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
    Confirm,
    Cancel,
    SessionEnd,
}

fn parse_line(line: &str) -> Option<Event> {
    if let Some(rest) = line.strip_prefix("SESSION_START:") {
        // Format: SESSION_START:<source>:<session_id>
        // Split on the last ':' so source names with ':' are handled safely.
        let (src, id_str) = rest.rsplit_once(':')?;
        let id = id_str.parse::<u64>().ok()?;
        Some(Event::SessionStart(src.to_owned(), id))
    } else if let Some(tok) = line.strip_prefix("TOKEN:") {
        Some(Event::Token(tok.to_owned()))
    } else if line == "BACKSPACE" {
        Some(Event::Backspace)
    } else if line == "CONFIRM" {
        Some(Event::Confirm)
    } else if line == "CANCEL" {
        Some(Event::Cancel)
    } else if line == "SESSION_END" {
        Some(Event::SessionEnd)
    } else {
        None  // unknown line — ignore
    }
}

// ── Rust-side state ───────────────────────────────────────────────────────────

pub struct DisplayClientRust {
    queue:              Arc<Mutex<VecDeque<Event>>>,
    started:            bool,
    /// The session ID of the currently active auth session, as broadcast by
    /// the daemon in SESSION_START.  Used to tag UI_CANCEL commands so the
    /// daemon can ignore cancels that belong to a different session.
    current_session_id: u64,
    /// Sender half for outgoing commands to the daemon (e.g. "UI_CANCEL:<id>\n").
    /// Set when the background reader connects, cleared on disconnect.
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

        // ── Signals ───────────────────────────────────────────────────────────

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

        #[qsignal]
        fn session_ended(self: Pin<&mut DisplayClient>);

        // ── Invokables ────────────────────────────────────────────────────────

        #[qinvokable]
        fn start_listening(self: Pin<&mut DisplayClient>);

        #[qinvokable]
        fn poll(self: Pin<&mut DisplayClient>);

        /// Send a UI-initiated cancel to the daemon.
        /// Safe to call from QML (Qt main thread) — does not require tokio.
        #[qinvokable]
        fn send_ui_cancel(self: Pin<&mut DisplayClient>);
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
                    // Store session ID before emitting the signal so QML can
                    // immediately call send_ui_cancel() with the correct ID.
                    self.as_mut().rust_mut().current_session_id = id;
                    self.as_mut().session_started(QString::from(&src));
                }
                Event::Token(t)  => self.as_mut().token_added(QString::from(&t)),
                Event::Backspace => self.as_mut().backspace_pressed(),
                Event::Confirm   => self.as_mut().confirmed(),
                Event::Cancel    => self.as_mut().cancelled(),
                Event::SessionEnd => self.as_mut().session_ended(),
            }
        }
    }

    fn send_ui_cancel(self: Pin<&mut Self>) {
        // UnboundedSender::send is sync — no tokio runtime needed on caller thread.
        let id    = self.rust().current_session_id;
        let guard = self.rust().cmd_tx.lock().unwrap();
        if let Some(tx) = guard.as_ref() {
            let _ = tx.send(format!("UI_CANCEL:{id}\n"));
        }
        // If not connected yet, the cancel is silently ignored — nothing to abort.
    }
}

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

                // Split into read (events from daemon) and write (commands to daemon).
                let (read_half, mut write_half) = stream.into_split();

                // Channel for UI-initiated commands (from Qt main thread → write task).
                let (tx, mut rx) = mpsc::unbounded_channel::<String>();
                *cmd_tx.lock().unwrap() = Some(tx);

                // Spawn a task that forwards outgoing commands to the socket.
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
                            if let Some(event) = parse_line(&line) {
                                queue.lock().unwrap().push_back(event);
                            }
                        }
                        _ => break,
                    }
                }

                // Connection dropped — clear the sender so send_ui_cancel is a no-op.
                *cmd_tx.lock().unwrap() = None;
                eprintln!("deckery-auth-ui: disconnected, reconnecting…");
            }
        }
    }
}
