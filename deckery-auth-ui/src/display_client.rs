//! `DisplayClient` — cxx-qt QObject that subscribes to the auth daemon's
//! D-Bus display interface and makes events accessible to QML.
//!
//! Threading model
//! ───────────────
//! A background tokio thread connects to the system bus, subscribes to
//! `org.deckery.AuthDisplay1` signals, and pushes `Event` values into a
//! `Mutex<VecDeque>`.  QML calls `poll()` every 50 ms via a `Timer`;
//! `poll()` drains the queue and emits the appropriate Qt signals on the
//! main thread.
//!
//! UI-Cancel
//! ─────────
//! `send_ui_cancel()` is a synchronous invokable — it sends the session ID
//! over a `tokio::sync::mpsc::UnboundedSender` to the background thread,
//! which then calls the D-Bus method `UiCancel(session_id)` asynchronously.
//! This keeps the Qt main thread non-blocking.

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
    /// Session ID — only the owning UI reacts.
    SessionEnd(u64),
}

// ── D-Bus proxy ───────────────────────────────────────────────────────────────

/// Auto-generated proxy for `org.deckery.AuthDisplay1`.
#[zbus::proxy(
    interface = "org.deckery.AuthDisplay1",
    default_service = "org.deckery.AuthDisplay1",
    default_path = "/org/deckery/AuthDisplay",
)]
trait AuthDisplay {
    /// Request cancellation of the active session from the UI side.
    async fn ui_cancel(&self, session_id: u64) -> zbus::Result<()>;

    #[zbus(signal)]
    fn session_start(&self, source: String, session_id: u64) -> zbus::Result<()>;

    #[zbus(signal)]
    fn token(&self, token: String) -> zbus::Result<()>;

    #[zbus(signal)]
    fn backspace(&self) -> zbus::Result<()>;

    #[zbus(signal)]
    fn confirm(&self, session_id: u64) -> zbus::Result<()>;

    #[zbus(signal)]
    fn cancel(&self, session_id: u64) -> zbus::Result<()>;

    #[zbus(signal)]
    fn session_end(&self, session_id: u64) -> zbus::Result<()>;
}

// ── Rust-side state ───────────────────────────────────────────────────────────

pub struct DisplayClientRust {
    queue:              Arc<Mutex<VecDeque<Event>>>,
    started:            bool,
    /// The session ID of the currently active auth session.
    /// Used to tag UI_CANCEL commands so the daemon can ignore stale cancels.
    current_session_id: u64,
    /// Sender to background thread for UiCancel requests (carries session ID).
    /// Set when connected to D-Bus, cleared on disconnect.
    cmd_tx:             Arc<Mutex<Option<UnboundedSender<u64>>>>,
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

        /// Send a UI-initiated cancel to the daemon via D-Bus.
        /// Safe to call from QML (Qt main thread) — does not block.
        #[qinvokable]
        fn send_ui_cancel(self: Pin<&mut DisplayClient>);
    }
}

use core::pin::Pin;
use cxx_qt::CxxQtType;
use cxx_qt_lib::QString;

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
                    self.as_mut().rust_mut().current_session_id = id;
                    self.as_mut().session_started(QString::from(&src));
                }
                Event::Token(t)   => self.as_mut().token_added(QString::from(&t)),
                Event::Backspace  => self.as_mut().backspace_pressed(),
                Event::Confirm(id) if id == self.rust().current_session_id
                    => self.as_mut().confirmed(),
                Event::Cancel(id) if id == self.rust().current_session_id
                    => self.as_mut().cancelled(),
                Event::SessionEnd(id) if id == self.rust().current_session_id
                    => self.as_mut().session_ended(),
                Event::Confirm(_) | Event::Cancel(_) | Event::SessionEnd(_) => {}
            }
        }
    }

    fn send_ui_cancel(self: Pin<&mut Self>) {
        let id    = self.rust().current_session_id;
        let guard = self.rust().cmd_tx.lock().unwrap();
        if let Some(tx) = guard.as_ref() {
            let _ = tx.send(id);
        }
        // If not connected yet, the cancel is silently ignored — nothing to abort.
    }
}

// ── Background D-Bus reader ───────────────────────────────────────────────────

/// Continuously connects to the system bus, subscribes to
/// `org.deckery.AuthDisplay1` signals, and pushes events into the queue.
/// Retries automatically if the daemon is not yet running or the connection drops.
async fn reader_loop(
    queue:  Arc<Mutex<VecDeque<Event>>>,
    cmd_tx: Arc<Mutex<Option<UnboundedSender<u64>>>>,
) {
    loop {
        match connect_and_listen(&queue, &cmd_tx).await {
            Ok(()) => {
                eprintln!("deckery-auth-ui: D-Bus connection ended, reconnecting…");
            }
            Err(e) => {
                eprintln!("deckery-auth-ui: D-Bus error ({e}), retrying in 2s");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
        *cmd_tx.lock().unwrap() = None;
    }
}

async fn connect_and_listen(
    queue:  &Arc<Mutex<VecDeque<Event>>>,
    cmd_tx: &Arc<Mutex<Option<UnboundedSender<u64>>>>,
) -> zbus::Result<()> {
    use futures_util::StreamExt;

    let conn = zbus::Connection::system().await?;
    eprintln!("deckery-auth-ui: connected to D-Bus system bus");

    let proxy = AuthDisplayProxy::new(&conn).await?;
    eprintln!("deckery-auth-ui: subscribed to org.deckery.AuthDisplay1");

    // Subscribe to all signals.
    let mut session_starts = proxy.receive_session_start().await?;
    let mut tokens         = proxy.receive_token().await?;
    let mut backspaces     = proxy.receive_backspace().await?;
    let mut confirms       = proxy.receive_confirm().await?;
    let mut cancels        = proxy.receive_cancel().await?;
    let mut session_ends   = proxy.receive_session_end().await?;

    // Channel: Qt main thread → background thread for UiCancel calls.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<u64>();
    *cmd_tx.lock().unwrap() = Some(tx);

    // Spawn a task that forwards UiCancel requests to the D-Bus method.
    let proxy_cancel = proxy.clone();
    tokio::spawn(async move {
        while let Some(session_id) = rx.recv().await {
            if let Err(e) = proxy_cancel.ui_cancel(session_id).await {
                eprintln!("deckery-auth-ui: UiCancel D-Bus call failed: {e}");
            }
        }
    });

    loop {
        tokio::select! {
            Some(sig) = session_starts.next() => {
                if let Ok(args) = sig.args() {
                    queue.lock().unwrap().push_back(
                        Event::SessionStart(args.source().to_string(), *args.session_id())
                    );
                }
            }
            Some(sig) = tokens.next() => {
                if let Ok(args) = sig.args() {
                    queue.lock().unwrap().push_back(Event::Token(args.token().to_string()));
                }
            }
            Some(_) = backspaces.next() => {
                queue.lock().unwrap().push_back(Event::Backspace);
            }
            Some(sig) = confirms.next() => {
                if let Ok(args) = sig.args() {
                    queue.lock().unwrap().push_back(Event::Confirm(*args.session_id()));
                }
            }
            Some(sig) = cancels.next() => {
                if let Ok(args) = sig.args() {
                    queue.lock().unwrap().push_back(Event::Cancel(*args.session_id()));
                }
            }
            Some(sig) = session_ends.next() => {
                if let Ok(args) = sig.args() {
                    queue.lock().unwrap().push_back(Event::SessionEnd(*args.session_id()));
                }
            }
            // All signal streams ended → daemon disappeared or connection dropped.
            else => break,
        }
    }

    Ok(())
}
