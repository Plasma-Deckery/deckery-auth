//! `DisplayClient` — cxx-qt QObject that subscribes to the auth daemon's
//! display socket and makes events accessible to QML.
//!
//! Threading model
//! ───────────────
//! A background tokio thread reads lines from `display.sock` and pushes
//! `Event` values into a `Mutex<VecDeque>`. QML calls `poll()` every 50 ms
//! via a `Timer`; `poll()` drains the queue and emits the appropriate Qt
//! signals on the main thread.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

// ── Event type ────────────────────────────────────────────────────────────────

#[derive(Debug)]
enum Event {
    SessionStart(String),
    Token(String),
    Backspace,
    Confirm,
    Cancel,
    SessionEnd,
}

fn parse_line(line: &str) -> Event {
    if let Some(src) = line.strip_prefix("SESSION_START:") {
        Event::SessionStart(src.to_owned())
    } else if let Some(tok) = line.strip_prefix("TOKEN:") {
        Event::Token(tok.to_owned())
    } else if line == "BACKSPACE" {
        Event::Backspace
    } else if line == "CONFIRM" {
        Event::Confirm
    } else if line == "CANCEL" {
        Event::Cancel
    } else {
        Event::SessionEnd
    }
}

// ── Rust-side state ───────────────────────────────────────────────────────────

pub struct DisplayClientRust {
    queue:   Arc<Mutex<VecDeque<Event>>>,
    started: bool,
}

impl Default for DisplayClientRust {
    fn default() -> Self {
        Self {
            queue:   Arc::new(Mutex::new(VecDeque::new())),
            started: false,
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
    }

}

use core::pin::Pin;
use cxx_qt::CxxQtType;
use cxx_qt_lib::QString;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixStream;

const DISPLAY_SOCKET: &str = "/run/deckery/display.sock";

impl ffi::DisplayClient {
    fn start_listening(mut self: Pin<&mut Self>) {
        if self.rust().started {
            return;
        }
        let queue = self.rust().queue.clone();
        self.as_mut().rust_mut().started = true;

        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime")
                .block_on(reader_loop(queue));
        });
    }

    fn poll(mut self: Pin<&mut Self>) {
        let events: Vec<Event> = {
            let mut q = self.rust().queue.lock().unwrap();
            q.drain(..).collect()
        };

        for event in events {
            match event {
                Event::SessionStart(src) => self.as_mut().session_started(QString::from(&src)),
                Event::Token(t)          => self.as_mut().token_added(QString::from(&t)),
                Event::Backspace         => self.as_mut().backspace_pressed(),
                Event::Confirm           => self.as_mut().confirmed(),
                Event::Cancel            => self.as_mut().cancelled(),
                Event::SessionEnd        => self.as_mut().session_ended(),
            }
        }
    }
}

async fn reader_loop(queue: Arc<Mutex<VecDeque<Event>>>) {
    loop {
        match UnixStream::connect(DISPLAY_SOCKET).await {
            Err(e) => {
                eprintln!("deckery-auth-ui: {DISPLAY_SOCKET} unavailable ({e}), retrying in 2s");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            Ok(stream) => {
                eprintln!("deckery-auth-ui: connected to {DISPLAY_SOCKET}");
                let mut lines = BufReader::new(stream).lines();
                loop {
                    match lines.next_line().await {
                        Ok(Some(line)) => {
                            queue.lock().unwrap().push_back(parse_line(&line));
                        }
                        _ => break,
                    }
                }
                eprintln!("deckery-auth-ui: disconnected, reconnecting…");
            }
        }
    }
}
