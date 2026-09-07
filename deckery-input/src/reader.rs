//! [`TokenReader`] — async translation of controller events into [`Token`]s.
//!
//! # Token rules
//!
//! - Every button press emits [`Token::Chord`] containing all currently held
//!   buttons (including the one just pressed), in press order.
//! - Every button release emits [`Token::Release`] immediately.
//! - Control buttons (Confirm / Backspace / Cancel) emit [`Token::Control`]
//!   on press only; their release is silently ignored.
//! - Key auto-repeat events (value = 2) are ignored throughout.
//!
//! [`Token::Release`] encodes to an empty string and is therefore excluded
//! from the PAM credential. It exists solely for the visualization layer.

use evdev::{EventType, InputEvent, Key};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, Notify};

use deckery_controller::{
    ControllerEvent, HapticRequest, LizardModeHandle, LizardModeSuppression,
    PadFrame, SteamDeckController,
};

use crate::{Button, ControlAction, Token};

// ── Key → token mapping ───────────────────────────────────────────────────────

fn key_to_button(key: Key) -> Option<Button> {
    match key {
        Key::BTN_SOUTH  => Some(Button::A),
        Key::BTN_EAST   => Some(Button::B),
        Key::BTN_NORTH  => Some(Button::X),  // BTN_NORTH = 0x133 = BTN_X alias
        Key::BTN_WEST   => Some(Button::Y),  // BTN_WEST  = 0x134 = BTN_Y alias
        // Shoulder buttons — regular buttons, not special modifiers.
        Key::BTN_TL     => Some(Button::L1),
        Key::BTN_TR     => Some(Button::R1),
        // Triggers (digital)
        Key::BTN_TL2    => Some(Button::L2),
        Key::BTN_TR2    => Some(Button::R2),
        // Back paddles — requires the Plasma-Deckery evdev fork.
        Key::BTN_GRIPL  => Some(Button::L4),
        Key::BTN_GRIPR  => Some(Button::R4),
        Key::BTN_GRIPL2 => Some(Button::L5),
        Key::BTN_GRIPR2 => Some(Button::R5),
        // D-pad as discrete key events (BTN_DPAD_*).
        Key::BTN_DPAD_UP    => Some(Button::Up),
        Key::BTN_DPAD_DOWN  => Some(Button::Down),
        Key::BTN_DPAD_LEFT  => Some(Button::Left),
        Key::BTN_DPAD_RIGHT => Some(Button::Right),
        _ => None,
    }
}

fn key_to_control(key: Key) -> Option<ControlAction> {
    match key {
        Key::BTN_START  => Some(ControlAction::Confirm),
        Key::BTN_SELECT => Some(ControlAction::Backspace),
        Key::BTN_BASE   => Some(ControlAction::Cancel),
        _ => None,
    }
}

// ── TokenReader ───────────────────────────────────────────────────────────────

/// Translates a stream of [`ControllerEvent`]s into auth [`Token`]s.
///
/// Construct via [`TokenReader::open`] for production use, or
/// [`TokenReader::from_channel`] for testing.
pub struct TokenReader {
    rx:           mpsc::Receiver<ControllerEvent>,
    path:         PathBuf,
    /// Keeps Lizard Mode suppression alive. `None` in tests (no hardware).
    _lizard_mode: Option<LizardModeHandle>,
    /// Haptic feedback channel. `None` if no hidraw sibling was found.
    haptic_tx:    Option<mpsc::Sender<HapticRequest>>,
    /// Keeps the PadFrame receiver alive when using the hidraw backend.
    ///
    /// The hidraw reader task exits as soon as the PadFrame receiver is dropped
    /// (it treats that as "trackpad router gone"). We don't consume pad frames
    /// here, but we must hold the receiver so the reader keeps running and
    /// continues to forward controller events via `event_tx`.
    _pad_rx:      Option<mpsc::Receiver<PadFrame>>,
    /// Buttons currently held down, in press order (oldest first).
    held:         Vec<Button>,
}

impl TokenReader {
    // ── Constructors ──────────────────────────────────────────────────────────

    /// Create a `TokenReader` from an existing event channel.
    ///
    /// Used in tests and by higher-level code that manages the hardware task
    /// separately. Lizard Mode suppression and haptics are not active.
    pub fn from_channel(rx: mpsc::Receiver<ControllerEvent>, path: PathBuf) -> Self {
        Self { rx, path, _lizard_mode: None, haptic_tx: None, _pad_rx: None, held: Vec::new() }
    }

    /// Find the Steam Deck controller, start Lizard Mode suppression and
    /// hidraw tasks, and return a ready `TokenReader`.
    pub async fn open() -> Result<Self, std::io::Error> {
        let controller = SteamDeckController::find()
            .ok_or_else(|| std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no Steam Deck controller found — is the controller connected?",
            ))?;

        let path = controller.evdev_path.clone();
        let lizard_cfg = LizardModeSuppression {
            suppress_buttons: true,
            suppress_mouse:   true,
        };

        let session = controller.start(
            Arc::new(Notify::new()),
            Some(lizard_cfg),
        ).await?;

        // The hidraw reader sends PadFrames via an mpsc channel (capacity 64).
        // TokenReader doesn't use pad data, but must keep the receiver alive so
        // the reader task doesn't exit.  Simply holding the receiver without
        // reading it fills the channel after 64 unique pad states (< 1 s of
        // sensor noise), after which every `tx.send().await` in the reader
        // blocks — preventing button events from being synthesised at all.
        //
        // Fix: spawn a drain task that reads and discards frames continuously.
        // This keeps the channel empty so the reader never stalls.  When
        // `TokenReader` is dropped, `event_rx` is dropped → the reader exits on
        // its next `event_tx.send(...).is_err()` → `frame_tx` is dropped → the
        // drain task sees `None` from `recv()` and exits cleanly.
        if let Some(mut pad_rx) = session.pad_rx {
            tokio::spawn(async move { while pad_rx.recv().await.is_some() {} });
        }

        Ok(Self {
            rx:           session.event_rx,
            path,
            _lizard_mode: Some(session.lizard_mode),
            haptic_tx:    session.haptic_tx,
            _pad_rx:      None,   // drained by the task above; None is safe here
            held:         Vec::new(),
        })
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// The `/dev/input/eventN` path of the grabbed device.
    pub fn path(&self) -> &std::path::Path { &self.path }

    /// Haptic feedback sender, if available.
    pub fn haptic_tx(&self) -> Option<&mpsc::Sender<HapticRequest>> {
        self.haptic_tx.as_ref()
    }

    /// Wait for the next [`Token`].
    ///
    /// Returns `Err` when the channel is closed (device gone or hardware task
    /// exited).
    pub async fn next_token(&mut self) -> Result<Token, std::io::Error> {
        loop {
            match self.rx.recv().await {
                Some(ControllerEvent::Input(event)) => {
                    if let Some(token) = self.process(event) {
                        return Ok(token);
                    }
                }
                Some(ControllerEvent::Reconnected) => self.reset(),
                Some(ControllerEvent::ReleaseAll)  => self.reset(),
                None => return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "controller event channel closed",
                )),
            }
        }
    }

    /// Reset held-button state (called on reconnect).
    pub fn reset(&mut self) {
        self.held.clear();
    }

    // ── Event processing ──────────────────────────────────────────────────────

    fn process(&mut self, event: InputEvent) -> Option<Token> {
        if event.event_type() != EventType::KEY { return None; }
        let key      = Key::new(event.code());
        let value    = event.value();
        let pressed  = value == 1;
        let released = value == 0;
        // value == 2 is auto-repeat — ignored

        if pressed {
            if let Some(action) = key_to_control(key) {
                return Some(Token::Control(action));
            }
        }

        if let Some(button) = key_to_button(key) {
            if pressed  { return Some(self.handle_press(button)); }
            if released { return Some(self.handle_release(button)); }
        }

        None
    }

    fn handle_press(&mut self, button: Button) -> Token {
        self.held.push(button);
        Token::Chord(self.held.clone())
    }

    fn handle_release(&mut self, button: Button) -> Token {
        self.held.retain(|&b| b != button);
        Token::Release(button)
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use evdev::EventType;

    fn press(key: Key) -> ControllerEvent {
        ControllerEvent::Input(InputEvent::new(EventType::KEY, key.code(), 1))
    }

    fn release(key: Key) -> ControllerEvent {
        ControllerEvent::Input(InputEvent::new(EventType::KEY, key.code(), 0))
    }

    fn make_reader() -> (mpsc::Sender<ControllerEvent>, TokenReader) {
        let (tx, rx) = mpsc::channel(64);
        let reader = TokenReader::from_channel(rx, PathBuf::from("/dev/input/test"));
        (tx, reader)
    }

    fn chord(buttons: &[Button]) -> Token {
        Token::Chord(buttons.to_vec())
    }

    // ── Single-button presses ─────────────────────────────────────────────────

    #[tokio::test]
    async fn simple_press_face_buttons() {
        let (tx, mut reader) = make_reader();
        for (key, btn) in [
            (Key::BTN_SOUTH, Button::A),
            (Key::BTN_EAST,  Button::B),
            (Key::BTN_NORTH, Button::X),
            (Key::BTN_WEST,  Button::Y),
        ] {
            tx.send(press(key)).await.unwrap();
            assert_eq!(reader.next_token().await.unwrap(), chord(&[btn]));
            tx.send(release(key)).await.unwrap();
            assert_eq!(reader.next_token().await.unwrap(), Token::Release(btn));
        }
    }

    #[tokio::test]
    async fn shoulder_buttons_are_regular() {
        let (tx, mut reader) = make_reader();
        tx.send(press(Key::BTN_TL)).await.unwrap();
        assert_eq!(reader.next_token().await.unwrap(), chord(&[Button::L1]));
        tx.send(release(Key::BTN_TL)).await.unwrap();
        assert_eq!(reader.next_token().await.unwrap(), Token::Release(Button::L1));

        tx.send(press(Key::BTN_TR)).await.unwrap();
        assert_eq!(reader.next_token().await.unwrap(), chord(&[Button::R1]));
        tx.send(release(Key::BTN_TR)).await.unwrap();
        assert_eq!(reader.next_token().await.unwrap(), Token::Release(Button::R1));
    }

    #[tokio::test]
    async fn triggers_and_paddles() {
        let (tx, mut reader) = make_reader();
        for (key, btn) in [
            (Key::BTN_TL2,    Button::L2),
            (Key::BTN_TR2,    Button::R2),
            (Key::BTN_GRIPL,  Button::L4),
            (Key::BTN_GRIPR,  Button::R4),
            (Key::BTN_GRIPL2, Button::L5),
            (Key::BTN_GRIPR2, Button::R5),
        ] {
            tx.send(press(key)).await.unwrap();
            assert_eq!(reader.next_token().await.unwrap(), chord(&[btn]));
            tx.send(release(key)).await.unwrap();
            assert_eq!(reader.next_token().await.unwrap(), Token::Release(btn));
        }
    }

    #[tokio::test]
    async fn dpad_directions() {
        let (tx, mut reader) = make_reader();
        for (key, btn) in [
            (Key::BTN_DPAD_UP,    Button::Up),
            (Key::BTN_DPAD_DOWN,  Button::Down),
            (Key::BTN_DPAD_LEFT,  Button::Left),
            (Key::BTN_DPAD_RIGHT, Button::Right),
        ] {
            tx.send(press(key)).await.unwrap();
            assert_eq!(reader.next_token().await.unwrap(), chord(&[btn]));
            tx.send(release(key)).await.unwrap();
            assert_eq!(reader.next_token().await.unwrap(), Token::Release(btn));
        }
    }

    // ── Control actions ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn control_actions() {
        let (tx, mut reader) = make_reader();
        for (key, expected) in [
            (Key::BTN_START,  ControlAction::Confirm),
            (Key::BTN_SELECT, ControlAction::Backspace),
            (Key::BTN_BASE,   ControlAction::Cancel),
        ] {
            tx.send(press(key)).await.unwrap();
            assert_eq!(reader.next_token().await.unwrap(), Token::Control(expected));
            tx.send(release(key)).await.unwrap(); // silently ignored
        }
        tx.send(press(Key::BTN_SOUTH)).await.unwrap();
        assert_eq!(reader.next_token().await.unwrap(), chord(&[Button::A]));
    }

    // ── Chords (multi-button) ─────────────────────────────────────────────────

    #[tokio::test]
    async fn chord_down_a() {
        // Hold ↓, press A → held grows: [↓] then [↓, A].
        let (tx, mut reader) = make_reader();
        tx.send(press(Key::BTN_DPAD_DOWN)).await.unwrap();
        assert_eq!(reader.next_token().await.unwrap(), chord(&[Button::Down]));

        tx.send(press(Key::BTN_SOUTH)).await.unwrap();
        assert_eq!(reader.next_token().await.unwrap(), chord(&[Button::Down, Button::A]));

        tx.send(release(Key::BTN_SOUTH)).await.unwrap();
        assert_eq!(reader.next_token().await.unwrap(), Token::Release(Button::A));
        tx.send(release(Key::BTN_DPAD_DOWN)).await.unwrap();
        assert_eq!(reader.next_token().await.unwrap(), Token::Release(Button::Down));
    }

    #[tokio::test]
    async fn chord_three_buttons() {
        // Hold ↓, press A, press B → [↓], [↓,A], [↓,A,B].
        let (tx, mut reader) = make_reader();
        tx.send(press(Key::BTN_DPAD_DOWN)).await.unwrap();
        assert_eq!(reader.next_token().await.unwrap(), chord(&[Button::Down]));

        tx.send(press(Key::BTN_SOUTH)).await.unwrap();
        assert_eq!(reader.next_token().await.unwrap(), chord(&[Button::Down, Button::A]));

        tx.send(press(Key::BTN_EAST)).await.unwrap();
        assert_eq!(reader.next_token().await.unwrap(), chord(&[Button::Down, Button::A, Button::B]));
    }

    #[tokio::test]
    async fn chord_l1_a() {
        let (tx, mut reader) = make_reader();
        tx.send(press(Key::BTN_TL)).await.unwrap();
        assert_eq!(reader.next_token().await.unwrap(), chord(&[Button::L1]));

        tx.send(press(Key::BTN_SOUTH)).await.unwrap();
        assert_eq!(reader.next_token().await.unwrap(), chord(&[Button::L1, Button::A]));

        tx.send(release(Key::BTN_TL)).await.unwrap();
        assert_eq!(reader.next_token().await.unwrap(), Token::Release(Button::L1));
        tx.send(release(Key::BTN_SOUTH)).await.unwrap();
        assert_eq!(reader.next_token().await.unwrap(), Token::Release(Button::A));
    }

    #[tokio::test]
    async fn sequential_presses_no_chord() {
        // Release ↓ before pressing A → separate single-button chords.
        let (tx, mut reader) = make_reader();
        tx.send(press(Key::BTN_DPAD_DOWN)).await.unwrap();
        assert_eq!(reader.next_token().await.unwrap(), chord(&[Button::Down]));
        tx.send(release(Key::BTN_DPAD_DOWN)).await.unwrap();
        assert_eq!(reader.next_token().await.unwrap(), Token::Release(Button::Down));
        tx.send(press(Key::BTN_SOUTH)).await.unwrap();
        assert_eq!(reader.next_token().await.unwrap(), chord(&[Button::A]));
        tx.send(release(Key::BTN_SOUTH)).await.unwrap();
        assert_eq!(reader.next_token().await.unwrap(), Token::Release(Button::A));
    }

    // ── Key repeat ignored ────────────────────────────────────────────────────

    #[tokio::test]
    async fn key_repeat_ignored() {
        let (tx, mut reader) = make_reader();
        tx.send(ControllerEvent::Input(
            InputEvent::new(EventType::KEY, Key::BTN_SOUTH.code(), 2)
        )).await.unwrap();
        tx.send(press(Key::BTN_EAST)).await.unwrap();
        assert_eq!(reader.next_token().await.unwrap(), chord(&[Button::B]));
    }

    // ── Reconnect ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn reconnect_clears_held() {
        let (tx, mut reader) = make_reader();
        tx.send(press(Key::BTN_DPAD_DOWN)).await.unwrap();
        assert_eq!(reader.next_token().await.unwrap(), chord(&[Button::Down]));

        tx.send(ControllerEvent::Reconnected).await.unwrap();

        // held cleared — next press is a fresh single-button chord.
        tx.send(press(Key::BTN_SOUTH)).await.unwrap();
        assert_eq!(reader.next_token().await.unwrap(), chord(&[Button::A]));
    }

    // ── Channel closed ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn channel_closed_returns_error() {
        let (tx, mut reader) = make_reader();
        drop(tx);
        assert!(reader.next_token().await.is_err());
    }
}
