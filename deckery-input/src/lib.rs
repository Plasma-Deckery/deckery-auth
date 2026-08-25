//! Controller input library for Deckery authentication.
//!
//! Reads button events from the Steam Deck controller (and compatible
//! handhelds via HHD) and produces a stream of typed [`Token`]s.
//!
//! # Token model
//!
//! Every physical button event becomes a token:
//!
//! - **Press** — a button was pressed. Always emitted.
//! - **Release** — a button was released. Always emitted.
//! - **Chord** — a button was pressed while another button was already held.
//!   The chord token *replaces* the Press of the second button. The held
//!   button's own Press was already emitted when it was first pressed.
//! - **Control** — reserved buttons (Confirm / Backspace / Cancel) that drive
//!   the auth UI. Never part of the PIN credential.
//!
//! L1 and R1 are regular buttons — they participate in Chords just like any
//! other button. There is no special phrase/modifier concept in this layer;
//! higher-level interpretation (e.g. fighting-game move detection) belongs
//! in the UI or animation layer above.
//!
//! # Encoding
//!
//! | Token | Encoding |
//! |---|---|
//! | `Press(A)` | `"A"` |
//! | `Release(A)` | `"A~"` |
//! | `Press(Down)` | `"↓"` |
//! | `Release(Down)` | `"↓~"` |
//! | `Chord(Down, A)` | `"↓+A"` |
//! | `Press(L1)` | `"L1"` |
//!
//! The grammar is unambiguous: D-pad directions use Unicode arrows (`↑↓←→`),
//! releases append `~`, chords use `+` between two button names.
//!
//! # Example: Hadouken (↓ → A in sequence)
//! `↓ ↓~ → →~ A A~`
//!
//! # Example: Crouching punch (hold ↓, press A)
//! `↓ ↓+A ↓~ A~`

mod reader;

pub use deckery_controller::ControllerEvent;
pub use reader::TokenReader;

// ── Button ────────────────────────────────────────────────────────────────────

/// A pressable input button.
///
/// L1 and R1 are regular buttons — they can appear in [`Token::Press`],
/// [`Token::Release`], and [`Token::Chord`] just like any other button.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Button {
    // Face buttons
    A,
    B,
    X,
    Y,
    // D-Pad
    Up,
    Down,
    Left,
    Right,
    // Shoulder buttons — regular buttons, not special modifiers
    L1,
    R1,
    // Triggers (digital)
    L2,
    R2,
    // Back paddles — Steam Deck and some other handhelds.
    // Requires the Plasma-Deckery evdev fork (BTN_GRIPL/GRIPR/GRIPL2/GRIPR2).
    L4,
    R4,
    L5,
    R5,
}

impl Button {
    /// Short encoding used in the PAM credential string.
    pub fn encode(self) -> &'static str {
        match self {
            Button::A     => "A",
            Button::B     => "B",
            Button::X     => "X",
            Button::Y     => "Y",
            Button::Up    => "↑",
            Button::Down  => "↓",
            Button::Left  => "←",
            Button::Right => "→",
            Button::L1    => "L1",
            Button::R1    => "R1",
            Button::L2    => "L2",
            Button::R2    => "R2",
            Button::L4    => "L4",
            Button::R4    => "R4",
            Button::L5    => "L5",
            Button::R5    => "R5",
        }
    }
}

// ── ControlAction ─────────────────────────────────────────────────────────────

/// Buttons reserved for controlling the auth UI — never part of the PIN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControlAction {
    /// Start / Menu — submit the current sequence for authentication.
    Confirm,
    /// Select / Back — delete the last token from the sequence.
    Backspace,
    /// QAM (three-dots) button — cancel authentication.
    Cancel,
}

// ── Token ─────────────────────────────────────────────────────────────────────

/// A single unit of controller input.
///
/// Every press and release of a regular button produces a token.
/// [`Token::Chord`] covers all presses — one button or many simultaneously.
/// [`Token::Release`] and [`Token::Control`] encode to empty strings and
/// are excluded from the PAM credential; they exist for the visualization layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// One or more buttons pressed simultaneously.
    ///
    /// A single tap is `Chord(vec![A])`. Holding ↓ then pressing A gives
    /// `Chord(vec![↓])` followed by `Chord(vec![↓, A])`. Encoded by joining
    /// button names with `+`, e.g. `"↓+A+B"`.
    Chord(Vec<Button>),

    /// A button was released. Visualization-only — encodes to `""`.
    Release(Button),

    /// A reserved control button was pressed. Encodes to `""`.
    Control(ControlAction),
}

impl Token {
    /// Encode this token to its PAM credential string fragment.
    ///
    /// Only [`Token::Chord`] contributes to the credential.
    pub fn encode(&self) -> String {
        match self {
            Token::Chord(buttons) => buttons
                .iter()
                .map(|b| b.encode())
                .collect::<Vec<_>>()
                .join("+"),
            Token::Release(_) => String::new(),
            Token::Control(_) => String::new(),
        }
    }
}

/// Encode a full sequence of tokens into the credential string sent to PAM.
pub fn encode_sequence(tokens: &[Token]) -> String {
    tokens.iter().map(Token::encode).collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_button_chord() {
        assert_eq!(Token::Chord(vec![Button::A]).encode(),     "A");
        assert_eq!(Token::Chord(vec![Button::Up]).encode(),    "↑");
        assert_eq!(Token::Chord(vec![Button::Down]).encode(),  "↓");
        assert_eq!(Token::Chord(vec![Button::L1]).encode(),    "L1");
        assert_eq!(Token::Chord(vec![Button::L2]).encode(),    "L2");
    }

    #[test]
    fn multi_button_chord() {
        assert_eq!(Token::Chord(vec![Button::Down, Button::A]).encode(),          "↓+A");
        assert_eq!(Token::Chord(vec![Button::L1,   Button::A]).encode(),          "L1+A");
        assert_eq!(Token::Chord(vec![Button::Down, Button::A, Button::B]).encode(), "↓+A+B");
    }

    #[test]
    fn release_and_control_encode_empty() {
        assert_eq!(Token::Release(Button::A).encode(),              "");
        assert_eq!(Token::Release(Button::Down).encode(),           "");
        assert_eq!(Token::Control(ControlAction::Confirm).encode(), "");
        assert_eq!(Token::Control(ControlAction::Cancel).encode(),  "");
    }

    #[test]
    fn arrows_distinct_from_shoulder() {
        assert_ne!(Button::Left.encode(),  Button::L1.encode());
        assert_ne!(Button::Left.encode(),  Button::L2.encode());
        assert_ne!(Button::Right.encode(), Button::R1.encode());
        assert_eq!(Button::Left.encode(),  "←");
        assert_eq!(Button::L1.encode(),    "L1");
        assert_eq!(Button::L2.encode(),    "L2");
    }

    #[test]
    fn hadouken_sequence() {
        // ↓ → A tapped in sequence — releases excluded from credential.
        let tokens = vec![
            Token::Chord(vec![Button::Down]),  Token::Release(Button::Down),
            Token::Chord(vec![Button::Right]), Token::Release(Button::Right),
            Token::Chord(vec![Button::A]),     Token::Release(Button::A),
        ];
        assert_eq!(encode_sequence(&tokens), "↓→A");
    }

    #[test]
    fn crouching_punch() {
        // Hold ↓, press A while ↓ held — credential: ↓ then ↓+A.
        let tokens = vec![
            Token::Chord(vec![Button::Down]),
            Token::Chord(vec![Button::Down, Button::A]),
            Token::Release(Button::A),
            Token::Release(Button::Down),
        ];
        assert_eq!(encode_sequence(&tokens), "↓↓+A");
    }

    #[test]
    fn three_button_chord() {
        // Hold ↓, press A, press B — credential: ↓, ↓+A, ↓+A+B.
        let tokens = vec![
            Token::Chord(vec![Button::Down]),
            Token::Chord(vec![Button::Down, Button::A]),
            Token::Chord(vec![Button::Down, Button::A, Button::B]),
        ];
        assert_eq!(encode_sequence(&tokens), "↓↓+A↓+A+B");
    }

    #[test]
    fn konami_code() {
        let tokens = vec![
            Token::Chord(vec![Button::Up]),    Token::Release(Button::Up),
            Token::Chord(vec![Button::Up]),    Token::Release(Button::Up),
            Token::Chord(vec![Button::Down]),  Token::Release(Button::Down),
            Token::Chord(vec![Button::Down]),  Token::Release(Button::Down),
            Token::Chord(vec![Button::Left]),  Token::Release(Button::Left),
            Token::Chord(vec![Button::Right]), Token::Release(Button::Right),
            Token::Chord(vec![Button::Left]),  Token::Release(Button::Left),
            Token::Chord(vec![Button::Right]), Token::Release(Button::Right),
            Token::Chord(vec![Button::B]),     Token::Release(Button::B),
            Token::Chord(vec![Button::A]),     Token::Release(Button::A),
        ];
        assert_eq!(encode_sequence(&tokens), "↑↑↓↓←→←→BA");
    }
}
