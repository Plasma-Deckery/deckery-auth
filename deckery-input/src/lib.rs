//! `deckery-input` — controller input library for Deckery auth.
//!
//! Reads button events from the Steam Deck controller (and compatible
//! handhelds via HHD) and produces a stream of typed [`Token`]s.
//!
//! No UI, no PAM, no D-Bus. Pure evdev → tokens.
//!
//! # Token model
//!
//! - [`Token::SimplePress`] — a button pressed with no modifier held
//! - [`Token::PhraseEnd`] — L1 or R1 held, buttons tapped in sequence, modifier released
//! - [`Token::PhraseEmpty`] — modifier pressed and released with no taps (discarded by caller)
//!
//! # Encoding
//!
//! Each token encodes to a short unambiguous string for the PAM credential:
//! `SimplePress(A)` → `"a"`, `PhraseEnd(L1, [A,B,X])` → `"L(a,b,x)"`.
//! See [`Token::encode`].

mod device;
mod reader;

pub use device::find_controller;
pub use reader::TokenReader;

// ── Button ────────────────────────────────────────────────────────────────────

/// A pressable input button (excluding modifiers and control actions).
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
    // Triggers (digital)
    L2,
    R2,
    // Back paddles (Steam Deck + some others)
    L4,
    R4,
    L5,
    R5,
}

impl Button {
    /// Short encoding string used in the PAM credential.
    pub fn encode(self) -> &'static str {
        match self {
            Button::A => "a",
            Button::B => "b",
            Button::X => "x",
            Button::Y => "y",
            Button::Up => "u",
            Button::Down => "d",
            Button::Left => "l",
            Button::Right => "r",
            Button::L2 => "l2",
            Button::R2 => "r2",
            Button::L4 => "l4",
            Button::R4 => "r4",
            Button::L5 => "l5",
            Button::R5 => "r5",
        }
    }
}

// ── Modifier ──────────────────────────────────────────────────────────────────

/// A phrase modifier. L1 or R1 held opens a phrase; releasing closes it.
/// Modifiers never appear as standalone [`Token::SimplePress`] inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Modifier {
    L1,
    R1,
}

impl Modifier {
    pub fn encode(self) -> char {
        match self {
            Modifier::L1 => 'L',
            Modifier::R1 => 'R',
        }
    }
}

// ── ControlAction ─────────────────────────────────────────────────────────────

/// Buttons reserved for control actions — never part of the PIN sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControlAction {
    /// Start / Menu — confirm authentication.
    Confirm,
    /// Select / Back — delete last token (backspace).
    Backspace,
    /// Home / Steam — cancel authentication.
    Cancel,
}

// ── Token ─────────────────────────────────────────────────────────────────────

/// A single unit of controller input as seen by the auth daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// A button pressed with no modifier held.
    SimplePress(Button),

    /// A modifier was held, buttons were tapped in order, modifier released.
    /// The `Vec<Button>` is the ordered sequence of taps.
    PhraseEnd(Modifier, Vec<Button>),

    /// Modifier pressed and released with no taps — caller should ignore this.
    PhraseEmpty,

    /// A control action (confirm / backspace / cancel).
    Control(ControlAction),
}

impl Token {
    /// Encode this token to its PAM credential string fragment.
    ///
    /// - `SimplePress(A)` → `"a"`
    /// - `PhraseEnd(L1, [A,B,X])` → `"L(a,b,x)"`
    /// - `PhraseEmpty` and `Control(_)` → `""` (contribute nothing to the credential)
    pub fn encode(&self) -> String {
        match self {
            Token::SimplePress(btn) => btn.encode().to_string(),
            Token::PhraseEnd(modifier, taps) => {
                let inner = taps
                    .iter()
                    .map(|b| b.encode())
                    .collect::<Vec<_>>()
                    .join(",");
                format!("{}({})", modifier.encode(), inner)
            }
            Token::PhraseEmpty | Token::Control(_) => String::new(),
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
    fn simple_press_encoding() {
        assert_eq!(Token::SimplePress(Button::A).encode(), "a");
        assert_eq!(Token::SimplePress(Button::Up).encode(), "u");
        assert_eq!(Token::SimplePress(Button::L2).encode(), "l2");
        assert_eq!(Token::SimplePress(Button::L4).encode(), "l4");
    }

    #[test]
    fn phrase_encoding() {
        let t = Token::PhraseEnd(Modifier::L1, vec![Button::A, Button::B, Button::X]);
        assert_eq!(t.encode(), "L(a,b,x)");

        let t = Token::PhraseEnd(Modifier::R1, vec![Button::Down, Button::Y]);
        assert_eq!(t.encode(), "R(d,y)");
    }

    #[test]
    fn phrase_single_tap() {
        let t = Token::PhraseEnd(Modifier::L1, vec![Button::A]);
        assert_eq!(t.encode(), "L(a)");
    }

    #[test]
    fn empty_phrase_encodes_empty() {
        assert_eq!(Token::PhraseEmpty.encode(), "");
    }

    #[test]
    fn full_sequence() {
        let tokens = vec![
            Token::SimplePress(Button::Up),
            Token::SimplePress(Button::Up),
            Token::SimplePress(Button::Down),
            Token::PhraseEnd(Modifier::L1, vec![Button::A, Button::B]),
            Token::SimplePress(Button::B),
        ];
        assert_eq!(encode_sequence(&tokens), "uudL(a,b)b");
    }

    #[test]
    fn konami_code() {
        let tokens = vec![
            Token::SimplePress(Button::Up),
            Token::SimplePress(Button::Up),
            Token::SimplePress(Button::Down),
            Token::SimplePress(Button::Down),
            Token::SimplePress(Button::Left),
            Token::SimplePress(Button::Right),
            Token::SimplePress(Button::Left),
            Token::SimplePress(Button::Right),
            Token::SimplePress(Button::B),
            Token::SimplePress(Button::A),
        ];
        assert_eq!(encode_sequence(&tokens), "uuddlrlrba");
    }
}
