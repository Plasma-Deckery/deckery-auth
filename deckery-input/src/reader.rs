//! [`TokenReader`] — translates raw evdev events into [`Token`]s.

use evdev::{Device, EventType, Key};
use std::collections::HashSet;

use crate::{Button, ControlAction, Modifier, Token};

/// Maps evdev [`Key`] codes to our [`Button`] type.
fn key_to_button(key: Key) -> Option<Button> {
    match key {
        Key::BTN_SOUTH => Some(Button::A),
        Key::BTN_EAST  => Some(Button::B),
        Key::BTN_NORTH => Some(Button::Y),
        Key::BTN_WEST  => Some(Button::X),
        Key::BTN_TL2   => Some(Button::L2),
        Key::BTN_TR2   => Some(Button::R2),
        // Back paddles — Steam Deck uses BTN_TRIGGER_HAPPY* for paddles
        Key::BTN_TRIGGER_HAPPY1 => Some(Button::L4),
        Key::BTN_TRIGGER_HAPPY2 => Some(Button::R4),
        Key::BTN_TRIGGER_HAPPY3 => Some(Button::L5),
        Key::BTN_TRIGGER_HAPPY4 => Some(Button::R5),
        _ => None,
    }
}

fn key_to_modifier(key: Key) -> Option<Modifier> {
    match key {
        Key::BTN_TL => Some(Modifier::L1),
        Key::BTN_TR => Some(Modifier::R1),
        _ => None,
    }
}

fn key_to_control(key: Key) -> Option<ControlAction> {
    match key {
        Key::BTN_START  => Some(ControlAction::Confirm),
        Key::BTN_SELECT => Some(ControlAction::Backspace),
        Key::BTN_MODE   => Some(ControlAction::Cancel), // Home / Steam button
        _ => None,
    }
}

/// State of one modifier (L1 or R1).
#[derive(Debug, Default)]
struct ModifierState {
    held: bool,
    taps: Vec<Button>,
}

/// Reads raw evdev events from a controller device and produces [`Token`]s.
///
/// Call [`TokenReader::next_token`] in a loop to receive tokens one at a time.
/// Blocks until the next relevant event arrives.
pub struct TokenReader {
    device: Device,
    l1: ModifierState,
    r1: ModifierState,
    /// D-Pad axis state: tracks which direction is currently active.
    dpad_x: i32,
    dpad_y: i32,
    /// Keys currently held (for detecting simultaneous presses in future).
    _held_keys: HashSet<Key>,
}

impl TokenReader {
    pub fn new(device: Device) -> Self {
        Self {
            device,
            l1: ModifierState::default(),
            r1: ModifierState::default(),
            dpad_x: 0,
            dpad_y: 0,
            _held_keys: HashSet::new(),
        }
    }

    /// Block until the next [`Token`] is produced.
    pub fn next_token(&mut self) -> Result<Token, std::io::Error> {
        loop {
            // Collect into Vec first to end the borrow on self.device before
            // calling self.process_event(), which also needs &mut self.
            let events: Vec<_> = self.device.fetch_events()?.collect();
            for event in events {
                if let Some(token) = self.process_event(event) {
                    return Ok(token);
                }
            }
        }
    }

    fn process_event(&mut self, event: evdev::InputEvent) -> Option<Token> {
        match event.event_type() {
            EventType::KEY => self.handle_key(Key::new(event.code()), event.value()),
            EventType::ABSOLUTE => self.handle_absolute(event.code(), event.value()),
            _ => None,
        }
    }

    /// Handle a key press (value=1), release (value=0), or repeat (value=2).
    fn handle_key(&mut self, key: Key, value: i32) -> Option<Token> {
        let pressed  = value == 1;
        let released = value == 0;

        // Control actions fire on press.
        if pressed {
            if let Some(action) = key_to_control(key) {
                return Some(Token::Control(action));
            }
        }

        // Modifier press/release.
        if let Some(modifier) = key_to_modifier(key) {
            return self.handle_modifier(modifier, pressed, released);
        }

        // Regular button press (only on press, not repeat or release).
        if pressed {
            if let Some(button) = key_to_button(key) {
                return self.handle_button(button);
            }
        }

        None
    }

    fn handle_modifier(&mut self, modifier: Modifier, pressed: bool, released: bool) -> Option<Token> {
        let state = match modifier {
            Modifier::L1 => &mut self.l1,
            Modifier::R1 => &mut self.r1,
        };

        if pressed {
            state.held = true;
            state.taps.clear();
            return None;
        }

        if released && state.held {
            state.held = false;
            let taps = std::mem::take(&mut state.taps);
            return Some(if taps.is_empty() {
                Token::PhraseEmpty
            } else {
                Token::PhraseEnd(modifier, taps)
            });
        }

        None
    }

    fn handle_button(&mut self, button: Button) -> Option<Token> {
        // If either modifier is held, this tap goes into that phrase.
        if self.l1.held {
            self.l1.taps.push(button);
            return None;
        }
        if self.r1.held {
            self.r1.taps.push(button);
            return None;
        }
        // No modifier held — simple press.
        Some(Token::SimplePress(button))
    }

    /// Handle D-Pad absolute axis events (ABS_HAT0X / ABS_HAT0Y).
    fn handle_absolute(&mut self, code: u16, value: i32) -> Option<Token> {
        const ABS_HAT0X: u16 = 16;
        const ABS_HAT0Y: u16 = 17;

        match code {
            ABS_HAT0X => {
                let prev = self.dpad_x;
                self.dpad_x = value;
                // Only produce a token on the transition from 0 → direction.
                if prev == 0 && value != 0 {
                    let button = if value > 0 { Button::Right } else { Button::Left };
                    return self.handle_button(button);
                }
            }
            ABS_HAT0Y => {
                let prev = self.dpad_y;
                self.dpad_y = value;
                if prev == 0 && value != 0 {
                    let button = if value > 0 { Button::Down } else { Button::Up };
                    return self.handle_button(button);
                }
            }
            _ => {}
        }
        None
    }
}
