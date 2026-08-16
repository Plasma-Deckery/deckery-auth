//! `deckery-input-test` — prints tokens to stdout as controller buttons are pressed.
//!
//! Usage: sudo deckery-input-test
//!
//! Requires read access to /dev/input/eventX (root or input group).

use deckery_input::{ControlAction, Token, encode_sequence, find_controller};

fn main() {
    let (path, device) = match find_controller() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!("Is the controller connected? Try: ls /dev/input/by-id/");
            std::process::exit(1);
        }
    };

    println!("Controller found: {}", path.display());
    println!("Device name:      {}", device.name().unwrap_or("(unknown)"));
    println!("Press buttons — Ctrl+C to quit\n");
    println!("{:<20} {}", "TOKEN", "SEQUENCE SO FAR");
    println!("{}", "-".repeat(50));

    let mut reader = deckery_input::TokenReader::new(device);
    let mut sequence: Vec<Token> = Vec::new();

    loop {
        let token = match reader.next_token() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("Read error: {e}");
                std::process::exit(1);
            }
        };

        match &token {
            Token::PhraseEmpty => {
                println!("{:<20} (empty phrase — ignored)", "PhraseEmpty");
                continue;
            }
            Token::Control(ControlAction::Backspace) => {
                sequence.pop();
                println!("{:<20} {}", "Backspace", encode_sequence(&sequence));
                continue;
            }
            Token::Control(ControlAction::Confirm) => {
                println!("\nConfirm pressed.");
                println!("Final credential: {}", encode_sequence(&sequence));
                sequence.clear();
                println!("(sequence cleared)\n");
                continue;
            }
            Token::Control(ControlAction::Cancel) => {
                println!("\nCancel pressed — sequence cleared.");
                sequence.clear();
                continue;
            }
            _ => {}
        }

        let encoded = token.encode();
        sequence.push(token.clone());
        println!("{:<20} {}", format!("{token:?}"), encode_sequence(&sequence));
        drop(encoded);
    }
}
