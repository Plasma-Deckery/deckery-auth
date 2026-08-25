//! `deckery-input-test` — prints tokens to stdout as controller buttons are pressed.
//!
//! Usage: deckery-input-test
//!
//! Controls:
//!   Start (BTN_START)   — Confirm: print credential, clear sequence
//!   Select (BTN_SELECT) — Backspace: remove last token
//!   QAM (BTN_BASE)      — Cancel: clear sequence; press twice to exit

use std::io::Write;
use deckery_input::{ControlAction, Token, TokenReader};

#[tokio::main]
async fn main() {
    let mut reader = match TokenReader::open().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: {e}");
            eprintln!("Try: ls /dev/input/by-id/");
            std::process::exit(1);
        }
    };

    println!("Controller: {}", reader.path().display());
    println!("Press buttons — QAM twice to quit\n");
    println!("{:<35} SEQUENCE", "TOKEN");
    println!("{}", "-".repeat(65));

    let mut sequence: Vec<Token> = Vec::new();
    let mut last_was_cancel = false;

    loop {
        let token = match reader.next_token().await {
            Ok(t)  => t,
            Err(e) => {
                eprintln!("\nRead error: {e}");
                std::process::exit(1);
            }
        };

        match &token {
            Token::Control(ControlAction::Cancel) => {
                if last_was_cancel {
                    println!("\nDouble Cancel — exiting.");
                    std::process::exit(0);
                }
                last_was_cancel = true;
                sequence.clear();
                println!("{:<35} (cleared)", "Control(Cancel)");
            }
            Token::Control(ControlAction::Backspace) => {
                last_was_cancel = false;
                sequence.pop();
                println!("{:<35} {}", "Control(Backspace)", display_sequence(&sequence));
            }
            Token::Control(ControlAction::Confirm) => {
                last_was_cancel = false;
                println!("\nConfirm — credential: {}", display_sequence(&sequence));
                sequence.clear();
                println!("(cleared)\n");
            }
            Token::Release(_) => {
                // Visualization only — not stored in the sequence.
                let label = format!("{token:?}");
                println!("{:<35} {}", label, display_sequence(&sequence));
            }
            _ => {
                last_was_cancel = false;
                sequence.push(token.clone());
                let label = format!("{token:?}");
                println!("{:<35} {}", label, display_sequence(&sequence));
                let _ = std::io::stdout().flush();
            }
        }
    }
}

/// Format the sequence with spaces between tokens for readability.
/// The actual credential string has no separators — this is display only.
fn display_sequence(tokens: &[Token]) -> String {
    tokens
        .iter()
        .map(Token::encode)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}
