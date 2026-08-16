//! `deckery-polkit-agent` — polkit authentication agent for Deckery.
//!
//! Replaces the Plasma built-in polkit agent. Shows a Layer Shell popup
//! when an application requests authorization via polkit. Supports:
//!   - Password authentication via pam_unix.so (keyboard / virtual keyboard)
//!   - PIN authentication via pam_deckery.so (controller button combos — Step 3)
//!
//! Registers with polkitd at startup via polkit-agent-rs (libpolkit-agent-1).
//! Uses iced_layershell for the Wayland Layer Shell surface.
//!
//! See: https://github.com/Plasma-Deckery/deckery-auth/issues/6

fn main() {
    println!("deckery-polkit-agent: not yet implemented");
}
