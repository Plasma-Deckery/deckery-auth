//! Device detection — finds the Steam Deck controller in /dev/input/.

use evdev::Device;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DeviceError {
    #[error("no controller device found in /dev/input/")]
    NotFound,
    #[error("evdev error: {0}")]
    Evdev(#[from] std::io::Error),
}

/// Known controller device names as reported by HHD / the kernel driver.
/// HHD normalises handheld controllers to a consistent name.
const KNOWN_NAMES: &[&str] = &[
    "Steam Deck Controller",
    "Steam Controller",
    "Microsoft X-Box 360 pad",  // HHD emulation on some handhelds
    "Xbox Wireless Controller", // HHD emulation on others
];

/// Find the first input device that looks like a handheld controller.
/// Returns the device path and an opened [`Device`].
pub fn find_controller() -> Result<(PathBuf, Device), DeviceError> {
    for entry in evdev::enumerate() {
        let (path, device) = entry;
        let name = device.name().unwrap_or("");
        if KNOWN_NAMES.iter().any(|n| name.contains(n)) {
            return Ok((path, device));
        }
    }
    Err(DeviceError::NotFound)
}
