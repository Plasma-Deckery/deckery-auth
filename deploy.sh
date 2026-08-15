#!/usr/bin/env bash
# deploy.sh — build and install deckery-auth
#
# Usage:
#   ./deploy.sh [--mode=dev|rpm]
#
# Modes:
#   dev (default)  Build inside the deckery distrobox, install pam_deckery.so
#                  to /usr/local/lib/security/ (writable on Bazzite), and
#                  create /etc/deckery/. Full path required in pam.d config
#                  because /usr/local/lib/security/ is not a standard PAM
#                  search path. Prints the pam.d snippet to use.
#
#   rpm            Build only. Leaves artifacts in target/release/ for the
#                  RPM build process to pick up — no copying, no system changes.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Defaults ──────────────────────────────────────────────────────────────────

MODE="dev"

# ── Argument parsing ──────────────────────────────────────────────────────────

for arg in "$@"; do
    case "$arg" in
        --mode=dev) MODE="dev" ;;
        --mode=rpm) MODE="rpm" ;;
        *)
            echo "Unknown argument: $arg" >&2
            echo "Usage: $0 [--mode=dev|rpm]" >&2
            exit 1
            ;;
    esac
done

# ── Paths ─────────────────────────────────────────────────────────────────────

DISTROBOX="deckery"
SO_SRC="$SCRIPT_DIR/target/release/libpam_deckery.so"

# dev-mode install targets
DEV_PAM_DIR="/usr/local/lib/security"
DEV_PAM_SO="$DEV_PAM_DIR/pam_deckery.so"
DECKERY_CONF_DIR="/etc/deckery"

# ── Build ─────────────────────────────────────────────────────────────────────

echo "==> Building (distrobox: $DISTROBOX)"
distrobox enter "$DISTROBOX" -- cargo build --release --manifest-path "$SCRIPT_DIR/Cargo.toml"

if [[ "$MODE" == "rpm" ]]; then
    echo ""
    echo "==> rpm mode: build complete."
    echo "    Artifacts:"
    echo "      $SO_SRC"
    echo "      $SCRIPT_DIR/target/release/deckery-pin-set"
    exit 0
fi

# ── Dev mode: install ─────────────────────────────────────────────────────────

echo ""
echo "==> Installing (dev mode)"

echo "    mkdir -p $DEV_PAM_DIR"
sudo mkdir -p "$DEV_PAM_DIR"

echo "    cp libpam_deckery.so -> $DEV_PAM_SO"
sudo cp "$SO_SRC" "$DEV_PAM_SO"

echo "    mkdir -p $DECKERY_CONF_DIR"
sudo mkdir -p "$DECKERY_CONF_DIR"

echo ""
echo "==> Done. pam_deckery.so installed to $DEV_PAM_SO"
echo ""
echo "── pam.d snippet ────────────────────────────────────────────────────────"
echo "   /usr/local/lib/security/ is not a standard PAM search path."
echo "   Use the full path in /etc/pam.d/<service>:"
echo ""
echo "   auth  sufficient  $DEV_PAM_SO"
echo "   auth  sufficient  pam_unix.so"
echo "   auth  required    pam_deny.so"
echo ""
echo "   For testing without touching /etc/pam.d/sudo, create an isolated"
echo "   test service first:"
echo ""
echo "   sudo tee /etc/pam.d/deckery-test <<'EOF'"
echo "   auth  sufficient  $DEV_PAM_SO"
echo "   auth  sufficient  pam_unix.so"
echo "   auth  required    pam_deny.so"
echo "   EOF"
echo ""
echo "   Then set the PIN (requires a real terminal):"
echo "   sudo $SCRIPT_DIR/target/release/deckery-pin-set"
echo "─────────────────────────────────────────────────────────────────────────"
