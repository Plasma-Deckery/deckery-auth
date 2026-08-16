#!/usr/bin/env bash
# deploy.sh — build and install deckery-auth
#
# Usage:
#   ./deploy.sh [--mode=dev|rpm]
#
# Modes:
#   dev (default)  Build inside the deckery distrobox, install pam_deckery.so
#                  to /usr/local/lib/security/ (writable on Bazzite), create
#                  /etc/deckery/, write /etc/pam.d/deckery-test, and run an
#                  isolated PAM smoke test:
#                    1. Set a test PIN via deckery-pin-set --stdin (tests hash
#                       generation through our real code, no hardcoded hash)
#                    2. Verify correct PIN → PAM_SUCCESS
#                    3. Verify wrong PIN  → PAM auth failure
#                    4. Restore original pin.hash (real PIN untouched)
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
PIN_SET_BIN="$SCRIPT_DIR/target/release/deckery-pin-set"
PAM_TEST_BIN="$SCRIPT_DIR/target/release/deckery-pam-test"

# dev-mode install targets
DEV_PAM_DIR="/usr/local/lib/security"
DEV_PAM_SO="$DEV_PAM_DIR/pam_deckery.so"
DECKERY_CONF_DIR="/etc/deckery"
HASH_FILE="$DECKERY_CONF_DIR/pin.hash"
HASH_BACKUP="$DECKERY_CONF_DIR/pin.hash.deploy-bak"
PAM_TEST_SERVICE="/etc/pam.d/deckery-test"

TEST_PIN="1234"

# ── Build ─────────────────────────────────────────────────────────────────────

echo "==> Building (distrobox: $DISTROBOX)"
distrobox enter "$DISTROBOX" -- cargo build --release --manifest-path "$SCRIPT_DIR/Cargo.toml"

if [[ "$MODE" == "rpm" ]]; then
    echo ""
    echo "==> rpm mode: build complete."
    echo "    Artifacts:"
    echo "      $SO_SRC"
    echo "      $PIN_SET_BIN"
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

echo "    writing $PAM_TEST_SERVICE"
sudo tee "$PAM_TEST_SERVICE" > /dev/null <<EOF
auth  sufficient  $DEV_PAM_SO
auth  sufficient  pam_unix.so
auth  required    pam_deny.so
EOF

# ── Dev mode: activate for sudo ───────────────────────────────────────────────
# authselect does not manage service-specific files like /etc/pam.d/sudo —
# only the common stacks (system-auth, password-auth, etc.). Direct editing
# is therefore safe and the established approach (same as howdy, google-
# authenticator-libpam). Idempotent: skipped if already present.

echo "    activating pam_deckery.so in /etc/pam.d/sudo"
if ! sudo grep -q "pam_deckery.so" /etc/pam.d/sudo; then
    sudo sed -i "/auth.*include.*system-auth/i auth  sufficient  $DEV_PAM_SO" /etc/pam.d/sudo
    echo "    ✓ added"
else
    echo "    (already present — skipped)"
fi

# ── Dev mode: smoke test ──────────────────────────────────────────────────────

echo ""
echo "==> Smoke test"

# Backup existing hash if present
HASH_EXISTED=false
if [[ -f "$HASH_FILE" ]]; then
    HASH_EXISTED=true
    echo "    backing up existing pin.hash"
    sudo cp "$HASH_FILE" "$HASH_BACKUP"
fi

# Set test PIN via our real deckery-pin-set binary (tests hash generation too)
echo "    setting test PIN via deckery-pin-set --stdin"
printf '%s\n' "$TEST_PIN" | sudo "$PIN_SET_BIN" --stdin

PASS=0
FAIL=0

echo ""
echo "    [1/2] correct PIN ($TEST_PIN) → expect: Authentication successful"
if sudo "$PAM_TEST_BIN" deckery-test "$USER" "$TEST_PIN"; then
    echo "    ✓ PASS"
    PASS=$((PASS + 1))
else
    echo "    ✗ FAIL"
    FAIL=$((FAIL + 1))
fi

echo ""
echo "    [2/2] wrong PIN (9999) → expect: Authentication failure"
if ! sudo "$PAM_TEST_BIN" deckery-test "$USER" "9999"; then
    echo "    ✓ PASS"
    PASS=$((PASS + 1))
else
    echo "    ✗ FAIL (wrong PIN was accepted — this is a bug)"
    FAIL=$((FAIL + 1))
fi

# Restore original hash
echo ""
if [[ "$HASH_EXISTED" == true ]]; then
    echo "    restoring original pin.hash"
    sudo mv "$HASH_BACKUP" "$HASH_FILE"
else
    echo "    removing test hash (no original to restore)"
    sudo rm -f "$HASH_FILE"
fi

# Report
echo ""
if [[ $FAIL -eq 0 ]]; then
    echo "==> Smoke test passed ($PASS/2) ✓"
    echo ""
    echo "    pam_deckery.so is installed and verified at $DEV_PAM_SO"
    echo "    Active for sudo:   /etc/pam.d/sudo"
    echo "    Test PAM service:  $PAM_TEST_SERVICE"
    echo ""
    echo "    Set your real PIN:"
    echo "    sudo $PIN_SET_BIN"
else
    echo "==> Smoke test FAILED ($FAIL/2 failures)" >&2
    exit 1
fi
