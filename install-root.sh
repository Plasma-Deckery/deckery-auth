#!/usr/bin/env bash
# install-root.sh — Runs as root (via pkexec). Does all privileged install steps
# in one shot so only a single password prompt is needed.
#
# Usage (from deckery-auth directory):
#   pkexec bash install-root.sh
#   pkexec bash install-root.sh --uninstall

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

UNINSTALL=false
for arg in "$@"; do
    [[ "$arg" == "--uninstall" ]] && UNINSTALL=true
done

SO_SRC="$SCRIPT_DIR/target/release/libpam_deckery.so"
DAEMON_BIN_SRC="$SCRIPT_DIR/target/release/deckery-auth-daemon"
PIN_SET_BIN="$SCRIPT_DIR/target/release/deckery-pin-set"
PAM_TEST_BIN="$SCRIPT_DIR/target/release/deckery-pam-test"

DEV_PAM_DIR="/usr/local/lib/security"
DEV_PAM_SO="$DEV_PAM_DIR/pam_deckery.so"
DAEMON_BIN_INSTALL="/usr/local/bin/deckery-auth-daemon"
DAEMON_SERVICE_SRC="$SCRIPT_DIR/deckery-auth-daemon.service"
DAEMON_SERVICE_INSTALL="/etc/systemd/system/deckery-auth-daemon.service"
DECKERY_CONF_DIR="/etc/deckery"
HASH_FILE="$DECKERY_CONF_DIR/pin.hash"
PAM_SUDO="/etc/pam.d/sudo"
PAM_TEST_SERVICE="/etc/pam.d/deckery-test"
TEST_PIN="1234"

# ── Uninstall ──────────────────────────────────────────────────────────────────

if [[ "$UNINSTALL" == true ]]; then
    echo "==> Uninstalling deckery-auth"

    # Remove PAM entry
    if grep -q "pam_deckery" "$PAM_SUDO" 2>/dev/null; then
        sed -i '/pam_deckery/d' "$PAM_SUDO"
        echo "    removed pam_deckery from $PAM_SUDO"
    fi

    # Stop and disable daemon
    systemctl stop  deckery-auth-daemon 2>/dev/null || true
    systemctl disable deckery-auth-daemon 2>/dev/null || true
    rm -f "$DAEMON_SERVICE_INSTALL"
    systemctl daemon-reload
    echo "    daemon service removed"

    rm -f "$DAEMON_BIN_INSTALL" && echo "    removed $DAEMON_BIN_INSTALL"
    rm -f "$DEV_PAM_SO"         && echo "    removed $DEV_PAM_SO"
    echo ""
    echo "NOTE: $HASH_FILE was NOT removed."
    echo "==> Uninstall complete."
    exit 0
fi

# ── Install ────────────────────────────────────────────────────────────────────

echo "==> Installing pam_deckery.so"
mkdir -p "$DEV_PAM_DIR"
cp "$SO_SRC" "$DEV_PAM_SO"
chmod 755 "$DEV_PAM_SO"
echo "    $DEV_PAM_SO"

# ── Smoke test (conversation fallback — no daemon running) ─────────────────────

echo ""
echo "==> Smoke test"

# Stop daemon if running so PAM conversation fallback path is exercised
if systemctl is-active --quiet deckery-auth-daemon 2>/dev/null; then
    systemctl stop deckery-auth-daemon
    echo "    (daemon paused for test)"
fi

mkdir -p "$DECKERY_CONF_DIR"
tee "$PAM_TEST_SERVICE" > /dev/null <<EOF
auth  sufficient  $DEV_PAM_SO
auth  sufficient  pam_unix.so
auth  required    pam_deny.so
EOF

HASH_EXISTED=false
if [[ -f "$HASH_FILE" ]]; then
    HASH_EXISTED=true
    cp "$HASH_FILE" "${HASH_FILE}.bak"
fi

printf '%s\n' "$TEST_PIN" | "$PIN_SET_BIN" --stdin

PASS=0; FAIL=0

echo "    [1/2] correct PIN ($TEST_PIN) → expect success"
if "$PAM_TEST_BIN" deckery-test "$SUDO_USER" "$TEST_PIN" 2>&1; then
    echo "    ✓ PASS"; PASS=$((PASS+1))
else
    echo "    ✗ FAIL"; FAIL=$((FAIL+1))
fi

echo "    [2/2] wrong PIN (9999) → expect failure"
if ! "$PAM_TEST_BIN" deckery-test "$SUDO_USER" "9999" 2>&1; then
    echo "    ✓ PASS"; PASS=$((PASS+1))
else
    echo "    ✗ FAIL (wrong PIN accepted — bug!)"; FAIL=$((FAIL+1))
fi

# Restore
if [[ "$HASH_EXISTED" == true ]]; then
    mv "${HASH_FILE}.bak" "$HASH_FILE"
else
    rm -f "$HASH_FILE"
fi
rm -f "$PAM_TEST_SERVICE"

if [[ $FAIL -gt 0 ]]; then
    echo ""
    echo "==> Smoke test FAILED ($FAIL/2) — aborting." >&2
    exit 1
fi
echo ""
echo "==> Smoke test passed ($PASS/2) ✓"

# ── PAM /etc/pam.d/sudo ────────────────────────────────────────────────────────

echo ""
echo "==> Configuring $PAM_SUDO"

# Remove any existing pam_deckery line (old or new) and insert fresh
sed -i '/pam_deckery/d' "$PAM_SUDO"
# Insert after the #%PAM-1.0 header line
sed -i "1a auth  sufficient  $DEV_PAM_SO  source=sudo" "$PAM_SUDO"
echo "    inserted: auth sufficient $DEV_PAM_SO source=sudo"

# ── Daemon ─────────────────────────────────────────────────────────────────────

echo ""
echo "==> Installing deckery-auth-daemon"
cp "$DAEMON_BIN_SRC" "$DAEMON_BIN_INSTALL"
chmod 755 "$DAEMON_BIN_INSTALL"
echo "    $DAEMON_BIN_INSTALL"

cp "$DAEMON_SERVICE_SRC" "$DAEMON_SERVICE_INSTALL"
systemctl daemon-reload
systemctl enable --now deckery-auth-daemon
echo "    service enabled and started"

echo ""
echo "==> Done."
echo ""
echo "    Set your real PIN:"
echo "    pkexec $PIN_SET_BIN"
echo ""
echo "    Watch daemon logs:"
echo "    journalctl -u deckery-auth-daemon -f"
