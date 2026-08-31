#!/usr/bin/env bash
# deploy.sh — build, install, or uninstall deckery-auth (dev)
#
# Usage:
#   ./deploy.sh [--mode=dev|rpm] [--uninstall]
#
# Modes:
#   dev (default)  Build inside the deckery distrobox, install pam_deckery.so
#                  to /usr/local/lib/security/ (writable on Bazzite), run an
#                  isolated PAM smoke test, then activate via configure-pam.sh.
#                  Also installs deckery-auth-daemon and enables its systemd unit.
#
#   rpm            Build only. Leaves artifacts in target/release/ for the
#                  RPM build process — no system changes.
#
# Flags:
#   --uninstall    Reverse the install: remove pam_deckery.so from
#                  /etc/pam.d/sudo, stop and remove the daemon service, and
#                  clean up installed files.
#                  Does NOT remove /etc/deckery/pin.hash.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Defaults ──────────────────────────────────────────────────────────────────

MODE="dev"
UNINSTALL=false

# ── Argument parsing ──────────────────────────────────────────────────────────

for arg in "$@"; do
    case "$arg" in
        --mode=dev)  MODE="dev" ;;
        --mode=rpm)  MODE="rpm" ;;
        --uninstall) UNINSTALL=true ;;
        *)
            echo "Unknown argument: $arg" >&2
            echo "Usage: $0 [--mode=dev|rpm] [--uninstall]" >&2
            exit 1
            ;;
    esac
done

# ── Paths ─────────────────────────────────────────────────────────────────────

DISTROBOX="deckery"

SO_SRC="$SCRIPT_DIR/target/release/libpam_deckery.so"
PIN_SET_BIN="$SCRIPT_DIR/target/release/deckery-pin-set"
PAM_TEST_BIN="$SCRIPT_DIR/target/release/deckery-pam-test"
DAEMON_BIN_SRC="$SCRIPT_DIR/target/release/deckery-auth-daemon"
UI_BIN_SRC="$SCRIPT_DIR/target/release/deckery-auth-ui"
INSTALL_SCRIPT="$SCRIPT_DIR/configure-pam.sh"

DEV_PAM_DIR="/usr/local/lib/security"
DEV_PAM_SO="$DEV_PAM_DIR/pam_deckery.so"
DAEMON_BIN_INSTALL="/usr/local/bin/deckery-auth-daemon"
DAEMON_SERVICE_SRC="$SCRIPT_DIR/deckery-auth-daemon.service"
DAEMON_SERVICE_INSTALL="/etc/systemd/system/deckery-auth-daemon.service"
UI_BIN_INSTALL="/usr/local/bin/deckery-auth-ui"
UI_SERVICE_SRC="$SCRIPT_DIR/deckery-auth-ui.service"
UI_SERVICE_INSTALL="/etc/systemd/user/deckery-auth-ui.service"
DBUS_POLICY_SRC="$SCRIPT_DIR/org.deckery.AuthDisplay1.conf"
DBUS_POLICY_INSTALL="/etc/dbus-1/system.d/org.deckery.AuthDisplay1.conf"

DECKERY_CONF_DIR="/etc/deckery"
HASH_FILE="$DECKERY_CONF_DIR/pin.hash"
HASH_BACKUP="$DECKERY_CONF_DIR/pin.hash.deploy-bak"
PAM_TEST_SERVICE="/etc/pam.d/deckery-test"

TEST_PIN="1234"

# ── Uninstall ─────────────────────────────────────────────────────────────────

if [[ "$UNINSTALL" == true ]]; then
    echo "==> Uninstalling deckery-auth (dev)"
    echo ""

    sudo bash "$INSTALL_SCRIPT" --uninstall

    echo "    removing D-Bus policy $DBUS_POLICY_INSTALL"
    if [[ -f "$DBUS_POLICY_INSTALL" ]]; then
        sudo rm "$DBUS_POLICY_INSTALL"
        echo "    ✓ removed"
    else
        echo "    (not present — skipped)"
    fi

    echo "    removing $DEV_PAM_SO"
    if [[ -f "$DEV_PAM_SO" ]]; then
        sudo rm "$DEV_PAM_SO"
        echo "    ✓ removed"
    else
        echo "    (not present — skipped)"
    fi

    echo "    stopping and disabling deckery-auth-ui (user service)"
    if systemctl --user is-active --quiet deckery-auth-ui 2>/dev/null; then
        systemctl --user stop deckery-auth-ui
    fi
    if systemctl --user is-enabled --quiet deckery-auth-ui 2>/dev/null; then
        systemctl --user disable deckery-auth-ui
    fi
    if [[ -f "$UI_SERVICE_INSTALL" ]]; then
        sudo rm "$UI_SERVICE_INSTALL"
        systemctl --user daemon-reload
        echo "    ✓ user service removed"
    else
        echo "    (user service not present — skipped)"
    fi

    echo "    removing $UI_BIN_INSTALL"
    if [[ -f "$UI_BIN_INSTALL" ]]; then
        sudo rm "$UI_BIN_INSTALL"
        echo "    ✓ removed"
    else
        echo "    (not present — skipped)"
    fi

    echo "    stopping and disabling deckery-auth-daemon"
    if systemctl is-active --quiet deckery-auth-daemon 2>/dev/null; then
        sudo systemctl stop deckery-auth-daemon
    fi
    if systemctl is-enabled --quiet deckery-auth-daemon 2>/dev/null; then
        sudo systemctl disable deckery-auth-daemon
    fi
    if [[ -f "$DAEMON_SERVICE_INSTALL" ]]; then
        sudo rm "$DAEMON_SERVICE_INSTALL"
        sudo systemctl daemon-reload
        echo "    ✓ service removed"
    else
        echo "    (service not present — skipped)"
    fi

    echo "    removing $DAEMON_BIN_INSTALL"
    if [[ -f "$DAEMON_BIN_INSTALL" ]]; then
        sudo rm "$DAEMON_BIN_INSTALL"
        echo "    ✓ removed"
    else
        echo "    (not present — skipped)"
    fi

    echo ""
    echo "    NOTE: /etc/deckery/pin.hash was NOT removed."
    echo "    Remove manually if needed: sudo rm $HASH_FILE"
    echo ""
    echo "==> Uninstall complete."
    exit 0
fi

# ── Build ─────────────────────────────────────────────────────────────────────

echo "==> Building (distrobox: $DISTROBOX)"
distrobox enter "$DISTROBOX" -- cargo build --release --manifest-path "$SCRIPT_DIR/Cargo.toml"

if [[ "$MODE" == "rpm" ]]; then
    echo ""
    echo "==> rpm mode: build complete."
    echo "    Artifacts:"
    echo "      $SO_SRC"
    echo "      $PIN_SET_BIN"
    echo "      $DAEMON_BIN_SRC"
    echo "      $UI_BIN_SRC"
    exit 0
fi

# ── Install PAM module ────────────────────────────────────────────────────────

echo ""
echo "==> Installing PAM module"

echo "    mkdir -p $DEV_PAM_DIR"
sudo mkdir -p "$DEV_PAM_DIR"

# Use pkexec (polkit) for the .so copy — this step atomically replaces the
# installed pam_deckery.so.  We deliberately avoid `sudo cp` here because
# sudo itself goes through pam_deckery: if the currently installed .so is
# broken (e.g. crashes on conv()), `sudo cp` would segfault before the fix
# lands. pkexec uses polkit, bypassing /etc/pam.d/sudo entirely.
echo "    cp libpam_deckery.so -> $DEV_PAM_SO  (via pkexec — polkit dialog)"
pkexec cp "$SO_SRC" "$DEV_PAM_SO"

echo "    mkdir -p $DECKERY_CONF_DIR"
sudo mkdir -p "$DECKERY_CONF_DIR"

# ── Smoke test ────────────────────────────────────────────────────────────────
# Uses an isolated /etc/pam.d/deckery-test service — /etc/pam.d/sudo is not
# touched until the test passes.
#
# pam_deckery no longer has a keyboard-fallback conversation path; it only
# authenticates via the running deckery-auth-daemon. The smoke test therefore
# spins up a minimal Python mock socket that responds with a known PIN so the
# full path (socket → PIN → hash verification) can be exercised without a
# real controller.

echo ""
echo "==> Smoke test"

# Stop the daemon for the duration of the smoke test so the mock socket can
# bind to the same path. It is restarted (or left stopped) at the end.
DAEMON_WAS_RUNNING=false
if systemctl is-active --quiet deckery-auth-daemon 2>/dev/null; then
    echo "    stopping deckery-auth-daemon for smoke test"
    sudo systemctl stop deckery-auth-daemon
    DAEMON_WAS_RUNNING=true
fi

MOCK_SOCK="/run/deckery/auth.sock"
MOCK_PID=""

# Start a mock daemon socket.
#
# Takes two PIN arguments:
#   $1  sudo_pin   — returned for connections from source "sudo"
#                    (i.e. sudo's own PAM auth, which also goes through
#                    pam_deckery — we always answer correctly so sudo works)
#   $2  test_pin   — returned for all other sources (the deckery-test service)
#
# pam_deckery sends the source name as the first line before reading the PIN,
# so the mock can distinguish the two callers.
start_mock_daemon() {
    local sudo_pin="$1"
    local test_pin="$2"
    sudo mkdir -p "$(dirname "$MOCK_SOCK")"
    sudo rm -f "$MOCK_SOCK"
    sudo python3 -c "
import socket, sys, os
sock_path, sudo_pin, test_pin = sys.argv[1], sys.argv[2], sys.argv[3]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sock_path)
os.chmod(sock_path, 0o600)
s.listen(5)
s.settimeout(30)
while True:
    try:
        conn, _ = s.accept()
        source = conn.makefile('r').readline().strip()
        pin = sudo_pin if source == 'sudo' else test_pin
        conn.sendall((pin + '\n').encode())
        conn.close()
    except Exception:
        break
" "$MOCK_SOCK" "$sudo_pin" "$test_pin" &
    MOCK_PID=$!
    # Give the mock socket a moment to bind before pam_deckery tries to connect.
    sleep 0.2
}

stop_mock_daemon() {
    if [[ -n "$MOCK_PID" ]]; then
        sudo kill "$MOCK_PID" 2>/dev/null || true
        sudo rm -f "$MOCK_SOCK"
        MOCK_PID=""
    fi
}

echo "    writing $PAM_TEST_SERVICE"
sudo tee "$PAM_TEST_SERVICE" > /dev/null <<EOF
auth  sufficient  $DEV_PAM_SO
auth  required    pam_deny.so
EOF

# Backup existing hash if present
HASH_EXISTED=false
if [[ -f "$HASH_FILE" ]]; then
    HASH_EXISTED=true
    echo "    backing up existing pin.hash"
    sudo cp "$HASH_FILE" "$HASH_BACKUP"
fi

# Set test PIN via deckery-pin-set --stdin (tests hash generation too).
echo "    setting test PIN via deckery-pin-set --stdin"
printf '%s\n' "$TEST_PIN" | sudo "$PIN_SET_BIN" --stdin

PASS=0
FAIL=0

echo ""
echo "    [1/2] correct PIN ($TEST_PIN) — mock socket returns correct PIN → expect success"
# sudo_pin=TEST_PIN so sudo's own PAM auth succeeds; test_pin=TEST_PIN so
# pam_deckery accepts the PIN.
start_mock_daemon "$TEST_PIN" "$TEST_PIN"
if sudo "$PAM_TEST_BIN" deckery-test "$USER" "$TEST_PIN"; then
    echo "    ✓ PASS"
    PASS=$((PASS + 1))
else
    echo "    ✗ FAIL"
    FAIL=$((FAIL + 1))
fi
stop_mock_daemon

echo ""
echo "    [2/2] wrong PIN — mock socket returns wrong PIN (9999) → expect failure"
# sudo_pin=TEST_PIN so sudo auth still works; test_pin=9999 (wrong) so
# pam_deckery rejects it and auth fails.
start_mock_daemon "$TEST_PIN" "9999"
if ! sudo "$PAM_TEST_BIN" deckery-test "$USER" "$TEST_PIN"; then
    echo "    ✓ PASS"
    PASS=$((PASS + 1))
else
    echo "    ✗ FAIL (wrong PIN was accepted — this is a bug)"
    FAIL=$((FAIL + 1))
fi
stop_mock_daemon

# Restore original hash
echo ""
if [[ "$HASH_EXISTED" == true ]]; then
    echo "    restoring original pin.hash"
    sudo mv "$HASH_BACKUP" "$HASH_FILE"
else
    echo "    removing test hash (no original to restore)"
    sudo rm -f "$HASH_FILE"
fi

# Always remove the test service — it has no purpose after the smoke test
echo "    removing $PAM_TEST_SERVICE"
sudo rm -f "$PAM_TEST_SERVICE"

if [[ $FAIL -gt 0 ]]; then
    # Restore daemon state before exiting on failure
    if [[ "$DAEMON_WAS_RUNNING" == true ]]; then
        sudo systemctl start deckery-auth-daemon || true
    fi
    echo ""
    echo "==> Smoke test FAILED ($FAIL/2 failures) — aborting install" >&2
    exit 1
fi

echo ""
echo "==> Smoke test passed ($PASS/2) ✓"

# ── Activate PAM module ───────────────────────────────────────────────────────

echo ""
echo "==> Activating PAM module"
sudo bash "$INSTALL_SCRIPT" --so-path="$DEV_PAM_SO"

# ── Install D-Bus policy ──────────────────────────────────────────────────────

echo ""
echo "==> Installing D-Bus policy"
echo "    cp org.deckery.AuthDisplay1.conf -> $DBUS_POLICY_INSTALL"
sudo cp "$DBUS_POLICY_SRC" "$DBUS_POLICY_INSTALL"
echo "    ✓ policy installed"

# ── Install daemon ────────────────────────────────────────────────────────────

echo ""
echo "==> Installing deckery-auth-daemon"

echo "    cp deckery-auth-daemon -> $DAEMON_BIN_INSTALL"
sudo cp "$DAEMON_BIN_SRC" "$DAEMON_BIN_INSTALL"

echo "    installing service unit -> $DAEMON_SERVICE_INSTALL"
sudo cp "$DAEMON_SERVICE_SRC" "$DAEMON_SERVICE_INSTALL"
sudo systemctl daemon-reload

echo "    enabling and starting deckery-auth-daemon"
sudo systemctl enable --now deckery-auth-daemon
echo "    ✓ daemon running"

# ── Install UI ────────────────────────────────────────────────────────────────

echo ""
echo "==> Installing deckery-auth-ui"

echo "    cp deckery-auth-ui -> $UI_BIN_INSTALL"
sudo cp "$UI_BIN_SRC" "$UI_BIN_INSTALL"

echo "    installing user service unit -> $UI_SERVICE_INSTALL"
sudo cp "$UI_SERVICE_SRC" "$UI_SERVICE_INSTALL"
systemctl --user daemon-reload

echo "    enabling and starting deckery-auth-ui"
systemctl --user enable --now deckery-auth-ui
echo "    ✓ UI running"

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo "==> Done."
echo ""
echo "    pam_deckery.so:        $DEV_PAM_SO"
echo "    deckery-auth-daemon:   $DAEMON_BIN_INSTALL (system service, enabled)"
echo "    deckery-auth-ui:       $UI_BIN_INSTALL (user service, enabled)"
echo "    Active for:            /etc/pam.d/sudo"
echo ""
echo "    Set your real PIN:"
echo "    sudo $PIN_SET_BIN"
echo ""
echo "    Test controller PIN entry:"
echo "    sudo systemctl status deckery-auth-daemon"
echo "    (then trigger a sudo prompt and press buttons on the controller)"
