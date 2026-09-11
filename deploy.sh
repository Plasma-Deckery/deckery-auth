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

# ── Privilege model ────────────────────────────────────────────────────────────
#
# Build steps run as the invoking user (distrobox / Podman are rootless).
# Install steps need root.  We escalate exactly once via pkexec after the
# build completes — one password prompt total.
#
# Protocol:
#   Phase 1 (user)  — build; then exec pkexec with DECKERY_INSTALL=1
#   Phase 2 (root)  — install; user identity passed via ORIG_USER env var
#
# For --uninstall there is no build phase; pkexec is called immediately.
# For --mode=rpm  the script exits after the build; no escalation needed.

# When re-invoked by pkexec we are root and DECKERY_INSTALL=1.
INSTALL_PHASE="${DECKERY_INSTALL:-0}"

# Determine original user (set by pkexec env or sudo).
if [[ $EUID -eq 0 ]]; then
    ORIG_USER="${ORIG_USER:-${SUDO_USER:-}}"
    if [[ -z "$ORIG_USER" ]]; then
        echo "deploy.sh: cannot determine original user (ORIG_USER not set)" >&2
        exit 1
    fi
else
    ORIG_USER="$USER"
fi

ORIG_UID=$(id -u "$ORIG_USER")
ORIG_XDG="${XDG_RUNTIME_DIR:-/run/user/$ORIG_UID}"
ORIG_DBUS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=$ORIG_XDG/bus}"

# Helper: run a systemctl --user command as the original user.
user_systemctl() {
    sudo -u "$ORIG_USER" \
        XDG_RUNTIME_DIR="$ORIG_XDG" \
        DBUS_SESSION_BUS_ADDRESS="$ORIG_DBUS" \
        systemctl --user "$@"
}

# Escalate to root for the install phase (single pkexec prompt).
escalate_for_install() {
    exec pkexec env \
        DECKERY_INSTALL=1 \
        ORIG_USER="$ORIG_USER" \
        XDG_RUNTIME_DIR="$ORIG_XDG" \
        DBUS_SESSION_BUS_ADDRESS="$ORIG_DBUS" \
        bash "$SCRIPT_DIR/deploy.sh" "$@"
    echo "deploy.sh: pkexec not found — re-run as root" >&2
    exit 1
}

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
DISTROBOX_UI="deckery-ui-build"

SO_SRC="$SCRIPT_DIR/target/release/libpam_deckery.so"
PIN_SET_BIN="$SCRIPT_DIR/target/release/deckery-pin-set"
PAM_TEST_BIN="$SCRIPT_DIR/target/release/deckery-pam-test"
DAEMON_BIN_SRC="$SCRIPT_DIR/target/release/deckery-auth-daemon"
UI_BIN_SRC="$SCRIPT_DIR/target/release/deckery-auth-ui"
POLKIT_AGENT_BIN_SRC="$SCRIPT_DIR/target/release/deckery-polkit-agent"
INSTALL_SCRIPT="$SCRIPT_DIR/configure-pam.sh"

DEV_PAM_DIR="/usr/local/lib/security"
DEV_PAM_SO="$DEV_PAM_DIR/pam_deckery.so"
DAEMON_BIN_INSTALL="/usr/local/bin/deckery-auth-daemon"
DAEMON_SERVICE_SRC="$SCRIPT_DIR/deckery-auth-daemon.service"
DAEMON_SERVICE_INSTALL="/etc/systemd/system/deckery-auth-daemon.service"
PIN_SET_BIN_INSTALL="/usr/local/bin/deckery-pin-set"
UI_BIN_INSTALL="/usr/local/bin/deckery-auth-ui"
UI_SERVICE_SRC="$SCRIPT_DIR/deckery-auth-ui.service"
UI_SERVICE_INSTALL="/etc/systemd/user/deckery-auth-ui.service"
POLKIT_AGENT_BIN_INSTALL="/usr/local/bin/deckery-polkit-agent"
POLKIT_AGENT_SERVICE_SRC="$SCRIPT_DIR/deckery-polkit-agent.service"
POLKIT_AGENT_SERVICE_INSTALL="/etc/systemd/user/deckery-polkit-agent.service"
DECKERY_CONF_DIR="/etc/deckery"
HASH_FILE="$DECKERY_CONF_DIR/pin.hash"
HASH_BACKUP="$DECKERY_CONF_DIR/pin.hash.deploy-bak"
PAM_TEST_SERVICE="/etc/pam.d/deckery-test"

TEST_PIN="1234"

# ── Uninstall ─────────────────────────────────────────────────────────────────

if [[ "$UNINSTALL" == true ]]; then
    # No build needed — escalate immediately if not root.
    if [[ $EUID -ne 0 ]]; then escalate_for_install "--uninstall"; fi

    echo "==> Uninstalling deckery-auth (dev)"
    echo ""

    bash "$INSTALL_SCRIPT" --uninstall

    echo "    removing $DEV_PAM_SO"
    if [[ -f "$DEV_PAM_SO" ]]; then
        rm "$DEV_PAM_SO"
        echo "    ✓ removed"
    else
        echo "    (not present — skipped)"
    fi

    echo "    stopping and disabling deckery-auth-ui (user service)"
    if user_systemctl is-active --quiet deckery-auth-ui 2>/dev/null; then
        user_systemctl stop deckery-auth-ui
    fi
    if user_systemctl is-enabled --quiet deckery-auth-ui 2>/dev/null; then
        user_systemctl disable deckery-auth-ui
    fi
    if [[ -f "$UI_SERVICE_INSTALL" ]]; then
        rm "$UI_SERVICE_INSTALL"
        user_systemctl daemon-reload
        echo "    ✓ user service removed"
    else
        echo "    (user service not present — skipped)"
    fi

    echo "    removing $UI_BIN_INSTALL"
    if [[ -f "$UI_BIN_INSTALL" ]]; then
        rm "$UI_BIN_INSTALL"
        echo "    ✓ removed"
    else
        echo "    (not present — skipped)"
    fi

    echo "    stopping, disabling, and unmasking deckery-polkit-agent / plasma-polkit-agent"
    if user_systemctl is-active --quiet deckery-polkit-agent 2>/dev/null; then
        user_systemctl stop deckery-polkit-agent
    fi
    if user_systemctl is-enabled --quiet deckery-polkit-agent 2>/dev/null; then
        user_systemctl disable deckery-polkit-agent
    fi
    if [[ -f "$POLKIT_AGENT_SERVICE_INSTALL" ]]; then
        rm "$POLKIT_AGENT_SERVICE_INSTALL"
        echo "    ✓ polkit agent service removed"
    else
        echo "    (polkit agent service not present — skipped)"
    fi
    # Unmask plasma-polkit-agent so KDE's agent can take over again.
    user_systemctl unmask plasma-polkit-agent.service 2>/dev/null || true
    echo "    ✓ plasma-polkit-agent.service unmasked"
    user_systemctl daemon-reload

    echo "    removing $POLKIT_AGENT_BIN_INSTALL"
    if [[ -f "$POLKIT_AGENT_BIN_INSTALL" ]]; then
        rm "$POLKIT_AGENT_BIN_INSTALL"
        echo "    ✓ removed"
    else
        echo "    (not present — skipped)"
    fi

    echo "    stopping and disabling deckery-auth-daemon"
    if systemctl is-active --quiet deckery-auth-daemon 2>/dev/null; then
        systemctl stop deckery-auth-daemon
    fi
    if systemctl is-enabled --quiet deckery-auth-daemon 2>/dev/null; then
        systemctl disable deckery-auth-daemon
    fi
    if [[ -f "$DAEMON_SERVICE_INSTALL" ]]; then
        rm "$DAEMON_SERVICE_INSTALL"
        systemctl daemon-reload
        echo "    ✓ service removed"
    else
        echo "    (service not present — skipped)"
    fi

    echo "    removing $DAEMON_BIN_INSTALL"
    if [[ -f "$DAEMON_BIN_INSTALL" ]]; then
        rm "$DAEMON_BIN_INSTALL"
        echo "    ✓ removed"
    else
        echo "    (not present — skipped)"
    fi

    echo "    removing $PIN_SET_BIN_INSTALL"
    if [[ -f "$PIN_SET_BIN_INSTALL" ]]; then
        rm "$PIN_SET_BIN_INSTALL"
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

# ── Build (runs as invoking user — distrobox/Podman are rootless) ─────────────

# PAM, daemon, pin-set, polkit-agent: built in the system/Rust distrobox.
# UI: built in the Qt distrobox (needs Qt 6.10+, lives in deckery-ui-build).

if [[ "$INSTALL_PHASE" != "1" ]]; then
    echo "==> Building PAM / daemon / pin-set / polkit-agent (distrobox: $DISTROBOX)"
    distrobox enter "$DISTROBOX" -- \
        cargo build --release --manifest-path "$SCRIPT_DIR/Cargo.toml" \
        -p deckery-pam -p deckery-pam-test -p deckery-auth-daemon -p deckery-pin-set \
        -p deckery-input --bin deckery-input-test \
        -p deckery-polkit-agent

    echo ""
    echo "==> Building UI (distrobox: $DISTROBOX_UI)"
    distrobox enter "$DISTROBOX_UI" -- \
        cargo build --release --manifest-path "$SCRIPT_DIR/Cargo.toml" \
        -p deckery-auth-ui

    if [[ "$MODE" == "rpm" ]]; then
        echo ""
        echo "==> rpm mode: build complete."
        echo "    Artifacts:"
        echo "      $SO_SRC"
        echo "      $PIN_SET_BIN"
        echo "      $DAEMON_BIN_SRC"
        echo "      $UI_BIN_SRC"
        echo "      $POLKIT_AGENT_BIN_SRC"
        exit 0
    fi

    # Build done — escalate to root for the install phase (one pkexec prompt).
    echo ""
    echo "==> Build complete. Escalating for install…"
    escalate_for_install "$@"
fi

# ── Install (running as root via pkexec) ──────────────────────────────────────

# ── Install PAM module ────────────────────────────────────────────────────────

echo ""
echo "==> Installing PAM module"

echo "    mkdir -p $DEV_PAM_DIR"
mkdir -p "$DEV_PAM_DIR"

echo "    cp libpam_deckery.so -> $DEV_PAM_SO"
cp "$SO_SRC" "$DEV_PAM_SO"

echo "    mkdir -p $DECKERY_CONF_DIR"
mkdir -p "$DECKERY_CONF_DIR"

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
    systemctl stop deckery-auth-daemon
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
    mkdir -p "$(dirname "$MOCK_SOCK")"
    rm -f "$MOCK_SOCK"
    python3 -c "
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
        f = conn.makefile('r')
        source = f.readline().strip()
        pin = sudo_pin if source == 'sudo' else test_pin
        # Multi-turn protocol: send PIN:<encoded>, read CORRECT/WRONG from pam_deckery.
        conn.sendall(('PIN:' + pin + '\n').encode())
        f.readline()  # consume CORRECT or WRONG (we don't act on it — just one attempt)
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
        kill "$MOCK_PID" 2>/dev/null || true
        rm -f "$MOCK_SOCK"
        MOCK_PID=""
    fi
}

echo "    writing $PAM_TEST_SERVICE"
tee "$PAM_TEST_SERVICE" > /dev/null <<EOF
auth  sufficient  $DEV_PAM_SO
auth  required    pam_deny.so
EOF

# Backup existing hash if present
HASH_EXISTED=false
if [[ -f "$HASH_FILE" ]]; then
    HASH_EXISTED=true
    echo "    backing up existing pin.hash"
    cp "$HASH_FILE" "$HASH_BACKUP"
fi

# Set test PIN via deckery-pin-set --stdin (tests hash generation too).
echo "    setting test PIN via deckery-pin-set --stdin"
printf '%s\n' "$TEST_PIN" | "$PIN_SET_BIN" --stdin

PASS=0
FAIL=0

echo ""
echo "    [1/2] correct PIN ($TEST_PIN) — mock socket returns correct PIN → expect success"
# sudo_pin=TEST_PIN so sudo's own PAM auth succeeds; test_pin=TEST_PIN so
# pam_deckery accepts the PIN.
start_mock_daemon "$TEST_PIN" "$TEST_PIN"
if "$PAM_TEST_BIN" deckery-test "$USER" "$TEST_PIN"; then
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
if ! "$PAM_TEST_BIN" deckery-test "$USER" "$TEST_PIN"; then
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
    mv "$HASH_BACKUP" "$HASH_FILE"
else
    echo "    removing test hash (no original to restore)"
    rm -f "$HASH_FILE"
fi

# Always remove the test service — it has no purpose after the smoke test
echo "    removing $PAM_TEST_SERVICE"
rm -f "$PAM_TEST_SERVICE"

if [[ $FAIL -gt 0 ]]; then
    # Restore daemon state before exiting on failure
    if [[ "$DAEMON_WAS_RUNNING" == true ]]; then
        systemctl start deckery-auth-daemon || true
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
bash "$INSTALL_SCRIPT" --so-path="$DEV_PAM_SO"

# ── Install daemon ────────────────────────────────────────────────────────────

echo ""
echo "==> Installing deckery-auth-daemon"

echo "    cp deckery-auth-daemon -> $DAEMON_BIN_INSTALL"
install -m 755 "$DAEMON_BIN_SRC" "$DAEMON_BIN_INSTALL"

echo "    installing service unit -> $DAEMON_SERVICE_INSTALL"
cp "$DAEMON_SERVICE_SRC" "$DAEMON_SERVICE_INSTALL"
systemctl daemon-reload

echo "    enabling and starting deckery-auth-daemon"
systemctl enable --now deckery-auth-daemon
echo "    ✓ daemon running"

# ── Install UI ────────────────────────────────────────────────────────────────

echo ""
echo "==> Installing deckery-auth-ui"

# Stop before copying — running binaries are locked on Linux.
if user_systemctl is-active --quiet deckery-auth-ui 2>/dev/null; then
    echo "    stopping deckery-auth-ui"
    user_systemctl stop deckery-auth-ui
fi

echo "    cp deckery-auth-ui -> $UI_BIN_INSTALL"
install -m 755 "$UI_BIN_SRC" "$UI_BIN_INSTALL"

echo "    installing user service unit -> $UI_SERVICE_INSTALL"
cp "$UI_SERVICE_SRC" "$UI_SERVICE_INSTALL"
user_systemctl daemon-reload

echo "    enabling and starting deckery-auth-ui"
user_systemctl enable --now deckery-auth-ui
echo "    ✓ UI running"

# ── Install deckery-pin-set ───────────────────────────────────────────────────

echo ""
echo "==> Installing deckery-pin-set"

echo "    cp deckery-pin-set -> $PIN_SET_BIN_INSTALL"
install -m 755 "$PIN_SET_BIN" "$PIN_SET_BIN_INSTALL"
echo "    ✓ installed"

# ── Install deckery-polkit-agent ──────────────────────────────────────────────

echo ""
echo "==> Installing deckery-polkit-agent"

# Stop before copying — running binary is locked on Linux.
if user_systemctl is-active --quiet deckery-polkit-agent 2>/dev/null; then
    echo "    stopping deckery-polkit-agent"
    user_systemctl stop deckery-polkit-agent
fi

echo "    cp deckery-polkit-agent -> $POLKIT_AGENT_BIN_INSTALL"
install -m 755 "$POLKIT_AGENT_BIN_SRC" "$POLKIT_AGENT_BIN_INSTALL"

echo "    installing user service unit -> $POLKIT_AGENT_SERVICE_INSTALL"
cp "$POLKIT_AGENT_SERVICE_SRC" "$POLKIT_AGENT_SERVICE_INSTALL"

# Mask KDE's built-in polkit agent so only ours runs.
echo "    masking plasma-polkit-agent.service"
user_systemctl mask plasma-polkit-agent.service
echo "    ✓ plasma-polkit-agent.service masked"

user_systemctl daemon-reload

echo "    enabling and starting deckery-polkit-agent"
user_systemctl enable --now deckery-polkit-agent
echo "    ✓ polkit agent running"

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo "==> Done."
echo ""
echo "    pam_deckery.so:        $DEV_PAM_SO"
echo "    deckery-auth-daemon:   $DAEMON_BIN_INSTALL (system service, enabled)"
echo "    deckery-auth-ui:       $UI_BIN_INSTALL (user service, enabled)"
echo "    deckery-pin-set:       $PIN_SET_BIN_INSTALL"
echo "    deckery-polkit-agent:  $POLKIT_AGENT_BIN_INSTALL (user service, enabled)"
echo "    Active for:            /etc/pam.d/sudo, /etc/pam.d/polkit-1"
echo ""
echo "    Set your PIN (controller):  sudo deckery-pin-set"
echo "    Set your PIN (keyboard):    sudo deckery-pin-set --keyboard"
echo ""
echo "    Test controller PIN entry:"
echo "    sudo systemctl status deckery-auth-daemon"
echo "    (then trigger a sudo prompt and press buttons on the controller)"
echo ""
echo "    Test polkit auth:"
echo "    pkexec id"
echo "    (should show the deckery auth overlay)"
