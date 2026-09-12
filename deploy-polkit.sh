#!/usr/bin/env bash
# deploy-polkit.sh — build, install, or uninstall the deckery-polkit-agent
#
# Kept separate from deploy.sh so sudo auth (pam_deckery.so) is never at
# risk: if the polkit agent is broken, sudo still works through the normal
# PAM stack.
#
# Usage:
#   ./deploy-polkit.sh [--uninstall]
#
# Requires: deckery-auth-daemon already installed (deploy.sh ran first).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Privilege model ────────────────────────────────────────────────────────────
# Phase 1 (user)  — build in deckery-ui-build distrobox
# Phase 2 (root)  — install binary + service; pkexec escalation
# User-level work — mask/unmask/enable/disable user services (no root needed)

INSTALL_PHASE="${DECKERY_INSTALL:-0}"

if [[ $EUID -eq 0 ]]; then
    ORIG_USER="${ORIG_USER:-${SUDO_USER:-}}"
    if [[ -z "$ORIG_USER" ]]; then
        echo "deploy-polkit.sh: cannot determine original user (ORIG_USER not set)" >&2
        exit 1
    fi
else
    ORIG_USER="$USER"
fi

ORIG_UID=$(id -u "$ORIG_USER")
ORIG_XDG="${XDG_RUNTIME_DIR:-/run/user/$ORIG_UID}"
ORIG_DBUS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=$ORIG_XDG/bus}"

user_systemctl() {
    sudo -u "$ORIG_USER" \
        XDG_RUNTIME_DIR="$ORIG_XDG" \
        DBUS_SESSION_BUS_ADDRESS="$ORIG_DBUS" \
        systemctl --user "$@"
}

escalate_for_install() {
    exec pkexec env \
        DECKERY_INSTALL=1 \
        ORIG_USER="$ORIG_USER" \
        XDG_RUNTIME_DIR="$ORIG_XDG" \
        DBUS_SESSION_BUS_ADDRESS="$ORIG_DBUS" \
        bash "$SCRIPT_DIR/deploy-polkit.sh" "$@"
    echo "deploy-polkit.sh: pkexec not found — re-run as root" >&2
    exit 1
}

# ── Paths ──────────────────────────────────────────────────────────────────────

DISTROBOX_UI="deckery-ui-build"
TARGET_FEDORA="$SCRIPT_DIR/target-fedora"

POLKIT_AGENT_BIN_SRC="$TARGET_FEDORA/release/deckery-polkit-agent"
POLKIT_AGENT_BIN_INSTALL="/usr/local/bin/deckery-polkit-agent"
POLKIT_AGENT_SERVICE_SRC="$SCRIPT_DIR/deckery-polkit-agent.service"
POLKIT_AGENT_SERVICE_INSTALL="/etc/systemd/user/deckery-polkit-agent.service"

DEV_PAM_SO="/usr/local/lib/security/pam_deckery.so"

# ── Argument parsing ──────────────────────────────────────────────────────────

UNINSTALL=false
for arg in "$@"; do
    case "$arg" in
        --uninstall) UNINSTALL=true ;;
        *)
            echo "Unknown argument: $arg" >&2
            echo "Usage: $0 [--uninstall]" >&2
            exit 1
            ;;
    esac
done

# ── Uninstall ─────────────────────────────────────────────────────────────────

if [[ "$UNINSTALL" == true ]]; then
    if [[ $EUID -ne 0 ]]; then escalate_for_install "--uninstall"; fi

    echo "==> Uninstalling deckery-polkit-agent"
    echo ""

    echo "    stopping and disabling deckery-polkit-agent"
    if user_systemctl is-active --quiet deckery-polkit-agent 2>/dev/null; then
        user_systemctl stop deckery-polkit-agent
    fi
    if user_systemctl is-enabled --quiet deckery-polkit-agent 2>/dev/null; then
        user_systemctl disable deckery-polkit-agent
    fi
    if [[ -f "$POLKIT_AGENT_SERVICE_INSTALL" ]]; then
        rm "$POLKIT_AGENT_SERVICE_INSTALL"
        echo "    ✓ service removed"
    else
        echo "    (service not present — skipped)"
    fi

    echo "    unmasking plasma-polkit-agent.service"
    user_systemctl unmask plasma-polkit-agent.service 2>/dev/null || true
    echo "    ✓ KDE agent restored"

    user_systemctl daemon-reload

    echo "    removing $POLKIT_AGENT_BIN_INSTALL"
    if [[ -f "$POLKIT_AGENT_BIN_INSTALL" ]]; then
        rm "$POLKIT_AGENT_BIN_INSTALL"
        echo "    ✓ removed"
    else
        echo "    (not present — skipped)"
    fi

    echo ""
    echo "==> Uninstall complete. KDE polkit agent is active again."
    exit 0
fi

# ── Build (user phase) ────────────────────────────────────────────────────────

if [[ "$INSTALL_PHASE" != "1" ]]; then
    echo "==> Building deckery-polkit-agent (distrobox: $DISTROBOX_UI, target: target-fedora)"
    distrobox enter "$DISTROBOX_UI" -- bash -c \
        "cd '$SCRIPT_DIR' && CARGO_TARGET_DIR='$TARGET_FEDORA' cargo build --release -p deckery-polkit-agent"

    echo ""
    echo "==> Build complete. Escalating for install…"
    escalate_for_install "$@"
fi

# ── Install (root phase via pkexec) ───────────────────────────────────────────

echo ""
echo "==> Installing deckery-polkit-agent"

# Stop the running agent before replacing the binary.
if user_systemctl is-active --quiet deckery-polkit-agent 2>/dev/null; then
    echo "    stopping deckery-polkit-agent"
    user_systemctl stop deckery-polkit-agent
fi

echo "    cp deckery-polkit-agent -> $POLKIT_AGENT_BIN_INSTALL"
install -m 755 "$POLKIT_AGENT_BIN_SRC" "$POLKIT_AGENT_BIN_INSTALL"

echo "    installing service unit -> $POLKIT_AGENT_SERVICE_INSTALL"
cp "$POLKIT_AGENT_SERVICE_SRC" "$POLKIT_AGENT_SERVICE_INSTALL"

# No PAM stack change needed: the agent talks directly to deckery-auth-daemon
# via /run/deckery/polkit.sock — no pam_deckery.so involved on the polkit path.

# Mask KDE's built-in polkit agent so ours is the only one running.
echo "    masking plasma-polkit-agent.service"
user_systemctl mask plasma-polkit-agent.service
echo "    ✓ masked"

user_systemctl daemon-reload

echo "    enabling and starting deckery-polkit-agent"
user_systemctl enable --now deckery-polkit-agent
echo "    ✓ running"

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo "==> Done."
echo ""
echo "    deckery-polkit-agent:  $POLKIT_AGENT_BIN_INSTALL (user service, enabled)"
echo "    Socket:                /run/deckery/polkit.sock (0666, exe-verified)"
echo ""
echo "    Test:  pkexec id"
echo "    Undo:  ./deploy-polkit.sh --uninstall"
