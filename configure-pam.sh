#!/usr/bin/env bash
# configure-pam.sh — register or remove pam_deckery.so in the auth chain
#
# Single source of truth for PAM configuration changes. Called by:
#   - deploy.sh       (dev installs, passing the dev .so path)
#   - RPM %post       (production installs, passing /usr/lib64/security/pam_deckery.so)
#   - RPM %preun      (uninstall, passing --uninstall)
#
# Does NOT copy the .so file — that is the caller's responsibility.
# Does NOT touch /etc/deckery/pin.hash — the PIN hash belongs to the user.
#
# Usage:
#   sudo configure-pam.sh --so-path=<absolute-path>   # register in auth chain
#   sudo configure-pam.sh --uninstall                  # remove from auth chain

set -euo pipefail

SO_PATH=""
UNINSTALL=false

for arg in "$@"; do
    case "$arg" in
        --so-path=*) SO_PATH="${arg#--so-path=}" ;;
        --uninstall) UNINSTALL=true ;;
        *)
            echo "Unknown argument: $arg" >&2
            echo "Usage: $0 --so-path=<path> | --uninstall" >&2
            exit 1
            ;;
    esac
done

if [[ "$UNINSTALL" == true ]]; then
    # ── Uninstall ──────────────────────────────────────────────────────────────
    echo "    removing pam_deckery.so from /etc/pam.d/sudo"
    if grep -q "pam_deckery.so" /etc/pam.d/sudo 2>/dev/null; then
        sed -i '/pam_deckery.so/d' /etc/pam.d/sudo
        echo "    ✓ removed"
    else
        echo "    (not present — skipped)"
    fi

    echo "    removing /etc/pam.d/polkit-1 (deckery override)"
    if [[ -f /etc/pam.d/polkit-1 ]]; then
        rm /etc/pam.d/polkit-1
        echo "    ✓ removed (polkit-1 falls back to /usr/lib/pam.d/polkit-1)"
    else
        echo "    (not present — skipped)"
    fi
    exit 0
fi

# ── Install ────────────────────────────────────────────────────────────────────

if [[ -z "$SO_PATH" ]]; then
    echo "Error: --so-path is required for installation" >&2
    echo "Usage: $0 --so-path=<path> | --uninstall" >&2
    exit 1
fi

# authselect does not manage service-specific files like /etc/pam.d/sudo —
# only the common stacks (system-auth, password-auth, etc.). Direct editing
# is therefore safe and the established approach (same as howdy,
# google-authenticator-libpam). Idempotent: skipped if already present.
echo "    activating pam_deckery.so in /etc/pam.d/sudo"
if ! grep -q "pam_deckery.so" /etc/pam.d/sudo 2>/dev/null; then
    sed -i "/auth.*include.*system-auth/i auth  [success=done authinfo_unavail=ignore auth_err=ignore default=die]  $SO_PATH  source=sudo" /etc/pam.d/sudo
    echo "    ✓ added"
else
    echo "    (already present — skipped)"
fi

# polkit-1: create /etc/pam.d/polkit-1 (takes precedence over
# /usr/lib/pam.d/polkit-1; survives package updates to the latter).
# pam_deckery.so runs first — daemon handles PIN/password via the controller
# overlay. If the daemon is unreachable it returns AUTHINFO_UNAVAIL and PAM
# falls through to the regular system-auth stack (pam_unix.so).
echo "    activating pam_deckery.so in /etc/pam.d/polkit-1"
if [[ ! -f /etc/pam.d/polkit-1 ]] || ! grep -q "pam_deckery.so" /etc/pam.d/polkit-1 2>/dev/null; then
    cat > /etc/pam.d/polkit-1 <<EOF
#%PAM-1.0
# pam_deckery.so: controller PIN / keyboard password via deckery-auth-daemon.
# Inserted by configure-pam.sh — remove with: configure-pam.sh --uninstall
auth  [success=done authinfo_unavail=ignore auth_err=ignore default=die]  $SO_PATH  source=polkit-1
auth       include      system-auth
account    include      system-auth
password   include      system-auth
session    include      system-auth
EOF
    echo "    ✓ created /etc/pam.d/polkit-1"
else
    echo "    (already present — skipped)"
fi
