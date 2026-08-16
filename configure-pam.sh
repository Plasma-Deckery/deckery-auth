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
    sed -i "/auth.*include.*system-auth/i auth  sufficient  $SO_PATH" /etc/pam.d/sudo
    echo "    ✓ added"
else
    echo "    (already present — skipped)"
fi
