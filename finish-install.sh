#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="/home/philipp/Programming/deckery-auth"

# 1. Fix PAM entry: add source=sudo
sed -i 's|auth  sufficient  /usr/local/lib/security/pam_deckery.so.*|auth  sufficient  /usr/local/lib/security/pam_deckery.so  source=sudo|' /etc/pam.d/sudo
echo "PAM: source=sudo set"

# 2. Install daemon binary + service
cp "$SCRIPT_DIR/target/release/deckery-auth-daemon" /usr/local/bin/deckery-auth-daemon
cp "$SCRIPT_DIR/deckery-auth-daemon.service" /etc/systemd/system/deckery-auth-daemon.service
echo "Daemon binary + service installed"

# 3. Start
systemctl daemon-reload
systemctl enable --now deckery-auth-daemon
echo "Daemon started"

echo ""
cat /etc/pam.d/sudo
echo ""
systemctl status deckery-auth-daemon --no-pager -l
