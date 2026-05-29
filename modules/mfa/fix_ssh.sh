#!/usr/bin/env bash
# One-shot SSH access recovery: fixes KbdInteractiveAuthentication,
# removes pam_google_authenticator from sshd PAM, and clears the
# willadmin TOTP token so password-only SSH works again.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: run as root: sudo bash $0"
    exit 1
fi

SSHD_CFG="/etc/ssh/sshd_config"
PAM_SSHD="/etc/pam.d/sshd"

echo "=== Step 1: Fix KbdInteractiveAuthentication in sshd_config ==="
cp "$SSHD_CFG" "${SSHD_CFG}.fix.$(date +%Y%m%d%H%M%S)"
sed -i -E '/^[[:space:]]*(KbdInteractiveAuthentication|ChallengeResponseAuthentication)/d' "$SSHD_CFG"
echo "KbdInteractiveAuthentication yes" >> "$SSHD_CFG"
echo "  Done."

echo ""
echo "=== Step 2: Remove pam_google_authenticator from $PAM_SSHD ==="
if grep -q "pam_google_authenticator" "$PAM_SSHD"; then
    cp "$PAM_SSHD" "${PAM_SSHD}.fix.$(date +%Y%m%d%H%M%S)"
    sed -i '/pam_google_authenticator/d' "$PAM_SSHD"
    echo "  Removed."
else
    echo "  Not present — skipped."
fi

echo ""
echo "=== Step 3: Remove willadmin TOTP token ==="
GA_FILE="/home/willadmin/.google_authenticator"
if [[ -f "$GA_FILE" ]]; then
    cp "$GA_FILE" "${GA_FILE}.fix.$(date +%Y%m%d%H%M%S)"
    rm -f "$GA_FILE"
    echo "  Token removed (backed up)."
else
    echo "  No token file found — skipped."
fi

echo ""
echo "=== Step 4: Restart sshd ==="
systemctl restart sshd
echo "  Restarted."

echo ""
echo "=== Verification ==="
echo -n "  KbdInteractiveAuthentication: "
sshd -T | grep -i kbdinteractive

echo ""
echo "=== Done. Test SSH from the remote machine now. ==="
