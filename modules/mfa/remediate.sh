#!/usr/bin/env bash
# MFA lockout remediation script.
# Run as root: sudo bash remediate.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: run as root: sudo bash $0"
    exit 1
fi

echo "=== MFA Lockout Remediation ==="

# 1. Unlock any faillock-locked accounts
echo ""
echo "[1] Resetting faillock for all users with recorded failures..."
while IFS=: read -r user _ uid _; do
    if (( uid >= 1000 )); then
        count=$(faillock --user "$user" 2>/dev/null | grep -c "V" || true)
        if (( count > 0 )); then
            faillock --user "$user" --reset
            echo "    Cleared faillock for: $user"
        fi
    fi
done < /etc/passwd
# Always reset willadmin explicitly in case UID check differs
faillock --user willadmin --reset 2>/dev/null && echo "    Cleared faillock for: willadmin" || true

# 2. Remove AuthenticationMethods from sshd_config
SSHD_CFG="/etc/ssh/sshd_config"
echo ""
echo "[2] Removing AuthenticationMethods from $SSHD_CFG..."
if grep -qiE "^[[:space:]]*AuthenticationMethods" "$SSHD_CFG"; then
    cp "$SSHD_CFG" "${SSHD_CFG}.pre-remediate.$(date +%Y%m%d%H%M%S)"
    sed -i -E '/^[[:space:]]*AuthenticationMethods/d' "$SSHD_CFG"
    echo "    Removed AuthenticationMethods line."
else
    echo "    AuthenticationMethods not present — no change needed."
fi

# 3. Remove pam_google_authenticator from PAM files if present but module missing
if ! command -v google-authenticator &>/dev/null && ! ls /lib*/security/pam_google_authenticator.so &>/dev/null 2>&1; then
    echo ""
    echo "[3] google-authenticator not installed — removing any PAM references..."
    for pam_file in /etc/pam.d/sshd /etc/pam.d/sudo; do
        if grep -q "pam_google_authenticator" "$pam_file" 2>/dev/null; then
            cp "$pam_file" "${pam_file}.pre-remediate.$(date +%Y%m%d%H%M%S)"
            sed -i '/pam_google_authenticator/d' "$pam_file"
            echo "    Removed pam_google_authenticator from $pam_file"
        fi
    done
fi

# 4. Reload sshd
echo ""
echo "[4] Reloading SSH daemon..."
if systemctl is-active --quiet sshd 2>/dev/null; then
    systemctl restart sshd && echo "    sshd restarted successfully."
elif systemctl is-active --quiet ssh 2>/dev/null; then
    systemctl restart ssh && echo "    ssh restarted successfully."
else
    echo "    WARNING: sshd service not active — start it manually."
fi

echo ""
echo "=== Remediation complete. Test SSH login in a new terminal before closing this session. ==="
