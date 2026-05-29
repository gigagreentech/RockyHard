#!/usr/bin/env bash
# Fix sudo MFA: change "include" to "substack" for the auth line.
#
# Root cause: system-auth has "pam_unix.so sufficient". With "include",
# a successful password short-circuits the ENTIRE sudo auth stack and
# pam_google_authenticator is never reached. With "substack", the
# short-circuit is contained inside system-auth; control returns to
# sudo's stack and TOTP is enforced next.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo bash $0"
    exit 1
fi

echo "=== Backing up PAM files ==="
cp /etc/pam.d/sudo   /etc/pam.d/sudo.bak.$(date +%Y%m%d%H%M%S)
cp /etc/pam.d/sudo-i /etc/pam.d/sudo-i.bak.$(date +%Y%m%d%H%M%S)
echo "  Done."

echo ""
echo "=== Writing /etc/pam.d/sudo ==="
cat > /etc/pam.d/sudo << 'EOF'
#%PAM-1.0
auth       substack     system-auth
auth       required     pam_google_authenticator.so nullok
account    include      system-auth
password   include      system-auth
session    include      system-auth
EOF
cat -n /etc/pam.d/sudo

echo ""
echo "=== Writing /etc/pam.d/sudo-i ==="
cat > /etc/pam.d/sudo-i << 'EOF'
#%PAM-1.0
auth       substack     sudo
auth       required     pam_google_authenticator.so nullok
account    include      sudo
password   include      sudo
session    optional     pam_keyinit.so force revoke
session    include      sudo
EOF
cat -n /etc/pam.d/sudo-i

echo ""
echo "=== Invalidating sudo credential cache ==="
sudo -k
echo "  Done."

echo ""
echo "=== Done ==="
echo "  Test now: sudo -k && sudo whoami"
echo "  Expected: password prompt, then verification code prompt."
