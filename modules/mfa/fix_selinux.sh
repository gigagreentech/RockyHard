#!/usr/bin/env bash
# Diagnose and fix SELinux denials blocking pam_google_authenticator from
# writing the used-code tempfile in the user home directory.
# Run as root from a LOCAL terminal (not SSH).
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: run as root: sudo bash $0"
    exit 1
fi

echo "=== Step 1: Remove dontaudit suppression ==="
semodule -DB
echo "  dontaudit rules disabled — all denials will now be logged."

echo ""
echo "=== Step 2: Attempt SSH login ==="
echo "  From your Windows machine, try to SSH in as willadmin."
echo "  It will still fail — that is expected. We just need it to generate an AVC."
echo ""
read -rp "  Press Enter once you have attempted the SSH login..."

echo ""
echo "=== Step 3: Capture AVC denials ==="
AVC_OUTPUT=$(ausearch -m avc --start recent 2>/dev/null || true)

if [[ -z "$AVC_OUTPUT" ]]; then
    echo "  No AVCs found. Restoring dontaudit rules."
    semodule -B
    echo ""
    echo "  SELinux is NOT the cause. Check /var/log/secure for other errors."
    exit 1
fi

echo "$AVC_OUTPUT" | tail -30
echo ""

echo "=== Step 4: Build and install SELinux policy module ==="
POLICY_DIR=$(mktemp -d)
echo "$AVC_OUTPUT" | audit2allow -M google_authenticator_sshd -d "$POLICY_DIR" 2>/dev/null \
    || echo "$AVC_OUTPUT" | audit2allow -M google_authenticator_sshd 2>/dev/null

if [[ -f "google_authenticator_sshd.pp" ]]; then
    semodule -i google_authenticator_sshd.pp
    echo "  Policy module installed: google_authenticator_sshd"
    mv google_authenticator_sshd.pp google_authenticator_sshd.te "$POLICY_DIR/" 2>/dev/null || true
else
    echo "  audit2allow did not produce a .pp file. Trying manual policy..."

    cat > "${POLICY_DIR}/google_authenticator_sshd.te" <<'POLICY'
module google_authenticator_sshd 1.0;

require {
    type sshd_t;
    type user_home_dir_t;
    type user_home_t;
    type auth_home_t;
    class dir  { write add_name remove_name };
    class file { create write read getattr open rename unlink lock };
}

allow sshd_t user_home_dir_t:dir  { write add_name remove_name };
allow sshd_t user_home_t:file     { create write read getattr open rename unlink lock };
allow sshd_t auth_home_t:file     { create write read getattr open rename unlink lock };
POLICY

    pushd "$POLICY_DIR" > /dev/null
    checkmodule -M -m -o google_authenticator_sshd.mod google_authenticator_sshd.te
    semodule_package -o google_authenticator_sshd.pp -m google_authenticator_sshd.mod
    semodule -i google_authenticator_sshd.pp
    popd > /dev/null
    echo "  Manual policy module installed."
fi

echo ""
echo "=== Step 5: Restore dontaudit rules ==="
semodule -B
echo "  dontaudit rules restored."

echo ""
echo "=== Step 6: Reset faillock ==="
faillock --user willadmin --reset
echo "  faillock cleared for willadmin."

echo ""
echo "=== Done ==="
echo "  Try SSH now. If it still fails, run:"
echo "    journalctl -u sshd -n 20 --no-pager"
