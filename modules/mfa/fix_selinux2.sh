#!/usr/bin/env bash
# Install a targeted SELinux policy that allows pam_google_authenticator
# (running inside sshd) to create and update the used-code tempfile in
# user home directories.
#
# Root cause: sshd_t is denied { create } on user_home_dir_t files.
# The dontaudit rule in the base policy silences the denial so it never
# appears in ausearch, even with authlogin_yubikey on.
#
# AVC confirmed: avc: denied { create } for comm="sshd"
#   name=".google_authenticator~YsaSdO"
#   scontext=system_u:system_r:sshd_t
#   tcontext=system_u:object_r:user_home_dir_t tclass=file permissive=0
#
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: run as root: sudo bash $0"
    exit 1
fi

MODULE_NAME="google_authenticator_sshd"
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

echo "=== Remove previous (broken) module if present ==="
if semodule -l 2>/dev/null | grep -q "$MODULE_NAME"; then
    semodule -r "$MODULE_NAME" && echo "  Removed old module." || true
fi

echo ""
echo "=== Writing policy ==="
cat > "${WORK_DIR}/${MODULE_NAME}.te" <<'POLICY'
module google_authenticator_sshd 1.0;

require {
    type sshd_t;
    type user_home_dir_t;
    type user_home_t;
    type auth_home_t;
    class dir  { write add_name remove_name };
    class file { create write read getattr open unlink rename lock };
}

# pam_google_authenticator runs inside sshd (sshd_t).  After accepting a
# valid TOTP code it must atomically write a tempfile then rename it over
# ~/.google_authenticator to record the used code (DISALLOW_REUSE).
# Without these rules the tempfile creation is silently denied and the
# entire PAM auth fails even though the code was correct.
allow sshd_t user_home_dir_t:dir  { write add_name remove_name };
allow sshd_t user_home_t:file     { create write read getattr open unlink rename lock };
allow sshd_t auth_home_t:file     { create write read getattr open unlink rename lock };
POLICY

echo "  Written: ${WORK_DIR}/${MODULE_NAME}.te"
cat "${WORK_DIR}/${MODULE_NAME}.te"

echo ""
echo "=== Compiling ==="
pushd "$WORK_DIR" > /dev/null
checkmodule -M -m -o "${MODULE_NAME}.mod" "${MODULE_NAME}.te"
semodule_package -o "${MODULE_NAME}.pp" -m "${MODULE_NAME}.mod"
echo "  Compiled OK."

echo ""
echo "=== Installing ==="
semodule -i "${MODULE_NAME}.pp"
echo "  Installed: $MODULE_NAME"
popd > /dev/null

echo ""
echo "=== Verifying ==="
semodule -l | grep "$MODULE_NAME" && echo "  Module confirmed loaded." || echo "  WARNING: module not found in list."

echo ""
echo "=== Resetting faillock ==="
faillock --user willadmin --reset
echo "  faillock cleared."

echo ""
echo "=== Fixing token file permissions ==="
GA_FILE="/home/willadmin/.google_authenticator"
if [[ -f "$GA_FILE" ]]; then
    chmod 600 "$GA_FILE"
    chown willadmin:willadmin "$GA_FILE"
    ls -lZ "$GA_FILE"
fi

echo ""
echo "=== Done ==="
echo "  Try SSH now: ssh willadmin@<ip>"
echo "  Expected flow: Password → Verification code → logged in"
