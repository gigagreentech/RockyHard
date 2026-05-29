#!/usr/bin/env bash
# =============================================================================
# Module  : session_timeout
# Purpose : Enforce automatic session termination after a defined period of
#           inactivity across all access paths — SSH, local console/shell,
#           and GUI desktop sessions.
#
# Satisfies CMMC AC.L2-3.1.11 (Session Termination) and NIST SP 800-171
# 3.1.11: "Terminate (automatically) user sessions after a defined condition."
#
# This module performs the following actions in order:
#
#   1. SHELL / CONSOLE TIMEOUT  (/etc/profile.d/session_timeout.sh)
#      Exports TMOUT=<SESSION_TIMEOUT> as a read-only variable for all
#      interactive bash and sh sessions, including local TTY logins and any
#      shell opened after login.  Using readonly prevents unprivileged users
#      from unsetting or changing the value.
#      The file is created or replaced; a timestamped backup is taken if it
#      already exists.
#
#   2. SSH SESSION TIMEOUT  (/etc/ssh/sshd_config)
#      Sets two sshd directives:
#        ClientAliveInterval <SESSION_TIMEOUT>
#          sshd sends a keepalive probe to the client after this many seconds
#          of inactivity on the encrypted channel.
#        ClientAliveCountMax 0
#          sshd disconnects the client if it does not respond to the first
#          probe.  Together these directives terminate idle SSH sessions after
#          exactly SESSION_TIMEOUT seconds with no grace period.
#      Each directive is replaced in place if already present (active or
#      commented); otherwise it is appended to the end of the file.
#      sshd is reloaded after the change so existing active sessions are not
#      dropped mid-work.
#      Skipped with a warning if sshd_config is not found.
#
#   3. GUI SESSION TIMEOUT  (GNOME / dconf)
#      Configures the GNOME desktop to lock the screen and require
#      re-authentication after SESSION_TIMEOUT seconds of inactivity.
#      Settings are applied via the system-level dconf database so they are
#      enforced for all users and cannot be overridden from the GNOME Settings
#      panel.
#        /etc/dconf/profile/user
#          Tells GNOME user sessions to read from system-db:local.  Written
#          only if the file is absent or does not already reference local.
#        /etc/dconf/db/local.d/01-session-timeout
#          Keyfile setting four dconf keys:
#            org/gnome/desktop/session idle-delay         — activates screensaver
#            org/gnome/desktop/screensaver lock-enabled   — locks on activation
#            org/gnome/desktop/screensaver lock-delay     — locks immediately (0 s)
#            org/gnome/desktop/screensaver idle-activation-enabled — auto-activate
#        /etc/dconf/db/local.d/locks/01-session-timeout
#          Locks all four keys so they are greyed out and non-editable in the
#          GNOME Settings UI.
#      dconf update is run to compile the database after all files are written.
#      Skipped with a warning if dconf is not installed.
#
# Configuration values read from config.conf:
#   SESSION_TIMEOUT = 900   (seconds; 900 = 15 minutes)
#
# Files modified:
#   /etc/profile.d/session_timeout.sh               — shell/console idle timeout
#   /etc/ssh/sshd_config                            — SSH ClientAlive directives
#   /etc/dconf/profile/user                         — dconf user profile
#   /etc/dconf/db/local.d/01-session-timeout        — GNOME idle settings keyfile
#   /etc/dconf/db/local.d/locks/01-session-timeout  — dconf key locks
#
# Dependencies:
#   printf, chmod             — coreutils
#   grep, sed                 — util-linux
#   systemctl                 — systemd (to reload sshd)
#   dconf                     — GNOME settings backend (GUI timeout only)
#   openssh-server            — sshd must be installed for SSH timeout
#
# Must be run as root (enforced by check_root in master.sh).
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../config.conf"
source "$SCRIPT_DIR/../../lib/common.sh"

# Fall back to 900 s (15 minutes) if the config value is absent or empty.
SESSION_TIMEOUT="${SESSION_TIMEOUT:-900}"

# --- Shell / console timeout ---
apply_shell_timeout() {
    local profile_file="/etc/profile.d/session_timeout.sh"

    backup_file "$profile_file"

    # readonly prevents users from unsetting or lowering TMOUT from within their
    # session.  export ensures the value propagates to child processes.
    cat > "$profile_file" <<EOF
# Managed by hardening/modules/session_timeout — do not edit manually.
# Satisfies CMMC AC.L2-3.1.11 (Session Termination).
readonly TMOUT=${SESSION_TIMEOUT}
export TMOUT
EOF

    chmod 644 "$profile_file"
    log_info "Shell/console timeout set to ${SESSION_TIMEOUT}s via $profile_file."
}

# --- SSH session timeout ---
apply_ssh_timeout() {
    local sshd_config="/etc/ssh/sshd_config"

    if [[ ! -f "$sshd_config" ]]; then
        log_warn "sshd_config not found at $sshd_config — skipping SSH timeout configuration."
        log_warn "Install openssh-server and re-run this module to configure the SSH timeout."
        return
    fi

    backup_file "$sshd_config"

    # Replace any existing ClientAliveInterval line (active or commented) in
    # place to avoid duplicates.  Append if no such line exists.
    if grep -qE "^\s*#*\s*ClientAliveInterval" "$sshd_config"; then
        sed -i "s|^\s*#*\s*ClientAliveInterval.*|ClientAliveInterval ${SESSION_TIMEOUT}|" "$sshd_config"
        log_info "SSH ClientAliveInterval updated to ${SESSION_TIMEOUT}s."
    else
        echo "ClientAliveInterval ${SESSION_TIMEOUT}" >> "$sshd_config"
        log_info "SSH ClientAliveInterval ${SESSION_TIMEOUT}s appended to $sshd_config."
    fi

    # ClientAliveCountMax 0 means the connection is dropped after the very first
    # unanswered keepalive probe, giving a hard cutoff at ClientAliveInterval seconds
    # with no grace period.
    if grep -qE "^\s*#*\s*ClientAliveCountMax" "$sshd_config"; then
        sed -i "s|^\s*#*\s*ClientAliveCountMax.*|ClientAliveCountMax 0|" "$sshd_config"
        log_info "SSH ClientAliveCountMax set to 0 (disconnect on first missed probe)."
    else
        echo "ClientAliveCountMax 0" >> "$sshd_config"
        log_info "SSH ClientAliveCountMax 0 appended to $sshd_config."
    fi

    # Reload rather than restart so active SSH sessions are not dropped.
    if systemctl is-active --quiet sshd 2>/dev/null; then
        systemctl reload sshd
        log_info "sshd reloaded — SSH idle timeout is now active."
    elif systemctl is-active --quiet ssh 2>/dev/null; then
        systemctl reload ssh
        log_info "ssh reloaded — SSH idle timeout is now active."
    else
        log_warn "sshd is not currently running. Timeout will take effect when sshd next starts."
    fi
}

# --- GUI (GNOME) session timeout ---
apply_gui_timeout() {
    if ! command_exists dconf; then
        log_warn "dconf not found — skipping GUI session timeout configuration."
        log_warn "Install dconf (gnome-settings-daemon) and re-run to configure the GUI timeout."
        return
    fi

    local user_profile="/etc/dconf/profile/user"
    local local_db_dir="/etc/dconf/db/local.d"
    local locks_dir="$local_db_dir/locks"
    local settings_file="$local_db_dir/01-session-timeout"
    local locks_file="$locks_dir/01-session-timeout"

    mkdir -p "$local_db_dir" "$locks_dir"

    # Write the user dconf profile only if it is missing or does not already
    # reference system-db:local, to avoid clobbering custom profile entries.
    if [[ ! -f "$user_profile" ]] || ! grep -q "system-db:local" "$user_profile"; then
        backup_file "$user_profile"
        printf 'user-db:user\nsystem-db:local\n' > "$user_profile"
        log_info "dconf user profile written to $user_profile."
    fi

    backup_file "$settings_file"
    cat > "$settings_file" <<EOF
[org/gnome/desktop/session]
idle-delay=uint32 ${SESSION_TIMEOUT}

[org/gnome/desktop/screensaver]
lock-enabled=true
lock-delay=uint32 0
idle-activation-enabled=true
EOF
    log_info "GNOME idle settings written to $settings_file."

    # Lock all four keys so the values are enforced system-wide and cannot be
    # changed from the GNOME Settings panel by any user.
    backup_file "$locks_file"
    cat > "$locks_file" <<'EOF'
/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/desktop/screensaver/lock-delay
/org/gnome/desktop/screensaver/idle-activation-enabled
EOF
    log_info "GNOME timeout keys locked — users cannot override via Settings."

    dconf update
    log_info "GUI session timeout set to ${SESSION_TIMEOUT}s (GNOME dconf)."
}

# --- Artifact ---
save_artifact() {
    local artifact
    artifact=$(artifact_file "session_timeout")

    local tmout_val ssh_interval ssh_count_max dconf_delay dconf_lock_enabled ssh_status gui_status

    tmout_val=$(grep -E "^readonly TMOUT=" /etc/profile.d/session_timeout.sh 2>/dev/null \
        | cut -d= -f2 || echo "not configured")

    ssh_interval=$(grep -E "^\s*ClientAliveInterval\s" /etc/ssh/sshd_config 2>/dev/null \
        | awk '{print $2}' || echo "not configured")
    ssh_count_max=$(grep -E "^\s*ClientAliveCountMax\s" /etc/ssh/sshd_config 2>/dev/null \
        | awk '{print $2}' || echo "not configured")

    if [[ -f /etc/dconf/db/local.d/01-session-timeout ]]; then
        dconf_delay=$(grep "idle-delay" /etc/dconf/db/local.d/01-session-timeout 2>/dev/null \
            | grep -oP '\d+' || echo "not set")
        dconf_lock_enabled=$(grep "lock-enabled" /etc/dconf/db/local.d/01-session-timeout 2>/dev/null \
            | awk -F= '{print $2}' | tr -d ' ' || echo "not set")
        gui_status="Configured"
    elif ! command_exists dconf; then
        dconf_delay="N/A"; dconf_lock_enabled="N/A"
        gui_status="Skipped (dconf not installed)"
    else
        dconf_delay="N/A"; dconf_lock_enabled="N/A"
        gui_status="Not configured"
    fi

    [[ -f /etc/ssh/sshd_config ]] && ssh_status="Configured" || ssh_status="Skipped (sshd_config not found)"

    cat > "$artifact" <<EOF
SESSION TIMEOUT CONFIGURATION REPORT
======================================
Generated  : $(date '+%Y-%m-%d %H:%M:%S')
Hostname   : $(hostname)
OS         : $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
Applied by : hardening/modules/session_timeout/harden.sh
Satisfies  : CMMC AC.L2-3.1.11 (Session Termination)

CONFIGURED TIMEOUT
------------------
  Timeout : ${SESSION_TIMEOUT}s ($(( SESSION_TIMEOUT / 60 )) minutes)

SHELL / CONSOLE TIMEOUT  (/etc/profile.d/session_timeout.sh)
-------------------------------------------------------------
  TMOUT    : $tmout_val (read-only, exported)
  Status   : Configured

SSH SESSION TIMEOUT  (/etc/ssh/sshd_config)
--------------------------------------------
  ClientAliveInterval : $ssh_interval
  ClientAliveCountMax : $ssh_count_max
  Status              : $ssh_status

GUI SESSION TIMEOUT  (GNOME dconf)
------------------------------------
  idle-delay          : $dconf_delay
  lock-enabled        : $dconf_lock_enabled
  Settings file       : /etc/dconf/db/local.d/01-session-timeout
  Locks file          : /etc/dconf/db/local.d/locks/01-session-timeout
  Status              : $gui_status
EOF

    log_info "Artifact saved: $artifact"
}

# --- Main ---
log_section "Session Timeout"

apply_shell_timeout
apply_ssh_timeout
apply_gui_timeout

save_artifact
log_info "Session timeout module complete."
