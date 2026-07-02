#!/usr/bin/env bash
# =============================================================================
# Module  : auditd
# Purpose : Install auditd and manage system audit rules and log review.
#
# auditd is the Linux audit daemon — it records security-relevant events
# (logins, privilege escalation, file access, syscalls) to a tamper-evident
# log at /var/log/audit/audit.log.  Rules are loaded from /etc/audit/rules.d/
# and compiled into /etc/audit/audit.rules by augenrules.
#
# Menu:
#   ── Status ──
#     1) View status          — service state, active rules, log size
#     2) Enable / disable     — install, start+enable or stop+disable
#     3) Deploy baseline rules — CIS/CMMC-aligned ruleset
#   ── Audit Log ──
#     4) Recent events        — last 50 audit events (all types)
#     5) Authentication        — login, logout, and failed auth attempts
#     6) Privilege escalation  — sudo, su, and setuid execution
#     7) File access           — sensitive file reads and modifications
#     8) Follow live feed      — stream new events in real time (Ctrl+C)
#   ── Reports ──
#     9) Summary report        — aureport overview statistics
#    10) Failed events         — actions that returned an error or were denied
#   ──
#    11) Exit
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../lib/common.sh"
source "$SCRIPT_DIR/../../config.conf"

check_root

AUDIT_CONF="/etc/audit/auditd.conf"
RULES_DIR="/etc/audit/rules.d"
BASELINE_RULES="$RULES_DIR/99-hardening-baseline.rules"
AUDIT_LOG="/var/log/audit/audit.log"

# =============================================================================
# Helpers
# =============================================================================

_header() {
    echo ""
    echo "  ┌─────────────────────────────────────────────────────────┐"
    printf  "  │  %-55s│\n" "$1"
    echo "  └─────────────────────────────────────────────────────────┘"
    echo ""
}

_auditd_installed() {
    command_exists auditctl && rpm -q audit &>/dev/null
}

_auditd_running() {
    systemctl is-active auditd &>/dev/null
}

_require_auditd() {
    if ! _auditd_installed; then
        log_warn "auditd is not installed. Use option 2 (Enable / disable) to install it."
        return 1
    fi
}

_rule_count() {
    auditctl -l 2>/dev/null | grep -c "^-" || echo "0"
}

_log_size() {
    if [[ -f "$AUDIT_LOG" ]]; then
        du -sh "$AUDIT_LOG" 2>/dev/null | awk '{print $1}'
    else
        echo "N/A"
    fi
}

_save_artifact() {
    local _artifact
    _artifact=$(artifact_file "auditd")
    {
        echo "AUDITD CONFIGURATION REPORT"
        echo "==========================="
        echo "Generated  : $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Hostname   : $(hostname)"
        echo ""
        echo "SERVICE STATE"
        echo "-------------"
        if _auditd_installed; then
            echo "  Installed : yes"
            echo "  Running   : $( _auditd_running && echo yes || echo no )"
            echo "  Enabled   : $(systemctl is-enabled auditd 2>/dev/null || echo unknown)"
            echo "  Log size  : $(_log_size)"
            echo "  Rules     : $(_rule_count) active"
        else
            echo "  Installed : no"
        fi
        echo ""
        echo "ACTIVE RULES"
        echo "------------"
        auditctl -l 2>/dev/null || echo "  (unavailable)"
        echo ""
        echo "BASELINE RULES FILE"
        echo "-------------------"
        if [[ -f "$BASELINE_RULES" ]]; then
            cat "$BASELINE_RULES"
        else
            echo "  (not deployed)"
        fi
    } > "$_artifact"
    log_info "Artifact saved: $_artifact"
}

# =============================================================================
# Action: View status
# =============================================================================

action_show_status() {
    _header "auditd Status"

    if ! _auditd_installed; then
        echo -e "  ${YELLOW}auditd is not installed.${NC}"
        echo "  Use option 2 (Enable / disable) to install and start it."
        echo ""
        return
    fi

    local _running _enabled _rules _logsize
    _running=$( _auditd_running && echo "running" || echo "stopped" )
    _enabled=$(systemctl is-enabled auditd 2>/dev/null || echo "unknown")
    _rules=$(_rule_count)
    _logsize=$(_log_size)

    printf "  %-24s " "Service:"
    if [[ "$_running" == "running" ]]; then
        echo -e "${GREEN}running${NC}"
    else
        echo -e "${RED}stopped${NC}"
    fi
    printf "  %-24s %s\n" "Enabled at boot:" "$_enabled"
    printf "  %-24s %s\n" "Active rules:" "$_rules"
    printf "  %-24s %s\n" "Log file size:" "$_logsize"
    echo ""

    if _auditd_running; then
        echo "  auditctl status:"
        printf "  %s\n" "$(printf '%.0s─' {1..56})"
        auditctl -s 2>/dev/null | sed 's/^/  /' || echo "  (unavailable)"
        echo ""
        echo "  Active rules:"
        printf "  %s\n" "$(printf '%.0s─' {1..56})"
        auditctl -l 2>/dev/null | sed 's/^/  /' || echo "  (no rules loaded)"
        echo ""
    fi

    echo "  Recent auditd service messages:"
    printf "  %s\n" "$(printf '%.0s─' {1..56})"
    journalctl -u auditd --no-pager -n 10 2>/dev/null | sed 's/^/  /' \
        || echo "  (no journal entries)"
    echo ""
}

# =============================================================================
# Action: Enable / disable
# =============================================================================

action_toggle() {
    _header "Enable / Disable auditd"

    if ! _auditd_installed; then
        echo "  auditd is not installed."
        echo ""
        read -rp "  Install auditd now? [Y/n]: " _ok
        [[ "${_ok,,}" =~ ^n ]] && { log_info "Cancelled."; return; }
        log_section "Installing auditd"
        dnf install -y audit audit-libs
        log_info "auditd installed."
        echo ""
    fi

    if _auditd_running; then
        echo -e "  ${YELLOW}Warning: disabling auditd stops all system audit event logging.${NC}"
        echo ""
        read -rp "  Stop and disable auditd? [y/N]: " _ok
        [[ "${_ok,,}" =~ ^y ]] || { log_info "Cancelled."; return; }
        systemctl stop auditd
        systemctl disable auditd
        log_info "auditd stopped and disabled."
    else
        echo "  auditd is currently stopped."
        echo ""
        read -rp "  Start and enable auditd? [Y/n]: " _ok
        [[ "${_ok,,}" =~ ^n ]] && { log_info "Cancelled."; return; }
        systemctl enable --now auditd
        log_info "auditd started and enabled."

        if [[ ! -f "$BASELINE_RULES" ]]; then
            echo ""
            read -rp "  No baseline rules found. Deploy them now? [Y/n]: " _ok
            [[ "${_ok,,}" =~ ^n ]] || _deploy_baseline_rules
        fi
    fi
    _save_artifact
}

# =============================================================================
# Action: Deploy baseline rules
# =============================================================================

_deploy_baseline_rules() {
    log_info "Writing baseline audit rules to $BASELINE_RULES..."
    mkdir -p "$RULES_DIR"

    if [[ -f "$BASELINE_RULES" ]]; then
        backup_file "$BASELINE_RULES"
    fi

    cat > "$BASELINE_RULES" <<'RULES'
## Hardening Baseline Audit Rules
## Generated by hardening/modules/auditd — do not edit manually.
## Satisfies: CMMC AC.L2-3.1.11, AU.L2-3.3.1, AU.L2-3.3.2; CIS Rocky Linux 9

## Buffer size — increase if events are being lost
-b 8192

## Failure mode: 1 = log to kernel ring buffer, 2 = panic (use 1 for production)
-f 1

## ── Clock and time changes ──────────────────────────────────────────────────
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

## ── User and group account changes ──────────────────────────────────────────
-w /etc/group    -p wa -k identity
-w /etc/passwd   -p wa -k identity
-w /etc/gshadow  -p wa -k identity
-w /etc/shadow   -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

## ── Sudoers changes ─────────────────────────────────────────────────────────
-w /etc/sudoers   -p wa -k scope
-w /etc/sudoers.d -p wa -k scope

## ── Login and session events ─────────────────────────────────────────────────
-w /var/log/lastlog   -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-w /var/run/utmp      -p wa -k session
-w /var/log/wtmp      -p wa -k logins
-w /var/log/btmp      -p wa -k logins

## ── Privilege escalation ────────────────────────────────────────────────────
-a always,exit -F path=/usr/bin/sudo   -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-sudo
-a always,exit -F path=/usr/bin/su     -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-su
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-priv_change
-a always,exit -F path=/usr/bin/chsh   -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-priv_change
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-passwd
-a always,exit -F path=/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-passwd
-a always,exit -F path=/usr/sbin/usermod  -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-user_change
-a always,exit -F path=/usr/sbin/useradd  -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-user_change
-a always,exit -F path=/usr/sbin/userdel  -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-user_change
-a always,exit -F path=/usr/sbin/groupadd -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-group_change
-a always,exit -F path=/usr/sbin/groupmod -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-group_change
-a always,exit -F path=/usr/sbin/groupdel -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-group_change

## ── Permission and ownership changes ────────────────────────────────────────
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod

## ── Unsuccessful file access ─────────────────────────────────────────────────
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM  -F auid>=1000 -F auid!=-1 -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM  -F auid>=1000 -F auid!=-1 -k access

## ── Network configuration changes ───────────────────────────────────────────
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/hosts              -p wa -k system-locale
-w /etc/sysconfig/network  -p wa -k system-locale

## ── Kernel module loading/unloading ─────────────────────────────────────────
-w /sbin/insmod  -p x -k modules
-w /sbin/rmmod   -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,delete_module -k modules

## ── File deletion by users ───────────────────────────────────────────────────
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=-1 -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=-1 -k delete

## ── Mount operations ─────────────────────────────────────────────────────────
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -k mounts

## ── Make rules immutable — requires reboot to modify rules after this point ──
## Uncomment to lock rules. Only enable when the ruleset is fully validated.
## -e 2
RULES

    augenrules --load 2>/dev/null || auditctl -R "$BASELINE_RULES" 2>/dev/null \
        || log_warn "Could not load rules — check auditd service status."

    log_info "Baseline rules deployed ($BASELINE_RULES)."
    log_info "Rules loaded: $(_rule_count) active."
}

action_deploy_rules() {
    _header "Deploy Baseline Audit Rules"

    _require_auditd || return

    if [[ -f "$BASELINE_RULES" ]]; then
        echo -e "  ${YELLOW}Baseline rules are already deployed at:${NC}"
        echo "  $BASELINE_RULES"
        echo ""
        read -rp "  Overwrite and reload? [y/N]: " _ok
        [[ "${_ok,,}" =~ ^y ]] || { log_info "Cancelled."; return; }
    else
        echo "  Deploys a CIS/CMMC-aligned ruleset covering:"
        echo "    • Clock and time changes"
        echo "    • User/group account modifications"
        echo "    • Sudoers changes"
        echo "    • Login and session events"
        echo "    • Privilege escalation (sudo, su, useradd, etc.)"
        echo "    • File permission and ownership changes"
        echo "    • Unsuccessful file access attempts"
        echo "    • Network configuration changes"
        echo "    • Kernel module loading/unloading"
        echo "    • File deletion by users"
        echo "    • Mount operations"
        echo ""
        read -rp "  Deploy baseline rules? [Y/n]: " _ok
        [[ "${_ok,,}" =~ ^n ]] && { log_info "Cancelled."; return; }
    fi

    _deploy_baseline_rules
    _save_artifact
}

# =============================================================================
# Action: Audit log viewers
# =============================================================================

_check_log_access() {
    if ! command_exists ausearch; then
        log_warn "ausearch not found — install the 'audit' package."
        return 1
    fi
    if [[ ! -r "$AUDIT_LOG" ]]; then
        log_warn "Cannot read $AUDIT_LOG — ensure auditd is running and you are root."
        return 1
    fi
}

action_recent_events() {
    _header "Recent Audit Events"

    _require_auditd || return
    _check_log_access || return

    echo "  Last 50 audit events (all types):"
    printf "  %s\n" "$(printf '%.0s─' {1..56})"
    ausearch -i --start today 2>/dev/null | tail -300 | sed 's/^/  /' \
        || echo "  (no events found)"
    echo ""
}

action_auth_events() {
    _header "Authentication Events"

    _require_auditd || return
    _check_log_access || return

    echo "  Login, logout, and authentication events for today:"
    printf "  %s\n" "$(printf '%.0s─' {1..56})"
    local _events
    _events=$(ausearch -i -m USER_LOGIN,USER_AUTH,USER_LOGOUT,ANOM_LOGIN_FAILURES \
        --start today 2>/dev/null | tail -300 || true)
    if [[ -z "$_events" ]]; then
        echo "  (no authentication events found today)"
    else
        echo "$_events" | sed 's/^/  /'
    fi
    echo ""
    echo "  Failed login summary:"
    printf "  %s\n" "$(printf '%.0s─' {1..56})"
    aureport -au --failed --start today 2>/dev/null | sed 's/^/  /' \
        || echo "  (unavailable)"
    echo ""
}

action_priv_events() {
    _header "Privilege Escalation Events"

    _require_auditd || return
    _check_log_access || return

    echo "  sudo, su, and privileged command execution for today:"
    printf "  %s\n" "$(printf '%.0s─' {1..56})"

    # ausearch does not accept comma-separated keys — run once per key
    local _events _keys=(
        privileged-sudo
        privileged-su
        privileged-priv_change
        privileged-passwd
        privileged-user_change
        privileged-group_change
    )
    local _k
    _events=""
    for _k in "${_keys[@]}"; do
        local _chunk
        _chunk=$(ausearch -i -k "$_k" --start today 2>/dev/null || true)
        [[ -n "$_chunk" ]] && _events="${_events}${_chunk}"$'\n'
    done

    if [[ -z "$_events" ]]; then
        echo "  (no privilege escalation events found today)"
        echo "  Tip: deploy baseline rules (option 3) to enable this tracking."
    else
        echo "$_events" | tail -300 | sed 's/^/  /'
    fi
    echo ""
}

action_file_events() {
    _header "File Access Events"

    _require_auditd || return
    _check_log_access || return

    echo "  Options:"
    echo "    1) Identity / account file changes  — /etc/passwd, shadow, group"
    echo "    2) Sudoers changes"
    echo "    3) Permission/ownership changes"
    echo "    4) Unsuccessful file access attempts"
    echo "    5) File deletions"
    echo "    6) Back"
    echo ""
    read -rp "  Selection [1-6, default=1]: " _sel
    echo ""

    local _events=""
    case "${_sel:-1}" in
        1)
            echo "  Identity file changes (today):"
            printf "  %s\n" "$(printf '%.0s─' {1..56})"
            _events=$(ausearch -i -k identity --start today 2>/dev/null | tail -300 || true)
            ;;
        2)
            echo "  Sudoers changes (today):"
            printf "  %s\n" "$(printf '%.0s─' {1..56})"
            _events=$(ausearch -i -k scope --start today 2>/dev/null | tail -300 || true)
            ;;
        3)
            echo "  Permission and ownership changes (today):"
            printf "  %s\n" "$(printf '%.0s─' {1..56})"
            _events=$(ausearch -i -k perm_mod --start today 2>/dev/null | tail -300 || true)
            ;;
        4)
            echo "  Unsuccessful file access attempts (today):"
            printf "  %s\n" "$(printf '%.0s─' {1..56})"
            _events=$(ausearch -i -k access --start today 2>/dev/null | tail -300 || true)
            ;;
        5)
            echo "  File deletions by users (today):"
            printf "  %s\n" "$(printf '%.0s─' {1..56})"
            _events=$(ausearch -i -k delete --start today 2>/dev/null | tail -300 || true)
            ;;
        6) return ;;
        *) echo "  Invalid selection."; return ;;
    esac

    if [[ -z "$_events" ]]; then
        echo "  (no matching events found today)"
        echo "  Tip: ensure baseline rules are deployed (option 3)."
    else
        echo "$_events" | sed 's/^/  /'
    fi
    echo ""
}

action_live_feed() {
    _header "Live Audit Feed"

    _require_auditd || return

    if [[ ! -r "$AUDIT_LOG" ]]; then
        log_warn "Cannot read $AUDIT_LOG — ensure auditd is running and you are root."
        return
    fi

    echo "  Options:"
    echo "    1) All events"
    echo "    2) Authentication events only"
    echo "    3) Privilege escalation only"
    echo "    4) Back"
    echo ""
    read -rp "  Selection [1-4, default=1]: " _sel
    echo ""

    local _pattern=""
    case "${_sel:-1}" in
        1) _pattern="" ;;
        2) _pattern="USER_LOGIN\|USER_AUTH\|USER_LOGOUT\|ANOM_LOGIN" ;;
        3) _pattern="USER_CMD\|SYSCALL.*sudo\|key=.*priv" ;;
        4) return ;;
        *) echo "  Invalid selection."; return ;;
    esac

    echo "  Streaming audit events — press Ctrl+C to stop."
    echo ""

    if [[ -n "$_pattern" ]]; then
        tail -f "$AUDIT_LOG" 2>/dev/null \
            | grep --line-buffered "$_pattern" \
            | sed 's/^/  /' || true
    else
        tail -f "$AUDIT_LOG" 2>/dev/null | sed 's/^/  /' || true
    fi
}

# =============================================================================
# Action: Reports
# =============================================================================

action_summary_report() {
    _header "Audit Summary Report"

    _require_auditd || return

    if ! command_exists aureport; then
        log_warn "aureport not found — install the 'audit' package."
        return
    fi

    echo "  Overview (today):"
    printf "  %s\n" "$(printf '%.0s─' {1..56})"
    aureport --start today 2>/dev/null | sed 's/^/  /' || echo "  (unavailable)"
    echo ""
    echo "  Authentication summary (today):"
    printf "  %s\n" "$(printf '%.0s─' {1..56})"
    aureport -au --start today 2>/dev/null | sed 's/^/  /' || echo "  (unavailable)"
    echo ""
    echo "  Executable summary (today):"
    printf "  %s\n" "$(printf '%.0s─' {1..56})"
    aureport -x --summary --start today 2>/dev/null | head -30 | sed 's/^/  /' \
        || echo "  (unavailable)"
    echo ""
}

action_failed_report() {
    _header "Failed Events Report"

    _require_auditd || return

    if ! command_exists aureport; then
        log_warn "aureport not found — install the 'audit' package."
        return
    fi

    echo "  All failed audit events (today):"
    printf "  %s\n" "$(printf '%.0s─' {1..56})"
    aureport --failed --start today 2>/dev/null | sed 's/^/  /' || echo "  (unavailable)"
    echo ""
    echo "  Failed authentication attempts (today):"
    printf "  %s\n" "$(printf '%.0s─' {1..56})"
    aureport -au --failed --start today 2>/dev/null | sed 's/^/  /' || echo "  (unavailable)"
    echo ""
    echo "  Failed file access attempts (today):"
    printf "  %s\n" "$(printf '%.0s─' {1..56})"
    ausearch -i -k access --start today 2>/dev/null | tail -200 | sed 's/^/  /' \
        || echo "  (unavailable)"
    echo ""
}

# =============================================================================
# Main TUI loop
# =============================================================================

log_section "Auditd"

while true; do
    _header "Auditd — System Audit Logging"
    echo ""

    # Inline status bar
    _rc=0
    printf "  %-24s " "auditd:"
    if _auditd_installed; then
        if _auditd_running; then
            printf "${GREEN}running${NC}"
            _rc=$(_rule_count)
            if [[ "$_rc" -eq 0 ]]; then
                echo -e " — ${YELLOW}no rules loaded (deploy baseline rules)${NC}"
            else
                echo -e " — ${_rc} rules active"
            fi
        else
            echo -e "${RED}stopped${NC}"
        fi
    else
        echo -e "${YELLOW}not installed${NC}"
    fi
    echo ""

    echo "  ── Status ───────────────────────────────────────────────────"
    echo "    1) View status          — service state, active rules, log size"
    echo "    2) Enable / disable     — install, start+enable or stop+disable"
    echo "    3) Deploy baseline rules — CIS/CMMC-aligned ruleset for this system"
    echo ""
    echo "  ── Audit Log ────────────────────────────────────────────────"
    echo "    4) Recent events        — last 50 audit events (all types)"
    echo "    5) Authentication        — login, logout, and failed auth attempts"
    echo "    6) Privilege escalation  — sudo, su, and privileged commands"
    echo "    7) File access           — identity, sudoers, permissions, deletions"
    echo "    8) Follow live feed      — stream new audit events (Ctrl+C to stop)"
    echo ""
    echo "  ── Reports ──────────────────────────────────────────────────"
    echo "    9) Summary report        — aureport overview and statistics"
    echo "   10) Failed events         — failed access attempts and auth failures"
    echo ""
    echo "  ─────────────────────────────────────────────────────────────"
    echo "   11) Exit"
    echo ""
    read -rp "  Selection [1-11, default=1]: " _sel
    echo ""

    case "${_sel:-1}" in
         1) action_show_status ;;
         2) action_toggle ;;
         3) action_deploy_rules ;;
         4) action_recent_events ;;
         5) action_auth_events ;;
         6) action_priv_events ;;
         7) action_file_events ;;
         8) action_live_feed ;;
         9) action_summary_report ;;
        10) action_failed_report ;;
        11) log_info "Exiting auditd module."; exit 0 ;;
         *) echo "  Invalid selection." ;;
    esac

    echo ""
    read -rp "  Return to auditd menu? [Y/n]: " _again
    [[ "${_again,,}" =~ ^n ]] && break
done
