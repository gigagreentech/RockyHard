#!/usr/bin/env bash
# =============================================================================
# Module  : time_sync
# Purpose : Configure the system time source by selecting NTP servers from a
#           preset list or entering custom addresses, then writing the correct
#           configuration for the detected time-sync daemon and verifying that
#           the clock is synchronised.
#
# Supports chrony (RHEL 8+/Rocky — preferred), ntpd (RHEL 7/CentOS/legacy),
# and systemd-timesyncd (Debian/Ubuntu minimal installs).
# The daemon is detected automatically; chrony is installed if none is found
# on dnf/yum systems.
#
# This module performs the following actions in order:
#
#   1. ENVIRONMENT DETECTION
#      Identifies the active or installed time-sync daemon:
#        chrony      — preferred; /etc/chrony.conf; service chronyd
#        ntpd        — legacy; /etc/ntp.conf; service ntpd
#        timesyncd   — systemd built-in; /etc/systemd/timesyncd.conf
#      If no daemon is found on a dnf/yum system, chrony is installed.
#
#   2. SETTINGS SELECTION (interactive)
#      The operator selects an NTP server preset or enters custom addresses:
#        1) NTP Pool Project  — pool.ntp.org (global round-robin, recommended)
#        2) Cloudflare        — time.cloudflare.com (privacy-first, low latency)
#        3) Google            — time.google.com (global anycast)
#        4) NIST              — time.nist.gov and redundant NIST servers
#        5) Custom            — enter one or more server addresses manually
#      The operator may also:
#        - Set or change the system timezone (default: keep current)
#        - Enable/disable iburst for faster initial synchronisation (default: yes)
#
#   3. CONFIGURATION PREVIEW
#      All selected settings are shown before any changes are made.
#
#   4. DAEMON CONFIGURATION
#      Writes the configuration file for the detected daemon:
#        chrony    : /etc/chrony.conf   (pool/server lines, driftfile, rtcsync)
#        ntpd      : /etc/ntp.conf      (server lines, drift, restrict defaults)
#        timesyncd : /etc/systemd/timesyncd.conf  (NTP= and FallbackNTP= lines)
#      The original config is backed up with a timestamp before overwriting.
#
#   5. TIMEZONE
#      Sets the system timezone via timedatectl (preferred) or by symlinking
#      /etc/localtime to the appropriate entry in /usr/share/zoneinfo/.
#
#   6. SERVICE ENABLEMENT
#      Enables and (re)starts the configured daemon.  Disables competing
#      time-sync services to prevent conflicts (e.g. stops systemd-timesyncd
#      when chrony takes over).
#
#   7. SYNC VERIFICATION
#      Waits up to 30 seconds for initial synchronisation then logs status:
#        chrony    : chronyc tracking
#        ntpd      : ntpq -p
#        timesyncd : timedatectl timesync-status
#
#   8. ARTIFACT
#      Writes a timestamped report to artifacts/time_sync/ recording the
#      daemon, configured servers, timezone, and verified sync state.
#
# Configuration values read from config.conf:
#   TIME_SERVERS  = ""     (space-separated server list; empty = prompt)
#   TIME_TIMEZONE = ""     (e.g. UTC, America/New_York; empty = keep current)
#   TIME_IBURST   = yes    (yes/no — pass iburst to server/pool directives)
#
# Files written:
#   /etc/chrony.conf              (chrony systems)
#   /etc/ntp.conf                 (ntpd systems)
#   /etc/systemd/timesyncd.conf   (systemd-timesyncd systems)
#
# Must be run as root (enforced by check_root in master.sh).
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../config.conf"
source "$SCRIPT_DIR/../../lib/common.sh"

check_root

# Settings — populated by prompts, with config.conf values as defaults
TIME_SERVERS="${TIME_SERVERS:-}"
TIME_TIMEZONE="${TIME_TIMEZONE:-}"
TIME_IBURST="${TIME_IBURST:-yes}"

# Derived — set by detect_environment
TIME_DAEMON=""
DAEMON_CONF=""
DAEMON_SERVICE=""

# NTP server presets
PRESET_POOL="0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org 3.pool.ntp.org"
PRESET_CLOUDFLARE="time.cloudflare.com"
PRESET_GOOGLE="time1.google.com time2.google.com time3.google.com time4.google.com"
PRESET_NIST="time.nist.gov time-a-g.nist.gov time-b-g.nist.gov time-c-g.nist.gov"

# --- Environment detection ---
detect_environment() {
    # Detection order: chrony > ntpd > systemd-timesyncd
    if command_exists chronyc \
        || systemctl list-unit-files 2>/dev/null | grep -q "^chronyd"; then
        TIME_DAEMON="chrony"
        DAEMON_CONF="/etc/chrony.conf"
        DAEMON_SERVICE="chronyd"
    elif command_exists ntpq \
        || systemctl list-unit-files 2>/dev/null | grep -q "^ntpd\.service"; then
        TIME_DAEMON="ntp"
        DAEMON_CONF="/etc/ntp.conf"
        DAEMON_SERVICE="ntpd"
    elif systemctl list-unit-files 2>/dev/null | grep -q "systemd-timesyncd"; then
        TIME_DAEMON="timesyncd"
        DAEMON_CONF="/etc/systemd/timesyncd.conf"
        DAEMON_SERVICE="systemd-timesyncd"
    else
        # No daemon found — install chrony on RPM-based systems
        if command_exists dnf || command_exists yum; then
            log_warn "No time-sync daemon detected — chrony will be installed."
            TIME_DAEMON="chrony"
            DAEMON_CONF="/etc/chrony.conf"
            DAEMON_SERVICE="chronyd"
        elif command_exists apt-get; then
            log_warn "No time-sync daemon detected — installing chrony."
            DEBIAN_FRONTEND=noninteractive apt-get install -y chrony
            TIME_DAEMON="chrony"
            DAEMON_CONF="/etc/chrony.conf"
            DAEMON_SERVICE="chronyd"
        else
            log_error "No time-sync daemon found and no supported package manager available."
            exit 1
        fi
    fi

    log_info "Time-sync daemon : $TIME_DAEMON"
    log_info "Config file      : $DAEMON_CONF"
    log_info "Service          : $DAEMON_SERVICE"
}

# --- Interactive prompts ---
prompt_settings() {
    echo ""
    echo "  Configure time source settings (press Enter to accept the default):"

    # ── NTP servers ──────────────────────────────────────────────────────────
    echo ""
    echo "  ── NTP Servers ─────────────────────────────────────────────────────"

    if [[ -n "$TIME_SERVERS" ]]; then
        echo "  Servers from config.conf: $TIME_SERVERS"
        while true; do
            read -rp "  Keep these servers? [Y/n]: " ans
            ans="${ans:-y}"
            case "${ans,,}" in
                y|yes) break ;;
                n|no)  TIME_SERVERS=""; break ;;
                *) echo "  Enter y or n." ;;
            esac
        done
    fi

    if [[ -z "$TIME_SERVERS" ]]; then
        echo ""
        echo "  Select an NTP server preset:"
        echo "    1) NTP Pool Project  — pool.ntp.org        (global round-robin, recommended)"
        echo "    2) Cloudflare        — time.cloudflare.com  (privacy-first, low latency)"
        echo "    3) Google            — time.google.com      (global anycast)"
        echo "    4) NIST              — time.nist.gov        (US government reference)"
        echo "    5) Custom            — enter server addresses manually"
        echo ""
        while true; do
            read -rp "  Preset [1-5, default: 1]: " ans
            ans="${ans:-1}"
            case "$ans" in
                1) TIME_SERVERS="$PRESET_POOL";       break ;;
                2) TIME_SERVERS="$PRESET_CLOUDFLARE"; break ;;
                3) TIME_SERVERS="$PRESET_GOOGLE";     break ;;
                4) TIME_SERVERS="$PRESET_NIST";       break ;;
                5) prompt_custom_servers;              break ;;
                *) echo "  Enter a number from 1 to 5." ;;
            esac
        done
    fi

    # ── iburst ───────────────────────────────────────────────────────────────
    echo ""
    while true; do
        read -rp "  Enable iburst for faster initial synchronisation? [Y/n] (default: Y): " ans
        ans="${ans:-y}"
        case "${ans,,}" in
            y|yes) TIME_IBURST="yes"; break ;;
            n|no)  TIME_IBURST="no";  break ;;
            *) echo "  Enter y or n." ;;
        esac
    done

    # ── Timezone ─────────────────────────────────────────────────────────────
    echo ""
    echo "  ── Timezone ────────────────────────────────────────────────────────"
    local current_tz
    current_tz=$(current_timezone)
    echo "  Current timezone: $current_tz"
    while true; do
        read -rp "  Change timezone? [y/N] (default: N): " ans
        ans="${ans:-n}"
        case "${ans,,}" in
            y|yes) prompt_timezone; break ;;
            n|no)  break ;;
            *) echo "  Enter y or n." ;;
        esac
    done
}

prompt_custom_servers() {
    echo ""
    echo "  Enter NTP server addresses, one per line."
    echo "  Type END on its own line when finished."
    echo "  Examples: ntp1.example.com  192.168.1.10  ptbtime1.ptb.de"
    echo ""
    TIME_SERVERS=""
    local line
    while IFS= read -r line; do
        [[ "$line" == "END" ]] && break
        [[ -z "$line" ]] && continue
        TIME_SERVERS+="${line} "
    done
    TIME_SERVERS="${TIME_SERVERS% }"
    if [[ -z "$TIME_SERVERS" ]]; then
        log_warn "No servers entered — defaulting to NTP Pool Project."
        TIME_SERVERS="$PRESET_POOL"
    fi
}

prompt_timezone() {
    echo ""
    echo "  Enter a timezone name (e.g. UTC, America/New_York, Europe/London)."
    echo "  Run 'timedatectl list-timezones' to see all valid names."
    while true; do
        read -rp "  Timezone: " ans
        if [[ -z "$ans" ]]; then
            echo "  A timezone name is required."
            continue
        fi
        if timedatectl list-timezones 2>/dev/null | grep -qx "$ans" \
            || [[ -f "/usr/share/zoneinfo/$ans" ]]; then
            TIME_TIMEZONE="$ans"
            log_info "Timezone will be set to: $TIME_TIMEZONE"
            break
        else
            echo "  '$ans' is not a recognised timezone."
            echo "  Run 'timedatectl list-timezones' to see valid names."
        fi
    done
}

current_timezone() {
    timedatectl show --property=Timezone --value 2>/dev/null \
        || cat /etc/timezone 2>/dev/null \
        || readlink /etc/localtime 2>/dev/null | sed 's|.*/zoneinfo/||' \
        || echo "unknown"
}

# --- Preview ---
preview_configuration() {
    echo ""
    log_info "Time sync configuration preview:"
    echo ""

    local iburst_label=""
    [[ "$TIME_IBURST" == "yes" ]] && iburst_label="  (iburst)"

    echo "    Daemon           : $TIME_DAEMON  ($DAEMON_SERVICE)"
    echo "    Config file      : $DAEMON_CONF"
    echo ""
    echo "    NTP Servers${iburst_label}"
    for srv in $TIME_SERVERS; do
        echo "      $srv"
    done
    echo ""
    echo "    Timezone"
    if [[ -n "$TIME_TIMEZONE" ]]; then
        echo "      Current  : $(current_timezone)"
        echo "      New      : $TIME_TIMEZONE"
    else
        echo "      $(current_timezone)  (no change)"
    fi
    echo ""

    while true; do
        read -rp "  Apply this configuration? [Y/n]: " confirm
        confirm="${confirm:-y}"
        case "${confirm,,}" in
            y|yes) break ;;
            n|no)
                log_warn "Time sync configuration not applied. Re-run to try again."
                exit 0
                ;;
            *) echo "  Enter y or n." ;;
        esac
    done
}

# --- Install chrony (RPM systems only, when not already present) ---
install_chrony() {
    if command_exists chronyd; then
        return
    fi
    log_info "Installing chrony..."
    if command_exists dnf; then
        dnf install -y chrony
    elif command_exists yum; then
        yum install -y chrony
    fi
    log_info "chrony installed."
}

# --- Configure chrony ---
configure_chrony() {
    backup_file "$DAEMON_CONF"
    mkdir -p "$(dirname "$DAEMON_CONF")"

    local iburst_opt=""
    [[ "$TIME_IBURST" == "yes" ]] && iburst_opt=" iburst"

    {
        echo "# Managed by hardening/modules/time_sync/harden.sh — do not edit manually."
        echo ""
        for srv in $TIME_SERVERS; do
            # pool.ntp.org servers use the pool directive; all others use server
            if [[ "$srv" == *.pool.ntp.org ]]; then
                echo "pool ${srv}${iburst_opt} maxsources 4"
            else
                echo "server ${srv}${iburst_opt}"
            fi
        done
        cat <<'CHRONYEOF'

# Clock drift compensation
driftfile /var/lib/chrony/drift

# Step the clock on the first three updates if offset > 1.0 s,
# then slew continuously from that point forward.
makestep 1.0 3

# Keep the hardware clock in sync with the system clock
rtcsync

# Logging
logdir /var/log/chrony
CHRONYEOF
    } > "$DAEMON_CONF"

    log_info "chrony configuration written to $DAEMON_CONF."
}

# --- Configure ntpd ---
configure_ntp() {
    backup_file "$DAEMON_CONF"

    local iburst_opt=""
    [[ "$TIME_IBURST" == "yes" ]] && iburst_opt=" iburst"

    {
        echo "# Managed by hardening/modules/time_sync/harden.sh — do not edit manually."
        echo ""
        for srv in $TIME_SERVERS; do
            echo "server ${srv}${iburst_opt}"
        done
        cat <<'NTPEOF'

# Clock drift file
driftfile /var/lib/ntp/drift

# Deny all access by default; allow queries only from loopback
restrict default nomodify notrap nopeer noquery
restrict 127.0.0.1
restrict ::1

# Logging
logfile /var/log/ntp.log
NTPEOF
    } > "$DAEMON_CONF"

    log_info "ntpd configuration written to $DAEMON_CONF."
}

# --- Configure systemd-timesyncd ---
configure_timesyncd() {
    backup_file "$DAEMON_CONF"

    local servers_arr
    read -r -a servers_arr <<< "$TIME_SERVERS"

    local primary fallback
    if [[ ${#servers_arr[@]} -ge 2 ]]; then
        primary="${servers_arr[0]}"
        fallback="${servers_arr[*]:1}"
    else
        primary="${servers_arr[0]:-pool.ntp.org}"
        fallback="0.pool.ntp.org 1.pool.ntp.org"
    fi

    {
        echo "# Managed by hardening/modules/time_sync/harden.sh — do not edit manually."
        echo "[Time]"
        echo "NTP=${primary}"
        echo "FallbackNTP=${fallback}"
    } > "$DAEMON_CONF"

    log_info "systemd-timesyncd configuration written to $DAEMON_CONF."
}

# --- Set timezone ---
set_timezone() {
    [[ -z "$TIME_TIMEZONE" ]] && return

    if command_exists timedatectl; then
        timedatectl set-timezone "$TIME_TIMEZONE"
        log_info "Timezone set to $TIME_TIMEZONE via timedatectl."
    elif [[ -f "/usr/share/zoneinfo/$TIME_TIMEZONE" ]]; then
        ln -sf "/usr/share/zoneinfo/$TIME_TIMEZONE" /etc/localtime
        echo "$TIME_TIMEZONE" > /etc/timezone
        log_info "Timezone set to $TIME_TIMEZONE via symlink."
    else
        log_warn "Could not set timezone '$TIME_TIMEZONE' — zoneinfo file not found."
    fi
}

# --- Enable services ---
enable_services() {
    systemctl daemon-reload

    # Disable any competing time-sync daemon before starting the chosen one
    case "$TIME_DAEMON" in
        chrony)
            systemctl stop ntpd             2>/dev/null || true
            systemctl disable ntpd          2>/dev/null || true
            systemctl stop systemd-timesyncd    2>/dev/null || true
            systemctl disable systemd-timesyncd 2>/dev/null || true
            ;;
        ntp)
            systemctl stop chronyd          2>/dev/null || true
            systemctl disable chronyd       2>/dev/null || true
            systemctl stop systemd-timesyncd    2>/dev/null || true
            systemctl disable systemd-timesyncd 2>/dev/null || true
            ;;
        timesyncd)
            systemctl stop chronyd          2>/dev/null || true
            systemctl disable chronyd       2>/dev/null || true
            systemctl stop ntpd             2>/dev/null || true
            systemctl disable ntpd          2>/dev/null || true
            ;;
    esac

    if systemctl enable --now "$DAEMON_SERVICE" 2>/dev/null; then
        log_info "Service $DAEMON_SERVICE enabled and started."
    else
        log_warn "Could not start $DAEMON_SERVICE — check $DAEMON_CONF for errors."
    fi

    # Ensure NTP sync is active at the timedatectl layer
    if command_exists timedatectl; then
        timedatectl set-ntp true 2>/dev/null || true
    fi
}

# --- Verify sync ---
verify_sync() {
    log_info "Waiting for initial synchronisation (up to 30 s)..."
    local waited=0
    while (( waited < 30 )); do
        case "$TIME_DAEMON" in
            chrony)
                chronyc tracking 2>/dev/null | grep -q "^Reference ID" && break ;;
            ntp)
                ntpq -p 2>/dev/null | grep -qE "^\*" && break ;;
            timesyncd)
                timedatectl timesync-status 2>/dev/null | grep -q "Server:" && break ;;
        esac
        sleep 5
        waited=$(( waited + 5 ))
    done

    log_info "Sync status:"
    case "$TIME_DAEMON" in
        chrony)
            chronyc tracking 2>/dev/null \
                | while IFS= read -r line; do log_info "  $line"; done \
                || log_warn "  chronyc tracking unavailable."
            ;;
        ntp)
            ntpq -p 2>/dev/null \
                | while IFS= read -r line; do log_info "  $line"; done \
                || log_warn "  ntpq unavailable."
            ;;
        timesyncd)
            timedatectl timesync-status 2>/dev/null \
                | while IFS= read -r line; do log_info "  $line"; done \
                || log_warn "  timedatectl timesync-status unavailable."
            ;;
    esac
}

# --- Artifact ---
save_artifact() {
    local artifact
    artifact=$(artifact_file "time_sync")

    local final_tz daemon_version sync_status

    final_tz=$(current_timezone)

    case "$TIME_DAEMON" in
        chrony)
            daemon_version=$(chronyd --version 2>/dev/null | head -1 || echo "unavailable")
            sync_status=$(chronyc tracking 2>/dev/null || echo "unavailable")
            ;;
        ntp)
            daemon_version=$(ntpd --version 2>&1 | head -1 || echo "unavailable")
            sync_status=$(ntpq -p 2>/dev/null || echo "unavailable")
            ;;
        timesyncd)
            daemon_version=$(systemctl show systemd-timesyncd \
                --property=Description --value 2>/dev/null || echo "unavailable")
            sync_status=$(timedatectl timesync-status 2>/dev/null || echo "unavailable")
            ;;
    esac

    {
        cat <<EOF
TIME SYNC CONFIGURATION REPORT
================================
Generated  : $(date '+%Y-%m-%d %H:%M:%S')
Hostname   : $(hostname)
OS         : $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
Applied by : hardening/modules/time_sync/harden.sh

DAEMON
------
  Name     : $TIME_DAEMON
  Service  : $DAEMON_SERVICE
  Config   : $DAEMON_CONF
  Version  : $daemon_version

NTP SERVERS
-----------
EOF
        for srv in $TIME_SERVERS; do
            echo "  $srv"
        done
        cat <<EOF
  iburst   : $TIME_IBURST

TIMEZONE
--------
  Active   : $final_tz

SYNC STATUS  (at time of installation)
---------------------------------------
$sync_status
EOF
    } > "$artifact"

    log_info "Artifact saved: $artifact"
}

# --- Main ---
log_section "Time Sync"

detect_environment

[[ "$TIME_DAEMON" == "chrony" ]] && install_chrony

prompt_settings
preview_configuration

case "$TIME_DAEMON" in
    chrony)    configure_chrony ;;
    ntp)       configure_ntp ;;
    timesyncd) configure_timesyncd ;;
esac

set_timezone
enable_services
verify_sync
save_artifact

log_info "Time sync module complete."
