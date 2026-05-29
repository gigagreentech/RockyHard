#!/usr/bin/env bash
# =============================================================================
# Module  : antivirus
# Purpose : Two-level antivirus management menu. Top level selects ClamAV or
#           Microsoft Defender (MDE). Each sub-menu provides install, scan
#           configuration, status, and service control options.
#
# Sub-modules:
#   clamav.sh — ClamAV full install and configure
#   mde.sh    — Microsoft Defender for Endpoint full install and configure
#
# Must be run as root (enforced by check_root in master.sh).
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../config.conf"
source "$SCRIPT_DIR/../../lib/common.sh"

log_section "Antivirus"

# =============================================================================
# Shared helper
# =============================================================================

# Reads an mdatp health field; returns "unavailable" if field name is rejected
get_mde_field() {
    local val
    val=$(mdatp health --field "$1" 2>/dev/null) || true
    if [[ -z "$val" || "$val" == *"Invalid argument"* ]]; then
        echo "unavailable"
    else
        echo "$val"
    fi
}

# =============================================================================
# ClamAV — status
# =============================================================================

show_clamav_status() {
    echo ""
    echo "  ── ClamAV Status ───────────────────────────────────────────────"

    if ! command -v clamd &>/dev/null && ! command -v clamdscan &>/dev/null && ! command -v clamscan &>/dev/null; then
        echo "  ClamAV is not installed."
        echo ""
        return
    fi

    local clam_ver
    clam_ver=$(clamscan --version 2>/dev/null | head -1 || echo "unavailable")
    echo "  Version          : $clam_ver"

    local clamd_svc="clamd@scan"
    systemctl list-units --type=service --all 2>/dev/null | grep -q "clamav-daemon" \
        && clamd_svc="clamav-daemon"

    local freshclam_svc="clamav-freshclam"

    local clamd_active clamd_enabled freshclam_active
    if systemctl is-active --quiet "$clamd_svc" 2>/dev/null; then clamd_active="active"; else clamd_active="inactive"; fi
    if systemctl is-enabled --quiet "$clamd_svc" 2>/dev/null; then clamd_enabled="enabled"; else clamd_enabled="disabled"; fi
    if systemctl is-active --quiet "$freshclam_svc" 2>/dev/null \
       || systemctl is-active --quiet freshclam 2>/dev/null; then
        freshclam_active="active"
    else
        freshclam_active="inactive"
    fi

    echo "  clamd service    : $clamd_active ($clamd_enabled)"
    echo "  freshclam service: $freshclam_active"

    local db_date
    db_date=$(sigtool --info /var/lib/clamav/main.cvd 2>/dev/null \
           | grep "Build time" | awk -F: '{print $2}' | xargs 2>/dev/null \
           || echo "unavailable")
    echo "  Virus DB date    : $db_date"

    if [[ -f /etc/clamd.d/scan.conf ]]; then
        echo "  Config file      : /etc/clamd.d/scan.conf"
    elif [[ -f /etc/clamav/clamd.conf ]]; then
        echo "  Config file      : /etc/clamav/clamd.conf"
    fi

    echo ""
    echo "  Scheduled Scan:"
    local clam_timer_file="/etc/systemd/system/clamav-scheduled-scan.timer"
    if [[ -f "$clam_timer_file" ]]; then
        local timer_active on_calendar next_run
        if systemctl is-active --quiet clamav-scheduled-scan.timer 2>/dev/null; then
            timer_active="active"
        else
            timer_active="inactive"
        fi
        on_calendar=$(grep -i "^OnCalendar" "$clam_timer_file" | awk -F= '{print $2}' | xargs)
        next_run=$(systemctl status clamav-scheduled-scan.timer 2>/dev/null \
                   | grep -i "Trigger:" | sed 's/.*Trigger:[[:space:]]*//' | xargs)
        echo "    Timer status     : $timer_active"
        echo "    Schedule         : ${on_calendar:-unavailable}"
        echo "    Next run         : ${next_run:-unavailable}"
    else
        echo "    Timer unit       : not installed"
    fi

    local clam_scan_script="/var/lib/hardening/clamav-scan.sh"
    if [[ -f "$clam_scan_script" ]]; then
        local scan_paths max_size detect_pua on_access
        scan_paths=$(grep  "^SCAN_PATHS="      "$clam_scan_script" | head -1 | cut -d'"' -f2)
        max_size=$(grep    "^MAX_FILE_SIZE="   "$clam_scan_script" | head -1 | cut -d'"' -f2)
        detect_pua=$(grep  "^DETECT_PUA="     "$clam_scan_script" | head -1 | cut -d'"' -f2)
        on_access=$(grep   "^ON_ACCESS_SCAN=" "$clam_scan_script" | head -1 | cut -d'"' -f2)
        [[ -n "$scan_paths"  ]] && echo "    Scan paths       : $scan_paths"
        [[ -n "$max_size"    ]] && echo "    Max file size    : ${max_size} MB"
        [[ -n "$detect_pua"  ]] && echo "    Detect PUA       : $detect_pua"
        [[ -n "$on_access"   ]] && echo "    On-access scan   : $on_access"
    fi
    echo ""
}

# =============================================================================
# ClamAV — scan configuration
# =============================================================================

setup_clamav_scan_config() {
    echo ""
    echo "  ── ClamAV Scan Configuration ───────────────────────────────────"

    local scan_script="/var/lib/hardening/clamav-scan.sh"
    local scan_log="/var/log/clamav/scheduled-scan.log"

    # Read existing values as defaults
    local scan_paths max_size detect_pua scan_schedule scan_hour scan_day
    scan_paths=$(grep   "^SCAN_PATHS="    "$scan_script" 2>/dev/null | head -1 | cut -d'"' -f2 || echo "/home /tmp /var/tmp")
    max_size=$(grep     "^MAX_FILE_SIZE=" "$scan_script" 2>/dev/null | head -1 | cut -d'"' -f2 || echo "100")
    detect_pua=$(grep   "^DETECT_PUA="   "$scan_script" 2>/dev/null | head -1 | cut -d'"' -f2 || echo "yes")
    scan_schedule=$(grep "^OnCalendar"   /etc/systemd/system/clamav-scheduled-scan.timer 2>/dev/null \
                    | awk -F= '{print $2}' | xargs)
    [[ "$scan_schedule" == *"-*-*"* && "$scan_schedule" != *" "*-*-* ]] \
        && scan_sched_freq="daily" || scan_sched_freq="weekly"
    scan_sched_freq="${CLAMAV_SCAN_SCHEDULE:-daily}"
    scan_hour="${CLAMAV_SCAN_HOUR:-2}"
    scan_day="${CLAMAV_SCAN_DAY:-Sunday}"
    echo ""

    read -rp "  Scan paths (space-separated, default: $scan_paths): " ans
    [[ -n "$ans" ]] && scan_paths="$ans"

    read -rp "  Max file size MB (default: $max_size): " ans
    [[ "$ans" =~ ^[0-9]+$ ]] && max_size="$ans"

    while true; do
        read -rp "  Detect PUA [yes/no] (default: $detect_pua): " ans
        ans="${ans:-$detect_pua}"
        case "${ans,,}" in yes|no) detect_pua="${ans,,}"; break ;; *) echo "  Enter yes or no." ;; esac
    done

    while true; do
        read -rp "  Frequency [daily/weekly] (default: $scan_sched_freq): " ans
        ans="${ans:-$scan_sched_freq}"
        case "${ans,,}" in daily|weekly) scan_sched_freq="${ans,,}"; break ;; *) echo "  Enter daily or weekly." ;; esac
    done

    while true; do
        read -rp "  Scan hour (0-23, default: $scan_hour): " ans
        ans="${ans:-$scan_hour}"
        if [[ "$ans" =~ ^[0-9]+$ && "$ans" -ge 0 && "$ans" -le 23 ]]; then
            scan_hour="$ans"; break
        else
            echo "  Enter a number between 0 and 23."
        fi
    done

    if [[ "$scan_sched_freq" == "weekly" ]]; then
        while true; do
            read -rp "  Scan day [Monday-Sunday] (default: $scan_day): " ans
            ans="${ans:-$scan_day}"
            case "${ans,,}" in
                sun|sunday|mon|monday|tue|tuesday|wed|wednesday|thu|thursday|fri|friday|sat|saturday)
                    scan_day="$ans"; break ;;
                *) echo "  Enter a day name." ;;
            esac
        done
    fi

    local hour_fmt
    hour_fmt=$(printf '%02d' "$scan_hour")

    # Write updated scan script
    mkdir -p /var/lib/hardening
    cat > "$scan_script" <<EOF
#!/usr/bin/env bash
# ClamAV scheduled scan script — managed by hardening/modules/antivirus/harden.sh
set -euo pipefail
SCAN_PATHS="${scan_paths}"
MAX_FILE_SIZE="${max_size}"
DETECT_PUA="${detect_pua}"
ON_ACCESS_SCAN="no"
SCAN_LOG="${scan_log}"
mkdir -p "\$(dirname "\$SCAN_LOG")"
{
    echo "========================================"
    echo "ClamAV Scheduled Scan"
    echo "Started  : \$(date '+%Y-%m-%d %H:%M:%S')"
    echo "Hostname : \$(hostname)"
    echo "========================================"
} >> "\$SCAN_LOG"
if command -v clamdscan &>/dev/null; then
    clamdscan --fdpass --recursive \$SCAN_PATHS >> "\$SCAN_LOG" 2>&1 || true
else
    clamscan --recursive --max-filesize=\${MAX_FILE_SIZE}M \
        \$([ "\$DETECT_PUA" = "yes" ] && echo "--detect-pua") \
        \$SCAN_PATHS >> "\$SCAN_LOG" 2>&1 || true
fi
echo "Completed: \$(date '+%Y-%m-%d %H:%M:%S')" >> "\$SCAN_LOG"
echo "" >> "\$SCAN_LOG"
EOF
    chmod 750 "$scan_script"

    # Build OnCalendar
    local on_calendar sys_day
    case "${scan_day,,}" in
        sun|sunday)    sys_day="Sun" ;;
        mon|monday)    sys_day="Mon" ;;
        tue|tuesday)   sys_day="Tue" ;;
        wed|wednesday) sys_day="Wed" ;;
        thu|thursday)  sys_day="Thu" ;;
        fri|friday)    sys_day="Fri" ;;
        sat|saturday)  sys_day="Sat" ;;
        *)             sys_day="Sun" ;;
    esac
    if [[ "$scan_sched_freq" == "weekly" ]]; then
        on_calendar="${sys_day} *-*-* ${hour_fmt}:00:00"
    else
        on_calendar="*-*-* ${hour_fmt}:00:00"
    fi

    # Write/update systemd timer
    mkdir -p /var/lib/hardening
    cat > /etc/systemd/system/clamav-scheduled-scan.service <<EOF
[Unit]
Description=ClamAV Scheduled Scan (evidence log)
After=clamd@scan.service

[Service]
Type=oneshot
ExecStart=${scan_script}
StandardOutput=journal
StandardError=journal
EOF

    cat > /etc/systemd/system/clamav-scheduled-scan.timer <<EOF
[Unit]
Description=ClamAV Scheduled Scan Timer (${scan_sched_freq} at ${hour_fmt}:00)

[Timer]
OnCalendar=${on_calendar}
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now clamav-scheduled-scan.timer
    log_info "ClamAV scan configuration updated — $scan_sched_freq at ${hour_fmt}:00."
    log_info "Scan log: $scan_log"
}

# =============================================================================
# ClamAV — service control
# =============================================================================

start_clamav() {
    local clamd_svc="clamd@scan"
    systemctl list-units --type=service --all 2>/dev/null | grep -q "clamav-daemon" \
        && clamd_svc="clamav-daemon"
    echo ""
    if systemctl start "$clamd_svc" 2>/dev/null; then
        log_info "$clamd_svc started."
    else
        log_warn "Failed to start $clamd_svc."
    fi
    systemctl start clamav-freshclam 2>/dev/null && log_info "clamav-freshclam started." || true
    echo ""
}

stop_clamav() {
    local clamd_svc="clamd@scan"
    systemctl list-units --type=service --all 2>/dev/null | grep -q "clamav-daemon" \
        && clamd_svc="clamav-daemon"
    echo ""
    if systemctl stop "$clamd_svc" 2>/dev/null; then
        log_info "$clamd_svc stopped."
    else
        log_warn "Failed to stop $clamd_svc."
    fi
    echo ""
}

toggle_clamav_service() {
    local clamd_svc="clamd@scan"
    systemctl list-units --type=service --all 2>/dev/null | grep -q "clamav-daemon" \
        && clamd_svc="clamav-daemon"
    echo ""
    if systemctl is-enabled --quiet "$clamd_svc" 2>/dev/null; then
        log_info "$clamd_svc is currently enabled."
        read -rp "  Disable it (stop at boot)? [y/N]: " ans
        if [[ "${ans,,}" == "y" ]]; then
            systemctl disable "$clamd_svc"
            log_info "$clamd_svc disabled."
        fi
    else
        log_info "$clamd_svc is currently disabled."
        read -rp "  Enable it (start at boot)? [y/N]: " ans
        if [[ "${ans,,}" == "y" ]]; then
            systemctl enable "$clamd_svc"
            log_info "$clamd_svc enabled."
        fi
    fi
    echo ""
}

# =============================================================================
# MDE — status
# =============================================================================

show_mde_status() {
    echo ""
    echo "  ── Microsoft Defender for Endpoint Status ──────────────────────"

    if ! command -v mdatp &>/dev/null; then
        echo "  MDE is not installed."
        echo ""
        return
    fi

    local fields=(
        "App version         :app_version"
        "Engine version      :engine_version"
        "Organisation ID     :org_id"
        "Agent healthy       :healthy"
        "Licensed            :licensed"
        "Release ring        :release_ring"
        "EDR machine ID      :edr_machine_id"
        "Real-time protection:real_time_protection_enabled"
        "RTP subsystem       :real_time_protection_subsystem"
        "Passive mode        :passive_mode_enabled"
        "Behavior monitoring :behavior_monitoring"
        "Cloud protection    :cloud_enabled"
        "Network protection  :network_protection_status"
        "  NP enforcement    :network_protection_enforcement_level"
        "Sample submission   :cloud_automatic_sample_submission_consent"
        "Cloud diagnostic    :cloud_diagnostic_enabled"
        "Log level           :log_level"
        "Definitions version :definitions_version"
        "Definitions status  :definitions_status"
        "Definitions updated :definitions_updated"
    )

    for entry in "${fields[@]}"; do
        local label field val
        label="${entry%%:*}"
        field="${entry##*:}"
        val=$(get_mde_field "$field")
        printf "  %-20s : %s\n" "$label" "$val"
    done

    echo ""
    local svc_active svc_enabled
    if systemctl is-active  --quiet mdatp 2>/dev/null; then svc_active="active";   else svc_active="inactive"; fi
    if systemctl is-enabled --quiet mdatp 2>/dev/null; then svc_enabled="enabled"; else svc_enabled="disabled"; fi
    echo "  mdatp service    : $svc_active ($svc_enabled)"

    echo ""
    echo "  Scheduled Scan:"
    local mde_timer_file="/etc/systemd/system/mdatp-scheduled-scan.timer"
    if [[ -f "$mde_timer_file" ]]; then
        local timer_active on_calendar next_run
        if systemctl is-active --quiet mdatp-scheduled-scan.timer 2>/dev/null; then
            timer_active="active"
        else
            timer_active="inactive"
        fi
        on_calendar=$(grep -i "^OnCalendar" "$mde_timer_file" | awk -F= '{print $2}' | xargs)
        next_run=$(systemctl status mdatp-scheduled-scan.timer 2>/dev/null \
                   | grep -i "Trigger:" | sed 's/.*Trigger:[[:space:]]*//' | xargs)
        echo "    Timer status     : $timer_active"
        echo "    Schedule         : ${on_calendar:-unavailable}"
        echo "    Next run         : ${next_run:-unavailable}"
    else
        echo "    Timer unit       : not installed (use 'Change scan configuration' to set up)"
    fi

    local mde_scan_script="/var/lib/hardening/mdatp-scan.sh"
    if [[ -f "$mde_scan_script" ]]; then
        local scan_type
        scan_type=$(grep "^SCAN_TYPE=" "$mde_scan_script" | head -1 | cut -d'"' -f2)
        [[ -n "$scan_type" ]] && echo "    Scan type        : $scan_type"
        echo "    Scan log         : /var/log/microsoft/mdatp/scheduled-scan.log"
    fi

    echo ""
    echo "  Exclusions:"
    mdatp exclusion list 2>/dev/null || echo "    (none or unavailable)"
    echo ""
}

# =============================================================================
# MDE — scan configuration
# =============================================================================

setup_mde_scan_config() {
    echo ""
    echo "  ── MDE Scan Configuration ──────────────────────────────────────"

    if ! command -v mdatp &>/dev/null; then
        log_warn "mdatp is not installed — install Microsoft Defender first."
        return
    fi

    local scan_type="${MDE_SCAN_TYPE:-full}"
    local scan_schedule="${MDE_SCAN_SCHEDULE:-daily}"
    local scan_hour="${MDE_SCAN_HOUR:-2}"
    local scan_day="${MDE_SCAN_DAY:-Sunday}"
    local scan_script="/var/lib/hardening/mdatp-scan.sh"
    local scan_log="/var/log/microsoft/mdatp/scheduled-scan.log"
    echo ""

    while true; do
        read -rp "  Scan type [quick/full] (default: $scan_type): " ans
        ans="${ans:-$scan_type}"
        case "${ans,,}" in quick|full) scan_type="${ans,,}"; break ;; *) echo "  Enter 'quick' or 'full'." ;; esac
    done

    while true; do
        read -rp "  Frequency [daily/weekly] (default: $scan_schedule): " ans
        ans="${ans:-$scan_schedule}"
        case "${ans,,}" in daily|weekly) scan_schedule="${ans,,}"; break ;; *) echo "  Enter 'daily' or 'weekly'." ;; esac
    done

    while true; do
        read -rp "  Scan hour (0-23, default: $scan_hour): " ans
        ans="${ans:-$scan_hour}"
        if [[ "$ans" =~ ^[0-9]+$ && "$ans" -ge 0 && "$ans" -le 23 ]]; then
            scan_hour="$ans"; break
        else
            echo "  Enter a number between 0 and 23."
        fi
    done

    if [[ "$scan_schedule" == "weekly" ]]; then
        while true; do
            read -rp "  Scan day [Monday-Sunday] (default: $scan_day): " ans
            ans="${ans:-$scan_day}"
            case "${ans,,}" in
                sun|sunday|mon|monday|tue|tuesday|wed|wednesday|thu|thursday|fri|friday|sat|saturday)
                    scan_day="$ans"; break ;;
                *) echo "  Enter a day name." ;;
            esac
        done
    fi

    local hour_fmt
    hour_fmt=$(printf '%02d' "$scan_hour")

    mkdir -p /var/lib/hardening
    cat > "$scan_script" <<EOF
#!/usr/bin/env bash
# MDE scheduled scan script — managed by hardening/modules/antivirus/harden.sh
set -euo pipefail
SCAN_LOG="${scan_log}"
SCAN_TYPE="${scan_type}"
mkdir -p "\$(dirname "\$SCAN_LOG")"
{
    echo "========================================"
    echo "Microsoft Defender Scheduled Scan"
    echo "Type     : \$SCAN_TYPE"
    echo "Started  : \$(date '+%Y-%m-%d %H:%M:%S')"
    echo "Hostname : \$(hostname)"
    echo "========================================"
} >> "\$SCAN_LOG"
mdatp scan "\$SCAN_TYPE" >> "\$SCAN_LOG" 2>&1 || true
echo "Completed: \$(date '+%Y-%m-%d %H:%M:%S')" >> "\$SCAN_LOG"
echo "" >> "\$SCAN_LOG"
EOF
    chmod 750 "$scan_script"

    local on_calendar sys_day
    case "${scan_day,,}" in
        sun|sunday)    sys_day="Sun" ;;
        mon|monday)    sys_day="Mon" ;;
        tue|tuesday)   sys_day="Tue" ;;
        wed|wednesday) sys_day="Wed" ;;
        thu|thursday)  sys_day="Thu" ;;
        fri|friday)    sys_day="Fri" ;;
        sat|saturday)  sys_day="Sat" ;;
        *)             sys_day="Sun" ;;
    esac
    if [[ "$scan_schedule" == "weekly" ]]; then
        on_calendar="${sys_day} *-*-* ${hour_fmt}:00:00"
    else
        on_calendar="*-*-* ${hour_fmt}:00:00"
    fi

    cat > /etc/systemd/system/mdatp-scheduled-scan.service <<EOF
[Unit]
Description=Microsoft Defender Scheduled Scan (evidence log)
After=mdatp.service network.target
Requires=mdatp.service

[Service]
Type=oneshot
ExecStart=${scan_script}
StandardOutput=journal
StandardError=journal
EOF

    cat > /etc/systemd/system/mdatp-scheduled-scan.timer <<EOF
[Unit]
Description=Microsoft Defender Scheduled Scan Timer (${scan_schedule} at ${hour_fmt}:00)

[Timer]
OnCalendar=${on_calendar}
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable --now mdatp-scheduled-scan.timer
    log_info "MDE scan configuration updated — $scan_schedule at ${hour_fmt}:00."
    log_info "Scan log: $scan_log"
}

# =============================================================================
# MDE — service control
# =============================================================================

start_mde() {
    echo ""
    if systemctl start mdatp 2>/dev/null; then
        log_info "mdatp started."
    else
        log_warn "Failed to start mdatp — check: journalctl -u mdatp"
    fi
    sleep 3
    local healthy
    healthy=$(get_mde_field healthy)
    echo "  Agent healthy : $healthy"
    echo ""
}

stop_mde() {
    echo ""
    if systemctl stop mdatp 2>/dev/null; then
        log_info "mdatp stopped."
    else
        log_warn "Failed to stop mdatp."
    fi
    echo ""
}

toggle_mde_service() {
    echo ""
    if systemctl is-enabled --quiet mdatp 2>/dev/null; then
        log_info "mdatp is currently enabled (starts at boot)."
        read -rp "  Disable it? [y/N]: " ans
        if [[ "${ans,,}" == "y" ]]; then
            systemctl disable mdatp
            log_info "mdatp disabled."
        fi
    else
        log_info "mdatp is currently disabled."
        read -rp "  Enable it (start at boot)? [y/N]: " ans
        if [[ "${ans,,}" == "y" ]]; then
            systemctl enable mdatp
            log_info "mdatp enabled."
        fi
    fi
    echo ""
}

restart_mde() {
    echo ""
    log_info "Restarting mdatp..."
    if systemctl restart mdatp 2>/dev/null; then
        log_info "mdatp restarted."
    else
        log_warn "Failed to restart mdatp — check: journalctl -u mdatp"
    fi
    if systemctl is-active --quiet mdatp-scheduled-scan.timer 2>/dev/null; then
        systemctl restart mdatp-scheduled-scan.timer
        log_info "mdatp-scheduled-scan.timer restarted."
    fi
    sleep 3
    local svc_status healthy
    if systemctl is-active --quiet mdatp 2>/dev/null; then svc_status="active"; else svc_status="inactive"; fi
    healthy=$(get_mde_field healthy)
    echo "  mdatp service : $svc_status"
    echo "  Agent healthy : $healthy"
    echo ""
}

# =============================================================================
# MDE — EICAR test alert
# =============================================================================

run_eicar_test() {
    echo ""
    echo "  ── MDE EICAR Test Alert ────────────────────────────────────────"

    if ! command -v mdatp &>/dev/null; then
        log_warn "mdatp is not installed — install Microsoft Defender first."
        return
    fi

    echo ""
    echo "  Downloads the EICAR standard test file and checks that MDE detects"
    echo "  it and generates an alert in the GCCH portal."
    echo "  The file is NOT malware — it is a harmless string for AV validation."
    echo ""
    echo "  Portal : https://security.microsoft.us → Incidents & Alerts"
    echo ""

    local eicar_file="/tmp/eicar.com.txt"

    log_info "Downloading EICAR test file..."
    if ! curl -fsSL -o "$eicar_file" https://secure.eicar.org/eicar.com.txt; then
        log_warn "curl failed — check network connectivity to secure.eicar.org."
        return
    fi

    if [[ ! -f "$eicar_file" ]]; then
        log_info "File was immediately quarantined by MDE — detection confirmed."
        echo "  Result : DETECTED — file quarantined on write"
        echo "  Check  : https://security.microsoft.us → Incidents & Alerts"
        echo ""
        return
    fi

    log_info "Test file written. Waiting 15 seconds for MDE to process it..."
    sleep 15

    local threat_output
    threat_output=$(mdatp threat list 2>/dev/null || echo "")

    echo ""
    if echo "$threat_output" | grep -qi "eicar\|test file\|virus"; then
        log_info "EICAR file detected by MDE."
        echo "  Result : DETECTED — alert visible in GCCH portal"
    else
        log_warn "Not found in threat list after 15 seconds — MDE may still be processing."
        echo "  Result : INCONCLUSIVE — verify manually: mdatp threat list"
    fi

    if [[ -f "$eicar_file" ]]; then
        rm -f "$eicar_file"
        log_info "Test file removed."
    else
        log_info "Test file already removed by MDE (expected)."
    fi

    echo ""
    echo "  Verify the alert: https://security.microsoft.us → Incidents & Alerts"
    echo ""
}

# =============================================================================
# Top-level: combined status view
# =============================================================================

show_av_status() {
    echo ""
    echo "  ══════════════════════════════════════════════════════════════"
    echo "   Current Antivirus Configuration"
    echo "  ══════════════════════════════════════════════════════════════"
    show_clamav_status
    show_mde_status
    echo "  ══════════════════════════════════════════════════════════════"
    echo ""
}

# =============================================================================
# Sub-menus
# =============================================================================

clamav_menu() {
    while true; do
        echo ""
        echo "  ── ClamAV ──────────────────────────────────────────────────────"
        echo ""
        echo "  1) Install ClamAV               — full install and configure"
        echo "  2) Change scan configuration    — update scan paths, schedule, and settings"
        echo "  3) View status                  — service state, version, schedule"
        echo "  4) Start services               — start clamd and freshclam"
        echo "  5) Stop service                 — stop clamd"
        echo "  6) Enable / Disable service     — control start-at-boot"
        echo "  b) Back"
        echo ""
        read -rp "  Enter choice: " choice
        case "$choice" in
            1) bash "$SCRIPT_DIR/clamav.sh" ;;
            2) setup_clamav_scan_config ;;
            3) show_clamav_status ;;
            4) start_clamav ;;
            5) stop_clamav ;;
            6) toggle_clamav_service ;;
            b|B) break ;;
            *) echo "  Invalid choice." ;;
        esac
    done
}

mde_menu() {
    while true; do
        echo ""
        echo "  ── Microsoft Defender for Endpoint ─────────────────────────────"
        echo ""
        echo "  1) Install Microsoft Defender   — full install and configure"
        echo "  2) Change scan configuration    — update scan type and schedule"
        echo "  3) View status                  — health, settings, schedule"
        echo "  4) Start service                — start mdatp"
        echo "  5) Stop service                 — stop mdatp"
        echo "  6) Restart service              — restart mdatp and scan timer"
        echo "  7) Enable / Disable service     — control start-at-boot"
        echo "  8) MDE test alert (EICAR)       — verify detection and portal alerting"
        echo "  b) Back"
        echo ""
        read -rp "  Enter choice: " choice
        case "$choice" in
            1) bash "$SCRIPT_DIR/mde.sh" ;;
            2) setup_mde_scan_config ;;
            3) show_mde_status ;;
            4) start_mde ;;
            5) stop_mde ;;
            6) restart_mde ;;
            7) toggle_mde_service ;;
            8) run_eicar_test ;;
            b|B) break ;;
            *) echo "  Invalid choice." ;;
        esac
    done
}

# =============================================================================
# Main menu
# =============================================================================

while true; do
    echo ""
    echo "  ── Antivirus ────────────────────────────────────────────────────"
    echo ""
    echo "  1) ClamAV                  — open-source AV (no licence required)"
    echo "  2) Microsoft Defender      — MDE for Linux (requires Defender for Servers licence)"
    echo "  3) View current AV status  — show all installed AV configuration"
    echo "  q) Quit"
    echo ""
    read -rp "  Enter choice: " choice
    case "$choice" in
        1) clamav_menu ;;
        2) mde_menu ;;
        3) show_av_status ;;
        q|Q) break ;;
        *) echo "  Invalid choice." ;;
    esac
done
