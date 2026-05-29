#!/usr/bin/env bash
# =============================================================================
# Module  : antivirus / mde
# Purpose : Install and configure Microsoft Defender for Endpoint (MDE) for
#           Linux, apply hardened behavioural settings, and establish a
#           scheduled scan timer that produces timestamped evidence logs of
#           routine scanning activity.
#
# CLOUD ENVIRONMENT: GCC High (GCCH)
# This module targets the Microsoft GCC High sovereign cloud.  All portal
# references and onboarding instructions use GCCH endpoints
# (*.microsoft.us, *.usgovcloudapi.net) rather than commercial endpoints.
#
# IMPORTANT: This module uses the RHEL 9-compatible Microsoft package
# repository (packages.microsoft.com).  Rocky Linux is binary-compatible
# with RHEL and MDE installs and operates correctly, but Microsoft does not
# officially list Rocky Linux as a supported distribution.  Document RHEL
# equivalence for compliance audits if required.
#
# A Defender for Servers P1 or P2 licence (GCC High SKU) is required.
# The onboarding script (MicrosoftDefenderATPOnboardingLinuxServer.py) must
# be downloaded from the GCC High Defender portal before running this module:
#   GCC High portal → Settings → Endpoints → Device management → Onboarding
#   URL    : https://security.microsoft.us
#   Select : Linux Server, Deployment method: Local Script
#   Place the extracted .py file at:
#     hardening/MDE/MicrosoftDefenderATPOnboardingLinuxServer.py
#
# REQUIRED NETWORK ENDPOINTS (outbound HTTPS/443 from this host):
#   winatp-gw-usgovvirginia.microsoft.com  — MDE GCCH primary
#   winatp-gw-usgovarizona.microsoft.com   — MDE GCCH secondary
#   *.blob.core.usgovcloudapi.net          — signature and engine updates
#   unitedstates.dp.microsoft.com          — diagnostic data pipeline
#   crl.microsoft.com                      — certificate revocation
#   ctldl.windowsupdate.com               — certificate trust list
#
# This module performs the following actions in order:
#
#   1. ONBOARDING SCRIPT VALIDATION
#      Checks for the onboarding script at hardening/MDE/ and prompts for
#      the path if not found there.
#
#   2. SETTINGS SELECTION (interactive, grouped by category)
#      Protection  : real-time, passive mode, cloud, PUA, behavior monitoring,
#                    network protection, tamper protection, sample submission
#      Diagnostics : log level, cloud diagnostic data
#      Exclusions  : additional folders, file extensions, process names
#      Network     : proxy server (optional)
#      Scheduling  : scan type, frequency, time, day, built-in scheduler
#
#   3. CONFIGURATION PREVIEW
#
#   4. PACKAGE INSTALLATION
#      Adds the Microsoft RHEL repo and installs mdatp.
#
#   5. ONBOARDING
#      Runs the Python onboarding script; verifies org_id is set.
#
#   6. MDE CONFIGURATION
#      Applies all settings via mdatp config / mdatp threat policy.
#      Adds /proc /sys /dev /run and any operator-defined exclusions.
#
#   7. SCHEDULED SCAN
#      Configures the MDE built-in scheduler via mdatp scheduled scan
#      (if enabled) and writes a systemd service + timer for evidence
#      logging to /var/log/microsoft/mdatp/scheduled-scan.log.
#
#   8. SERVICE ENABLEMENT
#
#   9. ARTIFACT
#      Writes a report to artifacts/mde/ with all live health fields.
#      The scan log is the ongoing evidence record for routine scanning.
#
# Files written:
#   /etc/yum.repos.d/microsoft-prod.repo  (RHEL/Rocky)
#   /var/lib/hardening/mdatp-scan.sh
#   /etc/systemd/system/mdatp-scheduled-scan.service
#   /etc/systemd/system/mdatp-scheduled-scan.timer
#
# Must be run as root.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../config.conf"
source "$SCRIPT_DIR/../../lib/common.sh"

# --- Settings (config.conf values as defaults) ---

# Onboarding
MDE_ONBOARDING_SCRIPT=""

# Release channel — controls which package repo is used.
# Network protection requires insiders-slow or insiders-fast.
# production = stable/GA; insiders-slow = preview (recommended for NP); insiders-fast = bleeding edge
MDE_RELEASE_CHANNEL="${MDE_RELEASE_CHANNEL:-production}"

# Protection
MDE_REAL_TIME="${MDE_REAL_TIME_PROTECTION:-enabled}"
MDE_PASSIVE="${MDE_PASSIVE_MODE:-disabled}"
MDE_CLOUD="${MDE_CLOUD_ENABLED:-enabled}"
MDE_PUA="${MDE_PUA_ACTION:-block}"
MDE_BEHAVIOR_MONITORING="${MDE_BEHAVIOR_MONITORING:-enabled}"
MDE_NETWORK_PROTECTION="${MDE_NETWORK_PROTECTION:-block}"
MDE_AUTO_SAMPLE="${MDE_AUTO_SAMPLE_SUBMISSION:-enabled}"

# Diagnostics
MDE_LOG_LEVEL="${MDE_LOG_LEVEL:-info}"
MDE_CLOUD_DIAGNOSTIC="${MDE_CLOUD_DIAGNOSTIC:-enabled}"

# Exclusions (space-separated strings)
MDE_EXCL_FOLDERS="${MDE_EXCL_FOLDERS:-}"
MDE_EXCL_EXTENSIONS="${MDE_EXCL_EXTENSIONS:-}"
MDE_EXCL_PROCESSES="${MDE_EXCL_PROCESSES:-}"

# Network
MDE_PROXY="${MDE_PROXY:-}"

# Scheduling
MDE_SCAN_TYPE="${MDE_SCAN_TYPE:-full}"
MDE_SCAN_SCHEDULE="${MDE_SCAN_SCHEDULE:-daily}"
MDE_SCAN_HOUR="${MDE_SCAN_HOUR:-2}"
MDE_SCAN_DAY="${MDE_SCAN_DAY:-Sunday}"

EICAR_TEST_RESULT="Not run"
MANAGED_CONFIG="/etc/opt/microsoft/mdatp/managed/mdatp_managed.json"

PKG_MANAGER=""
SCAN_SCRIPT="/var/lib/hardening/mdatp-scan.sh"
SCAN_LOG="/var/log/microsoft/mdatp/scheduled-scan.log"

# --- Helpers ---

# Maps a day name to the mdatp --day integer (1=Sun … 7=Sat)
day_to_mdatp_int() {
    case "${1,,}" in
        sun|sunday)    echo 1 ;;
        mon|monday)    echo 2 ;;
        tue|tuesday)   echo 3 ;;
        wed|wednesday) echo 4 ;;
        thu|thursday)  echo 5 ;;
        fri|friday)    echo 6 ;;
        sat|saturday)  echo 7 ;;
        *) echo 1 ;;
    esac
}

# Maps a day name to the systemd OnCalendar abbreviation
day_to_systemd() {
    case "${1,,}" in
        sun|sunday)    echo "Sun" ;;
        mon|monday)    echo "Mon" ;;
        tue|tuesday)   echo "Tue" ;;
        wed|wednesday) echo "Wed" ;;
        thu|thursday)  echo "Thu" ;;
        fri|friday)    echo "Fri" ;;
        sat|saturday)  echo "Sat" ;;
        *) echo "Sun" ;;
    esac
}

# --- Environment detection ---
detect_package_manager() {
    if command_exists dnf; then
        PKG_MANAGER="dnf"
    elif command_exists yum; then
        PKG_MANAGER="yum"
    elif command_exists apt-get; then
        PKG_MANAGER="apt"
    else
        log_error "No supported package manager found (dnf, yum, apt-get)."
        exit 1
    fi
    log_info "Package manager : $PKG_MANAGER"
}

# --- Prompt: onboarding script ---
prompt_onboarding_script() {
    local default_path
    default_path="$(cd "$SCRIPT_DIR/../.." && pwd)/MDE/MicrosoftDefenderATPOnboardingLinuxServer.py"

    echo ""
    echo "  Microsoft Defender for Endpoint requires an onboarding script from"
    echo "  the GCC High Defender portal."
    echo ""
    echo "  ── How to obtain the script ────────────────────────────────────────"
    echo "  1. Sign in to https://security.microsoft.us"
    echo "  2. Go to Settings → Endpoints → Device management → Onboarding"
    echo "  3. Select 'Linux Server' and deployment method 'Local Script'"
    echo "  4. Download the zip and extract MicrosoftDefenderATPOnboardingLinuxServer.py"
    echo ""
    echo "  NOTE: Use the GCC High portal (security.microsoft.us), not the"
    echo "        commercial portal (security.microsoft.com). The onboarding"
    echo "        package from the GCCH portal contains the GCCH-specific"
    echo "        endpoint configuration baked into the JSON blob."
    echo ""
    echo "  ── Where to place the script ───────────────────────────────────────"
    echo "  Place the .py file at:"
    echo "    $default_path"
    echo ""
    echo "  Press Enter to use that path, or type a different absolute path."
    echo ""

    while true; do
        read -rp "  Onboarding script path [default: $default_path]: " MDE_ONBOARDING_SCRIPT
        MDE_ONBOARDING_SCRIPT="${MDE_ONBOARDING_SCRIPT:-$default_path}"
        if [[ ! -f "$MDE_ONBOARDING_SCRIPT" ]]; then
            echo "  File not found: $MDE_ONBOARDING_SCRIPT"
            echo "  Place the script at the path above and press Enter, or type a different path."
        else
            log_info "Onboarding script: $MDE_ONBOARDING_SCRIPT"
            break
        fi
    done
}

# --- Prompt: all settings ---
prompt_settings() {
    echo ""

    # ── Release Channel ─────────────────────────────────────────────────────
    echo "  ── Release Channel ─────────────────────────────────────────────────"
    echo "  Controls which MDE package repository is used."
    echo "  Network protection is ONLY supported on insiders-slow or insiders-fast."
    echo "  Production is stable/GA but network protection will not function."
    echo ""
    while true; do
        read -rp "  Release channel [production/insiders-slow/insiders-fast] (default: $MDE_RELEASE_CHANNEL): " ans
        ans="${ans:-$MDE_RELEASE_CHANNEL}"
        case "${ans,,}" in
            production|insiders-slow|insiders-fast) MDE_RELEASE_CHANNEL="${ans,,}"; break ;;
            *) echo "  Enter 'production', 'insiders-slow', or 'insiders-fast'." ;;
        esac
    done
    echo ""

    # Auto-suggest passive mode if ClamAV is running
    if systemctl is-active --quiet "clamd@scan" 2>/dev/null \
        || systemctl is-active --quiet "clamav-daemon" 2>/dev/null; then
        echo "  Note: ClamAV is active. Passive mode is recommended to prevent"
        echo "        two AV engines conflicting over fanotify hooks."
        echo "        In passive mode MDE provides EDR/telemetry; ClamAV handles AV."
        echo ""
        MDE_PASSIVE="enabled"
    fi

    # ── Protection ──────────────────────────────────────────────────────────
    echo "  ── Protection ──────────────────────────────────────────────────────"

    while true; do
        read -rp "  Real-time protection [enabled/disabled] (default: $MDE_REAL_TIME): " ans
        ans="${ans:-$MDE_REAL_TIME}"
        case "${ans,,}" in enabled|disabled) MDE_REAL_TIME="${ans,,}"; break ;; *) echo "  Enter 'enabled' or 'disabled'." ;; esac
    done

    while true; do
        read -rp "  Passive mode [enabled/disabled] (default: $MDE_PASSIVE): " ans
        ans="${ans:-$MDE_PASSIVE}"
        case "${ans,,}" in enabled|disabled) MDE_PASSIVE="${ans,,}"; break ;; *) echo "  Enter 'enabled' or 'disabled'." ;; esac
    done

    while true; do
        read -rp "  Cloud-delivered protection [enabled/disabled] (default: $MDE_CLOUD): " ans
        ans="${ans:-$MDE_CLOUD}"
        case "${ans,,}" in enabled|disabled) MDE_CLOUD="${ans,,}"; break ;; *) echo "  Enter 'enabled' or 'disabled'." ;; esac
    done

    while true; do
        read -rp "  PUA action [block/audit] (default: $MDE_PUA): " ans
        ans="${ans:-$MDE_PUA}"
        case "${ans,,}" in block|audit) MDE_PUA="${ans,,}"; break ;; *) echo "  Enter 'block' or 'audit'." ;; esac
    done

    while true; do
        read -rp "  Behavior monitoring [enabled/disabled] (default: $MDE_BEHAVIOR_MONITORING): " ans
        ans="${ans:-$MDE_BEHAVIOR_MONITORING}"
        case "${ans,,}" in enabled|disabled) MDE_BEHAVIOR_MONITORING="${ans,,}"; break ;; *) echo "  Enter 'enabled' or 'disabled'." ;; esac
    done

    while true; do
        read -rp "  Network protection [block/audit/disabled] (default: $MDE_NETWORK_PROTECTION): " ans
        ans="${ans:-$MDE_NETWORK_PROTECTION}"
        case "${ans,,}" in block|audit|disabled) MDE_NETWORK_PROTECTION="${ans,,}"; break ;; *) echo "  Enter 'block', 'audit', or 'disabled'." ;; esac
    done
    if [[ "$MDE_NETWORK_PROTECTION" != "disabled" && "$MDE_RELEASE_CHANNEL" == "production" ]]; then
        echo ""
        echo "  WARNING: Network protection requires insiders-slow or insiders-fast channel."
        echo "           It will not start on the production channel."
        echo "           Change the release channel above to enable network protection."
        echo ""
    fi

    while true; do
        read -rp "  Automatic sample submission [enabled/disabled] (default: $MDE_AUTO_SAMPLE): " ans
        ans="${ans:-$MDE_AUTO_SAMPLE}"
        case "${ans,,}" in enabled|disabled) MDE_AUTO_SAMPLE="${ans,,}"; break ;; *) echo "  Enter 'enabled' or 'disabled'." ;; esac
    done

    # ── Diagnostics ─────────────────────────────────────────────────────────
    echo ""
    echo "  ── Diagnostics ─────────────────────────────────────────────────────"

    while true; do
        read -rp "  Log level [debug/info/warning/error/critical/disabled] (default: $MDE_LOG_LEVEL): " ans
        ans="${ans:-$MDE_LOG_LEVEL}"
        case "${ans,,}" in debug|info|warning|error|critical|disabled) MDE_LOG_LEVEL="${ans,,}"; break ;; *) echo "  Enter a valid log level." ;; esac
    done

    while true; do
        read -rp "  Cloud diagnostic data [enabled/disabled] (default: $MDE_CLOUD_DIAGNOSTIC): " ans
        ans="${ans:-$MDE_CLOUD_DIAGNOSTIC}"
        case "${ans,,}" in enabled|disabled) MDE_CLOUD_DIAGNOSTIC="${ans,,}"; break ;; *) echo "  Enter 'enabled' or 'disabled'." ;; esac
    done

    # ── Exclusions ──────────────────────────────────────────────────────────
    echo ""
    echo "  ── Exclusions (press Enter to skip each) ───────────────────────────"

    read -rp "  Additional folders to exclude (space-separated paths): " ans
    [[ -n "$ans" ]] && MDE_EXCL_FOLDERS="$ans"

    read -rp "  File extensions to exclude (e.g. .log .tmp .bak): " ans
    [[ -n "$ans" ]] && MDE_EXCL_EXTENSIONS="$ans"

    read -rp "  Processes to exclude (space-separated names): " ans
    [[ -n "$ans" ]] && MDE_EXCL_PROCESSES="$ans"

    # ── Network ─────────────────────────────────────────────────────────────
    echo ""
    echo "  ── Network ─────────────────────────────────────────────────────────"

    read -rp "  Proxy server for MDE traffic (e.g. https://proxy:8080, Enter to skip): " ans
    [[ -n "$ans" ]] && MDE_PROXY="$ans"

    # ── Scheduling ──────────────────────────────────────────────────────────
    echo ""
    echo "  ── Scheduling ──────────────────────────────────────────────────────"

    while true; do
        read -rp "  Scheduled scan type [quick/full] (default: $MDE_SCAN_TYPE): " ans
        ans="${ans:-$MDE_SCAN_TYPE}"
        case "${ans,,}" in quick|full) MDE_SCAN_TYPE="${ans,,}"; break ;; *) echo "  Enter 'quick' or 'full'." ;; esac
    done

    while true; do
        read -rp "  Scan frequency [daily/weekly] (default: $MDE_SCAN_SCHEDULE): " ans
        ans="${ans:-$MDE_SCAN_SCHEDULE}"
        case "${ans,,}" in daily|weekly) MDE_SCAN_SCHEDULE="${ans,,}"; break ;; *) echo "  Enter 'daily' or 'weekly'." ;; esac
    done

    while true; do
        read -rp "  Scan hour (0-23, default: $MDE_SCAN_HOUR): " ans
        ans="${ans:-$MDE_SCAN_HOUR}"
        if [[ "$ans" =~ ^[0-9]+$ && "$ans" -ge 0 && "$ans" -le 23 ]]; then
            MDE_SCAN_HOUR="$ans"; break
        else
            echo "  Enter a number between 0 and 23."
        fi
    done

    if [[ "$MDE_SCAN_SCHEDULE" == "weekly" ]]; then
        while true; do
            read -rp "  Scan day [Monday-Sunday] (default: $MDE_SCAN_DAY): " ans
            ans="${ans:-$MDE_SCAN_DAY}"
            case "${ans,,}" in
                sun|sunday|mon|monday|tue|tuesday|wed|wednesday|thu|thursday|fri|friday|sat|saturday)
                    MDE_SCAN_DAY="$ans"; break ;;
                *) echo "  Enter a day name (e.g. Monday, Tuesday)." ;;
            esac
        done
    fi
}

# --- Preview ---
preview_configuration() {
    local scan_time_fmt
    scan_time_fmt=$(printf '%02d:00' "$MDE_SCAN_HOUR")

    echo ""
    log_info "MDE configuration preview:"
    echo ""
    echo "  Channel"
    echo "    Release channel      : $MDE_RELEASE_CHANNEL"
    if [[ "$MDE_NETWORK_PROTECTION" != "disabled" && "$MDE_RELEASE_CHANNEL" == "production" ]]; then
        echo "    WARNING              : network protection will not start on production channel"
    fi
    echo ""
    echo "  Onboarding"
    echo "    Script               : $MDE_ONBOARDING_SCRIPT"
    echo ""
    echo "  Protection"
    echo "    Real-time protection : $MDE_REAL_TIME"
    echo "    Passive mode         : $MDE_PASSIVE"
    echo "    Cloud protection     : $MDE_CLOUD"
    echo "    PUA action           : $MDE_PUA"
    echo "    Behavior monitoring  : $MDE_BEHAVIOR_MONITORING"
    echo "    Network protection   : $MDE_NETWORK_PROTECTION"
    echo "    Sample submission    : $MDE_AUTO_SAMPLE"
    echo ""
    echo "  Diagnostics"
    echo "    Log level            : $MDE_LOG_LEVEL"
    echo "    Cloud diagnostic     : $MDE_CLOUD_DIAGNOSTIC"
    echo ""
    echo "  Exclusions"
    echo "    Folders              : ${MDE_EXCL_FOLDERS:-(none)}"
    echo "    Extensions           : ${MDE_EXCL_EXTENSIONS:-(none)}"
    echo "    Processes            : ${MDE_EXCL_PROCESSES:-(none)}"
    echo ""
    echo "  Network"
    echo "    Proxy                : ${MDE_PROXY:-(none)}"
    echo ""
    echo "  Scheduling"
    echo "    Scan type            : $MDE_SCAN_TYPE"
    if [[ "$MDE_SCAN_SCHEDULE" == "weekly" ]]; then
        echo "    Schedule             : weekly — $MDE_SCAN_DAY at $scan_time_fmt"
    else
        echo "    Schedule             : daily at $scan_time_fmt"
    fi
    echo "    Scan log             : $SCAN_LOG"
    echo ""

    while true; do
        read -rp "  Apply this configuration? [Y/n]: " confirm
        confirm="${confirm:-y}"
        case "${confirm,,}" in
            y|yes) break ;;
            n|no)
                log_warn "MDE configuration not applied. Re-run to try again."
                exit 0
                ;;
            *) echo "  Enter y or n." ;;
        esac
    done
}

# --- Install MDE ---
install_mde() {
    log_info "Adding Microsoft package repository..."

    case "$PKG_MANAGER" in
        dnf|yum)
            local rhel_ver
            rhel_ver=$(rpm -E '%{rhel}' 2>/dev/null || echo "9")
            [[ "$rhel_ver" == '%{rhel}' ]] && rhel_ver="9"

            local repo_file
            case "$MDE_RELEASE_CHANNEL" in
                insiders-fast) repo_file="insiders-fast.repo" ;;
                insiders-slow) repo_file="insiders-slow.repo" ;;
                *)             repo_file="prod.repo" ;;
            esac
            local repo_url="https://packages.microsoft.com/config/rhel/${rhel_ver}/${repo_file}"
            log_info "Release channel : $MDE_RELEASE_CHANNEL"
            log_info "Repo URL        : $repo_url"
            "$PKG_MANAGER" install -y curl
            curl -sSL "$repo_url" -o /etc/yum.repos.d/microsoft-prod.repo
            "$PKG_MANAGER" install -y mdatp
            ;;
        apt)
            apt-get install -y curl gpg
            curl -sSL https://packages.microsoft.com/keys/microsoft.asc \
                | gpg --dearmor -o /usr/share/keyrings/microsoft.gpg
            local codename channel_list
            codename=$(lsb_release -cs 2>/dev/null || echo "focal")
            case "$MDE_RELEASE_CHANNEL" in
                insiders-fast) channel_list="insiders-fast.list" ;;
                insiders-slow) channel_list="insiders-slow.list" ;;
                *)             channel_list="prod.list" ;;
            esac
            curl -sSL "https://packages.microsoft.com/config/ubuntu/${codename}/${channel_list}" \
                -o /etc/apt/sources.list.d/microsoft-mdatp.list
            apt-get update -qq
            apt-get install -y mdatp
            ;;
    esac

    log_info "mdatp package installed."
}

# --- Onboard ---
onboard_mde() {
    log_info "Running MDE onboarding script..."

    if ! command_exists python3; then
        log_error "python3 is required to run the onboarding script."
        log_error "Install it and re-run: dnf install -y python3"
        exit 1
    fi

    python3 "$MDE_ONBOARDING_SCRIPT"

    sleep 5

    local org_id
    org_id=$(mdatp health --field org_id 2>/dev/null || echo "unavailable")
    if [[ "$org_id" == "unavailable" || -z "$org_id" ]]; then
        log_warn "org_id is not set — onboarding may not have completed."
        log_warn "Check: mdatp health  and  journalctl -u mdatp"
    else
        log_info "Onboarding successful. Organisation ID: $org_id"
    fi
}

# --- EICAR onboarding test ---
test_onboarding() {
    echo ""
    echo "  ── EICAR Onboarding Test ───────────────────────────────────────────"
    echo "  This test downloads the EICAR standard test file and checks that"
    echo "  MDE detects it and generates an alert in the GCCH portal."
    echo ""
    echo "  The test file is NOT malware — it is a harmless string used solely"
    echo "  to verify AV detection.  MDE may quarantine or delete it automatically."
    echo ""
    echo "  Portal : https://security.microsoft.us → Incidents & Alerts"
    echo ""

    while true; do
        read -rp "  Run EICAR onboarding test? [Y/n]: " ans
        ans="${ans:-y}"
        case "${ans,,}" in
            y|yes) break ;;
            n|no)
                log_info "EICAR test skipped."
                EICAR_TEST_RESULT="Skipped by operator"
                return
                ;;
            *) echo "  Enter y or n." ;;
        esac
    done

    local eicar_file="/tmp/eicar.com.txt"

    log_info "Downloading EICAR test file..."
    if ! curl -fsSL -o "$eicar_file" https://secure.eicar.org/eicar.com.txt; then
        log_warn "curl failed — check network connectivity to secure.eicar.org."
        EICAR_TEST_RESULT="FAILED — could not download test file"
        return
    fi

    if [[ -f "$eicar_file" ]]; then
        log_info "Test file written to $eicar_file."
    else
        log_info "Test file was immediately quarantined by MDE — detection confirmed."
        EICAR_TEST_RESULT="DETECTED — file quarantined immediately on write"
        return
    fi

    log_info "Waiting 15 seconds for MDE to detect and process the file..."
    sleep 15

    # Check mdatp threat list for detection
    local threat_output
    threat_output=$(mdatp threat list 2>/dev/null || echo "")

    if echo "$threat_output" | grep -qi "eicar\|test file\|virus"; then
        log_info "EICAR test file detected by MDE."
        EICAR_TEST_RESULT="DETECTED — alert visible in MDE portal (security.microsoft.us)"
    else
        log_warn "EICAR test file not found in threat list after 15 seconds."
        log_warn "MDE may still be processing. Check the portal manually."
        EICAR_TEST_RESULT="INCONCLUSIVE — not in threat list after 15s; verify in portal"
    fi

    # Clean up — MDE may have already removed the file
    if [[ -f "$eicar_file" ]]; then
        rm -f "$eicar_file"
        log_info "Test file removed."
    else
        log_info "Test file was already removed by MDE (expected)."
    fi

    log_info "EICAR test result: $EICAR_TEST_RESULT"
    echo ""
    echo "  Verify the alert in the GCCH portal:"
    echo "    https://security.microsoft.us → Incidents & Alerts"
    echo ""
}

# --- Apply MDE settings via managed config JSON ---
configure_mde() {
    log_info "Writing MDE managed configuration to $MANAGED_CONFIG ..."

    # Map RTP/passive to managed JSON enforcementLevel
    local enforcement_level
    if [[ "$MDE_PASSIVE" == "enabled" ]]; then
        enforcement_level="passive"
    elif [[ "$MDE_REAL_TIME" == "enabled" ]]; then
        enforcement_level="real_time"
    else
        enforcement_level="on_demand"
    fi

    # Map sample submission: enabled → safe, disabled → none
    local sample_consent
    [[ "$MDE_AUTO_SAMPLE" == "enabled" ]] && sample_consent="safe" || sample_consent="none"

    # Map cloud diagnostic: enabled → optional, disabled → required
    local diag_level
    [[ "$MDE_CLOUD_DIAGNOSTIC" == "enabled" ]] && diag_level="optional" || diag_level="required"

    local cloud_bool
    [[ "$MDE_CLOUD" == "enabled" ]] && cloud_bool="true" || cloud_bool="false"

    mkdir -p "$(dirname "$MANAGED_CONFIG")"
    cat > "$MANAGED_CONFIG" <<EOF
{
    "antivirusEngine": {
        "enforcementLevel": "${enforcement_level}",
        "behaviorMonitoring": "${MDE_BEHAVIOR_MONITORING}",
        "threatTypeSettings": [
            {
                "key": "potentially_unwanted_application",
                "value": "${MDE_PUA}"
            }
        ]
    },
    "cloudService": {
        "enabled": ${cloud_bool},
        "automaticSampleSubmissionConsent": "${sample_consent}",
        "automaticDefinitionUpdateEnabled": true,
        "diagnosticLevel": "${diag_level}"
    },
    "networkProtection": {
        "enforcementLevel": "${MDE_NETWORK_PROTECTION}"
    }
}
EOF

    if python3 -m json.tool "$MANAGED_CONFIG" > /dev/null 2>&1; then
        log_info "  Managed config JSON validated."
    else
        log_error "  Managed config JSON is invalid — check $MANAGED_CONFIG"
        exit 1
    fi

    # Settings not in managed JSON
    if [[ -n "$MDE_PROXY" ]]; then
        mdatp config proxy --value "$MDE_PROXY" 2>/dev/null \
            && log_info "  Proxy configured: $MDE_PROXY" \
            || log_warn "  Failed to set proxy — set manually: mdatp config proxy --value $MDE_PROXY"
    fi

    mdatp log level set --level "$MDE_LOG_LEVEL" 2>/dev/null \
        && log_info "  Log level set: $MDE_LOG_LEVEL" \
        || log_warn "  Failed to set log level."

    # Restart to apply managed config
    log_info "Restarting mdatp to apply managed configuration..."
    systemctl restart mdatp
    sleep 5

    # Standard path exclusions
    for excl in /proc /sys /dev /run; do
        mdatp exclusion folder add --path "$excl" 2>/dev/null || true
    done

    if [[ -n "$MDE_EXCL_FOLDERS" ]]; then
        for excl in $MDE_EXCL_FOLDERS; do
            mdatp exclusion folder add --path "$excl" 2>/dev/null || true
            log_info "  Folder exclusion added: $excl"
        done
    fi

    if [[ -n "$MDE_EXCL_EXTENSIONS" ]]; then
        for ext in $MDE_EXCL_EXTENSIONS; do
            ext="${ext#.}"
            mdatp exclusion extension add --extension "$ext" 2>/dev/null || true
            log_info "  Extension exclusion added: .$ext"
        done
    fi

    if [[ -n "$MDE_EXCL_PROCESSES" ]]; then
        for proc in $MDE_EXCL_PROCESSES; do
            mdatp exclusion process add --name "$proc" 2>/dev/null || true
            log_info "  Process exclusion added: $proc"
        done
    fi

    log_info "MDE configuration applied."
}

# --- Write scan script and systemd units ---
configure_scheduled_scan() {
    mkdir -p /var/lib/hardening

    local hour_fmt
    hour_fmt=$(printf '%02d' "$MDE_SCAN_HOUR")

    # Scan shell script — called by the systemd service for evidence logging
    cat > "$SCAN_SCRIPT" <<EOF
#!/usr/bin/env bash
# MDE scheduled scan script.
# Managed by hardening/modules/antivirus/mde.sh — do not edit manually.
set -euo pipefail
SCAN_LOG="${SCAN_LOG}"
SCAN_TYPE="${MDE_SCAN_TYPE}"
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
    chmod 750 "$SCAN_SCRIPT"
    log_info "Scan script written to $SCAN_SCRIPT."

    # Systemd OnCalendar value
    local on_calendar
    if [[ "$MDE_SCAN_SCHEDULE" == "weekly" ]]; then
        on_calendar="$(day_to_systemd "$MDE_SCAN_DAY") *-*-* ${hour_fmt}:00:00"
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
ExecStart=${SCAN_SCRIPT}
StandardOutput=journal
StandardError=journal
EOF

    cat > /etc/systemd/system/mdatp-scheduled-scan.timer <<EOF
[Unit]
Description=Microsoft Defender Scheduled Scan Timer (${MDE_SCAN_SCHEDULE} at ${hour_fmt}:00)

[Timer]
OnCalendar=${on_calendar}
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    log_info "Systemd scan units written ($MDE_SCAN_SCHEDULE at ${hour_fmt}:00)."
}

# --- Enable service and timer ---
enable_service() {
    if systemctl enable --now mdatp 2>/dev/null; then
        log_info "mdatp service enabled and started."
    else
        log_warn "Could not start mdatp — check: journalctl -u mdatp"
    fi

    systemctl enable --now mdatp-scheduled-scan.timer
    local hour_fmt
    hour_fmt=$(printf '%02d' "$MDE_SCAN_HOUR")
    log_info "Scan timer enabled — fires $MDE_SCAN_SCHEDULE at ${hour_fmt}:00."
}

# --- Artifact ---
save_artifact() {
    local artifact
    artifact=$(artifact_file "mde")

    local hour_fmt
    hour_fmt=$(printf '%02d' "$MDE_SCAN_HOUR")

    # Reads a health field; returns "unavailable" if mdatp rejects the name
    get_field() {
        local val
        val=$(mdatp health --field "$1" 2>/dev/null) || true
        if [[ -z "$val" || "$val" == *"Invalid argument"* ]]; then
            echo "unavailable"
        else
            echo "$val"
        fi
    }

    local agent_version org_id health_status edr_machine_id \
          rtp_status rtp_subsystem passive_status cloud_status \
          behavior_status network_status sample_status \
          log_level_status cloud_diag_status def_version def_status \
          def_updated timer_status

    agent_version=$(get_field app_version)
    org_id=$(get_field org_id)
    health_status=$(get_field healthy)
    edr_machine_id=$(get_field edr_machine_id)
    rtp_status=$(get_field real_time_protection_enabled)
    rtp_subsystem=$(get_field real_time_protection_subsystem)
    passive_status=$(get_field passive_mode_enabled)
    cloud_status=$(get_field cloud_enabled)
    behavior_status=$(get_field behavior_monitoring)
    network_status=$(get_field network_protection_status)
    sample_status=$(get_field cloud_automatic_sample_submission_consent)
    log_level_status=$(get_field log_level)
    cloud_diag_status=$(get_field cloud_diagnostic_enabled)
    def_version=$(get_field definitions_version)
    def_status=$(get_field definitions_status)
    def_updated=$(get_field definitions_updated)

    if systemctl is-active --quiet mdatp-scheduled-scan.timer 2>/dev/null; then
        timer_status="Active"
    else
        timer_status="Inactive"
    fi

    local schedule_desc
    if [[ "$MDE_SCAN_SCHEDULE" == "weekly" ]]; then
        schedule_desc="Weekly — $MDE_SCAN_DAY at ${hour_fmt}:00"
    else
        schedule_desc="Daily at ${hour_fmt}:00"
    fi

    cat > "$artifact" <<EOF
MICROSOFT DEFENDER FOR ENDPOINT — GCCH CONFIGURATION REPORT
=============================================================
Generated  : $(date '+%Y-%m-%d %H:%M:%S')
Hostname   : $(hostname)
OS         : $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
Applied by : hardening/modules/antivirus/mde.sh
Config     : $MANAGED_CONFIG
Environment: GCC High (GCCH)

NOTE: Rocky Linux is not officially supported by Microsoft.
      The RHEL 9 package repository is used. Document RHEL equivalence
      for compliance audits if required.

RELEASE CHANNEL
---------------
  Channel             : $MDE_RELEASE_CHANNEL
  Note: Network protection requires insiders-slow or insiders-fast channel.
        It will not start on the production channel.

GCC HIGH ENVIRONMENT
--------------------
  Portal              : https://security.microsoft.us
  EDR machine ID      : $edr_machine_id
  Required endpoints  :
    winatp-gw-usgovvirginia.microsoft.com  (MDE GCCH primary)
    winatp-gw-usgovarizona.microsoft.com   (MDE GCCH secondary)
    *.blob.core.usgovcloudapi.net          (signature/engine updates)
    unitedstates.dp.microsoft.com          (diagnostic data pipeline)
    crl.microsoft.com                      (certificate revocation)
    ctldl.windowsupdate.com               (certificate trust list)

AGENT STATUS
------------
  App version          : $agent_version
  Organisation ID      : $org_id
  Agent healthy        : $health_status

PROTECTION  (applied via mdatp config)
---------------------------------------
  Real-time protection : $rtp_status
  RTP subsystem        : $rtp_subsystem
  Passive mode         : $passive_status
  Cloud protection     : $cloud_status
  Behavior monitoring  : $behavior_status (configured: $MDE_BEHAVIOR_MONITORING)
  Network protection   : $network_status (enforcement-level: $MDE_NETWORK_PROTECTION)
  Sample submission    : $sample_status

DIAGNOSTICS
-----------
  Log level            : $log_level_status
  Cloud diagnostic     : $cloud_diag_status

DEFINITIONS
-----------
  Version              : $def_version
  Status               : $def_status
  Last updated         : $def_updated

EXCLUSIONS
----------
  Standard paths       : /proc /sys /dev /run
  Additional folders   : ${MDE_EXCL_FOLDERS:-(none)}
  Extensions           : ${MDE_EXCL_EXTENSIONS:-(none)}
  Processes            : ${MDE_EXCL_PROCESSES:-(none)}

NETWORK
-------
  Proxy                : ${MDE_PROXY:-(none)}

SCHEDULED SCANNING
------------------
  Scan type            : $MDE_SCAN_TYPE
  Schedule             : $schedule_desc
  Systemd timer        : mdatp-scheduled-scan.timer ($timer_status)
  Scan script          : $SCAN_SCRIPT
  Scan log             : $SCAN_LOG

ONBOARDING TEST (EICAR)
-----------------------
  Result               : $EICAR_TEST_RESULT
  Test file URL        : https://secure.eicar.org/eicar.com.txt
  Portal alert check   : https://security.microsoft.us → Incidents & Alerts
  Note: A "DETECTED" result confirms MDE is active and reporting to the
        GCCH portal. An "INCONCLUSIVE" result may mean MDE is still
        initialising — re-run: curl -o /tmp/eicar.com.txt https://secure.eicar.org/eicar.com.txt

EVIDENCE OF ROUTINE SCANNING
------------------------------
  Each scheduled scan appends a timestamped entry to:
    $SCAN_LOG
  View the last scan result:
    tail -50 $SCAN_LOG
  View all timer executions:
    journalctl -u mdatp-scheduled-scan.service
  View MDE threat history:
    mdatp threat list
EOF

    log_info "Artifact saved: $artifact"
}

# --- Main ---
log_section "Antivirus — Microsoft Defender for Endpoint (GCC High)"

detect_package_manager
prompt_onboarding_script
prompt_settings
preview_configuration

echo ""
install_mde
onboard_mde
test_onboarding
configure_mde
configure_scheduled_scan
enable_service
save_artifact

log_info "MDE module complete."
