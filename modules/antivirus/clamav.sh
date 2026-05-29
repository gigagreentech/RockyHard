#!/usr/bin/env bash
# =============================================================================
# Module  : antivirus / clamav
# Purpose : Install and configure ClamAV antivirus with hardened settings,
#           automatic definition updates, and a scheduled scan timer that
#           produces timestamped evidence logs of routine scanning activity.
#
# This module performs the following actions in order:
#
#   1. ENVIRONMENT DETECTION
#      Detects the package manager (dnf/yum/apt) and derives the correct
#      clamd config path and service name for this distro:
#        RHEL/Rocky : /etc/clamd.d/scan.conf  — service clamd@scan
#        Debian/Ubuntu : /etc/clamav/clamd.conf — service clamav-daemon
#
#   2. SETTINGS SELECTION (interactive)
#      The operator configures:
#        - On-access real-time scanning (yes/no; default no — performance impact)
#        - Scan schedule (daily/weekly)
#        - Paths to scan (space-separated; default: /home /tmp /var/tmp)
#        - Maximum file size to scan in MB (default: 100)
#        - Detect potentially unwanted applications (yes/no; default: yes)
#        - Definition update frequency — checks per day (default: 24)
#        - Alerting methods — a numbered menu where the operator selects one or
#          more methods (or none).  Each selected method is then configured
#          interactively before the preview is shown:
#            1) Email          — threat notification sent via mail/mailx
#            2) Syslog         — detection logged via logger (security.alert)
#            3) Slack webhook  — message posted to an Incoming Webhook URL
#            4) Custom command — arbitrary command; %v=threat name, %f=file path
#            5) None           — all alerting disabled
#
#   3. CONFIGURATION PREVIEW
#      All selected settings are shown before any changes are made.
#
#   4. PACKAGE INSTALLATION
#      Installs clamav, clamd/clamav-daemon, and clamav-update/clamav-freshclam
#      using the detected package manager.
#
#   5. CLAMD CONFIGURATION  (scan.conf)
#      Writes a hardened clamd config from scratch covering:
#        - Unix socket (no TCP exposure)
#        - Scan engine settings (archives, PDF, ELF, HTML, mail, OLE2)
#        - Size/recursion limits to prevent zip-bomb DoS
#        - ExcludePath rules for /proc /sys /dev /run
#        - On-access settings if enabled
#        - Structured logging to /var/log/clamav/clamd.log
#
#   6. FRESHCLAM CONFIGURATION  (/etc/freshclam.conf)
#      Writes freshclam config with the operator's update frequency,
#      log rotation, and NotifyClamd to hot-reload definitions without
#      restarting the daemon.
#
#   7. INITIAL DEFINITION UPDATE
#      Runs freshclam to download the current virus database before
#      starting the daemon for the first time.
#
#   8. SCHEDULED SCAN  (/etc/systemd/system/)
#      Writes a scan shell script to /var/lib/hardening/clamav-scan.sh
#      containing the operator's chosen paths and logging to
#      /var/log/clamav/scheduled-scan.log.
#      Creates a pair of systemd units (service + timer) so scans run
#      automatically at the chosen frequency and results are recorded
#      in the system journal as well as the log file.
#
#   9. SERVICE ENABLEMENT
#      Enables and starts clamd (or clamav-daemon) and the freshclam
#      update service.  Enables the scan timer.
#
#  10. ARTIFACT
#      Writes a timestamped report to artifacts/clamav/ recording the
#      installed version, database version, all configuration settings,
#      and the scheduled scan path.  The scan log at
#      /var/log/clamav/scheduled-scan.log accumulates evidence of each
#      subsequent routine scan.
#
# Files written:
#   /etc/clamd.d/scan.conf  or  /etc/clamav/clamd.conf
#   /etc/freshclam.conf
#   /var/lib/hardening/clamav-scan.sh
#   /etc/systemd/system/clamav-scheduled-scan.service
#   /etc/systemd/system/clamav-scheduled-scan.timer
#
# Must be run as root.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../config.conf"
source "$SCRIPT_DIR/../../lib/common.sh"

# Settings — populated by prompts, with config.conf values as defaults
CLAMAV_ON_ACCESS="${CLAMAV_ON_ACCESS:-no}"
CLAMAV_ON_ACCESS_PATHS="${CLAMAV_ON_ACCESS_PATHS:-/home /tmp}"
CLAMAV_SCAN_SCHEDULE="${CLAMAV_SCAN_SCHEDULE:-daily}"
CLAMAV_SCAN_HOUR="${CLAMAV_SCAN_HOUR:-2}"
CLAMAV_SCAN_DAY="${CLAMAV_SCAN_DAY:-Sunday}"
CLAMAV_SCAN_PATHS="${CLAMAV_SCAN_PATHS:-/home /tmp /var/tmp}"
CLAMAV_MAX_FILE_SIZE="${CLAMAV_MAX_FILE_SIZE:-100}"
CLAMAV_MAX_RECURSION="${CLAMAV_MAX_RECURSION:-10}"
CLAMAV_SCAN_ARCHIVES="${CLAMAV_SCAN_ARCHIVES:-yes}"
CLAMAV_DETECT_PUA="${CLAMAV_DETECT_PUA:-yes}"
CLAMAV_ALERT_BROKEN="${CLAMAV_ALERT_BROKEN:-yes}"
CLAMAV_QUARANTINE_DIR="${CLAMAV_QUARANTINE_DIR:-}"
CLAMAV_LOG_VERBOSE="${CLAMAV_LOG_VERBOSE:-no}"
CLAMAV_DEF_UPDATES="${CLAMAV_DEF_UPDATES:-24}"

# Alerting
CLAMAV_ALERT_EMAIL="${CLAMAV_ALERT_EMAIL:-}"           # email address — leave empty to disable
CLAMAV_ALERT_SYSLOG="${CLAMAV_ALERT_SYSLOG:-yes}"      # log detections via logger to syslog
CLAMAV_ALERT_SLACK="${CLAMAV_ALERT_SLACK:-}"           # Slack incoming webhook URL — leave empty to disable
CLAMAV_ALERT_CUSTOM="${CLAMAV_ALERT_CUSTOM:-}"         # custom command; %v=virus name, %f=file path

# Derived — set by detect_environment
PKG_MANAGER=""
CLAMD_CONF=""
CLAMD_SERVICE=""
FRESHCLAM_CONF=""
ALERT_SCRIPT="/var/lib/hardening/clamav-alert.sh"
SCAN_SCRIPT="/var/lib/hardening/clamav-scan.sh"
SCAN_LOG="/var/log/clamav/scheduled-scan.log"

# --- Environment detection ---
detect_environment() {
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

    if [[ "$PKG_MANAGER" == "apt" ]]; then
        CLAMD_CONF="/etc/clamav/clamd.conf"
        CLAMD_SERVICE="clamav-daemon"
        FRESHCLAM_CONF="/etc/clamav/freshclam.conf"
    else
        CLAMD_CONF="/etc/clamd.d/scan.conf"
        CLAMD_SERVICE="clamd@scan"
        FRESHCLAM_CONF="/etc/freshclam.conf"
    fi

    log_info "Package manager : $PKG_MANAGER"
    log_info "clamd config    : $CLAMD_CONF"
    log_info "clamd service   : $CLAMD_SERVICE"
}

# --- Interactive prompts ---
prompt_settings() {
    echo ""
    echo "  Configure ClamAV settings (press Enter to accept the default):"
    echo ""

    # ── On-access scanning ───────────────────────────────────────────────────
    echo "  ── Real-time Protection ────────────────────────────────────────────"
    while true; do
        read -rp "  Enable on-access real-time scanning? [y/N] (default: N — performance impact): " ans
        ans="${ans:-n}"
        case "${ans,,}" in
            y|yes) CLAMAV_ON_ACCESS="yes"; break ;;
            n|no)  CLAMAV_ON_ACCESS="no";  break ;;
            *) echo "  Enter y or n." ;;
        esac
    done

    if [[ "$CLAMAV_ON_ACCESS" == "yes" ]]; then
        read -rp "  On-access paths to monitor (space-separated, default: $CLAMAV_ON_ACCESS_PATHS): " ans
        [[ -n "$ans" ]] && CLAMAV_ON_ACCESS_PATHS="$ans"
    fi

    # ── Scheduled scan ───────────────────────────────────────────────────────
    echo ""
    echo "  ── Scheduled Scan ──────────────────────────────────────────────────"
    while true; do
        read -rp "  Frequency [daily/weekly] (default: $CLAMAV_SCAN_SCHEDULE): " ans
        ans="${ans:-$CLAMAV_SCAN_SCHEDULE}"
        case "${ans,,}" in
            daily|weekly) CLAMAV_SCAN_SCHEDULE="${ans,,}"; break ;;
            *) echo "  Enter 'daily' or 'weekly'." ;;
        esac
    done

    while true; do
        read -rp "  Scan hour (0-23, default: $CLAMAV_SCAN_HOUR): " ans
        ans="${ans:-$CLAMAV_SCAN_HOUR}"
        if [[ "$ans" =~ ^[0-9]+$ && "$ans" -ge 0 && "$ans" -le 23 ]]; then
            CLAMAV_SCAN_HOUR="$ans"; break
        else
            echo "  Enter a number between 0 and 23."
        fi
    done

    if [[ "$CLAMAV_SCAN_SCHEDULE" == "weekly" ]]; then
        while true; do
            read -rp "  Scan day [Monday-Sunday] (default: $CLAMAV_SCAN_DAY): " ans
            ans="${ans:-$CLAMAV_SCAN_DAY}"
            case "${ans,,}" in
                sun|sunday|mon|monday|tue|tuesday|wed|wednesday|thu|thursday|fri|friday|sat|saturday)
                    CLAMAV_SCAN_DAY="$ans"; break ;;
                *) echo "  Enter a day name (e.g. Monday, Sunday)." ;;
            esac
        done
    fi

    read -rp "  Paths to scan (space-separated, default: $CLAMAV_SCAN_PATHS): " ans
    [[ -n "$ans" ]] && CLAMAV_SCAN_PATHS="$ans"

    # ── Scan engine ──────────────────────────────────────────────────────────
    echo ""
    echo "  ── Scan Engine ─────────────────────────────────────────────────────"
    while true; do
        read -rp "  Max file size to scan in MB (default: $CLAMAV_MAX_FILE_SIZE): " ans
        ans="${ans:-$CLAMAV_MAX_FILE_SIZE}"
        if [[ "$ans" =~ ^[0-9]+$ && "$ans" -gt 0 ]]; then
            CLAMAV_MAX_FILE_SIZE="$ans"; break
        else
            echo "  Enter a positive integer."
        fi
    done

    while true; do
        read -rp "  Max archive recursion depth (default: $CLAMAV_MAX_RECURSION): " ans
        ans="${ans:-$CLAMAV_MAX_RECURSION}"
        if [[ "$ans" =~ ^[0-9]+$ && "$ans" -gt 0 && "$ans" -le 30 ]]; then
            CLAMAV_MAX_RECURSION="$ans"; break
        else
            echo "  Enter a number between 1 and 30."
        fi
    done

    while true; do
        read -rp "  Scan inside archives (zip, tar, etc.)? [Y/n] (default: Y): " ans
        ans="${ans:-y}"
        case "${ans,,}" in
            y|yes) CLAMAV_SCAN_ARCHIVES="yes"; break ;;
            n|no)  CLAMAV_SCAN_ARCHIVES="no";  break ;;
            *) echo "  Enter y or n." ;;
        esac
    done

    while true; do
        read -rp "  Detect potentially unwanted applications (PUA)? [Y/n] (default: Y): " ans
        ans="${ans:-y}"
        case "${ans,,}" in
            y|yes) CLAMAV_DETECT_PUA="yes"; break ;;
            n|no)  CLAMAV_DETECT_PUA="no";  break ;;
            *) echo "  Enter y or n." ;;
        esac
    done

    while true; do
        read -rp "  Alert on broken/malformed executables? [Y/n] (default: Y): " ans
        ans="${ans:-y}"
        case "${ans,,}" in
            y|yes) CLAMAV_ALERT_BROKEN="yes"; break ;;
            n|no)  CLAMAV_ALERT_BROKEN="no";  break ;;
            *) echo "  Enter y or n." ;;
        esac
    done

    # ── Quarantine ───────────────────────────────────────────────────────────
    echo ""
    echo "  ── Quarantine ──────────────────────────────────────────────────────"
    read -rp "  Quarantine directory for infected files (Enter to disable, e.g. /var/quarantine): " ans
    [[ -n "$ans" ]] && CLAMAV_QUARANTINE_DIR="$ans"

    # ── Logging ──────────────────────────────────────────────────────────────
    echo ""
    echo "  ── Logging & Updates ───────────────────────────────────────────────"
    while true; do
        read -rp "  Enable verbose clamd logging? [y/N] (default: N): " ans
        ans="${ans:-n}"
        case "${ans,,}" in
            y|yes) CLAMAV_LOG_VERBOSE="yes"; break ;;
            n|no)  CLAMAV_LOG_VERBOSE="no";  break ;;
            *) echo "  Enter y or n." ;;
        esac
    done

    while true; do
        read -rp "  Definition update checks per day (1-24, default: $CLAMAV_DEF_UPDATES): " ans
        ans="${ans:-$CLAMAV_DEF_UPDATES}"
        if [[ "$ans" =~ ^[0-9]+$ && "$ans" -gt 0 && "$ans" -le 24 ]]; then
            CLAMAV_DEF_UPDATES="$ans"; break
        else
            echo "  Enter a number between 1 and 24."
        fi
    done

    prompt_alerting
}

# --- Alerting wizard ---
prompt_alerting() {
    echo ""
    echo "  ── Alerting ────────────────────────────────────────────────────────"
    echo "  Alerts fire on detection by both the real-time daemon (VirusEvent)"
    echo "  and the scheduled scan script."
    echo ""
    echo "  Available alerting methods:"
    echo "    1) Email          — threat notification sent via mail/mailx"
    echo "    2) Syslog         — detection logged via logger (security.alert)"
    echo "    3) Slack webhook  — message posted to an Incoming Webhook URL"
    echo "    4) Custom command — arbitrary command; %v=threat name, %f=file path"
    echo "    5) None           — disable all alerting"
    echo ""
    echo "  Select one or more methods, comma-separated (e.g. 1,2 or 5 for none)."

    # Reset all alerting to disabled before collecting choices
    CLAMAV_ALERT_EMAIL=""
    CLAMAV_ALERT_SYSLOG="no"
    CLAMAV_ALERT_SLACK=""
    CLAMAV_ALERT_CUSTOM=""

    local selections
    while true; do
        read -rp "  Alerting methods [default: 2]: " selections
        selections="${selections:-2}"
        # Strip spaces; allow digits 1-5 and commas only
        selections="${selections// /}"
        if ! [[ "$selections" =~ ^[1-5,]+$ ]]; then
            echo "  Enter numbers 1-5 separated by commas (e.g. 1,2)."
            continue
        fi
        # Disallow mixing None (5) with other choices
        if [[ "$selections" =~ 5 ]] && [[ "$selections" =~ [1-4] ]]; then
            echo "  Cannot combine 'None' (5) with other methods. Enter 5 alone or choose 1-4."
            continue
        fi
        break
    done

    if [[ "$selections" =~ 5 ]]; then
        log_info "No alerting configured."
        return
    fi

    [[ "$selections" =~ 1 ]] && _prompt_alert_email
    [[ "$selections" =~ 2 ]] && _prompt_alert_syslog
    [[ "$selections" =~ 3 ]] && _prompt_alert_slack
    [[ "$selections" =~ 4 ]] && _prompt_alert_custom
}

_prompt_alert_email() {
    echo ""
    echo "  ── Email Alert ─────────────────────────────────────────────────────"
    while true; do
        read -rp "  Recipient email address: " ans
        if [[ -n "$ans" ]]; then
            CLAMAV_ALERT_EMAIL="$ans"
            break
        else
            echo "  An email address is required."
        fi
    done
    if ! command -v mail &>/dev/null && ! command -v mailx &>/dev/null; then
        echo "  Note: 'mail'/'mailx' not found. Install mailx and configure an MTA"
        echo "        (e.g. postfix) for email alerts to work."
    fi
    log_info "Email alerting configured: $CLAMAV_ALERT_EMAIL"
}

_prompt_alert_syslog() {
    echo ""
    echo "  ── Syslog Alert ────────────────────────────────────────────────────"
    echo "  Detections will be logged via 'logger' with tag 'clamav-alert'"
    echo "  and priority security.alert."
    CLAMAV_ALERT_SYSLOG="yes"
    log_info "Syslog alerting enabled."
}

_prompt_alert_slack() {
    echo ""
    echo "  ── Slack Webhook Alert ─────────────────────────────────────────────"
    echo "  Paste your Slack Incoming Webhook URL."
    echo "  Format: https://hooks.slack.com/services/T.../B.../..."
    while true; do
        read -rp "  Slack webhook URL: " ans
        if [[ "$ans" =~ ^https:// ]]; then
            CLAMAV_ALERT_SLACK="$ans"
            break
        else
            echo "  Enter a valid HTTPS URL."
        fi
    done
    log_info "Slack alerting configured."
}

_prompt_alert_custom() {
    echo ""
    echo "  ── Custom Command Alert ────────────────────────────────────────────"
    echo "  Enter a shell command to run on detection."
    echo "  Substitution tokens:"
    echo "    %v  — threat/virus name"
    echo "    %f  — path of the infected file"
    echo "  Examples:"
    echo "    /opt/scripts/notify.sh '%v' '%f'"
    echo "    curl -s -X POST https://example.com/alert -d \"threat=%v&file=%f\""
    while true; do
        read -rp "  Custom command: " ans
        if [[ -n "$ans" ]]; then
            CLAMAV_ALERT_CUSTOM="$ans"
            break
        else
            echo "  A command is required."
        fi
    done
    log_info "Custom alerting configured."
}

# --- Preview ---
preview_configuration() {
    echo ""
    log_info "ClamAV configuration preview:"
    echo ""
    local hour_fmt scan_time_desc
    hour_fmt=$(printf '%02d' "$CLAMAV_SCAN_HOUR")
    if [[ "$CLAMAV_SCAN_SCHEDULE" == "weekly" ]]; then
        scan_time_desc="weekly — $CLAMAV_SCAN_DAY at ${hour_fmt}:00"
    else
        scan_time_desc="daily at ${hour_fmt}:00"
    fi

    echo "    Package manager      : $PKG_MANAGER"
    echo "    Config file          : $CLAMD_CONF"
    echo ""
    echo "    Real-time Protection"
    echo "    On-access scanning   : $CLAMAV_ON_ACCESS"
    [[ "$CLAMAV_ON_ACCESS" == "yes" ]] && \
    echo "    On-access paths      : $CLAMAV_ON_ACCESS_PATHS"
    echo ""
    echo "    Scheduled Scan"
    echo "    Schedule             : $scan_time_desc"
    echo "    Scan paths           : $CLAMAV_SCAN_PATHS"
    echo "    Scan log             : $SCAN_LOG"
    echo ""
    echo "    Scan Engine"
    echo "    Max file size        : ${CLAMAV_MAX_FILE_SIZE}M"
    echo "    Max recursion depth  : $CLAMAV_MAX_RECURSION"
    echo "    Scan archives        : $CLAMAV_SCAN_ARCHIVES"
    echo "    Detect PUA           : $CLAMAV_DETECT_PUA"
    echo "    Alert broken exec    : $CLAMAV_ALERT_BROKEN"
    echo ""
    echo "    Quarantine"
    echo "    Quarantine dir       : ${CLAMAV_QUARANTINE_DIR:-(disabled)}"
    echo ""
    echo "    Logging & Updates"
    echo "    Verbose logging      : $CLAMAV_LOG_VERBOSE"
    echo "    Definition updates   : $CLAMAV_DEF_UPDATES check(s) per day"
    echo ""
    echo "    Alerting"
    echo "    Alert email          : ${CLAMAV_ALERT_EMAIL:-(disabled)}"
    echo "    Syslog alerts        : $CLAMAV_ALERT_SYSLOG"
    echo "    Slack webhook        : ${CLAMAV_ALERT_SLACK:-(disabled)}"
    echo "    Custom command       : ${CLAMAV_ALERT_CUSTOM:-(none)}"
    echo ""
    while true; do
        read -rp "  Apply this configuration? [Y/n]: " confirm
        confirm="${confirm:-y}"
        case "${confirm,,}" in
            y|yes) break ;;
            n|no)
                log_warn "ClamAV configuration not applied. Re-run to try again."
                exit 0
                ;;
            *) echo "  Enter y or n." ;;
        esac
    done
}

# --- Install packages ---
install_clamav() {
    log_info "Installing ClamAV packages..."
    case "$PKG_MANAGER" in
        dnf|yum)
            # ClamAV is in EPEL on RHEL/Rocky — ensure it is enabled first
            if ! "$PKG_MANAGER" repolist enabled 2>/dev/null | grep -qi "epel"; then
                log_info "EPEL repository not found — installing epel-release..."
                "$PKG_MANAGER" install -y epel-release
                "$PKG_MANAGER" makecache -q
            fi
            "$PKG_MANAGER" install -y clamav clamd clamav-update
            ;;
        apt)
            apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y clamav clamav-daemon clamav-freshclam
            ;;
    esac
    log_info "ClamAV packages installed."
}

# --- Write clamd config ---
configure_clamd() {
    mkdir -p "$(dirname "$CLAMD_CONF")"
    backup_file "$CLAMD_CONF"

    local pua_val archives_val alert_broken_val verbose_val
    [[ "$CLAMAV_DETECT_PUA"    == "yes" ]] && pua_val="yes"          || pua_val="no"
    [[ "$CLAMAV_SCAN_ARCHIVES" == "yes" ]] && archives_val="yes"     || archives_val="no"
    [[ "$CLAMAV_ALERT_BROKEN"  == "yes" ]] && alert_broken_val="yes" || alert_broken_val="no"
    [[ "$CLAMAV_LOG_VERBOSE"   == "yes" ]] && verbose_val="yes"      || verbose_val="no"

    # Build on-access block
    local on_access_block=""
    if [[ "$CLAMAV_ON_ACCESS" == "yes" ]]; then
        on_access_block=$'\n# On-access real-time scanning\nScanOnAccess yes\n'
        for oa_path in $CLAMAV_ON_ACCESS_PATHS; do
            on_access_block+="OnAccessMountPath ${oa_path}"$'\n'
        done
        on_access_block+="OnAccessPrevention yes
OnAccessExcludeUname clamav
OnAccessExcludeUname clamscan
OnAccessExtraScanning yes"
    fi

    # Build quarantine block
    local quarantine_block=""
    if [[ -n "$CLAMAV_QUARANTINE_DIR" ]]; then
        mkdir -p "$CLAMAV_QUARANTINE_DIR"
        chmod 700 "$CLAMAV_QUARANTINE_DIR"
        quarantine_block=$'\n# Quarantine infected files\n'
        quarantine_block+="VirusEvent /bin/mv '%v' ${CLAMAV_QUARANTINE_DIR}/"
    fi

    cat > "$CLAMD_CONF" <<EOF
# Managed by hardening/modules/antivirus/clamav.sh — do not edit manually.

# --- Socket & process ---
LocalSocket /run/clamd.scan/clamd.sock
FixStaleSocket yes
LocalSocketMode 666
User clamscan

# --- Logging ---
LogFile /var/log/clamav/clamd.log
LogSyslog yes
LogRotate yes
LogTime yes
LogVerbose ${verbose_val}

# --- Database ---
DatabaseDirectory /var/lib/clamav

# --- Scan engine ---
ScanPE yes
ScanELF yes
ScanArchives ${archives_val}
ScanHTML yes
ScanMail yes
ScanOLE2 yes
ScanPDF yes
ScanSWF yes
ScanXMLDOCS yes
DetectPUA ${pua_val}
AlertBrokenExecutables ${alert_broken_val}

# --- Size and recursion limits (prevent zip-bomb DoS) ---
MaxScanSize $(( CLAMAV_MAX_FILE_SIZE * 4 ))M
MaxFileSize ${CLAMAV_MAX_FILE_SIZE}M
MaxRecursion ${CLAMAV_MAX_RECURSION}
MaxFiles 15000
MaxEmbeddedPE 10M
MaxHTMLNormalize 10M

# --- Exclusions ---
ExcludePath ^/proc
ExcludePath ^/sys
ExcludePath ^/dev
ExcludePath ^/run
${on_access_block}
${quarantine_block}
EOF

    # RHEL/Rocky requires the log directory to exist and be owned by clamscan
    mkdir -p /var/log/clamav
    if id clamscan &>/dev/null; then
        chown clamscan:clamscan /var/log/clamav
    fi

    log_info "clamd configuration written to $CLAMD_CONF."
}

# --- Write freshclam config ---
configure_freshclam() {
    backup_file "$FRESHCLAM_CONF"

    cat > "$FRESHCLAM_CONF" <<EOF
# Managed by hardening/modules/antivirus/clamav.sh — do not edit manually.

DatabaseDirectory /var/lib/clamav
UpdateLogFile /var/log/clamav/freshclam.log
LogSyslog yes
LogRotate yes
LogTime yes
DatabaseMirror database.clamav.net
Checks ${CLAMAV_DEF_UPDATES}
NotifyClamd ${CLAMD_CONF}
EOF

    log_info "freshclam configuration written to $FRESHCLAM_CONF."
}

# --- Write alert script and wire VirusEvent ---
configure_alerting() {
    if [[ -z "$CLAMAV_ALERT_EMAIL" && "$CLAMAV_ALERT_SYSLOG" != "yes" && \
          -z "$CLAMAV_ALERT_SLACK" && -z "$CLAMAV_ALERT_CUSTOM" ]]; then
        log_info "No alerting configured — skipping alert script."
        return
    fi

    mkdir -p /var/lib/hardening

    # Build the alert script — called by VirusEvent (daemon) and scan script (scheduled)
    # When called by VirusEvent, clamd sets:
    #   $CLAM_VIRUSEVENT_VIRUSNAME  — name of the detected threat
    #   $CLAM_VIRUSEVENT_FILENAME   — path to the infected file
    # When called from the scan script, these are passed as $1 and $2.
    cat > "$ALERT_SCRIPT" <<'ALERTEOF'
#!/usr/bin/env bash
# ClamAV alert script — managed by hardening/modules/antivirus/clamav.sh
set -euo pipefail

VIRUS_NAME="${CLAM_VIRUSEVENT_VIRUSNAME:-${1:-unknown}}"
FILE_PATH="${CLAM_VIRUSEVENT_FILENAME:-${2:-unknown}}"
HOSTNAME=$(hostname)
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
SUBJECT="[ClamAV] Threat detected on ${HOSTNAME}"
BODY="ClamAV threat detection alert

Hostname  : ${HOSTNAME}
Timestamp : ${TIMESTAMP}
Threat    : ${VIRUS_NAME}
File      : ${FILE_PATH}

Review the scan log for full details."

ALERTEOF

    # Append email block if configured
    if [[ -n "$CLAMAV_ALERT_EMAIL" ]]; then
        cat >> "$ALERT_SCRIPT" <<EOF
# Email alert
MAIL_CMD=""
command -v mailx &>/dev/null && MAIL_CMD="mailx"
command -v mail  &>/dev/null && MAIL_CMD="mail"
if [[ -n "\$MAIL_CMD" ]]; then
    echo "\$BODY" | "\$MAIL_CMD" -s "\$SUBJECT" "${CLAMAV_ALERT_EMAIL}" || true
else
    logger -t clamav-alert "mail command not available — email alert skipped"
fi
EOF
    fi

    # Append syslog block if configured
    if [[ "$CLAMAV_ALERT_SYSLOG" == "yes" ]]; then
        cat >> "$ALERT_SCRIPT" <<'EOF'

# Syslog alert
logger -t clamav-alert -p security.alert "THREAT DETECTED: ${VIRUS_NAME} in ${FILE_PATH}"
EOF
    fi

    # Append Slack webhook block if configured
    if [[ -n "$CLAMAV_ALERT_SLACK" ]]; then
        cat >> "$ALERT_SCRIPT" <<EOF

# Slack webhook alert
SLACK_PAYLOAD="{\"text\":\"*ClamAV Threat Detected* on \${HOSTNAME}\\\\nThreat: \${VIRUS_NAME}\\\\nFile: \${FILE_PATH}\\\\nTime: \${TIMESTAMP}\"}"
curl -s -X POST "${CLAMAV_ALERT_SLACK}" \\
    -H 'Content-type: application/json' \\
    --data "\${SLACK_PAYLOAD}" || true
EOF
    fi

    # Append custom command block if configured
    if [[ -n "$CLAMAV_ALERT_CUSTOM" ]]; then
        local safe_cmd="${CLAMAV_ALERT_CUSTOM//%v/\${VIRUS_NAME}}"
        safe_cmd="${safe_cmd//%f/\${FILE_PATH}}"
        cat >> "$ALERT_SCRIPT" <<EOF

# Custom alert command
${safe_cmd} || true
EOF
    fi

    chmod 750 "$ALERT_SCRIPT"
    log_info "Alert script written to $ALERT_SCRIPT."

    # Wire VirusEvent into clamd.conf
    if grep -q "^VirusEvent" "$CLAMD_CONF" 2>/dev/null; then
        sed -i "s|^VirusEvent.*|VirusEvent ${ALERT_SCRIPT}|" "$CLAMD_CONF"
    else
        echo "" >> "$CLAMD_CONF"
        echo "# Detection alerting" >> "$CLAMD_CONF"
        echo "VirusEvent ${ALERT_SCRIPT}" >> "$CLAMD_CONF"
    fi
    log_info "VirusEvent configured in $CLAMD_CONF."
}

# --- Pull initial definitions ---
update_definitions() {
    log_info "Downloading ClamAV virus definitions (this may take a moment)..."

    # On RHEL, stop freshclam service if running so the CLI call doesn't conflict
    systemctl stop clamav-freshclam 2>/dev/null || true
    systemctl stop freshclam 2>/dev/null || true

    if freshclam --quiet 2>/dev/null; then
        log_info "Virus definitions updated successfully."
    else
        log_warn "freshclam returned a non-zero exit — definitions may be current already."
        log_warn "Check /var/log/clamav/freshclam.log for details."
    fi
}

# --- Write scan script and systemd units ---
configure_scheduled_scan() {
    mkdir -p /var/lib/hardening

    # Scan shell script — called by the systemd service unit
    cat > "$SCAN_SCRIPT" <<EOF
#!/usr/bin/env bash
# ClamAV scheduled scan script.
# Managed by hardening/modules/antivirus/clamav.sh — do not edit manually.
set -euo pipefail
SCAN_LOG="${SCAN_LOG}"
SCAN_PATHS="${CLAMAV_SCAN_PATHS}"
mkdir -p "\$(dirname "\$SCAN_LOG")"
{
    echo "========================================"
    echo "ClamAV Scheduled Scan"
    echo "Started  : \$(date '+%Y-%m-%d %H:%M:%S')"
    echo "Hostname : \$(hostname)"
    echo "Paths    : \$SCAN_PATHS"
    echo "========================================"
} >> "\$SCAN_LOG"

ALERT_SCRIPT="${ALERT_SCRIPT}"

# Prefer clamdscan (uses running daemon — faster) with clamscan as fallback
SCAN_EXIT=0
if systemctl is-active --quiet ${CLAMD_SERVICE} 2>/dev/null; then
    # shellcheck disable=SC2086
    clamdscan --fdpass --multiscan --log="\$SCAN_LOG" \$SCAN_PATHS || SCAN_EXIT=\$?
else
    # shellcheck disable=SC2086
    clamscan -r --infected --log="\$SCAN_LOG" \$SCAN_PATHS || SCAN_EXIT=\$?
fi

# Exit code 1 = virus found; exit code 2 = scan error
if [[ "\$SCAN_EXIT" -eq 1 ]]; then
    echo "ALERT: Threats detected — see above for details." >> "\$SCAN_LOG"
    if [[ -x "\$ALERT_SCRIPT" ]]; then
        CLAM_VIRUSEVENT_VIRUSNAME="(see scan log)" \
        CLAM_VIRUSEVENT_FILENAME="\$SCAN_PATHS" \
        "\$ALERT_SCRIPT" || true
    fi
elif [[ "\$SCAN_EXIT" -eq 2 ]]; then
    echo "WARNING: Scan completed with errors (exit 2)." >> "\$SCAN_LOG"
else
    echo "Result  : Clean — no threats found." >> "\$SCAN_LOG"
fi

echo "Completed: \$(date '+%Y-%m-%d %H:%M:%S')" >> "\$SCAN_LOG"
echo "" >> "\$SCAN_LOG"
EOF
    chmod 750 "$SCAN_SCRIPT"
    log_info "Scan script written to $SCAN_SCRIPT."

    # Determine OnCalendar value
    local hour_fmt on_calendar sys_day
    hour_fmt=$(printf '%02d' "$CLAMAV_SCAN_HOUR")
    case "${CLAMAV_SCAN_DAY,,}" in
        sun|sunday)    sys_day="Sun" ;;
        mon|monday)    sys_day="Mon" ;;
        tue|tuesday)   sys_day="Tue" ;;
        wed|wednesday) sys_day="Wed" ;;
        thu|thursday)  sys_day="Thu" ;;
        fri|friday)    sys_day="Fri" ;;
        sat|saturday)  sys_day="Sat" ;;
        *)             sys_day="Sun" ;;
    esac
    if [[ "$CLAMAV_SCAN_SCHEDULE" == "weekly" ]]; then
        on_calendar="${sys_day} *-*-* ${hour_fmt}:00:00"
    else
        on_calendar="*-*-* ${hour_fmt}:00:00"
    fi

    # Systemd service unit
    cat > /etc/systemd/system/clamav-scheduled-scan.service <<EOF
[Unit]
Description=ClamAV Scheduled Virus Scan
Documentation=man:clamscan(1) man:clamdscan(1)
After=${CLAMD_SERVICE}.service network.target

[Service]
Type=oneshot
ExecStart=${SCAN_SCRIPT}
StandardOutput=journal
StandardError=journal
EOF

    # Systemd timer unit
    cat > /etc/systemd/system/clamav-scheduled-scan.timer <<EOF
[Unit]
Description=ClamAV Scheduled Scan Timer (${CLAMAV_SCAN_SCHEDULE} at ${hour_fmt}:00)

[Timer]
OnCalendar=${on_calendar}
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
EOF

    log_info "Systemd scan units written (${CLAMAV_SCAN_SCHEDULE} at ${hour_fmt}:00)."
}

# --- Enable services ---
enable_services() {
    systemctl daemon-reload

    # clamd daemon
    if systemctl enable --now "$CLAMD_SERVICE" 2>/dev/null; then
        log_info "Service $CLAMD_SERVICE enabled and started."
    else
        log_warn "Could not start $CLAMD_SERVICE — check $CLAMD_CONF for errors."
    fi

    # freshclam update service
    local freshclam_svc
    if systemctl list-unit-files 2>/dev/null | grep -q "clamav-freshclam"; then
        freshclam_svc="clamav-freshclam"
    elif systemctl list-unit-files 2>/dev/null | grep -q "freshclam"; then
        freshclam_svc="freshclam"
    else
        freshclam_svc=""
    fi

    if [[ -n "$freshclam_svc" ]]; then
        systemctl enable --now "$freshclam_svc" 2>/dev/null || true
        log_info "Service $freshclam_svc enabled and started."
    fi

    # Scheduled scan timer
    systemctl enable --now clamav-scheduled-scan.timer
    local hf
    hf=$(printf '%02d' "$CLAMAV_SCAN_HOUR")
    log_info "Scan timer enabled — $CLAMAV_SCAN_SCHEDULE at ${hf}:00."
}

# --- Artifact ---
save_artifact() {
    local artifact
    artifact=$(artifact_file "clamav")

    local clamav_version db_version db_date timer_status

    clamav_version=$(clamscan --version 2>/dev/null | head -1 || echo "unavailable")

    if command_exists sigtool && [[ -f /var/lib/clamav/main.cvd ]]; then
        db_version=$(sigtool --info /var/lib/clamav/main.cvd 2>/dev/null \
            | grep "^Version" | awk '{print $2}' || echo "unavailable")
        db_date=$(sigtool --info /var/lib/clamav/main.cvd 2>/dev/null \
            | grep "^Build time" | cut -d: -f2- | xargs || echo "unavailable")
    else
        db_version=$(ls /var/lib/clamav/*.cvd /var/lib/clamav/*.cld 2>/dev/null \
            | head -1 | xargs -I{} basename {} || echo "unavailable")
        db_date="see /var/lib/clamav/"
    fi

    systemctl is-active --quiet clamav-scheduled-scan.timer 2>/dev/null \
        && timer_status="Active" || timer_status="Inactive"

    cat > "$artifact" <<EOF
CLAMAV CONFIGURATION REPORT
==============================
Generated  : $(date '+%Y-%m-%d %H:%M:%S')
Hostname   : $(hostname)
OS         : $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
Applied by : hardening/modules/antivirus/clamav.sh

VERSION
-------
  ClamAV        : $clamav_version
  Database      : $db_version
  Database date : $db_date

CONFIGURATION  ($CLAMD_CONF)
$(printf '%0.s-' {1..50})
  On-access scanning  : $CLAMAV_ON_ACCESS
  On-access paths     : ${CLAMAV_ON_ACCESS_PATHS:-(n/a)}
  Scan archives       : $CLAMAV_SCAN_ARCHIVES
  Detect PUA          : $CLAMAV_DETECT_PUA
  Alert broken exec   : $CLAMAV_ALERT_BROKEN
  Max file size       : ${CLAMAV_MAX_FILE_SIZE}M
  Max recursion depth : $CLAMAV_MAX_RECURSION
  Quarantine dir      : ${CLAMAV_QUARANTINE_DIR:-(disabled)}
  Verbose logging     : $CLAMAV_LOG_VERBOSE
  Definition updates  : $CLAMAV_DEF_UPDATES check(s) per day

ALERTING
--------
  Alert email         : ${CLAMAV_ALERT_EMAIL:-(disabled)}
  Syslog alerts       : $CLAMAV_ALERT_SYSLOG
  Slack webhook       : ${CLAMAV_ALERT_SLACK:-(disabled)}
  Custom command      : ${CLAMAV_ALERT_CUSTOM:-(none)}
  Alert script        : $ALERT_SCRIPT
  VirusEvent          : wired into $CLAMD_CONF

SCHEDULED SCANNING
------------------
  Frequency   : $CLAMAV_SCAN_SCHEDULE at $(printf '%02d' "$CLAMAV_SCAN_HOUR"):00
  Scan paths  : $CLAMAV_SCAN_PATHS
  Scan script : $SCAN_SCRIPT
  Scan log    : $SCAN_LOG
  Timer unit  : clamav-scheduled-scan.timer
  Timer status: $timer_status

EVIDENCE OF ROUTINE SCANNING
------------------------------
  Each scheduled scan appends a timestamped entry to:
    $SCAN_LOG
  This file is the primary evidence record for routine AV scanning.
  View the last scan result:
    tail -50 $SCAN_LOG
  View all timer executions:
    journalctl -u clamav-scheduled-scan.service
EOF

    log_info "Artifact saved: $artifact"
}

# --- Main ---
log_section "Antivirus — ClamAV"

detect_environment
prompt_settings
preview_configuration

echo ""
install_clamav
configure_clamd
configure_freshclam
configure_alerting
update_definitions
configure_scheduled_scan
enable_services
save_artifact

log_info "ClamAV module complete."
