#!/usr/bin/env bash
# =============================================================================
# Module  : logon_banner
# Purpose : Display a legal warning banner to users before and after login,
#           and configure SSH to present the same banner pre-authentication.
#
# Banners serve two functions: legal notice (consent to monitoring) and
# deterrence (informs unauthorised users that access is prohibited).  They
# must be applied to both local console sessions and remote SSH sessions to
# be legally effective.
#
# This module performs the following actions in order:
#
#   1. BANNER SELECTION (interactive)
#      The operator selects one of two modes:
#        1) Default — applies the DEI standard legal warning banner.
#        2) Custom  — operator provides their own text either by typing it
#                     directly or by supplying the path to an existing file.
#
#   2. BANNER PREVIEW
#      The selected banner is displayed in full before any changes are made.
#      The operator must confirm before the module proceeds.
#
#   3. LOCAL CONSOLE BANNER  (/etc/issue)
#      Written before the login prompt on all local TTY sessions.
#      Replaces any existing content (e.g. the default OS name/version line).
#      A timestamped backup is taken before writing.
#
#   4. NETWORK PRE-LOGIN BANNER  (/etc/issue.net)
#      Written to the network banner file used by SSH and other network
#      services that present a pre-authentication message.  Keeping issue and
#      issue.net in sync ensures consistent messaging across all access paths.
#      A timestamped backup is taken before writing.
#
#   5. SSH BANNER CONFIGURATION  (/etc/ssh/sshd_config)
#      Sets the Banner directive in sshd_config to point to /etc/issue.net.
#      This causes sshd to send the banner to connecting clients before
#      authentication, satisfying legal notice requirements for SSH access.
#        - If a Banner directive already exists (active or commented), it is
#          replaced in place.
#        - If no Banner directive exists, one is appended to the file.
#      sshd is reloaded after the change so existing sessions are unaffected.
#      A timestamped backup of sshd_config is taken before modification.
#      Skipped with a warning if sshd_config is not found.
#
#   6. GUI LOGIN BANNER  (GDM / LightDM)
#      Configures the graphical login screen to display the banner.
#        GDM (GNOME Display Manager — default on RHEL/Fedora):
#          - Writes /etc/dconf/profile/gdm (created if absent) so GDM reads
#            the system-level dconf database.
#          - Writes /etc/dconf/db/gdm.d/01-banner with the dconf keyfile that
#            enables the banner and stores the text as a GVariant string.
#          - Runs `dconf update` to compile the database.
#          - Takes effect at the next GUI login without restarting GDM.
#        LightDM:
#          - Writes /etc/lightdm/lightdm.conf.d/50-banner.conf with the
#            greeter-message option (LightDM only supports a single line, so
#            newlines are collapsed to spaces).
#          - Restarts LightDM if it is currently running (will drop active
#            GUI sessions — the operator is warned before this happens).
#      Skipped with a warning if neither GDM nor LightDM is detected.
#
# Files modified:
#   /etc/issue                        — local console pre-login banner
#   /etc/issue.net                    — network pre-login banner (used by SSH)
#   /etc/ssh/sshd_config              — Banner directive updated to /etc/issue.net
#   /etc/dconf/profile/gdm            — GDM dconf profile (GDM only)
#   /etc/dconf/db/gdm.d/01-banner     — GDM banner keyfile (GDM only)
#   /etc/lightdm/lightdm.conf.d/50-banner.conf  — LightDM banner (LightDM only)
#
# Dependencies:
#   printf, cat               — coreutils
#   sed, awk                  — text processing
#   systemctl                 — systemd (to reload/restart services)
#   openssh-server            — sshd must be installed for SSH banner config
#   dconf                     — required for GDM banner configuration
#
# Must be run as root (enforced by check_root in master.sh).
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../config.conf"
source "$SCRIPT_DIR/../../lib/common.sh"

# --- Default banner ---
# Stored as a variable so it can be previewed and applied without a separate
# file. The single-quote heredoc (<<'EOF') prevents variable expansion inside
# the banner text, preserving all punctuation and special characters exactly.
DEFAULT_BANNER=$(cat <<'EOF'
********************************************************************************
*                            AUTHORISED USE ONLY                               *
********************************************************************************

You are accessing a Device Engineering Incorporated Information System (IS) for
authorized use only. This IS may contain federal contract information, controlled
technical information, and controlled unclassified information, which may be
subject to additional controls.

By using this IS (including any device attached to this IS by you, DEI or any
other person), you consent to the following:

Unauthorized use of this IS is prohibited and is subject to civil and criminal
penalties.

DEI routinely intercepts, and monitors, and audits communications on this IS.
At any time, DEI may inspect and seize data used in, stored on, or transiting
through this IS.

Communications, and data used in, stored on, or transiting through, this IS are
not private, are subject to routine monitoring, interception, and search, and may
be disclosed or used by DEI for any authorized purpose.

This IS includes security measures to protect the interests of DEI and its
clients, not for your personal benefit or privacy.

********************************************************************************
EOF
)

# Holds the final banner text to be applied — set by prompt functions below
BANNER_TEXT=""

# --- Banner selection ---
prompt_banner_choice() {
    echo ""
    echo "  Select logon banner:"
    echo ""
    echo "  1) Default — DEI standard legal warning banner"
    echo "  2) Custom  — provide your own banner text"
    echo ""
    while true; do
        read -rp "  Enter choice [1/2]: " choice
        case "$choice" in
            1)
                BANNER_TEXT="$DEFAULT_BANNER"
                log_info "Default DEI banner selected."
                break
                ;;
            2)
                prompt_custom_banner
                break
                ;;
            *) echo "  Invalid choice. Enter 1 or 2." ;;
        esac
    done
}

prompt_custom_banner() {
    echo ""
    echo "  How would you like to provide the banner text?"
    echo ""
    echo "  1) Type it now  — enter text line by line, type END on its own line when finished"
    echo "  2) Load from file — provide the path to a plain text file"
    echo ""
    while true; do
        read -rp "  Enter choice [1/2]: " input_choice
        case "$input_choice" in
            1) prompt_banner_inline; break ;;
            2) prompt_banner_file;   break ;;
            *) echo "  Invalid choice. Enter 1 or 2." ;;
        esac
    done
}

prompt_banner_inline() {
    echo ""
    echo "  Enter banner text below."
    echo "  Type END on its own line when finished:"
    echo ""

    BANNER_TEXT=""
    local line
    # Read lines until the sentinel "END" is entered on its own.
    # IFS= preserves leading/trailing whitespace on each line.
    while IFS= read -r line; do
        [[ "$line" == "END" ]] && break
        BANNER_TEXT+="${line}"$'\n'
    done

    # Strip the trailing newline added by the last iteration
    BANNER_TEXT="${BANNER_TEXT%$'\n'}"

    if [[ -z "$BANNER_TEXT" ]]; then
        log_warn "No text entered. Falling back to default banner."
        BANNER_TEXT="$DEFAULT_BANNER"
    fi
}

prompt_banner_file() {
    while true; do
        read -rp "  Enter path to banner file: " filepath
        if [[ -z "$filepath" ]]; then
            echo "  Path cannot be empty."
        elif [[ ! -f "$filepath" ]]; then
            echo "  File not found: $filepath"
        else
            BANNER_TEXT=$(cat "$filepath")
            log_info "Banner loaded from: $filepath"
            break
        fi
    done
}

# --- Preview and confirm ---
preview_banner() {
    echo ""
    log_info "Banner preview:"
    echo ""
    # Indent each line for readability inside the script's output
    while IFS= read -r line; do
        echo "    $line"
    done <<< "$BANNER_TEXT"
    echo ""

    while true; do
        read -rp "  Apply this banner? [Y/n]: " confirm
        confirm="${confirm:-y}"
        case "${confirm,,}" in
            y|yes) break ;;
            n|no)
                log_warn "Banner not applied. Re-run the module to try again."
                exit 0
                ;;
            *) echo "  Enter y or n." ;;
        esac
    done
}

# --- Apply banner to system files ---
apply_local_banner() {
    # /etc/issue is read by getty and displayed on the TTY before the login
    # prompt. Overwriting it replaces any existing OS identification line.
    backup_file /etc/issue
    printf '%s\n' "$BANNER_TEXT" > /etc/issue
    log_info "Banner written to /etc/issue (local console pre-login)."
}

apply_network_banner() {
    # /etc/issue.net is the network equivalent of /etc/issue. sshd reads this
    # file when the Banner directive is configured in sshd_config.
    backup_file /etc/issue.net
    printf '%s\n' "$BANNER_TEXT" > /etc/issue.net
    log_info "Banner written to /etc/issue.net (network/SSH pre-login)."
}

# --- Configure GUI (display manager) login banner ---
# GDM (GNOME Display Manager) reads banner settings from dconf.  The banner
# text is stored as a GVariant string in /etc/dconf/db/gdm.d/01-banner and
# activated by running `dconf update`.  A matching profile file is required
# so GDM knows to consult the system-level db.
configure_gdm_banner() {
    local gdm_profile="/etc/dconf/profile/gdm"
    local gdm_db_dir="/etc/dconf/db/gdm.d"
    local banner_keyfile="$gdm_db_dir/01-banner"

    if ! command_exists dconf; then
        log_warn "dconf not found — cannot configure GDM banner. Install dconf and re-run."
        return
    fi

    mkdir -p "$gdm_db_dir"

    # Write the GDM dconf profile only if it is missing or does not already
    # reference system-db:gdm, to avoid clobbering custom profiles.
    if [[ ! -f "$gdm_profile" ]] || ! grep -q "system-db:gdm" "$gdm_profile"; then
        backup_file "$gdm_profile"
        printf 'user-db:user\nsystem-db:gdm\nfile-db:/usr/share/gdm/greeter-dconf-defaults\n' \
            > "$gdm_profile"
        log_info "GDM dconf profile written to $gdm_profile."
    fi

    # Convert the banner to a single-line GVariant string:
    #   1. Escape backslashes so they survive GVariant parsing.
    #   2. Escape single quotes (the GVariant string delimiter).
    #   3. Collapse each newline to the two-character escape sequence \n.
    local escaped
    escaped=$(printf '%s' "$BANNER_TEXT" \
        | sed 's/\\/\\\\/g' \
        | sed "s/'/\\\\'/g" \
        | awk '{printf "%s\\n", $0}')
    escaped="${escaped%\\n}"   # strip the trailing \n added by awk

    backup_file "$banner_keyfile"
    {
        printf '[org/gnome/login-screen]\n'
        printf 'banner-message-enable=true\n'
        printf "banner-message-text='%s'\n" "$escaped"
    } > "$banner_keyfile"

    dconf update
    log_info "GDM banner configured via dconf — will appear at the GUI login screen."
}

# LightDM exposes a greeter-message option, but it only supports a single line.
# Newlines are collapsed to spaces so the message fits the field.
configure_lightdm_banner() {
    local conf_dir="/etc/lightdm/lightdm.conf.d"
    local banner_conf="$conf_dir/50-banner.conf"

    mkdir -p "$conf_dir"
    backup_file "$banner_conf"

    local oneliner
    oneliner=$(printf '%s' "$BANNER_TEXT" | tr '\n' ' ' | sed 's/  */ /g; s/^ //; s/ $//')

    printf '[Seat:*]\ngreeter-message=%s\n' "$oneliner" > "$banner_conf"
    log_info "LightDM banner configured in $banner_conf."

    # LightDM requires a full restart (unlike sshd which supports reload).
    # Warn the operator because this will drop any active GUI session.
    if systemctl is-active --quiet lightdm 2>/dev/null; then
        log_warn "Restarting LightDM — active GUI sessions will be terminated."
        systemctl restart lightdm
    fi
}

configure_gui_banner() {
    local gdm_present=false
    local lightdm_present=false

    # Detect GDM: service state takes priority; fall back to package presence
    # so the banner is configured even when the DM is installed but not yet started.
    if systemctl is-active --quiet gdm 2>/dev/null \
        || systemctl is-enabled --quiet gdm 2>/dev/null \
        || { command_exists rpm  && rpm  -q gdm  &>/dev/null; } \
        || { command_exists dpkg && dpkg -s gdm3 &>/dev/null 2>&1; }; then
        gdm_present=true
    fi

    if systemctl is-active --quiet lightdm 2>/dev/null \
        || systemctl is-enabled --quiet lightdm 2>/dev/null \
        || { command_exists rpm  && rpm  -q lightdm &>/dev/null; } \
        || { command_exists dpkg && dpkg -s lightdm &>/dev/null 2>&1; }; then
        lightdm_present=true
    fi

    if ! $gdm_present && ! $lightdm_present; then
        log_warn "No supported GUI display manager detected (GDM/LightDM) — skipping GUI banner."
        return
    fi

    $gdm_present     && configure_gdm_banner
    $lightdm_present && configure_lightdm_banner
}

# --- Configure SSH to present the banner ---
configure_ssh_banner() {
    local sshd_config="/etc/ssh/sshd_config"

    if [[ ! -f "$sshd_config" ]]; then
        log_warn "sshd_config not found at $sshd_config — skipping SSH banner configuration."
        log_warn "Install openssh-server and re-run this module to configure the SSH banner."
        return
    fi

    backup_file "$sshd_config"

    # Replace any existing Banner line (commented or active) in place to avoid
    # duplicates. If no Banner line exists at all, append one to the end.
    if grep -qE "^\s*#*\s*Banner" "$sshd_config"; then
        sed -i "s|^\s*#*\s*Banner.*|Banner /etc/issue.net|" "$sshd_config"
        log_info "SSH Banner directive updated in $sshd_config."
    else
        echo "Banner /etc/issue.net" >> "$sshd_config"
        log_info "SSH Banner directive appended to $sshd_config."
    fi

    # Reload rather than restart — reload re-reads the config without dropping
    # any currently active SSH sessions, making it safe to run on a live system.
    # Try both service name variants (sshd on RHEL, ssh on Debian).
    if systemctl is-active --quiet sshd 2>/dev/null; then
        systemctl reload sshd
        log_info "sshd reloaded — banner will appear on next SSH connection."
    elif systemctl is-active --quiet ssh 2>/dev/null; then
        systemctl reload ssh
        log_info "ssh service reloaded — banner will appear on next SSH connection."
    else
        log_warn "sshd does not appear to be running."
        log_warn "The banner will be presented when sshd is next started."
    fi
}

# --- Artifact ---
save_artifact() {
    local artifact
    artifact=$(artifact_file "logon_banner")

    local ssh_banner_directive gdm_keyfile_status lightdm_status

    ssh_banner_directive=$(grep -E "^\s*Banner\s" /etc/ssh/sshd_config 2>/dev/null \
        | awk '{print $2}' || echo "not configured")

    if [[ -f /etc/dconf/db/gdm.d/01-banner ]]; then
        gdm_keyfile_status="Configured (/etc/dconf/db/gdm.d/01-banner)"
    elif ! command_exists dconf; then
        gdm_keyfile_status="Skipped (dconf not installed)"
    else
        gdm_keyfile_status="Not configured"
    fi

    if [[ -f /etc/lightdm/lightdm.conf.d/50-banner.conf ]]; then
        lightdm_status="Configured (/etc/lightdm/lightdm.conf.d/50-banner.conf)"
    else
        lightdm_status="Not configured"
    fi

    cat > "$artifact" <<EOF
LOGON BANNER CONFIGURATION REPORT
====================================
Generated  : $(date '+%Y-%m-%d %H:%M:%S')
Hostname   : $(hostname)
OS         : $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
Applied by : hardening/modules/logon_banner/harden.sh

BANNER TEXT
-----------
$BANNER_TEXT

FILES MODIFIED
--------------
  /etc/issue         : $([ -f /etc/issue ] && echo "Written (local console pre-login)" || echo "Not found")
  /etc/issue.net     : $([ -f /etc/issue.net ] && echo "Written (network/SSH pre-login)" || echo "Not found")

SSH CONFIGURATION  (/etc/ssh/sshd_config)
------------------------------------------
  Banner directive   : $ssh_banner_directive

GUI CONFIGURATION
-----------------
  GDM (GNOME)        : $gdm_keyfile_status
  LightDM            : $lightdm_status
EOF

    log_info "Artifact saved: $artifact"
}

# --- Main ---
log_section "Logon Banner"

prompt_banner_choice
preview_banner

echo ""
apply_local_banner
apply_network_banner
configure_ssh_banner
configure_gui_banner

save_artifact

log_info "Logon banner module complete."
