#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source "$SCRIPT_DIR/config.conf"
source "$SCRIPT_DIR/lib/common.sh"

check_root

FIPS_ENABLED=$( [[ -r /proc/sys/crypto/fips_enabled ]] && cat /proc/sys/crypto/fips_enabled || echo 0 )

# Detect FDE by checking whether a crypt device exists anywhere in the
# ancestry of the root filesystem (handles LVM-on-LUKS layouts where the
# crypt layer is not mounted directly at /).
FDE_ENABLED=0
_root_dev=$(findmnt -n -o SOURCE / 2>/dev/null)
if [[ -n "$_root_dev" ]] && lsblk -s -o TYPE "$_root_dev" 2>/dev/null | grep -q "^crypt$"; then
    FDE_ENABLED=1
fi
unset _root_dev

# =============================================================================
# Category registry
# CATEGORIES      — array of internal keys (used for indirect variable lookup)
# CATEGORY_NAMES  — display names, index-aligned with CATEGORIES
# CATEGORY_DESCS  — one-line descriptions shown in the main menu
# CATEGORY_MODULES_<key> — space-separated module list for each category
# =============================================================================

CATEGORIES=(prerequisites access_control system_comms networking expansion)

CATEGORY_NAMES=(
    "Prerequisites"
    "Access Control"
    "System & Communication Protection"
    "Networking & Firewall"
    "App Control & Auditing"
)

CATEGORY_DESCS=(
    "Foundational services required by other modules — SMTP relay"
    "Password policy, user administration, logon banners, and session timeouts"
    "Antivirus, USB control, FIPS compliance, system updates, and time sync"
    "Network interface configuration — IP addressing and network controls"
    "Application allow-listing (fapolicyd), audit logging (auditd), package removal, and filesystem hardening"
)

CATEGORY_MODULES_prerequisites="hostname smtp_relay"
CATEGORY_MODULES_access_control="password_policy users mfa logon_banner session_timeout"
CATEGORY_MODULES_system_comms="antivirus usb_control fips updates time_sync encryption"
CATEGORY_MODULES_networking="networking firewall"
CATEGORY_MODULES_expansion="packages filesystem auditd app_control"

# Per-module descriptions shown in sub-menus (requires bash 4+)
declare -A MODULE_DESC
MODULE_DESC[hostname]="Set the system hostname via hostnamectl; updates /etc/hosts for local resolution — no reboot required"
MODULE_DESC[smtp_relay]="Install and configure msmtp as an SMTP relay — set relay host, credentials, and TLS; send a test email to verify delivery"
MODULE_DESC[password_policy]="Configure password complexity (pwquality), aging (login.defs), account lockout (faillock), and reuse prevention (pwhistory)"
MODULE_DESC[users]="Create admin, standard, or service accounts; add users to groups; inspect group memberships; list all system groups with permissions"
MODULE_DESC[mfa]="Install Google Authenticator TOTP via PAM; enforce MFA for SSH and/or sudo; guided per-user token enrollment with QR code"
MODULE_DESC[logon_banner]="Deploy a legal warning banner to /etc/issue (console), /etc/issue.net (SSH), and GUI login screens"
MODULE_DESC[session_timeout]="Terminate idle sessions after a configurable inactivity timeout across SSH, shell/console, and GUI desktop"
MODULE_DESC[antivirus]="Install and configure ClamAV or Microsoft Defender for Endpoint with definition updates and scheduled scanning"
MODULE_DESC[usb_control]="Block all USB mass storage or whitelist approved VID:PID devices via modprobe.d and udev rules"
MODULE_DESC[fips]="Run a 5-point FIPS 140 compliance check; optionally enable FIPS mode (requires reboot)"
MODULE_DESC[updates]="List and apply all pending package updates via dnf/yum/apt; check whether a reboot is required"
MODULE_DESC[encryption]="OS drive FDE status, second boot passphrase, recovery keyfile, data disk encryption, FDE setup guide, and recovery guide"
MODULE_DESC[time_sync]="Configure NTP time source from a preset or custom list; set timezone; verify clock synchronisation"
MODULE_DESC[networking]="Configure network interfaces — set static IP or DHCP, prefix, gateway, and DNS via NetworkManager"
MODULE_DESC[firewall]="Enable and configure firewalld — manage zones, allow/block services and ports"
MODULE_DESC[packages]="Remove known unnecessary packages (telnet, rsh, etc.) and disable unused services"
MODULE_DESC[filesystem]="Restrict permissions on sensitive files; apply noexec/nosuid/nodev to /tmp, /var/tmp, /dev/shm"
MODULE_DESC[auditd]="Install auditd and deploy a baseline ruleset covering logins, privilege escalation, and file access"
MODULE_DESC[app_control]="Allow-list trusted applications via fapolicyd — block untrusted executables in enforcing mode"

declare -A MODULE_NAME
MODULE_NAME[app_control]="Application Control"
MODULE_NAME[networking]="Network Setup"

# =============================================================================
# Core helpers
# =============================================================================

get_category_modules() {
    local cat_key="$1"
    local var="CATEGORY_MODULES_${cat_key}"
    echo "${!var:-}"
}

is_module_enabled() {
    local flag_var="MODULE_${1^^}"
    [[ "${!flag_var:-no}" == "yes" ]]
}

count_enabled_in_category() {
    local count=0
    local module
    for module in $(get_category_modules "$1"); do
        is_module_enabled "$module" && count=$(( count + 1 )) || true
    done
    echo "$count"
}

count_total_in_category() {
    local modules
    modules=$(get_category_modules "$1")
    [[ -z "$modules" ]] && echo "0" && return
    echo "$modules" | wc -w
}

# Warn if FIPS or FDE are not enabled. Returns 1 (blocking) if the user
# declines to continue, so callers can use:  _warn_compliance || continue
_warn_compliance() {
    local issues=()
    [[ "$FIPS_ENABLED" != "1" ]] && issues+=("FIPS mode is not enabled on this system")
    [[ "$FDE_ENABLED"  != "1" ]] && issues+=("Full Disk Encryption (FDE) is not active on the OS drive")

    [[ ${#issues[@]} -eq 0 ]] && return 0

    echo ""
    echo -e "${RED}  ╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}  ║  COMPLIANCE WARNING                                         ║${NC}"
    echo -e "${RED}  ╠══════════════════════════════════════════════════════════════╣${NC}"
    local issue
    for issue in "${issues[@]}"; do
        printf "${RED}  ║  • %-57s║\n${NC}" "$issue"
    done
    echo -e "${RED}  ║                                                              ║${NC}"
    echo -e "${RED}  ║  Controls applied may not satisfy compliance requirements.   ║${NC}"
    echo -e "${RED}  ║  Reinstall the OS with FIPS and FDE enabled for full         ║${NC}"
    echo -e "${RED}  ║  compliance. If FDE is enabled, ensure your recovery         ║${NC}"
    echo -e "${RED}  ║  passphrase or keyfile has been exported and stored safely.  ║${NC}"
    echo -e "${RED}  ║  See: Encryption module > Manage Key Slots.                 ║${NC}"
    echo -e "${RED}  ╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    read -rp "  Continue anyway? [y/N]: " _compliance_ok
    echo ""
    [[ "${_compliance_ok,,}" =~ ^y ]]
}

run_module() {
    local name="$1"
    local module_script="$SCRIPT_DIR/modules/$name/harden.sh"
    if [[ ! -f "$module_script" ]]; then
        log_warn "Module '$name' not found at $module_script — skipping."
        return
    fi
    log_section "Module: $name"
    bash "$module_script"
    log_info "Module '$name' completed."
}


# =============================================================================
# Display: main menu
# =============================================================================

show_main_menu() {
    printf "\033c"

    # Build colored status lines. printf "%-Ns" counts bytes not visible chars,
    # so ANSI codes break box alignment — compute padding manually instead.
    local fips_colored fips_suffix fips_visible fips_pad
    if [[ "$FIPS_ENABLED" == "1" ]]; then
        fips_colored="${GREEN}ENABLED${NC}";     fips_suffix="  — proceed with hardening"
        fips_visible=$(( 7  + ${#fips_suffix} ))
    else
        fips_colored="${RED}NOT ENABLED${NC}";  fips_suffix=" — reinstall in FIPS mode"
        fips_visible=$(( 11 + ${#fips_suffix} ))
    fi
    fips_pad=$(( 49 - fips_visible ))

    local fde_colored fde_suffix fde_visible fde_pad
    if [[ "$FDE_ENABLED" == "1" ]]; then
        fde_colored="${GREEN}ENABLED${NC}";     fde_suffix="  — OS drive is encrypted"
        fde_visible=$(( 7  + ${#fde_suffix} ))
    else
        fde_colored="${RED}NOT ENABLED${NC}";   fde_suffix=" — reinstall OS with FDE enabled"
        fde_visible=$(( 11 + ${#fde_suffix} ))
    fi
    fde_pad=$(( 49 - fde_visible ))

    local advisory=""
    if [[ "$FIPS_ENABLED" != "1" || "$FDE_ENABLED" != "1" ]]; then
        advisory="  For full compliance, reinstall with both FIPS mode and Full Disk\n  Encryption enabled at the OS installer. See Encryption module >\n  FDE Installation Guide for step-by-step instructions."
    fi

    echo ""
    echo "  ╔══════════════════════════════════════════════════════════════╗"
    echo "  ║              Linux Hardening Master Script                  ║"
    echo "  ╠══════════════════════════════════════════════════════════════╣"
    printf  "  ║  Hostname : %-49s║\n" "$(hostname)"
    printf  "  ║  OS       : %-49s║\n" "$(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')"
    printf  "  ║  Date     : %-49s║\n" "$(date '+%Y-%m-%d %H:%M:%S')"
    printf "  ║  FIPS     : %b%s%*s║\n" "$fips_colored" "$fips_suffix" "$fips_pad" ""
    printf "  ║  FDE      : %b%s%*s║\n" "$fde_colored"  "$fde_suffix"  "$fde_pad"  ""
    echo "  ╚══════════════════════════════════════════════════════════════╝"

    if [[ -n "$advisory" ]]; then
        echo ""
        echo -e "${YELLOW}${advisory}${NC}"
    fi

    echo ""
    echo "  Select a category:"
    echo ""

    local i=0
    for cat_key in "${CATEGORIES[@]}"; do
        local enabled total_mods
        enabled=$(count_enabled_in_category "$cat_key")
        total_mods=$(count_total_in_category "$cat_key")
        printf "  %s)  %-40s[%s/%s modules enabled]\n" \
            "$i" "${CATEGORY_NAMES[$i]}" "$enabled" "$total_mods"
        printf "       %s\n" "${CATEGORY_DESCS[$i]}"
        echo ""
        i=$(( i + 1 ))
    done

    echo "  ──────────────────────────────────────────────────────────────"
    echo "  q)  Quit"
    echo ""
}

# =============================================================================
# Display: category sub-menu
# =============================================================================

show_category_menu() {
    local cat_key="$1" cat_name="$2" cat_desc="$3"
    printf "\033c"
    echo ""
    echo "  ╔══════════════════════════════════════════════════════════════╗"
    printf  "  ║  Category : %-49s║\n" "$cat_name"
    printf  "  ║  %-61s║\n" "$cat_desc"
    echo "  ╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  Select a module to run:"
    echo ""

    local i=0 module status_label
    for module in $(get_category_modules "$cat_key"); do
        if is_module_enabled "$module"; then
            status_label="enabled "
        else
            status_label="disabled"
        fi
        printf "  %s)  %-20s [%s]\n" "$((i + 1))" "${MODULE_NAME[$module]:-$module}" "$status_label"
        printf "       %s\n" "${MODULE_DESC[$module]:-No description available.}"
        echo ""
        i=$(( i + 1 ))
    done

    echo "  ──────────────────────────────────────────────────────────────"
    echo "  b)  Back to main menu"
    echo "  q)  Quit"
    echo ""
}

# =============================================================================
# Category sub-menu loop
# =============================================================================

run_category_menu() {
    local cat_key="$1" cat_name="$2" cat_desc="$3"
    local modules_arr
    read -r -a modules_arr <<< "$(get_category_modules "$cat_key")"

    while true; do
        show_category_menu "$cat_key" "$cat_name" "$cat_desc"
        read -rp "  Enter choice: " choice

        case "$choice" in
            b|B)
                return
                ;;
            q|Q)
                echo ""
                log_info "Exiting."
                exit 0
                ;;
            ''|*[!0-9]*)
                echo -e "  ${RED}Invalid choice.${NC}"
                ;;
            *)
                if (( choice >= 1 && choice <= ${#modules_arr[@]} )); then
                    local selected="${modules_arr[$((choice - 1))]}"
                    if ! is_module_enabled "$selected"; then
                        echo ""
                        echo -e "  ${YELLOW}  '$selected' is disabled in config.conf.${NC}"
                        echo "  Set MODULE_${selected^^}=yes to enable it permanently."
                        echo ""
                        read -rp "  Run it anyway this session? [y/N]: " force
                        echo ""
                        if [[ ! "${force,,}" =~ ^y ]]; then
                            read -rp "  Press Enter to continue..."
                            continue
                        fi
                    fi
                    log_section "Linux Hardening Script Started"
                    run_module "$selected"
                    log_section "Complete"
                    log_info "Review the log at $LOG_FILE"
                else
                    echo -e "  ${RED}Invalid choice.${NC}"
                fi
                ;;
        esac

        echo ""
        read -rp "  Return to $cat_name menu? [Y/n]: " again
        [[ "$again" =~ ^[Nn]$ ]] && return
    done
}

# =============================================================================
# Main loop
# =============================================================================

while true; do
    show_main_menu
    read -rp "  Enter choice: " choice

    case "$choice" in
        q|Q)
            echo ""
            log_info "Exiting."
            exit 0
            ;;
        ''|*[!0-9]*)
            echo -e "  ${RED}Invalid choice.${NC}"
            ;;
        *)
            if (( choice >= 0 && choice < ${#CATEGORIES[@]} )); then
                _warn_compliance || continue
                run_category_menu \
                    "${CATEGORIES[$choice]}" \
                    "${CATEGORY_NAMES[$choice]}" \
                    "${CATEGORY_DESCS[$choice]}"
            else
                echo -e "  ${RED}Invalid choice.${NC}"
            fi
            ;;
    esac

    echo ""
    read -rp "  Return to main menu? [Y/n]: " again
    [[ "$again" =~ ^[Nn]$ ]] && break
done
