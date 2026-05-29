#!/usr/bin/env bash
# =============================================================================
# Module  : hostname
# Purpose : Set the system hostname using hostnamectl.
#
# Uses hostnamectl (systemd) which persists the change immediately without
# a reboot. /etc/hosts is updated so the new name resolves to 127.0.0.1
# locally — prevents sudo and other tools from hanging on DNS lookups.
#
# Hostname rules (RFC 952 / RFC 1123):
#   - Letters, digits, and hyphens only
#   - Cannot start or end with a hyphen
#   - Max 63 characters per label, 253 characters total
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../lib/common.sh"
source "$SCRIPT_DIR/../../config.conf"

check_root

HOSTS_FILE="/etc/hosts"

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

_validate_hostname() {
    local name="$1"
    if [[ ${#name} -gt 253 ]]; then
        echo "  Hostname too long (max 253 characters)."
        return 1
    fi
    if ! [[ "$name" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        echo "  Invalid hostname. Use letters, digits, and hyphens only."
        echo "  Labels cannot start or end with a hyphen."
        return 1
    fi
    return 0
}

_show_current() {
    echo "  Current hostname information:"
    echo ""
    printf "    %-20s %s\n" "Static hostname:" "$(hostnamectl --static 2>/dev/null || hostname)"
    printf "    %-20s %s\n" "Transient hostname:" "$(hostnamectl --transient 2>/dev/null || hostname)"
    printf "    %-20s %s\n" "FQDN:" "$(hostname -f 2>/dev/null || echo '(unavailable)')"
    echo ""
}

# =============================================================================
# Action: Set hostname
# =============================================================================

action_set_hostname() {
    _header "Set Hostname"

    _show_current

    local new_name
    while true; do
        read -rp "  New hostname: " new_name
        if [[ -z "$new_name" ]]; then
            echo "  Hostname cannot be empty."
            continue
        fi
        _validate_hostname "$new_name" && break
    done

    local old_name
    old_name=$(hostname)

    echo ""
    echo "  Change: ${old_name} → ${new_name}"
    read -rp "  Confirm? [Y/n]: " _ok
    [[ "${_ok,,}" =~ ^n ]] && { log_info "Cancelled."; return; }
    echo ""

    # Apply hostname.
    hostnamectl set-hostname "$new_name"
    log_info "Hostname set to '${new_name}'."

    # Update /etc/hosts so the new name resolves locally.
    # Replace any existing 127.0.0.1 line that references the old hostname,
    # and ensure the new name is present.
    backup_file "$HOSTS_FILE"

    if grep -qE "^127\.0\.0\.1[[:space:]]" "$HOSTS_FILE"; then
        # Add new_name to the 127.0.0.1 line if not already there.
        if ! grep -qE "^127\.0\.0\.1.*[[:space:]]${new_name}([[:space:]]|$)" "$HOSTS_FILE"; then
            sed -i "s/^127\.0\.0\.1.*/& ${new_name}/" "$HOSTS_FILE"
            log_info "Added '${new_name}' to 127.0.0.1 in ${HOSTS_FILE}."
        fi
        # Remove old hostname from 127.0.0.1 line if it differs.
        if [[ "$old_name" != "$new_name" ]] && \
           grep -qE "^127\.0\.0\.1.*[[:space:]]${old_name}([[:space:]]|$)" "$HOSTS_FILE"; then
            sed -i "s/[[:space:]]${old_name}//g" "$HOSTS_FILE"
            log_info "Removed old hostname '${old_name}' from ${HOSTS_FILE}."
        fi
    else
        echo "127.0.0.1   ${new_name} localhost" >> "$HOSTS_FILE"
        log_info "Added 127.0.0.1 entry for '${new_name}' to ${HOSTS_FILE}."
    fi

    echo ""
    _show_current
    log_info "No reboot required — change is effective immediately."
}

# =============================================================================
# Action: Show hostname
# =============================================================================

action_show_hostname() {
    _header "Current Hostname"
    _show_current

    echo "  /etc/hosts entries:"
    grep -E "^127\." "$HOSTS_FILE" 2>/dev/null | sed 's/^/    /' || echo "    (none)"
    echo ""
}

# =============================================================================
# Main landing page
# =============================================================================

while true; do
    _header "Hostname — Set System Hostname"
    echo "  Sets the system hostname using hostnamectl. The change takes"
    echo "  effect immediately and persists across reboots without requiring"
    echo "  a restart. /etc/hosts is updated to ensure local resolution."
    echo ""
    echo "    1) Set hostname          — change the system hostname"
    echo "    2) Show current hostname — display hostname and FQDN"
    echo "    3) Exit"
    echo ""
    read -rp "  Selection [1-3, default=1]: " _main
    echo ""

    case "${_main:-1}" in
        1) action_set_hostname ;;
        2) action_show_hostname ;;
        3) log_info "Exiting hostname module."; exit 0 ;;
        *) echo "  Invalid selection." ;;
    esac
done
