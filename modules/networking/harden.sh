#!/usr/bin/env bash
# =============================================================================
# Module  : networking
# Purpose : Configure network interfaces on this system — assign static IP
#           addresses or enable DHCP via NetworkManager (nmcli).
#
# This module performs the following actions:
#
#   1. IP ADDRESS CONFIGURATION  (interactive — action_set_ip)
#      The operator selects a NetworkManager-managed ethernet or Wi-Fi
#      interface, then chooses between:
#        DHCP   — sets ipv4.method auto and clears any static address,
#                 gateway, and DNS from the connection profile.
#        Static — prompts for IP address, prefix length (CIDR /1-32),
#                 default gateway, and primary DNS.  Existing profile
#                 values are offered as defaults (press Enter to keep).
#                 Input is validated before any change is applied.
#      In both cases the connection is brought up with `nmcli con up`
#      immediately after the profile is updated.
#
#      Warning: if the target interface carries the current SSH session,
#      applying a new address will disconnect that session.
#
# Requirements:
#   NetworkManager / nmcli  — standard on Rocky Linux 9 / RHEL 9
#   ip (iproute2)           — used in the artifact for live interface state
#
# Files modified:
#   NetworkManager connection profile for the selected interface
#   (typically /etc/NetworkManager/system-connections/<name>.nmconnection)
#
# Artifacts written:
#   hardening/artifacts/networking/<hostname>_<timestamp>.txt
#
# Must be run as root (enforced by check_root in master.sh).
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../config.conf"
source "$SCRIPT_DIR/../../lib/common.sh"

check_root

# Global parallel arrays populated by _load_interfaces.
declare -a CONN_NAMES=()
declare -a CONN_DEVICES=()

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

_validate_ip() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS='.'
    local -a _oct
    read -r -a _oct <<< "$ip"
    local o
    for o in "${_oct[@]}"; do
        (( 10#$o >= 0 && 10#$o <= 255 )) || return 1
    done
    return 0
}

_prompt_ip() {
    local prompt="$1" varname="$2" default="${3:-}"
    local _ip
    while true; do
        if [[ -n "$default" ]]; then
            read -rp "  $prompt [$default]: " _ip
            _ip="${_ip:-$default}"
        else
            read -rp "  $prompt: " _ip
        fi
        if _validate_ip "$_ip"; then
            printf -v "$varname" "%s" "$_ip"; break
        else
            echo "  Invalid address. Enter dotted-decimal, e.g. 192.168.1.100"
        fi
    done
}

_prompt_prefix() {
    local varname="$1" default="${2:-24}"
    local _p
    while true; do
        read -rp "  Subnet prefix length (1–32) [$default]: " _p
        _p="${_p:-$default}"
        if [[ "$_p" =~ ^[0-9]+$ ]] && (( _p >= 1 && _p <= 32 )); then
            printf -v "$varname" "%s" "$_p"; break
        else
            echo "  Must be an integer between 1 and 32."
        fi
    done
}

# Convert a CIDR prefix length (0-32) to a dotted-decimal subnet mask.
_prefix_to_mask() {
    local prefix="$1" mask=0 i
    for (( i = 0; i < prefix; i++ )); do
        mask=$(( mask | ( 1 << (31 - i) ) ))
    done
    printf "%d.%d.%d.%d" \
        $(( (mask >> 24) & 255 )) \
        $(( (mask >> 16) & 255 )) \
        $(( (mask >>  8) & 255 )) \
        $((  mask        & 255 ))
}

# Populate CONN_NAMES / CONN_DEVICES with ethernet and Wi-Fi interfaces that
# NetworkManager has an active connection profile for.
_load_interfaces() {
    CONN_NAMES=()
    CONN_DEVICES=()

    local _dev _type
    while IFS=: read -r _dev _type; do
        [[ "$_type" =~ ^(ethernet|wifi)$ ]] || continue
        local _conn
        _conn=$(nmcli -g GENERAL.CONNECTION dev show "$_dev" 2>/dev/null || true)
        [[ -z "$_conn" || "$_conn" == "--" ]] && continue
        CONN_NAMES+=("$_conn")
        CONN_DEVICES+=("$_dev")
    done < <(nmcli -t -f DEVICE,TYPE dev status 2>/dev/null || true)
}

_show_interface_table() {
    printf "\n  %-4s %-22s %-12s %-8s %-22s %-16s\n" \
        "#" "Connection" "Device" "Method" "IP / Prefix" "Gateway"
    printf "  %s\n" "$(printf '%.0s─' {1..88})"

    local i=0
    local _cname
    for _cname in "${CONN_NAMES[@]}"; do
        local _dev="${CONN_DEVICES[$i]}"
        local _method _addr _gw
        _method=$(nmcli -g ipv4.method   con show "$_cname" 2>/dev/null || echo "?")
        _addr=$(  nmcli -g ipv4.addresses con show "$_cname" 2>/dev/null | head -1 || echo "")
        _gw=$(    nmcli -g ipv4.gateway   con show "$_cname" 2>/dev/null || echo "")
        [[ "$_method" == "auto"   ]] && _method="dhcp"
        [[ "$_method" == "manual" ]] && _method="static"
        [[ -z "$_addr" ]] && _addr="(none)"
        [[ -z "$_gw"   ]] && _gw="(none)"
        printf "  %-4s %-22s %-12s %-8s %-22s %-16s\n" \
            "$((i + 1))" "$_cname" "$_dev" "$_method" "$_addr" "$_gw"
        i=$(( i + 1 ))
    done
    echo ""
}

# =============================================================================
# Action: View existing IP settings
# =============================================================================

action_show_ip() {
    _header "Existing IP Settings — Live System State"

    if ! command_exists nmcli; then
        log_error "nmcli not found. Ensure NetworkManager is installed and running."
        return
    fi

    _load_interfaces

    if [[ ${#CONN_NAMES[@]} -eq 0 ]]; then
        log_warn "No managed ethernet/Wi-Fi connections found."
        return
    fi

    local i=0
    local _cname
    for _cname in "${CONN_NAMES[@]}"; do
        local _dev="${CONN_DEVICES[$i]}"

        # Method from NM profile (auto = DHCP, manual = static).
        local _method
        _method=$(nmcli -g ipv4.method con show "$_cname" 2>/dev/null || echo "unknown")
        [[ "$_method" == "auto"   ]] && _method="DHCP"
        [[ "$_method" == "manual" ]] && _method="Static"

        # Live IP and prefix from the kernel — works for both DHCP and static.
        local _live_addr _live_ip _live_prefix _live_mask
        _live_addr=$(ip -4 addr show dev "$_dev" 2>/dev/null \
            | awk '/inet /{print $2}' | head -1 || echo "")
        _live_ip=$(    echo "$_live_addr" | cut -d/ -f1)
        _live_prefix=$(echo "$_live_addr" | cut -d/ -f2)

        if [[ -n "$_live_prefix" && "$_live_prefix" =~ ^[0-9]+$ ]]; then
            _live_mask=$(_prefix_to_mask "$_live_prefix")
        else
            _live_ip="(not assigned)"
            _live_prefix="—"
            _live_mask="—"
        fi

        # Live default gateway from the kernel routing table for this device.
        local _live_gw
        _live_gw=$(ip route show dev "$_dev" 2>/dev/null \
            | awk '/default/{print $3}' | head -1 || echo "")
        [[ -z "$_live_gw" ]] && _live_gw="(none)"

        # Live DNS — nmcli dev show carries DHCP-assigned entries alongside
        # any statically configured ones; pipe-separated in terse mode.
        local _dns_raw _dns1 _dns2
        _dns_raw=$(nmcli -g IP4.DNS dev show "$_dev" 2>/dev/null \
            | tr '|' ' ' | tr -s ' ' | sed 's/^ //;s/ $//' || echo "")
        _dns1=$(echo "$_dns_raw" | awk '{print $1}')
        _dns2=$(echo "$_dns_raw" | awk '{print $2}')
        [[ -z "$_dns1" ]] && _dns1="(none)"

        printf "  ┄┄ %s  (%s) ┄┄\n" "$_cname" "$_dev"
        printf "    %-16s %s\n" "Method:"        "$_method"
        printf "    %-16s %s\n" "IP Address:"    "$_live_ip"
        printf "    %-16s %s  (/%s)\n" "Subnet Mask:" "$_live_mask" "$_live_prefix"
        printf "    %-16s %s\n" "Gateway:"       "$_live_gw"
        printf "    %-16s %s\n" "Primary DNS:"   "$_dns1"
        printf "    %-16s %s\n" "Secondary DNS:" "${_dns2:-(none)}"
        echo ""

        i=$(( i + 1 ))
    done
}

# =============================================================================
# Action: Set IP address
# =============================================================================

action_set_ip() {
    _header "Set IP Address"

    if ! command_exists nmcli; then
        log_error "nmcli not found. Install and start NetworkManager to use this feature."
        return
    fi

    _load_interfaces

    if [[ ${#CONN_NAMES[@]} -eq 0 ]]; then
        log_warn "No managed ethernet/Wi-Fi connections found."
        log_warn "Ensure NetworkManager is running:  systemctl start NetworkManager"
        return
    fi

    _show_interface_table

    # --- Interface selection ---
    local _sel _cname _dev
    while true; do
        read -rp "  Select interface [1-${#CONN_NAMES[@]}]: " _sel
        if [[ "$_sel" =~ ^[0-9]+$ ]] && (( _sel >= 1 && _sel <= ${#CONN_NAMES[@]} )); then
            _cname="${CONN_NAMES[$(( _sel - 1 ))]}"
            _dev="${CONN_DEVICES[$(( _sel - 1 ))]}"
            break
        fi
        echo "  Invalid selection."
    done

    echo ""
    echo "  Interface : $_cname  ($_dev)"
    echo ""

    # Warn if the user is connected over SSH (any interface).
    if [[ -n "${SSH_CLIENT:-}" ]]; then
        echo -e "  ${YELLOW}Warning: you are connected via SSH.  Changing the active interface's${NC}"
        echo -e "  ${YELLOW}address may disconnect your session.${NC}"
        echo ""
    fi

    # --- Read current profile values to use as defaults ---
    local _cur_method _cur_ip_full _cur_ip _cur_prefix _cur_gw _cur_dns_raw _cur_dns1 _cur_dns2
    _cur_method=$(   nmcli -g ipv4.method    con show "$_cname" 2>/dev/null || echo "auto")
    _cur_ip_full=$(  nmcli -g ipv4.addresses con show "$_cname" 2>/dev/null | head -1 || echo "")
    _cur_ip=$(       echo "$_cur_ip_full" | cut -d/ -f1)
    _cur_prefix=$(   echo "$_cur_ip_full" | cut -d/ -f2 | awk '{print $1}')
    _cur_gw=$(       nmcli -g ipv4.gateway   con show "$_cname" 2>/dev/null || echo "")
    _cur_dns_raw=$(  nmcli -g ipv4.dns       con show "$_cname" 2>/dev/null \
                     | tr ',|' ' ' | tr -s ' ' | sed 's/^ //;s/ $//' || echo "")
    _cur_dns1=$(echo "$_cur_dns_raw" | awk '{print $1}')
    _cur_dns2=$(echo "$_cur_dns_raw" | awk '{print $2}')
    [[ -z "$_cur_prefix" ]] && _cur_prefix="24"

    # --- Method selection ---
    echo "  Address method:"
    echo "    1) DHCP    — obtain address automatically from the network"
    echo "    2) Static  — assign a fixed IP address, prefix, gateway, and DNS"
    echo ""
    local _method_choice
    while true; do
        read -rp "  Enter choice [1/2, default=1]: " _method_choice
        _method_choice="${_method_choice:-1}"
        case "$_method_choice" in
            1|2) break ;;
            *) echo "  Enter 1 or 2." ;;
        esac
    done
    echo ""

    if [[ "$_method_choice" == "1" ]]; then
        # ------------------------------------------------------------------ DHCP
        read -rp "  Set $_cname to DHCP and apply? [Y/n]: " _ok
        [[ "${_ok,,}" =~ ^n ]] && { log_info "Cancelled."; return; }
        echo ""

        nmcli con mod "$_cname" \
            ipv4.method    auto \
            ipv4.addresses "" \
            ipv4.gateway   "" \
            ipv4.dns       ""
        nmcli con up "$_cname" 2>/dev/null || true
        log_info "$_cname: switched to DHCP."
        _save_artifact "$_cname" "$_dev" "dhcp" "" "" "" ""
    else
        # ------------------------------------------------------------------ Static
        local _new_ip _new_prefix _new_gw _new_dns1 _new_dns2

        _prompt_ip "IP address"      _new_ip     "$_cur_ip"
        _prompt_prefix               _new_prefix "$_cur_prefix"
        echo ""
        _prompt_ip "Default gateway" _new_gw     "$_cur_gw"
        echo ""
        _prompt_ip "Primary DNS"     _new_dns1   "${_cur_dns1:-8.8.8.8}"
        echo ""
        # Secondary DNS is optional — press Enter to skip.
        _new_dns2=""
        while true; do
            if [[ -n "$_cur_dns2" ]]; then
                read -rp "  Secondary DNS (optional) [$_cur_dns2]: " _new_dns2
                _new_dns2="${_new_dns2:-$_cur_dns2}"
            else
                read -rp "  Secondary DNS (optional, Enter to skip): " _new_dns2
            fi
            [[ -z "$_new_dns2" ]] && break
            _validate_ip "$_new_dns2" && break
            echo "  Invalid address. Enter a dotted-decimal address or press Enter to skip."
        done
        echo ""

        echo "  ── Summary ──────────────────────────────────────────────"
        printf "    %-16s %s/%s\n" "IP / Prefix:"   "$_new_ip" "$_new_prefix"
        printf "    %-16s %s\n"    "Gateway:"        "$_new_gw"
        printf "    %-16s %s\n"    "Primary DNS:"    "$_new_dns1"
        printf "    %-16s %s\n"    "Secondary DNS:"  "${_new_dns2:-(none)}"
        echo "  ─────────────────────────────────────────────────────────"
        echo ""
        read -rp "  Apply to $_cname ($_dev)? [Y/n]: " _ok
        [[ "${_ok,,}" =~ ^n ]] && { log_info "Cancelled."; return; }
        echo ""

        # nmcli accepts space-separated DNS addresses as a single value.
        local _dns_arg="$_new_dns1"
        [[ -n "$_new_dns2" ]] && _dns_arg="$_new_dns1 $_new_dns2"

        nmcli con mod "$_cname" \
            ipv4.method    manual \
            ipv4.addresses "${_new_ip}/${_new_prefix}" \
            ipv4.gateway   "$_new_gw" \
            ipv4.dns       "$_dns_arg"
        nmcli con up "$_cname" 2>/dev/null || true
        log_info "$_cname: static ${_new_ip}/${_new_prefix}, gw ${_new_gw}, dns ${_dns_arg}."
        _save_artifact "$_cname" "$_dev" "static" "${_new_ip}/${_new_prefix}" "$_new_gw" "$_new_dns1" "$_new_dns2"
    fi
}

# =============================================================================
# Artifact
# =============================================================================

_save_artifact() {
    local conn="$1" device="$2" method="$3" address="$4" gateway="$5" dns1="$6" dns2="${7:-}"
    local artifact
    artifact=$(artifact_file "networking")

    cat > "$artifact" <<EOF
NETWORKING CONFIGURATION REPORT
=================================
Generated  : $(date '+%Y-%m-%d %H:%M:%S')
Hostname   : $(hostname)
OS         : $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
Applied by : hardening/modules/networking/harden.sh

IP CONFIGURATION
----------------
  Connection   : $conn
  Device       : $device
  Method       : $method
  Address      : ${address:-(assigned via DHCP)}
  Gateway      : ${gateway:-(assigned via DHCP)}
  Primary DNS  : ${dns1:-(assigned via DHCP)}
  Secondary DNS: ${dns2:-(none)}

LIVE INTERFACE STATE  (ip addr show $device)
---------------------------------------------
$(ip addr show "$device" 2>/dev/null | sed 's/^/  /' || echo "  (unavailable)")

LIVE ROUTING  (ip route show dev $device)
------------------------------------------
$(ip route show dev "$device" 2>/dev/null | sed 's/^/  /' || echo "  (unavailable)")
EOF
    log_info "Artifact saved: $artifact"
}

# =============================================================================
# Main TUI loop
# =============================================================================

log_section "Networking"

while true; do
    _header "Networking — Interface Configuration"
    echo "  Configure network interfaces using NetworkManager (nmcli)."
    echo ""
    echo "    1) View existing IP settings  — show current IP, method, mask, gateway, DNS"
    echo "    2) Set IP address             — configure static IP or DHCP on an interface"
    echo "    3) Exit"
    echo ""
    read -rp "  Selection [1-3, default=1]: " _sel
    echo ""

    case "${_sel:-1}" in
        1) action_show_ip ;;
        2) action_set_ip ;;
        3) log_info "Exiting networking module."; exit 0 ;;
        *) echo "  Invalid selection." ;;
    esac

    echo ""
    read -rp "  Return to networking menu? [Y/n]: " _again
    [[ "${_again,,}" =~ ^n ]] && break
done
