#!/usr/bin/env bash
# =============================================================================
# Module  : firewall
# Purpose : Enable and configure firewalld — manage zones, services, and
#           port access rules on Rocky Linux 9 / RHEL 9.
#
# This module performs the following actions:
#
#   1. STATUS VIEW
#      Shows the current firewalld service state (running/stopped), the
#      default zone, active zones, and the full ruleset for the default
#      zone (services, ports, protocols, and rich rules).
#
#   2. ENABLE / DISABLE
#      Starts and enables firewalld at boot (systemctl enable --now), or
#      stops and disables it (systemctl disable --now).  Disabling shows
#      a warning and requires explicit confirmation, as it removes all
#      active packet filtering.
#
#   3. ADD SERVICE
#      Allows a named firewalld service (e.g. ssh, http, https) in the
#      default zone.  Presents a quick-pick list of common services plus
#      a free-entry option.  Applied with --permanent and --reload.
#
#   4. REMOVE SERVICE
#      Removes a currently-allowed service from the default zone.
#      Extra confirmation is required before removing 'ssh' to prevent
#      accidental lockout.  Applied with --permanent and --reload.
#
#   5. OPEN PORT
#      Opens a specific port/protocol (e.g. 8080/tcp) in the default
#      zone.  Port number (1–65535) and protocol (tcp/udp) are validated
#      before the rule is applied.  Applied with --permanent and --reload.
#
#   6. CLOSE PORT
#      Removes a currently-open port from the default zone.  Presents
#      only ports that are explicitly open (services are managed
#      separately).  Applied with --permanent and --reload.
#
#   7. SET DEFAULT ZONE
#      Changes the firewalld default zone.  All available zones are
#      listed; the operator selects by number.
#
# Requirements:
#   firewalld / firewall-cmd  — standard on Rocky Linux 9 / RHEL 9
#   systemctl                 — systemd service manager
#
# Files modified:
#   firewalld zone files under /etc/firewalld/zones/ (via firewall-cmd)
#
# Artifacts written:
#   hardening/artifacts/firewall/<hostname>_<timestamp>.txt
#
# Must be run as root (enforced by check_root in master.sh).
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../config.conf"
source "$SCRIPT_DIR/../../lib/common.sh"

check_root

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

_require_firewalld() {
    if ! command_exists firewall-cmd; then
        log_error "firewall-cmd not found.  Install firewalld:  dnf install firewalld"
        return 1
    fi
}

_firewalld_running() {
    systemctl is-active --quiet firewalld 2>/dev/null
}

_default_zone() {
    firewall-cmd --get-default-zone 2>/dev/null || echo "public"
}

# =============================================================================
# Action: View firewall status
# =============================================================================

action_show_status() {
    _header "Firewall Status"

    _require_firewalld || return

    local _zone
    if _firewalld_running; then
        printf "  %-20s " "Service state:"
        echo -e "${GREEN}running${NC}"
        _zone=$(_default_zone)
        printf "  %-20s %s\n" "Default zone:" "$_zone"
        echo ""

        echo "  Active zones:"
        firewall-cmd --get-active-zones 2>/dev/null | sed 's/^/    /' || true
        echo ""

        printf "  Rules for zone '%s':\n" "$_zone"
        printf "  %s\n" "$(printf '%.0s─' {1..58})"
        firewall-cmd --list-all --zone="$_zone" 2>/dev/null | sed 's/^/  /' || true
    else
        printf "  %-20s " "Service state:"
        echo -e "${RED}stopped${NC}"
        echo ""
        echo "  Firewall is not running — no packet filtering is active."
        echo "  Use option 2 to enable it."
    fi
    echo ""
}

# =============================================================================
# Action: Enable / disable firewall
# =============================================================================

action_toggle_firewall() {
    _header "Enable / Disable Firewall"

    _require_firewalld || return

    if _firewalld_running; then
        echo "  Firewall is currently running."
        echo ""
        echo -e "  ${YELLOW}Warning: disabling the firewall removes all active packet filtering.${NC}"
        echo -e "  ${YELLOW}Only do this if the system is on a trusted, isolated network.${NC}"
        echo ""
        read -rp "  Stop and disable firewalld? [y/N]: " _ok
        [[ "${_ok,,}" =~ ^y ]] || { log_info "Cancelled."; return; }
        systemctl disable --now firewalld
        log_info "firewalld stopped and disabled at boot."
    else
        echo "  Firewall is currently stopped."
        echo ""
        read -rp "  Start and enable firewalld? [Y/n]: " _ok
        [[ "${_ok,,}" =~ ^n ]] && { log_info "Cancelled."; return; }
        systemctl enable --now firewalld
        log_info "firewalld started and enabled at boot."
    fi
    _save_artifact
}

# =============================================================================
# Action: Add service
# =============================================================================

action_add_service() {
    _header "Add Service"

    _require_firewalld || return

    if ! _firewalld_running; then
        log_warn "firewalld is not running.  Enable it first (option 2)."
        return
    fi

    local _zone
    _zone=$(_default_zone)

    echo "  Default zone: $_zone"
    echo ""
    echo "  Currently allowed services:"
    firewall-cmd --list-services --zone="$_zone" 2>/dev/null \
        | tr ' ' '\n' | grep -v '^$' | sed 's/^/    /' || echo "    (none)"
    echo ""

    local -a _common=(ssh http https ftp smtp dns ntp samba cockpit rdp dhcpv6-client)
    local -A _svc_ports=(
        [ssh]="22/tcp"
        [http]="80/tcp"
        [https]="443/tcp"
        [ftp]="21/tcp (ctrl), 20/tcp (data)"
        [smtp]="25/tcp"
        [dns]="53/tcp + 53/udp"
        [ntp]="123/udp"
        [samba]="137-139/udp+tcp, 445/tcp"
        [cockpit]="9090/tcp"
        [rdp]="3389/tcp"
        [dhcpv6-client]="546/udp"
    )
    local -A _svc_desc=(
        [ssh]="Secure Shell remote login"
        [http]="HTTP web server (unencrypted)"
        [https]="HTTPS web server (TLS encrypted)"
        [ftp]="File Transfer Protocol"
        [smtp]="Email delivery (server-to-server)"
        [dns]="Domain Name System"
        [ntp]="Network Time Protocol clock sync"
        [samba]="Windows file and print sharing (SMB/CIFS)"
        [cockpit]="Web-based server administration console"
        [rdp]="Remote Desktop Protocol (Windows)"
        [dhcpv6-client]="DHCPv6 client — receive IPv6 address from router"
    )

    echo "  Common services:"
    printf "  %-4s %-16s %-30s %s\n" "No." "Service" "Ports" "Description"
    printf "  %s\n" "$(printf '%.0s─' {1..82})"
    local i=1
    for _s in "${_common[@]}"; do
        printf "  %-4s %-16s %-30s %s\n" \
            "$i)" "$_s" "${_svc_ports[$_s]}" "${_svc_desc[$_s]}"
        i=$(( i + 1 ))
    done
    printf "  %-4s %-16s %-30s %s\n" "c)" "custom" "-" "Enter any firewalld service name"
    echo ""

    local _svc=""
    while true; do
        read -rp "  Select service to add: " _sel
        if [[ "$_sel" =~ ^[0-9]+$ ]] && (( _sel >= 1 && _sel <= ${#_common[@]} )); then
            _svc="${_common[$(( _sel - 1 ))]}"
            break
        elif [[ "${_sel,,}" == "c" ]]; then
            read -rp "  Custom service name: " _svc
            [[ -n "$_svc" ]] && break
            echo "  Name cannot be empty."
        else
            echo "  Invalid selection."
        fi
    done

    echo ""
    read -rp "  Add service '$_svc' to zone '$_zone'? [Y/n]: " _ok
    [[ "${_ok,,}" =~ ^n ]] && { log_info "Cancelled."; return; }

    if firewall-cmd --query-service="$_svc" --zone="$_zone" --permanent &>/dev/null; then
        log_info "'$_svc' is already allowed in zone '$_zone'."
        return
    fi

    firewall-cmd --add-service="$_svc" --zone="$_zone" --permanent
    firewall-cmd --reload
    log_info "Service '$_svc' added to zone '$_zone' (permanent)."
    _save_artifact
}

# =============================================================================
# Action: Remove service
# =============================================================================

action_remove_service() {
    _header "Remove Service"

    _require_firewalld || return

    if ! _firewalld_running; then
        log_warn "firewalld is not running.  Enable it first (option 2)."
        return
    fi

    local _zone
    _zone=$(_default_zone)

    echo "  Default zone: $_zone"
    echo ""

    local -a _svcs
    mapfile -t _svcs < <(firewall-cmd --list-services --zone="$_zone" 2>/dev/null \
        | tr ' ' '\n' | grep -v '^$' || true)

    if [[ ${#_svcs[@]} -eq 0 ]]; then
        log_info "No services are currently allowed in zone '$_zone'."
        return
    fi

    echo "  Allowed services in zone '$_zone':"
    local i=1
    for _s in "${_svcs[@]}"; do
        printf "    %2s) %s\n" "$i" "$_s"
        i=$(( i + 1 ))
    done
    echo ""

    local _svc=""
    while true; do
        read -rp "  Select service to remove [1-${#_svcs[@]}]: " _sel
        if [[ "$_sel" =~ ^[0-9]+$ ]] && (( _sel >= 1 && _sel <= ${#_svcs[@]} )); then
            _svc="${_svcs[$(( _sel - 1 ))]}"
            break
        fi
        echo "  Invalid selection."
    done

    echo ""
    if [[ "$_svc" == "ssh" ]]; then
        echo -e "  ${YELLOW}Warning: removing SSH will block all future SSH connections.${NC}"
        echo -e "  ${YELLOW}Ensure you have console/out-of-band access before continuing.${NC}"
        echo ""
        read -rp "  Remove SSH service anyway? [y/N]: " _ssh_ok
        [[ "${_ssh_ok,,}" =~ ^y ]] || { log_info "Cancelled."; return; }
    else
        read -rp "  Remove service '$_svc' from zone '$_zone'? [y/N]: " _ok
        [[ "${_ok,,}" =~ ^y ]] || { log_info "Cancelled."; return; }
    fi

    firewall-cmd --remove-service="$_svc" --zone="$_zone" --permanent
    firewall-cmd --reload
    log_info "Service '$_svc' removed from zone '$_zone' (permanent)."
    _save_artifact
}

# =============================================================================
# Action: Open port
# =============================================================================

action_open_port() {
    _header "Open Port"

    _require_firewalld || return

    if ! _firewalld_running; then
        log_warn "firewalld is not running.  Enable it first (option 2)."
        return
    fi

    local _zone
    _zone=$(_default_zone)

    echo "  Default zone: $_zone"
    echo ""
    echo "  Currently open ports:"
    local _cur_ports
    _cur_ports=$(firewall-cmd --list-ports --zone="$_zone" 2>/dev/null || echo "")
    if [[ -z "$_cur_ports" ]]; then
        echo "    (none)"
    else
        echo "$_cur_ports" | tr ' ' '\n' | grep -v '^$' | sed 's/^/    /' || true
    fi
    echo ""

    local _port _proto
    while true; do
        read -rp "  Port number (1-65535): " _port
        if [[ "$_port" =~ ^[0-9]+$ ]] && (( _port >= 1 && _port <= 65535 )); then
            break
        fi
        echo "  Must be an integer between 1 and 65535."
    done

    while true; do
        read -rp "  Protocol [tcp/udp, default=tcp]: " _proto
        _proto="${_proto:-tcp}"
        case "${_proto,,}" in
            tcp|udp) _proto="${_proto,,}"; break ;;
            *) echo "  Enter tcp or udp." ;;
        esac
    done

    local _rule="${_port}/${_proto}"
    echo ""
    read -rp "  Open port $_rule in zone '$_zone'? [Y/n]: " _ok
    [[ "${_ok,,}" =~ ^n ]] && { log_info "Cancelled."; return; }

    if firewall-cmd --query-port="$_rule" --zone="$_zone" --permanent &>/dev/null; then
        log_info "Port $_rule is already open in zone '$_zone'."
        return
    fi

    firewall-cmd --add-port="$_rule" --zone="$_zone" --permanent
    firewall-cmd --reload
    log_info "Port $_rule opened in zone '$_zone' (permanent)."
    _save_artifact
}

# =============================================================================
# Action: Close port
# =============================================================================

action_close_port() {
    _header "Close Port"

    _require_firewalld || return

    if ! _firewalld_running; then
        log_warn "firewalld is not running.  Enable it first (option 2)."
        return
    fi

    local _zone
    _zone=$(_default_zone)

    echo "  Default zone: $_zone"
    echo ""

    local -a _ports
    mapfile -t _ports < <(firewall-cmd --list-ports --zone="$_zone" 2>/dev/null \
        | tr ' ' '\n' | grep -v '^$' || true)

    if [[ ${#_ports[@]} -eq 0 ]]; then
        log_info "No custom ports are currently open in zone '$_zone'."
        return
    fi

    echo "  Open ports in zone '$_zone':"
    local i=1
    for _p in "${_ports[@]}"; do
        printf "    %2s) %s\n" "$i" "$_p"
        i=$(( i + 1 ))
    done
    echo ""

    local _rule=""
    while true; do
        read -rp "  Select port to close [1-${#_ports[@]}]: " _sel
        if [[ "$_sel" =~ ^[0-9]+$ ]] && (( _sel >= 1 && _sel <= ${#_ports[@]} )); then
            _rule="${_ports[$(( _sel - 1 ))]}"
            break
        fi
        echo "  Invalid selection."
    done

    echo ""
    read -rp "  Close port '$_rule' in zone '$_zone'? [y/N]: " _ok
    [[ "${_ok,,}" =~ ^y ]] || { log_info "Cancelled."; return; }

    firewall-cmd --remove-port="$_rule" --zone="$_zone" --permanent
    firewall-cmd --reload
    log_info "Port '$_rule' closed in zone '$_zone' (permanent)."
    _save_artifact
}

# =============================================================================
# Action: Set default zone
# =============================================================================

action_set_zone() {
    _header "Set Default Zone"

    _require_firewalld || return

    local _current_zone
    _current_zone=$(_default_zone)
    printf "  %-22s %s\n" "Current default zone:" "$_current_zone"
    echo ""

    local -a _zones
    mapfile -t _zones < <(firewall-cmd --get-zones 2>/dev/null \
        | tr ' ' '\n' | grep -v '^$' || true)

    echo "  Available zones:"
    local i=1
    for _z in "${_zones[@]}"; do
        printf "    %2s) %-12s" "$i" "$_z"
        # Annotate well-known zones so the operator knows what they mean.
        case "$_z" in
            public)   echo " — default; untrusted sources, only explicitly allowed services" ;;
            internal) echo " — internal network; more trusted than public" ;;
            trusted)  echo " — all connections accepted (use with caution)" ;;
            drop)     echo " — all incoming packets dropped with no reply" ;;
            block)    echo " — incoming connections rejected with icmp-host-prohibited" ;;
            dmz)      echo " — DMZ; limited access to internal network" ;;
            external) echo " — external network; NAT masquerading enabled" ;;
            home)     echo " — home network; most other systems trusted" ;;
            work)     echo " — work network; most other systems trusted" ;;
            *)        echo "" ;;
        esac
        i=$(( i + 1 ))
    done
    echo ""

    local _new_zone=""
    while true; do
        read -rp "  Select new default zone [1-${#_zones[@]}]: " _sel
        if [[ "$_sel" =~ ^[0-9]+$ ]] && (( _sel >= 1 && _sel <= ${#_zones[@]} )); then
            _new_zone="${_zones[$(( _sel - 1 ))]}"
            break
        fi
        echo "  Invalid selection."
    done

    echo ""
    read -rp "  Set default zone to '$_new_zone'? [Y/n]: " _ok
    [[ "${_ok,,}" =~ ^n ]] && { log_info "Cancelled."; return; }

    firewall-cmd --set-default-zone="$_new_zone"
    log_info "Default zone set to '$_new_zone'."
    _save_artifact
}

# =============================================================================
# Action: ICMP / ping control
# =============================================================================

action_icmp_control() {
    _header "ICMP / Ping Control"

    _require_firewalld || return

    if ! _firewalld_running; then
        log_warn "firewalld is not running.  Enable it first (option 2)."
        return
    fi

    local _zone
    _zone=$(_default_zone)

    # Current state: is echo-request blocked?
    local _blocked=false
    if firewall-cmd --query-icmp-block=echo-request --zone="$_zone" --permanent \
            &>/dev/null; then
        _blocked=true
    fi

    # Current ICMP blocks for context.
    local _all_blocks
    _all_blocks=$(firewall-cmd --list-icmp-blocks --zone="$_zone" 2>/dev/null || echo "")

    echo "  Default zone: $_zone"
    echo ""
    printf "  %-24s %s\n" "Incoming ping (echo-request):" \
        "$( [[ "$_blocked" == true ]] && echo "BLOCKED" || echo "allowed")"
    echo ""

    if [[ -n "$_all_blocks" ]]; then
        echo "  All ICMP types currently blocked in zone '$_zone':"
        echo "$_all_blocks" | tr ' ' '\n' | grep -v '^$' | sed 's/^/    /' || true
        echo ""
    fi

    echo "  Options:"
    echo "    1) Allow ping    — remove the echo-request ICMP block (servers respond to ping)"
    echo "    2) Block ping    — add an echo-request ICMP block (server does not respond to ping)"
    echo "    3) Back"
    echo ""
    read -rp "  Selection [1-3]: " _sel
    echo ""

    case "${_sel:-3}" in
        1)
            if [[ "$_blocked" == false ]]; then
                log_info "Ping is already allowed in zone '$_zone'."
                return
            fi
            firewall-cmd --remove-icmp-block=echo-request --zone="$_zone" --permanent
            firewall-cmd --reload
            log_info "Ping (echo-request) allowed in zone '$_zone' (permanent)."
            _save_artifact
            ;;
        2)
            if [[ "$_blocked" == true ]]; then
                log_info "Ping is already blocked in zone '$_zone'."
                return
            fi
            firewall-cmd --add-icmp-block=echo-request --zone="$_zone" --permanent
            firewall-cmd --reload
            log_info "Ping (echo-request) blocked in zone '$_zone' (permanent)."
            _save_artifact
            ;;
        3)
            return
            ;;
        *)
            echo "  Invalid selection."
            ;;
    esac
}

# =============================================================================
# Artifact
# =============================================================================

_save_artifact() {
    local artifact
    artifact=$(artifact_file "firewall")

    local _state _zone _enabled
    if _firewalld_running; then
        _state="running"
        _zone=$(_default_zone)
    else
        _state="stopped"
        _zone="N/A"
    fi
    _enabled=$(systemctl is-enabled firewalld 2>/dev/null || echo "unknown")

    cat > "$artifact" <<EOF
FIREWALL CONFIGURATION REPORT
================================
Generated  : $(date '+%Y-%m-%d %H:%M:%S')
Hostname   : $(hostname)
OS         : $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
Applied by : hardening/modules/firewall/harden.sh

SERVICE STATE
-------------
  State   : $_state
  Enabled : $_enabled

DEFAULT ZONE
------------
  Zone : $_zone

FULL RULESET  (firewall-cmd --list-all)
-----------------------------------------
$(firewall-cmd --list-all 2>/dev/null | sed 's/^/  /' || echo "  (firewalld not running)")
EOF
    log_info "Artifact saved: $artifact"
}

# =============================================================================
# Main TUI loop
# =============================================================================

log_section "Firewall"

while true; do
    _header "Firewall — firewalld Configuration"
    echo "  Manage firewalld zones, services, and port rules."
    echo ""
    echo "    1) View firewall status  — running state, zone, allowed services and ports"
    echo "    2) Enable / disable      — start+enable or stop+disable firewalld"
    echo "    3) Add service           — allow a named service through the firewall"
    echo "    4) Remove service        — block a currently-allowed service"
    echo "    5) Open port             — allow a custom port/protocol"
    echo "    6) Close port            — block a currently-open port"
    echo "    7) ICMP / ping control   — allow or block incoming ping (echo-request)"
    echo "    8) Set default zone      — change the active firewalld zone"
    echo "    9) Exit"
    echo ""
    read -rp "  Selection [1-9, default=1]: " _sel
    echo ""

    case "${_sel:-1}" in
        1) action_show_status ;;
        2) action_toggle_firewall ;;
        3) action_add_service ;;
        4) action_remove_service ;;
        5) action_open_port ;;
        6) action_close_port ;;
        7) action_icmp_control ;;
        8) action_set_zone ;;
        9) log_info "Exiting firewall module."; exit 0 ;;
        *) echo "  Invalid selection." ;;
    esac

    echo ""
    read -rp "  Return to firewall menu? [Y/n]: " _again
    [[ "${_again,,}" =~ ^n ]] && break
done
