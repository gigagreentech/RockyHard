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
#   8. VIEW DROP PACKET LOG
#      Reads dropped/rejected packet entries from the kernel journal
#      (requires log-denied to be set via option 9).  Supports viewing
#      recent entries, following the live feed, or filtering by source IP.
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

# Validate a plain IPv4 address (four dot-separated octets, each 0-255).
_validate_ip() {
    local _ip="$1"
    local _oct
    IFS='.' read -r -a _oct <<< "$_ip"
    [[ ${#_oct[@]} -eq 4 ]] || return 1
    local _o
    for _o in "${_oct[@]}"; do
        [[ "$_o" =~ ^[0-9]+$ ]]           || return 1
        (( _o >= 0 && _o <= 255 ))         || return 1
    done
}

# Validate a plain IP address or CIDR notation (e.g. 10.0.0.0/24 or 10.0.0.5).
_validate_cidr() {
    local _input="$1" _ip _pfx
    if [[ "$_input" == */* ]]; then
        _ip="${_input%/*}"
        _pfx="${_input#*/}"
        _validate_ip "$_ip" || return 1
        [[ "$_pfx" =~ ^[0-9]+$ ]] && (( _pfx >= 0 && _pfx <= 32 )) || return 1
    else
        _validate_ip "$_input" || return 1
    fi
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
        printf "  %-20s %s\n" "Drop logging:" \
            "$(firewall-cmd --get-log-denied 2>/dev/null || echo "unknown")"
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
    local _source=""
    read -rp "  Restrict '$_svc' to a specific source IP or subnet? [y/N]: " _restrict
    if [[ "${_restrict,,}" =~ ^y ]]; then
        while true; do
            read -rp "  Source IP or CIDR (e.g. 192.168.1.0/24 or 10.0.0.5): " _source
            _validate_cidr "$_source" && break
            echo "  Invalid address. Examples: 192.168.1.0/24   10.10.0.5"
        done
    fi

    echo ""
    if [[ -n "$_source" ]]; then
        local _rule="rule family=\"ipv4\" source address=\"${_source}\" service name=\"${_svc}\" accept"
        echo "  ── Rich rule ────────────────────────────────────────────"
        printf "  %s\n" "$_rule"
        echo "  ─────────────────────────────────────────────────────────"
        echo ""
        read -rp "  Apply to zone '$_zone'? [Y/n]: " _ok
        [[ "${_ok,,}" =~ ^n ]] && { log_info "Cancelled."; return; }
        firewall-cmd --add-rich-rule="$_rule" --zone="$_zone" --permanent
        firewall-cmd --reload
        log_info "Service '$_svc' restricted to source '$_source' in zone '$_zone' (permanent)."
    else
        read -rp "  Add service '$_svc' to zone '$_zone'? [Y/n]: " _ok
        [[ "${_ok,,}" =~ ^n ]] && { log_info "Cancelled."; return; }
        if firewall-cmd --query-service="$_svc" --zone="$_zone" --permanent &>/dev/null; then
            log_info "'$_svc' is already allowed in zone '$_zone'."
            return
        fi
        firewall-cmd --add-service="$_svc" --zone="$_zone" --permanent
        firewall-cmd --reload
        log_info "Service '$_svc' added to zone '$_zone' (permanent)."
    fi
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
# Action: Source IP restrictions
# =============================================================================

action_source_restrict() {
    _header "Source IP Restrictions"

    _require_firewalld || return

    if ! _firewalld_running; then
        log_warn "firewalld is not running.  Enable it first (option 2)."
        return
    fi

    local _zone
    _zone=$(_default_zone)

    local -a _rich_rules=()

    while true; do
        # Refresh list each iteration so removals are reflected immediately.
        mapfile -t _rich_rules < <(firewall-cmd --list-rich-rules --zone="$_zone" \
            2>/dev/null | grep -i "source address" || true)

        echo "  Default zone: $_zone"
        echo ""
        echo "  Current source restrictions:"
        if [[ ${#_rich_rules[@]} -eq 0 ]]; then
            echo "    (none)"
        else
            local _j=1
            for _r in "${_rich_rules[@]}"; do
                printf "    %2s) %s\n" "$_j" "$_r"
                _j=$(( _j + 1 ))
            done
        fi
        echo ""
        echo -e "  ${YELLOW}Note: for a restriction to work, the service must NOT also be in${NC}"
        echo -e "  ${YELLOW}the open services list — remove it with option 4 first.${NC}"
        echo ""
        echo "    1) Add restriction    — allow a service or port from a specific IP/subnet only"
        echo "    2) Remove restriction — delete an existing source restriction"
        echo "    3) Back"
        echo ""
        read -rp "  Selection [1-3, default=3]: " _sub
        echo ""

        case "${_sub:-3}" in
            1)
                # -------------------------------------------------------- type
                local _target_svc="" _target_port="" _target_proto=""
                local _type_ok=false
                while [[ "$_type_ok" == false ]]; do
                    read -rp "  Restrict a (s)ervice or (p)ort? [s/p]: " _type
                    case "${_type,,}" in
                        s|service) _type_ok=true ;;
                        p|port)    _type_ok=true ;;
                        *) echo "  Enter s or p." ;;
                    esac
                done
                echo ""

                case "${_type,,}" in
                    s|service)
                        local -a _common=(ssh http https ftp smtp dns ntp samba cockpit rdp dhcpv6-client)
                        echo "  Common services:"
                        local _k=1
                        for _s in "${_common[@]}"; do
                            printf "    %2s) %s\n" "$_k" "$_s"
                            _k=$(( _k + 1 ))
                        done
                        printf "    %2s) %s\n" "c" "Enter custom service name"
                        echo ""
                        while true; do
                            read -rp "  Select service: " _ssel
                            if [[ "$_ssel" =~ ^[0-9]+$ ]] && \
                               (( _ssel >= 1 && _ssel <= ${#_common[@]} )); then
                                _target_svc="${_common[$(( _ssel - 1 ))]}"
                                break
                            elif [[ "${_ssel,,}" == "c" ]]; then
                                read -rp "  Service name: " _target_svc
                                [[ -n "$_target_svc" ]] && break
                                echo "  Cannot be empty."
                            else
                                echo "  Invalid selection."
                            fi
                        done
                        # Warn if the service is also openly allowed in the zone.
                        if firewall-cmd --query-service="$_target_svc" \
                                --zone="$_zone" --permanent &>/dev/null; then
                            echo ""
                            echo -e "  ${YELLOW}Warning: '$_target_svc' is currently open to all sources.${NC}"
                            echo -e "  ${YELLOW}Use option 4 (Remove service) to limit it to this rule only.${NC}"
                        fi
                        ;;
                    p|port)
                        while true; do
                            read -rp "  Port number (1-65535): " _target_port
                            if [[ "$_target_port" =~ ^[0-9]+$ ]] && \
                               (( _target_port >= 1 && _target_port <= 65535 )); then
                                break
                            fi
                            echo "  Must be an integer between 1 and 65535."
                        done
                        while true; do
                            read -rp "  Protocol [tcp/udp, default=tcp]: " _target_proto
                            _target_proto="${_target_proto:-tcp}"
                            case "${_target_proto,,}" in
                                tcp|udp) _target_proto="${_target_proto,,}"; break ;;
                                *) echo "  Enter tcp or udp." ;;
                            esac
                        done
                        ;;
                esac

                # -------------------------------------------------- source IP
                echo ""
                local _source=""
                while true; do
                    read -rp "  Source IP or CIDR (e.g. 192.168.1.0/24 or 10.0.0.5): " _source
                    _validate_cidr "$_source" && break
                    echo "  Invalid address. Examples: 192.168.1.0/24   10.10.0.5"
                done

                # -------------------------------------------------- build rule
                local _rule=""
                if [[ -n "$_target_svc" ]]; then
                    _rule="rule family=\"ipv4\" source address=\"${_source}\" service name=\"${_target_svc}\" accept"
                else
                    _rule="rule family=\"ipv4\" source address=\"${_source}\" port port=\"${_target_port}\" protocol=\"${_target_proto}\" accept"
                fi

                echo ""
                echo "  ── Rich rule ────────────────────────────────────────────"
                printf "  %s\n" "$_rule"
                echo "  ─────────────────────────────────────────────────────────"
                echo ""
                read -rp "  Apply to zone '$_zone'? [Y/n]: " _ok
                [[ "${_ok,,}" =~ ^n ]] && { log_info "Cancelled."; echo ""; continue; }

                firewall-cmd --add-rich-rule="$_rule" --zone="$_zone" --permanent
                firewall-cmd --reload
                log_info "Source restriction added to zone '$_zone'."
                _save_artifact
                ;;

            2)
                if [[ ${#_rich_rules[@]} -eq 0 ]]; then
                    log_info "No source restrictions to remove."
                else
                    local _rsel=""
                    while true; do
                        read -rp "  Select restriction to remove [1-${#_rich_rules[@]}]: " _rsel
                        if [[ "$_rsel" =~ ^[0-9]+$ ]] && \
                           (( _rsel >= 1 && _rsel <= ${#_rich_rules[@]} )); then
                            break
                        fi
                        echo "  Invalid selection."
                    done
                    local _rem="${_rich_rules[$(( _rsel - 1 ))]}"
                    echo ""
                    printf "  Remove: %s\n" "$_rem"
                    echo ""
                    read -rp "  Confirm? [y/N]: " _ok
                    [[ "${_ok,,}" =~ ^y ]] || { log_info "Cancelled."; echo ""; continue; }
                    firewall-cmd --remove-rich-rule="$_rem" --zone="$_zone" --permanent
                    firewall-cmd --reload
                    log_info "Source restriction removed from zone '$_zone'."
                    _save_artifact
                fi
                ;;

            3) return ;;
            *) echo "  Invalid selection." ;;
        esac
        echo ""
    done
}

# =============================================================================
# Action: Configure drop logging
# =============================================================================

action_configure_logging() {
    _header "Configure Drop Logging"

    _require_firewalld || return

    local _current
    _current=$(firewall-cmd --get-log-denied 2>/dev/null || echo "unknown")
    printf "  %-22s %s\n" "Current log-denied:" "$_current"
    echo ""

    echo "  Log level:"
    echo "    1) off        — no logging (default)"
    echo "    2) all        — log all dropped and rejected packets"
    echo "    3) unicast    — log dropped unicast packets only"
    echo "    4) broadcast  — log dropped broadcast packets only"
    echo "    5) multicast  — log dropped multicast packets only"
    echo ""
    echo "  View logs with:  journalctl -f  or  grep kernel /var/log/messages"
    echo ""
    read -rp "  Select log level [1-5]: " _sel
    echo ""

    local _level
    case "${_sel:-}" in
        1) _level="off" ;;
        2) _level="all" ;;
        3) _level="unicast" ;;
        4) _level="broadcast" ;;
        5) _level="multicast" ;;
        *) echo "  Invalid selection."; return ;;
    esac

    read -rp "  Set log-denied to '$_level'? [Y/n]: " _ok
    [[ "${_ok,,}" =~ ^n ]] && { log_info "Cancelled."; return; }

    firewall-cmd --set-log-denied="$_level"
    log_info "Drop logging set to '$_level'. View with: journalctl -f"
    _save_artifact
}

# =============================================================================
# Action: View drop packet log
# =============================================================================

action_view_drop_log() {
    _header "View Drop Packet Log"

    _require_firewalld || return

    local _current
    _current=$(firewall-cmd --get-log-denied 2>/dev/null || echo "unknown")
    printf "  %-22s %s\n" "Current log-denied:" "$_current"
    echo ""

    if [[ "$_current" == "off" ]]; then
        echo -e "  ${YELLOW}Drop logging is currently disabled — no packets are being logged.${NC}"
        echo "  Use option 9 (Configure drop logging) to enable it first."
        echo ""
        return
    fi

    echo "  Options:"
    echo "    1) Recent entries   — last 100 dropped/rejected packets"
    echo "    2) Follow live      — stream new entries in real time (Ctrl+C to stop)"
    echo "    3) Filter by IP     — show drops from a specific source address"
    echo "    4) Email log        — send recent entries to an email address"
    echo "    5) Back"
    echo ""
    read -rp "  Selection [1-5, default=1]: " _sel
    echo ""

    case "${_sel:-1}" in
        1)
            echo "  Last 100 dropped/rejected packets:"
            printf "  %s\n" "$(printf '%.0s─' {1..58})"
            local _lines
            _lines=$(journalctl -k --no-pager -n 500 2>/dev/null \
                | grep 'SRC=' | tail -100 || true)
            if [[ -z "$_lines" ]]; then
                echo "  (no dropped packet entries found — packets may not have been dropped"
                echo "   since logging was enabled, or try increasing the journal window)"
            else
                echo "$_lines" | sed 's/^/  /'
            fi
            ;;
        2)
            echo "  Following drop log — press Ctrl+C to stop."
            echo ""
            journalctl -k -f 2>/dev/null \
                | grep --line-buffered 'SRC=' \
                | sed 's/^/  /' || true
            ;;
        3)
            local _filter_ip=""
            while true; do
                read -rp "  Source IP to filter (e.g. 203.0.113.5): " _filter_ip
                _validate_ip "$_filter_ip" && break
                echo "  Invalid IP address."
            done
            echo ""
            echo "  Dropped packets from $_filter_ip:"
            printf "  %s\n" "$(printf '%.0s─' {1..58})"
            local _filtered
            _filtered=$(journalctl -k --no-pager 2>/dev/null \
                | grep 'SRC=' | grep "SRC=${_filter_ip}" || true)
            if [[ -z "$_filtered" ]]; then
                echo "  (no entries found for source IP $_filter_ip)"
            else
                echo "$_filtered" | sed 's/^/  /'
            fi
            ;;
        4)
            local _msmtp_conf="/etc/msmtprc"
            if [[ ! -f "$_msmtp_conf" ]]; then
                log_warn "SMTP relay is not configured. Run Prerequisites > SMTP Relay first."
                return
            fi

            local _email_to=""
            while true; do
                read -rp "  Recipient email address: " _email_to
                [[ -n "$_email_to" ]] && break
                echo "  Address cannot be empty."
            done

            local _from_addr
            _from_addr=$(grep -E "^from[[:space:]]" "$_msmtp_conf" 2>/dev/null \
                | awk '{print $2}' || echo "root@$(hostname)")

            local _log_lines
            _log_lines=$(journalctl -k --no-pager -n 500 2>/dev/null \
                | grep 'SRC=' | tail -100 || true)
            [[ -z "$_log_lines" ]] && _log_lines="(no dropped packet entries found)"

            local _subject="Firewall Drop Packet Log — $(hostname) — $(date '+%Y-%m-%d %H:%M:%S')"

            if ! command_exists sendmail; then
                log_warn "sendmail not found. Install msmtp via Prerequisites > SMTP Relay first."
                return
            fi

            # Quick connectivity check so we fail fast instead of hanging 60 s.
            local _relay_host _relay_port
            _relay_host=$(grep -E "^host[[:space:]]" "$_msmtp_conf" 2>/dev/null | awk '{print $2}' || true)
            _relay_port=$(grep -E "^port[[:space:]]" "$_msmtp_conf" 2>/dev/null | awk '{print $2}' || echo "587")
            if [[ -n "$_relay_host" ]] && command_exists nc; then
                if ! nc -zw 5 "$_relay_host" "$_relay_port" 2>/dev/null; then
                    log_warn "Cannot reach relay ${_relay_host}:${_relay_port}."
                    log_warn "Check network connectivity and that outbound port ${_relay_port} is not blocked."
                    return
                fi
            fi

            echo ""
            log_info "Sending drop packet log to ${_email_to}..."

            local _msg
            printf -v _msg \
'From: %s\nTo: %s\nSubject: %s\n\nFirewall Drop Packet Log\n========================\nHost       : %s\nGenerated  : %s\nLog-denied : %s\n\n%s\n' \
                "$_from_addr" "$_email_to" "$_subject" \
                "$(hostname)" "$(date)" "$_current" "$_log_lines"

            # Call msmtp directly (not via sendmail) so --timeout is accepted.
            local _send_exit=0
            printf '%s' "$_msg" \
                | msmtp -C "$_msmtp_conf" --timeout=30 "$_email_to" \
                || _send_exit=$?

            if [[ $_send_exit -eq 0 ]]; then
                log_info "Log sent to ${_email_to}."
            else
                log_error "Send failed (msmtp exit ${_send_exit})."
            fi
            if [[ $_send_exit -ne 0 && -s /var/log/msmtp.log ]]; then
                echo ""
                echo "  Last msmtp log entries:"
                tail -5 /var/log/msmtp.log | sed 's/^/  /' || true
            fi
            ;;
        5) return ;;
        *) echo "  Invalid selection." ;;
    esac
    echo ""
}

# =============================================================================
# Action: Egress filtering (outbound traffic control)
# =============================================================================

_egress_policy="egress-filter"

_egress_enabled() {
    firewall-cmd --info-policy="$_egress_policy" --permanent &>/dev/null
}

_egress_enable() {
    echo "  Enabling egress filtering will block ALL outbound traffic from this"
    echo "  host except explicitly allowed services and ports."
    echo ""
    echo "  Default exceptions that will be added:"
    echo "    • ssh   (22/tcp)       — remote access"
    echo "    • dns   (53/tcp+udp)   — name resolution"
    echo "    • http  (80/tcp)       — package updates"
    echo "    • https (443/tcp)      — secure web / updates"
    echo "    • 587/tcp              — SMTP relay (outbound email)"
    echo ""
    echo -e "  ${YELLOW}Any outbound traffic not listed above will be silently dropped.${NC}"
    echo ""
    read -rp "  Enable egress filtering? [Y/n]: " _ok
    [[ "${_ok,,}" =~ ^n ]] && { log_info "Cancelled."; return; }

    log_section "Creating egress policy"
    firewall-cmd --new-policy="$_egress_policy" --permanent
    firewall-cmd --policy="$_egress_policy" --add-ingress-zone=HOST --permanent
    firewall-cmd --policy="$_egress_policy" --add-egress-zone=ANY  --permanent
    firewall-cmd --policy="$_egress_policy" --set-target=DROP       --permanent
    for _svc in ssh dns http https; do
        firewall-cmd --policy="$_egress_policy" --add-service="$_svc" --permanent
    done
    firewall-cmd --policy="$_egress_policy" --add-port=587/tcp --permanent
    firewall-cmd --reload
    log_info "Egress filtering enabled with default exceptions."
    _save_artifact
}

_egress_disable() {
    echo ""
    echo -e "  ${RED}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "  ${RED}║  WARNING                                                     ║${NC}"
    echo -e "  ${RED}║  Disabling egress filtering allows ALL outbound traffic.     ║${NC}"
    echo -e "  ${RED}║  Any protocol or destination that was previously blocked     ║${NC}"
    echo -e "  ${RED}║  will become reachable. This reduces the security posture.   ║${NC}"
    echo -e "  ${RED}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    read -rp "  Remove egress policy and allow all outbound traffic? [y/N]: " _ok
    [[ "${_ok,,}" =~ ^y ]] || { log_info "Cancelled."; return; }

    firewall-cmd --delete-policy="$_egress_policy" --permanent
    firewall-cmd --reload
    log_info "Egress filtering disabled. All outbound traffic is now allowed."
    _save_artifact
}

_egress_add_service() {
    _header "Add Outbound Service"

    local -a _common=(ssh dns http https smtp smtp-submission ntp samba cockpit rdp dhcpv6-client)
    local -A _svc_ports=(
        [ssh]="22/tcp"           [dns]="53/tcp+udp"     [http]="80/tcp"
        [https]="443/tcp"        [smtp]="25/tcp"         [smtp-submission]="587/tcp"
        [ntp]="123/udp"          [samba]="137-139+445"   [cockpit]="9090/tcp"
        [rdp]="3389/tcp"         [dhcpv6-client]="546/udp"
    )
    local -A _svc_desc=(
        [ssh]="Connect to remote systems"           [dns]="Hostname resolution"
        [http]="Software updates / web access"      [https]="Secure updates / web"
        [smtp]="Outbound email (port 25)"           [smtp-submission]="Outbound email (port 587)"
        [ntp]="Time synchronisation"                [samba]="Windows file sharing"
        [cockpit]="Web admin console"               [rdp]="Remote Desktop"
        [dhcpv6-client]="IPv6 address assignment"
    )

    echo "  Currently allowed outbound services:"
    firewall-cmd --policy="$_egress_policy" --list-services --permanent 2>/dev/null \
        | tr ' ' '\n' | grep -v '^$' | sed 's/^/    /' || echo "    (none)"
    echo ""
    echo "  Common services:"
    printf "  %-4s %-20s %-18s %s\n" "No." "Service" "Ports" "Description"
    printf "  %s\n" "$(printf '%.0s─' {1..76})"
    local _i=1
    for _s in "${_common[@]}"; do
        printf "  %-4s %-20s %-18s %s\n" \
            "$_i)" "$_s" "${_svc_ports[$_s]}" "${_svc_desc[$_s]}"
        _i=$(( _i + 1 ))
    done
    printf "  %-4s %-20s %-18s %s\n" "c)" "custom" "-" "Enter any firewalld service name"
    echo ""

    local _svc=""
    while true; do
        read -rp "  Select service to allow outbound: " _sel
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
    if firewall-cmd --policy="$_egress_policy" --query-service="$_svc" \
            --permanent &>/dev/null; then
        log_info "'$_svc' is already allowed outbound."
        return
    fi
    read -rp "  Allow outbound service '$_svc'? [Y/n]: " _ok
    [[ "${_ok,,}" =~ ^n ]] && { log_info "Cancelled."; return; }
    firewall-cmd --policy="$_egress_policy" --add-service="$_svc" --permanent
    firewall-cmd --reload
    log_info "Outbound service '$_svc' allowed."
    _save_artifact
}

_egress_remove_service() {
    _header "Remove Outbound Service"

    local -a _svcs
    mapfile -t _svcs < <(firewall-cmd --policy="$_egress_policy" --list-services \
        --permanent 2>/dev/null | tr ' ' '\n' | grep -v '^$' || true)

    if [[ ${#_svcs[@]} -eq 0 ]]; then
        log_info "No outbound services are currently allowed."
        return
    fi

    echo "  Allowed outbound services:"
    local _i=1
    for _s in "${_svcs[@]}"; do
        printf "    %2s) %s\n" "$_i" "$_s"
        _i=$(( _i + 1 ))
    done
    echo ""

    local _sel=""
    while true; do
        read -rp "  Select service to remove [1-${#_svcs[@]}]: " _sel
        [[ "$_sel" =~ ^[0-9]+$ ]] && (( _sel >= 1 && _sel <= ${#_svcs[@]} )) && break
        echo "  Invalid selection."
    done
    local _svc="${_svcs[$(( _sel - 1 ))]}"

    echo ""
    case "$_svc" in
        ssh)
            echo -e "  ${RED}╔═══════════════════════════════════════════════════════════════╗${NC}"
            echo -e "  ${RED}║  CRITICAL — SSH OUTBOUND                                    ║${NC}"
            echo -e "  ${RED}║  Removing SSH blocks this host from initiating SSH sessions. ║${NC}"
            echo -e "  ${RED}║  Inbound SSH (remote login to this host) is unaffected.     ║${NC}"
            echo -e "  ${RED}╚═══════════════════════════════════════════════════════════════╝${NC}"
            echo ""
            read -rp "  Type 'remove ssh' to confirm: " _confirm
            [[ "$_confirm" == "remove ssh" ]] || { log_info "Cancelled."; return; }
            ;;
        smtp|smtp-submission)
            echo -e "  ${YELLOW}Warning: removing SMTP blocks all outbound email from this host,${NC}"
            echo -e "  ${YELLOW}including drop packet log emails and system alerts.${NC}"
            echo ""
            read -rp "  Remove outbound '$_svc' anyway? [y/N]: " _ok
            [[ "${_ok,,}" =~ ^y ]] || { log_info "Cancelled."; return; }
            ;;
        http|https)
            echo -e "  ${YELLOW}Warning: removing $_svc blocks outbound package updates,${NC}"
            echo -e "  ${YELLOW}software downloads, and web-based management tools.${NC}"
            echo ""
            read -rp "  Remove outbound '$_svc' anyway? [y/N]: " _ok
            [[ "${_ok,,}" =~ ^y ]] || { log_info "Cancelled."; return; }
            ;;
        dns)
            echo -e "  ${YELLOW}Warning: removing DNS breaks hostname resolution.${NC}"
            echo -e "  ${YELLOW}Updates, email, NTP, and most network services will fail.${NC}"
            echo ""
            read -rp "  Remove outbound 'dns' anyway? [y/N]: " _ok
            [[ "${_ok,,}" =~ ^y ]] || { log_info "Cancelled."; return; }
            ;;
        *)
            read -rp "  Remove outbound service '$_svc'? [y/N]: " _ok
            [[ "${_ok,,}" =~ ^y ]] || { log_info "Cancelled."; return; }
            ;;
    esac

    firewall-cmd --policy="$_egress_policy" --remove-service="$_svc" --permanent
    firewall-cmd --reload
    log_info "Outbound service '$_svc' removed."
    _save_artifact
}

_egress_open_port() {
    _header "Open Outbound Port"

    echo "  Currently open outbound ports:"
    local _cur
    _cur=$(firewall-cmd --policy="$_egress_policy" --list-ports --permanent 2>/dev/null || true)
    if [[ -z "$_cur" ]]; then echo "    (none)"
    else echo "$_cur" | tr ' ' '\n' | grep -v '^$' | sed 's/^/    /' || true; fi
    echo ""

    local _port _proto
    while true; do
        read -rp "  Port number (1-65535): " _port
        [[ "$_port" =~ ^[0-9]+$ ]] && (( _port >= 1 && _port <= 65535 )) && break
        echo "  Must be an integer between 1 and 65535."
    done
    while true; do
        read -rp "  Protocol [tcp/udp, default=tcp]: " _proto
        _proto="${_proto:-tcp}"
        case "${_proto,,}" in tcp|udp) _proto="${_proto,,}"; break ;; *) echo "  Enter tcp or udp." ;; esac
    done

    local _rule="${_port}/${_proto}"
    echo ""
    if firewall-cmd --policy="$_egress_policy" --query-port="$_rule" \
            --permanent &>/dev/null; then
        log_info "Port ${_rule} is already open outbound."
        return
    fi
    read -rp "  Allow outbound ${_rule}? [Y/n]: " _ok
    [[ "${_ok,,}" =~ ^n ]] && { log_info "Cancelled."; return; }
    firewall-cmd --policy="$_egress_policy" --add-port="$_rule" --permanent
    firewall-cmd --reload
    log_info "Outbound port ${_rule} opened."
    _save_artifact
}

_egress_close_port() {
    _header "Close Outbound Port"

    local -a _ports
    mapfile -t _ports < <(firewall-cmd --policy="$_egress_policy" --list-ports \
        --permanent 2>/dev/null | tr ' ' '\n' | grep -v '^$' || true)

    if [[ ${#_ports[@]} -eq 0 ]]; then
        log_info "No custom outbound ports are currently open."
        return
    fi

    echo "  Open outbound ports:"
    local _i=1
    for _p in "${_ports[@]}"; do
        printf "    %2s) %s\n" "$_i" "$_p"
        _i=$(( _i + 1 ))
    done
    echo ""

    local _sel=""
    while true; do
        read -rp "  Select port to close [1-${#_ports[@]}]: " _sel
        [[ "$_sel" =~ ^[0-9]+$ ]] && (( _sel >= 1 && _sel <= ${#_ports[@]} )) && break
        echo "  Invalid selection."
    done
    local _rule="${_ports[$(( _sel - 1 ))]}"

    echo ""
    case "$_rule" in
        587/tcp|25/tcp)
            echo -e "  ${YELLOW}Warning: closing outbound SMTP blocks email delivery,${NC}"
            echo -e "  ${YELLOW}including drop packet log emails and system alerts.${NC}"
            echo ""
            read -rp "  Close outbound '${_rule}' anyway? [y/N]: " _ok
            [[ "${_ok,,}" =~ ^y ]] || { log_info "Cancelled."; return; }
            ;;
        *)
            read -rp "  Close outbound port '${_rule}'? [y/N]: " _ok
            [[ "${_ok,,}" =~ ^y ]] || { log_info "Cancelled."; return; }
            ;;
    esac

    firewall-cmd --policy="$_egress_policy" --remove-port="$_rule" --permanent
    firewall-cmd --reload
    log_info "Outbound port '${_rule}' closed."
    _save_artifact
}

_egress_icmp_control() {
    _header "ICMP / Ping Control — Outbound"

    local _allowed=false
    firewall-cmd --policy="$_egress_policy" --query-service=ping \
        --permanent &>/dev/null && _allowed=true || true

    printf "  %-24s " "Outbound ping:"
    [[ "$_allowed" == true ]] \
        && echo -e "${GREEN}allowed${NC}" \
        || echo -e "${RED}BLOCKED${NC}"
    echo ""
    echo "  Options:"
    echo "    1) Allow outbound ping  — this host can ping external systems"
    echo "    2) Block outbound ping  — this host cannot initiate ping requests"
    echo "    3) Back"
    echo ""
    read -rp "  Selection [1-3]: " _sel
    echo ""

    case "${_sel:-3}" in
        1)
            [[ "$_allowed" == true ]] && { log_info "Outbound ping is already allowed."; return; }
            firewall-cmd --policy="$_egress_policy" --add-service=ping --permanent
            firewall-cmd --reload
            log_info "Outbound ping (ICMP echo-request) allowed."
            _save_artifact
            ;;
        2)
            [[ "$_allowed" == false ]] && { log_info "Outbound ping is already blocked."; return; }
            firewall-cmd --policy="$_egress_policy" --remove-service=ping --permanent
            firewall-cmd --reload
            log_info "Outbound ping (ICMP echo-request) blocked."
            _save_artifact
            ;;
        3) return ;;
        *) echo "  Invalid selection." ;;
    esac
}

_egress_dest_restrict() {
    _header "Destination IP Restrictions — Outbound"

    local -a _rich_rules=()

    while true; do
        mapfile -t _rich_rules < <(firewall-cmd --policy="$_egress_policy" \
            --list-rich-rules --permanent 2>/dev/null \
            | grep -i "destination address" || true)

        echo "  Current destination restrictions:"
        if [[ ${#_rich_rules[@]} -eq 0 ]]; then
            echo "    (none)"
        else
            local _j=1
            for _r in "${_rich_rules[@]}"; do
                printf "    %2s) %s\n" "$_j" "$_r"
                _j=$(( _j + 1 ))
            done
        fi
        echo ""
        echo -e "  ${YELLOW}Note: for a destination restriction to work, the service must NOT${NC}"
        echo -e "  ${YELLOW}also be in the open outbound services list — remove it first.${NC}"
        echo ""
        echo "    1) Add restriction    — allow a service or port to a specific IP/subnet only"
        echo "    2) Remove restriction — delete an existing destination restriction"
        echo "    3) Back"
        echo ""
        read -rp "  Selection [1-3, default=3]: " _sub
        echo ""

        case "${_sub:-3}" in
            1)
                local _target_svc="" _target_port="" _target_proto=""
                local _type_ok=false
                while [[ "$_type_ok" == false ]]; do
                    read -rp "  Restrict a (s)ervice or (p)ort? [s/p]: " _type
                    case "${_type,,}" in
                        s|service) _type_ok=true ;;
                        p|port)    _type_ok=true ;;
                        *) echo "  Enter s or p." ;;
                    esac
                done
                echo ""

                case "${_type,,}" in
                    s|service)
                        local -a _common=(ssh dns http https smtp smtp-submission ntp samba cockpit rdp)
                        echo "  Common services:"
                        local _k=1
                        for _s in "${_common[@]}"; do
                            printf "    %2s) %s\n" "$_k" "$_s"
                            _k=$(( _k + 1 ))
                        done
                        printf "    %2s) %s\n" "c" "Enter custom service name"
                        echo ""
                        while true; do
                            read -rp "  Select service: " _ssel
                            if [[ "$_ssel" =~ ^[0-9]+$ ]] && \
                               (( _ssel >= 1 && _ssel <= ${#_common[@]} )); then
                                _target_svc="${_common[$(( _ssel - 1 ))]}"
                                break
                            elif [[ "${_ssel,,}" == "c" ]]; then
                                read -rp "  Service name: " _target_svc
                                [[ -n "$_target_svc" ]] && break
                                echo "  Cannot be empty."
                            else
                                echo "  Invalid selection."
                            fi
                        done
                        if firewall-cmd --policy="$_egress_policy" \
                                --query-service="$_target_svc" --permanent &>/dev/null; then
                            echo ""
                            echo -e "  ${YELLOW}Warning: '$_target_svc' is currently open to all destinations.${NC}"
                            echo -e "  ${YELLOW}Use option 4 (Remove service) to limit it to this rule only.${NC}"
                        fi
                        ;;
                    p|port)
                        while true; do
                            read -rp "  Port (1-65535): " _target_port
                            [[ "$_target_port" =~ ^[0-9]+$ ]] && \
                                (( _target_port >= 1 && _target_port <= 65535 )) && break
                            echo "  Must be 1-65535."
                        done
                        while true; do
                            read -rp "  Protocol [tcp/udp, default=tcp]: " _target_proto
                            _target_proto="${_target_proto:-tcp}"
                            case "${_target_proto,,}" in
                                tcp|udp) _target_proto="${_target_proto,,}"; break ;;
                                *) echo "  Enter tcp or udp." ;;
                            esac
                        done
                        ;;
                esac

                echo ""
                local _dest=""
                while true; do
                    read -rp "  Destination IP or CIDR (e.g. 10.0.0.0/24): " _dest
                    _validate_cidr "$_dest" && break
                    echo "  Invalid address. Examples: 192.168.1.0/24   10.10.0.5"
                done

                local _rule=""
                if [[ -n "$_target_svc" ]]; then
                    _rule="rule family=\"ipv4\" destination address=\"${_dest}\" service name=\"${_target_svc}\" accept"
                else
                    _rule="rule family=\"ipv4\" destination address=\"${_dest}\" port port=\"${_target_port}\" protocol=\"${_target_proto}\" accept"
                fi

                echo ""
                echo "  ── Rich rule ─────────────────────────────────────────────"
                printf "  %s\n" "$_rule"
                echo "  ──────────────────────────────────────────────────────────"
                echo ""
                read -rp "  Apply? [Y/n]: " _ok
                [[ "${_ok,,}" =~ ^n ]] && { log_info "Cancelled."; echo ""; continue; }
                firewall-cmd --policy="$_egress_policy" --add-rich-rule="$_rule" --permanent
                firewall-cmd --reload
                log_info "Destination restriction added."
                _save_artifact
                ;;

            2)
                if [[ ${#_rich_rules[@]} -eq 0 ]]; then
                    log_info "No destination restrictions to remove."
                else
                    local _rsel=""
                    while true; do
                        read -rp "  Select restriction to remove [1-${#_rich_rules[@]}]: " _rsel
                        [[ "$_rsel" =~ ^[0-9]+$ ]] && \
                            (( _rsel >= 1 && _rsel <= ${#_rich_rules[@]} )) && break
                        echo "  Invalid selection."
                    done
                    local _rem="${_rich_rules[$(( _rsel - 1 ))]}"
                    echo ""
                    printf "  Remove: %s\n" "$_rem"
                    echo ""
                    read -rp "  Confirm? [y/N]: " _ok
                    [[ "${_ok,,}" =~ ^y ]] || { log_info "Cancelled."; echo ""; continue; }
                    firewall-cmd --policy="$_egress_policy" --remove-rich-rule="$_rem" --permanent
                    firewall-cmd --reload
                    log_info "Destination restriction removed."
                    _save_artifact
                fi
                ;;

            3) return ;;
            *) echo "  Invalid selection." ;;
        esac
        echo ""
    done
}

_egress_view_drop_log() {
    _header "View Egress Drop Log"

    _require_firewalld || return

    local _current
    _current=$(firewall-cmd --get-log-denied 2>/dev/null || echo "unknown")
    printf "  %-22s %s\n" "Current log-denied:" "$_current"
    echo ""

    if [[ "$_current" == "off" ]]; then
        echo -e "  ${YELLOW}Drop logging is currently disabled — no packets are being logged.${NC}"
        echo "  Use option 9 (Configure drop logging) to enable it first."
        echo ""
        return
    fi

    echo "  Showing outbound-only drops (OUT= entries)."
    echo ""
    echo "  Options:"
    echo "    1) Recent entries       — last 100 egress-dropped packets"
    echo "    2) Follow live          — stream new entries in real time (Ctrl+C to stop)"
    echo "    3) Filter by dest IP    — show drops to a specific destination address"
    echo "    4) Email log            — send recent entries to an email address"
    echo "    5) Back"
    echo ""
    read -rp "  Selection [1-5, default=1]: " _sel
    echo ""

    case "${_sel:-1}" in
        1)
            echo "  Last 100 egress-dropped packets:"
            printf "  %s\n" "$(printf '%.0s─' {1..58})"
            local _lines
            _lines=$(journalctl -k --no-pager -n 500 2>/dev/null \
                | grep 'SRC=' | grep 'OUT=' | tail -100 || true)
            if [[ -z "$_lines" ]]; then
                echo "  (no egress drop entries found — ensure log-denied is enabled"
                echo "   and that egress filtering is active)"
            else
                echo "$_lines" | sed 's/^/  /'
            fi
            ;;
        2)
            echo "  Following egress drop log — press Ctrl+C to stop."
            echo ""
            journalctl -k -f 2>/dev/null \
                | grep --line-buffered 'SRC=' | grep --line-buffered 'OUT=' \
                | sed 's/^/  /' || true
            ;;
        3)
            local _filter_ip=""
            while true; do
                read -rp "  Destination IP to filter (e.g. 203.0.113.5): " _filter_ip
                _validate_ip "$_filter_ip" && break
                echo "  Invalid IP address."
            done
            echo ""
            echo "  Egress drops to $_filter_ip:"
            printf "  %s\n" "$(printf '%.0s─' {1..58})"
            local _filtered
            _filtered=$(journalctl -k --no-pager 2>/dev/null \
                | grep 'SRC=' | grep 'OUT=' | grep "DST=${_filter_ip}" || true)
            if [[ -z "$_filtered" ]]; then
                echo "  (no entries found for destination IP $_filter_ip)"
            else
                echo "$_filtered" | sed 's/^/  /'
            fi
            ;;
        4)
            local _msmtp_conf="/etc/msmtprc"
            if [[ ! -f "$_msmtp_conf" ]]; then
                log_warn "SMTP relay is not configured. Run Prerequisites > SMTP Relay first."
                return
            fi

            local _email_to=""
            while true; do
                read -rp "  Recipient email address: " _email_to
                [[ -n "$_email_to" ]] && break
                echo "  Address cannot be empty."
            done

            local _from_addr
            _from_addr=$(grep -E "^from[[:space:]]" "$_msmtp_conf" 2>/dev/null \
                | awk '{print $2}' || echo "root@$(hostname)")

            local _log_lines
            _log_lines=$(journalctl -k --no-pager -n 500 2>/dev/null \
                | grep 'SRC=' | grep 'OUT=' | tail -100 || true)
            [[ -z "$_log_lines" ]] && _log_lines="(no egress drop entries found)"

            local _subject="Firewall Egress Drop Log — $(hostname) — $(date '+%Y-%m-%d %H:%M:%S')"

            if ! command_exists sendmail; then
                log_warn "sendmail not found. Install msmtp via Prerequisites > SMTP Relay first."
                return
            fi

            local _relay_host _relay_port
            _relay_host=$(grep -E "^host[[:space:]]" "$_msmtp_conf" 2>/dev/null | awk '{print $2}' || true)
            _relay_port=$(grep -E "^port[[:space:]]" "$_msmtp_conf" 2>/dev/null | awk '{print $2}' || echo "587")
            if [[ -n "$_relay_host" ]] && command_exists nc; then
                if ! nc -zw 5 "$_relay_host" "$_relay_port" 2>/dev/null; then
                    log_warn "Cannot reach relay ${_relay_host}:${_relay_port}."
                    log_warn "Check network connectivity and that outbound port ${_relay_port} is not blocked."
                    return
                fi
            fi

            echo ""
            log_info "Sending egress drop log to ${_email_to}..."

            local _msg
            printf -v _msg \
'From: %s\nTo: %s\nSubject: %s\n\nFirewall Egress Drop Packet Log\n================================\nHost       : %s\nGenerated  : %s\nLog-denied : %s\n\n%s\n' \
                "$_from_addr" "$_email_to" "$_subject" \
                "$(hostname)" "$(date)" "$_current" "$_log_lines"

            local _send_exit=0
            printf '%s' "$_msg" \
                | msmtp -C "$_msmtp_conf" --timeout=30 "$_email_to" \
                || _send_exit=$?

            if [[ $_send_exit -eq 0 ]]; then
                log_info "Log sent to ${_email_to}."
            else
                log_error "Send failed (msmtp exit ${_send_exit})."
            fi
            if [[ $_send_exit -ne 0 && -s /var/log/msmtp.log ]]; then
                echo ""
                echo "  Last msmtp log entries:"
                tail -5 /var/log/msmtp.log | sed 's/^/  /' || true
            fi
            ;;
        5) return ;;
        *) echo "  Invalid selection." ;;
    esac
}

action_egress_filter() {
    _require_firewalld || return

    if ! _firewalld_running; then
        log_warn "firewalld is not running.  Enable it first (option 2)."
        return
    fi

    while true; do
        _header "Egress Filtering — Outbound Traffic Control"

        if _egress_enabled; then
            printf "  %-24s " "Egress filtering:"
            echo -e "${GREEN}ENABLED — outbound default DROP${NC}"
            echo ""
            echo "  Current outbound exceptions:"
            local _svcs _ports
            _svcs=$(firewall-cmd --policy="$_egress_policy" --list-services \
                --permanent 2>/dev/null | tr ' ' '\n' | grep -v '^$' || true)
            _ports=$(firewall-cmd --policy="$_egress_policy" --list-ports \
                --permanent 2>/dev/null | tr ' ' '\n' | grep -v '^$' || true)
            if [[ -z "$_svcs" && -z "$_ports" ]]; then
                echo "    (none — all outbound traffic is blocked)"
            else
                local _s _p
                for _s in $_svcs; do printf "    service : %s\n" "$_s"; done
                for _p in $_ports; do printf "    port    : %s\n" "$_p"; done
            fi
        else
            printf "  %-24s " "Egress filtering:"
            echo -e "${YELLOW}DISABLED — all outbound traffic allowed${NC}"
        fi

        echo ""
        echo "  ── Policy ───────────────────────────────────────────────────"
        if _egress_enabled; then
            echo "    1) Disable egress filtering  — remove policy; allow all outbound"
        else
            echo "    1) Enable egress filtering   — default-drop outbound; add SSH/DNS/HTTP/HTTPS/SMTP"
        fi
        echo "    2) View egress policy        — target, allowed services, ports, and rules"
        echo ""
        echo "  ── Outbound Rules ───────────────────────────────────────────"
        echo "    3) Add service               — allow a named service outbound"
        echo "    4) Remove service            — block a currently-allowed outbound service"
        echo "    5) Open port                 — allow a custom port/protocol outbound"
        echo "    6) Close port                — block a currently-open outbound port"
        echo "    7) ICMP / ping control       — allow or block outbound ping"
        echo "    8) Destination IP restrict.  — allow a service/port to specific IPs only"
        echo ""
        echo "  ── Test ─────────────────────────────────────────────────────"
        echo "    9) Test egress filtering     — verify allowed traffic passes, blocked traffic drops"
        echo ""
        echo "  ─────────────────────────────────────────────────────────────"
        echo "   10) Back"
        echo ""
        read -rp "  Selection [1-10, default=10]: " _sub
        echo ""

        case "${_sub:-10}" in
            1) if _egress_enabled; then _egress_disable; else _egress_enable; fi ;;
            2) action_view_egress_policy ;;
            3|4|5|6|7|8)
                if ! _egress_enabled; then
                    log_warn "Enable egress filtering first (option 1)."
                else
                    case "$_sub" in
                        3) _egress_add_service ;;
                        4) _egress_remove_service ;;
                        5) _egress_open_port ;;
                        6) _egress_close_port ;;
                        7) _egress_icmp_control ;;
                        8) _egress_dest_restrict ;;
                    esac
                fi
                ;;
            9) _egress_test ;;
           10) return ;;
            *) echo "  Invalid selection." ;;
        esac
        echo ""
    done
}

# =============================================================================
# Action: Test egress filtering
# =============================================================================

_egress_print_result() {
    local _label="$1" _exit="$2" _expect_open="$3"
    printf "  %-38s" "$_label"
    if [[ $_exit -eq 0 ]]; then
        if [[ "$_expect_open" == true ]]; then
            echo -e "${GREEN}[  OK  ]${NC}  reachable"
        else
            echo -e "${RED}[ OPEN! ]${NC} unexpectedly reachable"
        fi
    else
        if [[ "$_expect_open" == true ]]; then
            echo -e "${RED}[ FAIL ]${NC}  not reachable"
        else
            echo -e "${GREEN}[BLOCKED]${NC} not reachable"
        fi
    fi
}

_egress_run_all() {
    _require_firewalld || return

    if ! _egress_enabled; then
        log_warn "Egress filtering is not enabled — all outbound traffic is allowed."
        log_warn "Enable it first (option 1) before testing."
        return
    fi

    local _pass=0 _fail=0 _blocked=0 _not_blocked=0
    local _svcs _ports
    _svcs=$(firewall-cmd --policy="$_egress_policy" --list-services \
        --permanent 2>/dev/null | tr ' ' '\n' | grep -v '^$' || true)
    _ports=$(firewall-cmd --policy="$_egress_policy" --list-ports \
        --permanent 2>/dev/null | tr ' ' '\n' | grep -v '^$' || true)

    echo "  Testing allowed outbound traffic:"
    printf "  %s\n" "$(printf '%.0s─' {1..58})"

    local _svc _r
    for _svc in $_svcs; do
        _r=0
        case "$_svc" in
            ssh)             printf "  %-38s" "ssh → github.com:22"
                             nc -zw 5 github.com 22 &>/dev/null || _r=$? ;;
            dns)             printf "  %-38s" "dns → 8.8.8.8:53"
                             nc -zw 5 8.8.8.8 53 &>/dev/null || _r=$? ;;
            http)            printf "  %-38s" "http → example.com:80"
                             curl -fs --max-time 5 http://example.com -o /dev/null &>/dev/null || _r=$? ;;
            https)           printf "  %-38s" "https → example.com:443"
                             curl -fs --max-time 5 https://example.com -o /dev/null &>/dev/null || _r=$? ;;
            smtp)            printf "  %-38s" "smtp → smtp.office365.com:25"
                             nc -zw 5 smtp.office365.com 25 &>/dev/null || _r=$? ;;
            smtp-submission) printf "  %-38s" "smtp-sub → smtp.office365.com:587"
                             nc -zw 5 smtp.office365.com 587 &>/dev/null || _r=$? ;;
            ping)            printf "  %-38s" "ping → 8.8.8.8"
                             ping -c 1 -W 3 8.8.8.8 &>/dev/null || _r=$? ;;
            ntp)             printf "  %-38s" "ntp → pool.ntp.org:123/udp"
                             nc -uzw 5 pool.ntp.org 123 &>/dev/null || _r=$? ;;
            *)               printf "  %-38s%s\n" "$_svc" "(no test target — skipped)"; continue ;;
        esac
        if [[ $_r -eq 0 ]]; then
            echo -e "${GREEN}[  OK  ]${NC}"; _pass=$(( _pass + 1 ))
        else
            echo -e "${RED}[ FAIL ]${NC}"; _fail=$(( _fail + 1 ))
        fi
    done

    local _portproto _port _proto
    for _portproto in $_ports; do
        _port="${_portproto%/*}"; _proto="${_portproto#*/}"; _r=0
        printf "  %-38s" "${_portproto} → 8.8.8.8"
        if [[ "$_proto" == "udp" ]]; then
            nc -uzw 5 8.8.8.8 "$_port" &>/dev/null || _r=$?
        else
            nc -zw 5 8.8.8.8 "$_port" &>/dev/null || _r=$?
        fi
        if [[ $_r -eq 0 ]]; then
            echo -e "${GREEN}[  OK  ]${NC}"; _pass=$(( _pass + 1 ))
        else
            echo -e "${RED}[ FAIL ]${NC}"; _fail=$(( _fail + 1 ))
        fi
    done

    echo ""
    echo "  Testing blocked outbound traffic (should NOT connect):"
    printf "  %s\n" "$(printf '%.0s─' {1..58})"

    local -a _candidates=("23/tcp:telnet" "3306/tcp:mysql" "8080/tcp:alt-http" "5432/tcp:postgres")
    local _bt _portproto_b _label_b _port_b
    for _bt in "${_candidates[@]}"; do
        _portproto_b="${_bt%%:*}"; _label_b="${_bt##*:}"
        _port_b="${_portproto_b%/*}"; _r=0
        if echo "$_ports" | grep -qw "$_portproto_b" || \
           echo "$_svcs"  | grep -qw "$_label_b"; then
            printf "  %-38s%s\n" "${_portproto_b} (${_label_b})" "(in allow list — skipped)"
            continue
        fi
        printf "  %-38s" "${_portproto_b} (${_label_b}) → 8.8.8.8"
        nc -zw 3 8.8.8.8 "$_port_b" &>/dev/null || _r=$?
        if [[ $_r -ne 0 ]]; then
            echo -e "${GREEN}[BLOCKED]${NC}"; _blocked=$(( _blocked + 1 ))
        else
            echo -e "${RED}[ OPEN! ]${NC}"; _not_blocked=$(( _not_blocked + 1 ))
        fi
    done

    echo ""
    echo "  ── Summary ──────────────────────────────────────────────────"
    printf "  Allowed  : %d passed" "$_pass"
    [[ $_fail -gt 0 ]] \
        && printf ", ${RED}%d failed${NC}" "$_fail" \
        || printf ", 0 failed"
    echo ""
    printf "  Blocked  : %d blocked" "$_blocked"
    [[ $_not_blocked -gt 0 ]] \
        && printf ", ${RED}%d unexpectedly open${NC}" "$_not_blocked" \
        || printf ", 0 open"
    echo ""
    if [[ $_fail -eq 0 && $_not_blocked -eq 0 ]]; then
        echo -e "  ${GREEN}All tests passed.${NC}"
    else
        [[ $_fail        -gt 0 ]] && log_warn "Some allowed services failed — check relay/network connectivity."
        [[ $_not_blocked -gt 0 ]] && log_error "Some ports are open that should be blocked — review the egress policy."
    fi
    echo ""
}

_egress_custom_test() {
    _header "Custom Outbound Test"

    local _svcs _ports
    _svcs=$(firewall-cmd --policy="$_egress_policy" --list-services \
        --permanent 2>/dev/null | tr ' ' '\n' | grep -v '^$' || true)
    _ports=$(firewall-cmd --policy="$_egress_policy" --list-ports \
        --permanent 2>/dev/null | tr ' ' '\n' | grep -v '^$' || true)

    # Host
    local _host=""
    while true; do
        read -rp "  Destination host or IP: " _host
        [[ -n "$_host" ]] && break
        echo "  Cannot be empty."
    done

    # Protocol
    local _proto=""
    while true; do
        read -rp "  Protocol [tcp/udp/icmp, default=tcp]: " _proto
        _proto="${_proto:-tcp}"
        case "${_proto,,}" in
            tcp|udp|icmp) _proto="${_proto,,}"; break ;;
            *) echo "  Enter tcp, udp, or icmp." ;;
        esac
    done

    # Port (not needed for icmp)
    local _port=""
    if [[ "$_proto" != "icmp" ]]; then
        while true; do
            read -rp "  Port (1-65535): " _port
            [[ "$_port" =~ ^[0-9]+$ ]] && (( _port >= 1 && _port <= 65535 )) && break
            echo "  Must be between 1 and 65535."
        done
    fi

    # Check whether this is in the egress allow list
    local _in_policy=false _policy_note=""
    if [[ "$_proto" == "icmp" ]]; then
        echo "$_svcs" | grep -qw "ping" && _in_policy=true
        _policy_note="ping service"
    else
        local _rule="${_port}/${_proto}"
        echo "$_ports" | grep -qw "$_rule" && _in_policy=true
        # Also check named services for well-known ports
        case "$_rule" in
            22/tcp)  echo "$_svcs" | grep -qw "ssh"  && _in_policy=true; _policy_note="ssh service" ;;
            53/tcp|53/udp) echo "$_svcs" | grep -qw "dns"  && _in_policy=true; _policy_note="dns service" ;;
            80/tcp)  echo "$_svcs" | grep -qw "http" && _in_policy=true; _policy_note="http service" ;;
            443/tcp) echo "$_svcs" | grep -qw "https" && _in_policy=true; _policy_note="https service" ;;
            25/tcp)  echo "$_svcs" | grep -qw "smtp"  && _in_policy=true; _policy_note="smtp service" ;;
            587/tcp) echo "$_svcs" | grep -qw "smtp-submission" && _in_policy=true; _policy_note="smtp-submission service" ;;
        esac
    fi

    echo ""
    if [[ "$_in_policy" == true ]]; then
        local _note="${_policy_note:-${_port}/${_proto}}"
        echo -e "  ${GREEN}Policy: ${_note} is in the egress allow list — expect REACHABLE${NC}"
    else
        echo -e "  ${YELLOW}Policy: not in egress allow list — expect BLOCKED${NC}"
    fi
    echo ""

    # Run test
    local _label _r=0
    if [[ "$_proto" == "icmp" ]]; then
        _label="ping → ${_host}"
        printf "  %-38s" "$_label"
        ping -c 1 -W 5 "$_host" &>/dev/null || _r=$?
    elif [[ "$_proto" == "udp" ]]; then
        _label="${_host}:${_port}/udp"
        printf "  %-38s" "$_label"
        nc -uzw 5 "$_host" "$_port" &>/dev/null || _r=$?
    else
        _label="${_host}:${_port}/tcp"
        printf "  %-38s" "$_label"
        nc -zw 5 "$_host" "$_port" &>/dev/null || _r=$?
    fi

    _egress_print_result "$_label" "$_r" "$_in_policy"
    echo ""

    if [[ $_r -eq 0 && "$_in_policy" == false ]]; then
        log_warn "Traffic reached its destination but the egress policy should block it."
        log_warn "Check 'View egress policy' — a rich rule or service may be allowing it."
    elif [[ $_r -ne 0 && "$_in_policy" == true ]]; then
        log_warn "Traffic was blocked but the egress policy should allow it."
        log_warn "The destination may be unreachable, or check the policy with 'View egress policy'."
    fi
    echo ""
}

_egress_test() {
    _require_firewalld || return

    if ! _firewalld_running; then
        log_warn "firewalld is not running.  Enable it first (option 2)."
        return
    fi

    while true; do
        _header "Egress Connectivity Test"

        echo "  Options:"
        echo "    1) Run all tests    — test allowed services/ports pass, standard ports blocked"
        echo "    2) Custom test      — enter a host, port, and protocol to test"
        echo "    3) Back"
        echo ""
        read -rp "  Selection [1-3, default=3]: " _sel
        echo ""

        case "${_sel:-3}" in
            1) _egress_run_all ;;
            2) _egress_custom_test ;;
            3) return ;;
            *) echo "  Invalid selection." ;;
        esac
    done
}

# =============================================================================
# Action: View egress policy
# =============================================================================

action_view_egress_policy() {
    _header "Egress Policy — Outbound Rules"

    _require_firewalld || return

    if ! _egress_enabled; then
        printf "  %-24s " "Egress filtering:"
        echo -e "${YELLOW}DISABLED — all outbound traffic is allowed${NC}"
        echo ""
        echo "  Enable egress filtering (Egress filtering > Enable) to restrict"
        echo "  outbound traffic to approved services and ports only."
        echo ""
        return
    fi

    printf "  %-24s " "Egress filtering:"
    echo -e "${GREEN}ENABLED${NC}"
    printf "  %-24s %s\n" "Policy target:"  "DROP — unmatched outbound packets are silently dropped"
    printf "  %-24s %s\n" "Ingress zone:"   "HOST  — applies to traffic sourced from this machine"
    printf "  %-24s %s\n" "Egress zone:"    "ANY   — applies to all destinations"
    echo ""

    local _svcs _ports _rich _sep
    _sep="$(printf '%.0s─' {1..56})"
    _svcs=$(firewall-cmd --policy="$_egress_policy" --list-services \
        --permanent 2>/dev/null | tr ' ' '\n' | grep -v '^$' || true)
    _ports=$(firewall-cmd --policy="$_egress_policy" --list-ports \
        --permanent 2>/dev/null | tr ' ' '\n' | grep -v '^$' || true)
    _rich=$(firewall-cmd --policy="$_egress_policy" --list-rich-rules \
        --permanent 2>/dev/null || true)

    echo "  Allowed services:"
    printf "  %s\n" "$_sep"
    if [[ -z "$_svcs" ]]; then
        echo "    (none)"
    else
        for _s in $_svcs; do printf "    %s\n" "$_s"; done
    fi
    echo ""

    echo "  Allowed ports:"
    printf "  %s\n" "$_sep"
    if [[ -z "$_ports" ]]; then
        echo "    (none)"
    else
        for _p in $_ports; do printf "    %s\n" "$_p"; done
    fi
    echo ""

    echo "  Rich rules:"
    printf "  %s\n" "$_sep"
    if [[ -z "$_rich" ]]; then
        echo "    (none)"
    else
        echo "$_rich" | sed 's/^/    /'
    fi
    echo ""
}

# =============================================================================
# Action: Inbound filtering sub-menu
# =============================================================================

action_inbound_filter() {
    _require_firewalld || return

    if ! _firewalld_running; then
        log_warn "firewalld is not running.  Enable it first (option 2)."
        return
    fi

    while true; do
        _header "Inbound Filtering — Inbound Traffic Control"

        local _zone
        _zone=$(_default_zone)

        printf "  %-24s %s\n" "Default zone:" "$_zone"
        echo ""
        echo "  Current inbound exceptions:"
        local _svcs _ports
        _svcs=$(firewall-cmd --list-services --zone="$_zone" 2>/dev/null \
            | tr ' ' '\n' | grep -v '^$' || true)
        _ports=$(firewall-cmd --list-ports --zone="$_zone" 2>/dev/null \
            | tr ' ' '\n' | grep -v '^$' || true)
        if [[ -z "$_svcs" && -z "$_ports" ]]; then
            echo "    (none)"
        else
            local _s _p
            for _s in $_svcs; do printf "    service : %s\n" "$_s"; done
            for _p in $_ports; do printf "    port    : %s\n" "$_p"; done
        fi

        echo ""
        echo "  ── Inbound Rules ────────────────────────────────────────────"
        echo "    1) Add service               — allow a named service through the firewall"
        echo "    2) Remove service            — block a currently-allowed service"
        echo "    3) Open port                 — allow a custom port/protocol"
        echo "    4) Close port                — block a currently-open port"
        echo "    5) ICMP / ping control       — allow or block incoming ping (echo-request)"
        echo "    6) Source IP restrictions    — allow a service or port from specific IPs only"
        echo ""
        echo "  ─────────────────────────────────────────────────────────────"
        echo "    7) Back"
        echo ""
        read -rp "  Selection [1-7, default=7]: " _sub
        echo ""

        case "${_sub:-7}" in
            1) action_add_service ;;
            2) action_remove_service ;;
            3) action_open_port ;;
            4) action_close_port ;;
            5) action_icmp_control ;;
            6) action_source_restrict ;;
            7) return ;;
            *) echo "  Invalid selection." ;;
        esac
        echo ""
    done
}

# =============================================================================
# Artifact
# =============================================================================

_save_artifact() {
    local artifact
    artifact=$(artifact_file "firewall")

    local _state _zone _enabled _log_denied
    if _firewalld_running; then
        _state="running"
        _zone=$(_default_zone)
        _log_denied=$(firewall-cmd --get-log-denied 2>/dev/null || echo "unknown")
    else
        _state="stopped"
        _zone="N/A"
        _log_denied="N/A"
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
  State       : $_state
  Enabled     : $_enabled
  Drop logging: $_log_denied

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
    echo ""
    echo "  ── Status & Control ─────────────────────────────────────────"
    echo "    1) View firewall status     — running state, zones, services, log level"
    echo "    2) Enable / disable         — start+enable or stop+disable firewalld"
    echo "    3) Set default zone         — change the active firewalld zone"
    echo ""
    echo "  ── Inbound / Outbound ───────────────────────────────────────"
    echo "    4) Inbound filtering        — services, ports, ICMP, and source IP restrictions"
    echo "    5) Egress filtering         — default-drop all outbound; allow by exception"
    echo ""
    echo "  ── Drop Logging ─────────────────────────────────────────────"
    echo "    6) Configure drop logging   — set log level for dropped/rejected packets"
    echo "    7) View drop packet log     — browse, follow, filter, or email the drop log"
    echo ""
    echo "  ─────────────────────────────────────────────────────────────"
    echo "    8) Exit"
    echo ""
    read -rp "  Selection [1-8, default=1]: " _sel
    echo ""

    case "${_sel:-1}" in
        1) action_show_status ;;
        2) action_toggle_firewall ;;
        3) action_set_zone ;;
        4) action_inbound_filter ;;
        5) action_egress_filter ;;
        6) action_configure_logging ;;
        7) action_view_drop_log ;;
        8) log_info "Exiting firewall module."; exit 0 ;;
        *) echo "  Invalid selection." ;;
    esac

    echo ""
    read -rp "  Return to firewall menu? [Y/n]: " _again
    [[ "${_again,,}" =~ ^n ]] && break
done
