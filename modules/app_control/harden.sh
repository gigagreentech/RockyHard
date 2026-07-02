#!/usr/bin/env bash
# =============================================================================
# Module  : app_control
# Purpose : Application allow-listing via fapolicyd.
#
# fapolicyd is RHEL's native file access policy daemon. It maintains a trust
# database of allowed executables. In enforcing mode, any binary not in the
# trust database is blocked from executing.
#
# Trust sources:
#   RPM database — all installed RPM packages are trusted automatically
#   Custom trust — /etc/fapolicyd/trust.d/custom.trust (manual additions)
#
# Menu:
#   ── Status ──
#     1) View status       — service state, mode, and trust summary
#     2) Enable / disable  — install, start+enable or stop+disable
#   ── Trust Management ──
#     3) View trust list   — list all allowed applications and binaries
#     4) Add to trust      — allow a binary or application to run
#     5) Remove from trust — revoke trust; blocks execution in enforcing mode
#     6) Sync RPM database — trust all currently installed RPM packages
#   ── Discovery ──
#     7) Scan for executables — list binaries in standard system paths
#     8) Find untrusted       — show executables not in the trust database
#   ── Policy ──
#     9) Set mode          — permissive (log only) or enforcing (block)
#    10) View audit log    — show fapolicyd denials from journal
#   ──
#    11) Exit
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../lib/common.sh"
source "$SCRIPT_DIR/../../config.conf"

check_root

FAPOLICYD_CONF="/etc/fapolicyd/fapolicyd.conf"
CUSTOM_TRUST="/etc/fapolicyd/trust.d/custom.trust"

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

_fapolicyd_installed() {
    command_exists fapolicyd && rpm -q fapolicyd &>/dev/null
}

_fapolicyd_running() {
    systemctl is-active fapolicyd &>/dev/null
}

_require_fapolicyd() {
    if ! _fapolicyd_installed; then
        log_warn "fapolicyd is not installed. Use option 2 (Enable / disable) to install it."
        return 1
    fi
}

_get_mode() {
    if [[ -f "$FAPOLICYD_CONF" ]]; then
        local _val
        _val=$(grep -E '^permissive[[:space:]]*=' "$FAPOLICYD_CONF" 2>/dev/null \
            | awk -F= '{print $2}' | tr -d ' ' || echo "0")
        if [[ "$_val" == "1" ]]; then
            echo "permissive"
        else
            echo "enforcing"
        fi
    else
        echo "unknown"
    fi
}

# fapolicyd-cli --update signals the running daemon via /run/fapolicyd/fapolicyd.fifo,
# which only exists while the daemon is up. Skip it (and the SIGHUP reload) when
# stopped — trust.d changes are already on disk and apply on next start.
_fapolicyd_update() {
    if _fapolicyd_running; then
        fapolicyd-cli --update
        systemctl kill -s SIGHUP fapolicyd 2>/dev/null || true
    else
        log_warn "fapolicyd is not running — trust changes will apply when it starts (option 2)."
    fi
}

_deploy_default_rules() {
    local _rules_src="/usr/share/fapolicyd/sample-rules"
    local _rules_dst="/etc/fapolicyd/rules.d"
    local _rulelist="/usr/share/fapolicyd/default-ruleset.known-libs"

    if [[ ! -f "$_rulelist" ]]; then
        log_warn "Default ruleset list not found at $_rulelist — skipping rule deployment."
        return
    fi
    if [[ ! -d "$_rules_dst" ]]; then
        mkdir -p "$_rules_dst"
    fi

    log_info "Deploying default fapolicyd rules from $_rules_src..."
    local _rule _deployed=0
    while IFS= read -r _rule; do
        [[ -z "$_rule" || "$_rule" == \#* ]] && continue
        local _src="$_rules_src/$_rule"
        if [[ -f "$_src" ]]; then
            cp "$_src" "$_rules_dst/$_rule"
            _deployed=$(( _deployed + 1 ))
        else
            log_warn "Rule file not found: $_src"
        fi
    done < "$_rulelist"

    log_info "Deployed $_deployed rule files. Compiling..."
    fagenrules --load 2>/dev/null \
        || fagenrules 2>/dev/null \
        || log_warn "fagenrules failed — check /etc/fapolicyd/rules.d/ manually."
    log_info "Rules compiled and loaded."
}

_save_artifact() {
    local _artifact
    _artifact=$(artifact_file "app_control")
    {
        echo "APPLICATION CONTROL REPORT"
        echo "=========================="
        echo "Generated  : $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Hostname   : $(hostname)"
        echo ""
        echo "SERVICE STATE"
        echo "-------------"
        if _fapolicyd_installed; then
            echo "  Installed : yes"
            echo "  Running   : $( _fapolicyd_running && echo yes || echo no )"
            echo "  Mode      : $(_get_mode)"
            echo "  Enabled   : $(systemctl is-enabled fapolicyd 2>/dev/null || echo unknown)"
        else
            echo "  Installed : no"
        fi
        echo ""
        echo "TRUST DATABASE (first 200 entries)"
        echo "-----------------------------------"
        fapolicyd-cli --list 2>/dev/null | head -200 || echo "  (unavailable)"
    } > "$_artifact"
    log_info "Artifact saved: $_artifact"
}

# =============================================================================
# Action: View status
# =============================================================================

action_show_status() {
    _header "Application Control Status"

    if ! _fapolicyd_installed; then
        echo -e "  ${YELLOW}fapolicyd is not installed.${NC}"
        echo "  Use option 2 (Enable / disable) to install and start it."
        echo ""
        return
    fi

    local _running _enabled _mode
    _running=$( _fapolicyd_running && echo "running" || echo "stopped" )
    _enabled=$(systemctl is-enabled fapolicyd 2>/dev/null || echo "unknown")
    _mode=$(_get_mode)

    printf "  %-24s " "Service:"
    if [[ "$_running" == "running" ]]; then
        echo -e "${GREEN}running${NC}"
    else
        echo -e "${RED}stopped${NC}"
    fi
    printf "  %-24s %s\n" "Enabled at boot:" "$_enabled"
    printf "  %-24s " "Mode:"
    if [[ "$_mode" == "enforcing" ]]; then
        echo -e "${RED}enforcing — untrusted binaries are BLOCKED${NC}"
    elif [[ "$_mode" == "permissive" ]]; then
        echo -e "${YELLOW}permissive — untrusted binaries are logged only${NC}"
    else
        echo "$_mode"
    fi
    echo ""

    if _fapolicyd_running; then
        local _trust_count
        _trust_count=$(fapolicyd-cli --list 2>/dev/null | wc -l || echo "unknown")
        printf "  %-24s %s\n" "Trusted entries:" "$_trust_count"
        echo ""
    fi

    echo "  Recent fapolicyd journal entries:"
    printf "  %s\n" "$(printf '%.0s─' {1..56})"
    journalctl -u fapolicyd --no-pager -n 10 2>/dev/null | sed 's/^/  /' \
        || echo "  (no journal entries)"
    echo ""
}

# =============================================================================
# Action: Enable / disable
# =============================================================================

action_toggle() {
    _header "Enable / Disable fapolicyd"

    if ! _fapolicyd_installed; then
        echo "  fapolicyd is not installed."
        echo ""
        read -rp "  Install fapolicyd now? [Y/n]: " _ok
        [[ "${_ok,,}" =~ ^n ]] && { log_info "Cancelled."; return; }
        log_section "Installing fapolicyd"
        dnf install -y fapolicyd
        log_info "fapolicyd installed."

        # Deploy the default ruleset. The package ships rules in
        # /usr/share/fapolicyd/sample-rules/ but does not deploy them
        # automatically — without rules in rules.d/, fagenrules produces
        # nothing and fapolicyd allows all executions despite running.
        _deploy_default_rules
        echo ""
    fi

    if _fapolicyd_running; then
        echo -e "  ${YELLOW}Warning: disabling fapolicyd removes all application execution controls.${NC}"
        echo ""
        read -rp "  Stop and disable fapolicyd? [y/N]: " _ok
        [[ "${_ok,,}" =~ ^y ]] || { log_info "Cancelled."; return; }
        systemctl stop fapolicyd
        systemctl disable fapolicyd
        log_info "fapolicyd stopped and disabled."
    else
        echo "  fapolicyd is currently stopped."
        echo ""
        echo "  Which mode should it start in?"
        echo "    1) Permissive  — log untrusted execution attempts, do not block (recommended first run)"
        echo "    2) Enforcing   — block untrusted executables from running"
        echo "    3) Cancel"
        echo ""
        read -rp "  Selection [1-3, default=1]: " _mode_sel
        echo ""

        local _new_val _new_name
        case "${_mode_sel:-1}" in
            1) _new_val=1; _new_name="permissive" ;;
            2) _new_val=0; _new_name="enforcing"  ;;
            3) log_info "Cancelled."; return ;;
            *) echo "  Invalid selection."; return ;;
        esac

        if [[ "$_new_name" == "enforcing" ]]; then
            echo -e "  ${RED}╔═══════════════════════════════════════════════════════════════╗${NC}"
            echo -e "  ${RED}║  WARNING — ENFORCING MODE                                   ║${NC}"
            echo -e "  ${RED}║  Any executable NOT in the trust database will be BLOCKED.  ║${NC}"
            echo -e "  ${RED}║  Ensure your trust list is complete before proceeding.      ║${NC}"
            echo -e "  ${RED}╚═══════════════════════════════════════════════════════════════╝${NC}"
            echo ""
            read -rp "  Type 'enforce' to confirm: " _confirm
            [[ "$_confirm" == "enforce" ]] || { log_info "Cancelled."; return; }
        fi

        if [[ -f "$FAPOLICYD_CONF" ]]; then
            backup_file "$FAPOLICYD_CONF"
            if grep -q "^permissive[[:space:]]*=" "$FAPOLICYD_CONF" 2>/dev/null; then
                sed -i "s/^permissive[[:space:]]*=.*/permissive = ${_new_val}/" "$FAPOLICYD_CONF"
            else
                echo "permissive = ${_new_val}" >> "$FAPOLICYD_CONF"
            fi
        fi

        systemctl enable --now fapolicyd
        log_info "fapolicyd started and enabled in ${_new_name} mode."
    fi
    _save_artifact
}

# =============================================================================
# Action: View trust list
# =============================================================================

action_view_trust() {
    _header "Trust List"

    _require_fapolicyd || return

    echo "  Options:"
    echo "    1) Show all trusted entries"
    echo "    2) Search by path or name"
    echo "    3) Show custom trust files only"
    echo "    4) Back"
    echo ""
    read -rp "  Selection [1-4, default=1]: " _sel
    echo ""

    case "${_sel:-1}" in
        1)
            echo "  All trusted entries:"
            printf "  %s\n" "$(printf '%.0s─' {1..56})"
            fapolicyd-cli --list 2>/dev/null | sed 's/^/  /' || true
            ;;
        2)
            local _term=""
            while true; do
                read -rp "  Search term (path or filename): " _term
                [[ -n "$_term" ]] && break
                echo "  Cannot be empty."
            done
            echo ""
            echo "  Matches for '$_term':"
            printf "  %s\n" "$(printf '%.0s─' {1..56})"
            local _results
            _results=$(fapolicyd-cli --list 2>/dev/null | grep -i "$_term" || true)
            if [[ -z "$_results" ]]; then
                echo "  (no matches found)"
            else
                echo "$_results" | sed 's/^/  /'
            fi
            ;;
        3)
            echo "  Custom trust files in /etc/fapolicyd/trust.d/:"
            printf "  %s\n" "$(printf '%.0s─' {1..56})"
            if [[ -d /etc/fapolicyd/trust.d ]]; then
                local _found=0
                local _f
                for _f in /etc/fapolicyd/trust.d/*.trust; do
                    [[ -f "$_f" ]] || continue
                    _found=$(( _found + 1 ))
                    echo ""
                    echo "  File: $_f"
                    grep -v '^#' "$_f" | grep -v '^$' | sed 's/^/    /' \
                        || echo "    (empty)"
                done
                [[ $_found -eq 0 ]] && echo "  (no .trust files found)"
            else
                echo "  /etc/fapolicyd/trust.d/ does not exist."
            fi
            ;;
        4) return ;;
        *) echo "  Invalid selection." ;;
    esac
    echo ""
}

# =============================================================================
# Action: Add to trust
# =============================================================================

action_add_trust() {
    _header "Add to Trust List"

    _require_fapolicyd || return

    echo "  Trusted files are allowed to execute regardless of policy mode."
    echo ""
    echo "  Options:"
    echo "    1) Add a single file by path"
    echo "    2) Add all executables in a directory (recursive)"
    echo "    3) Trust VS Code remote server"
    echo "    4) Back"
    echo ""
    read -rp "  Selection [1-4, default=4]: " _sel
    echo ""

    case "${_sel:-4}" in
        1)
            local _path=""
            while true; do
                read -rp "  Full path to binary (e.g. /usr/local/bin/mytool): " _path
                [[ -n "$_path" ]] && break
                echo "  Path cannot be empty."
            done
            if [[ ! -f "$_path" ]]; then
                log_warn "File not found: $_path"
                return
            fi
            if [[ ! -x "$_path" ]]; then
                log_warn "$_path is not executable — add execute permission first."
                return
            fi
            echo ""
            read -rp "  Add '$_path' to trust? [Y/n]: " _ok
            [[ "${_ok,,}" =~ ^n ]] && { log_info "Cancelled."; return; }
            fapolicyd-cli --add --trust-file "$_path"
            _fapolicyd_update
            log_info "'$_path' added to trust database."
            ;;
        2)
            local _dir=""
            while true; do
                read -rp "  Directory path (e.g. /home/user/.vscode-server): " _dir
                [[ -n "$_dir" ]] && break
                echo "  Path cannot be empty."
            done
            if [[ ! -d "$_dir" ]]; then
                log_warn "Directory not found: $_dir"
                return
            fi
            echo ""
            echo "  Scanning '$_dir' recursively for executables..."
            local -a _execs
            mapfile -t _execs < <(find "$_dir" -type f -executable 2>/dev/null | sort || true)
            if [[ ${#_execs[@]} -eq 0 ]]; then
                log_info "No executables found under $_dir"
                return
            fi
            echo "  Found ${#_execs[@]} executables:"
            printf "    %s\n" "${_execs[@]}"
            echo ""
            read -rp "  Add all ${#_execs[@]} to trust? [Y/n]: " _ok
            [[ "${_ok,,}" =~ ^n ]] && { log_info "Cancelled."; return; }
            local _f _added=0
            for _f in "${_execs[@]}"; do
                fapolicyd-cli --add --trust-file "$_f" 2>/dev/null && _added=$(( _added + 1 )) || true
            done
            _fapolicyd_update
            log_info "Added $_added executables from '$_dir' to trust."
            ;;
        3)
            echo "  VS Code Remote SSH installs a server under ~/.vscode-server/ which"
            echo "  is not an RPM package and is blocked by fapolicyd in enforcing mode."
            echo ""
            echo -e "  ${YELLOW}Important: VS Code cannot install its server while fapolicyd is in${NC}"
            echo -e "  ${YELLOW}enforcing mode. This option follows a three-step process:${NC}"
            echo -e "  ${YELLOW}  1) Switch to permissive mode temporarily${NC}"
            echo -e "  ${YELLOW}  2) You reconnect via VS Code to let the server install/update${NC}"
            echo -e "  ${YELLOW}  3) Trust the installed files, then switch back to enforcing${NC}"
            echo ""

            # Step 1 — ensure permissive so VS Code server can install
            local _mode_before
            _mode_before=$(_get_mode)
            if [[ "$_mode_before" == "enforcing" ]]; then
                read -rp "  Switch to permissive mode now so VS Code server can install? [Y/n]: " _ok
                [[ "${_ok,,}" =~ ^n ]] && { log_info "Cancelled."; return; }
                if grep -q "^permissive[[:space:]]*=" "$FAPOLICYD_CONF" 2>/dev/null; then
                    sed -i "s/^permissive[[:space:]]*=.*/permissive = 1/" "$FAPOLICYD_CONF"
                else
                    echo "permissive = 1" >> "$FAPOLICYD_CONF"
                fi
                systemctl restart fapolicyd
                log_info "fapolicyd switched to permissive mode."
            fi

            # Step 2 — wait for user to connect VS Code
            echo ""
            echo "  fapolicyd is now in permissive mode."
            echo "  Connect via VS Code Remote SSH now to let the server install or update."
            echo "  Once VS Code shows as connected, return here and press Enter."
            echo ""
            read -rp "  Press Enter when VS Code has connected and the server is installed..."
            echo ""

            # Step 3 — scan and trust
            local -a _vs_dirs=()
            local _home
            while IFS= read -r _home; do
                [[ -d "$_home/.vscode-server" ]] && _vs_dirs+=("$_home/.vscode-server")
            done < <(awk -F: '$3 >= 1000 && $3 < 65534 {print $6}' /etc/passwd)
            [[ -d /root/.vscode-server ]] && _vs_dirs+=(/root/.vscode-server)

            if [[ ${#_vs_dirs[@]} -eq 0 ]]; then
                echo -e "  ${RED}No ~/.vscode-server directories found.${NC}"
                echo "  VS Code may not have connected successfully."
                echo "  If fapolicyd was switched to permissive, restore enforcing via option 10."
                echo ""
                return
            fi

            echo "  Found VS Code server directories:"
            printf "    %s\n" "${_vs_dirs[@]}"
            echo ""
            echo "  Scanning for executables..."
            local -a _execs=()
            local _d
            for _d in "${_vs_dirs[@]}"; do
                mapfile -t -O "${#_execs[@]}" _execs < <(
                    find "$_d" -type f -executable 2>/dev/null | sort || true)
            done

            if [[ ${#_execs[@]} -eq 0 ]]; then
                log_warn "No executables found in VS Code server directories."
                return
            fi

            echo "  Found ${#_execs[@]} executables."
            read -rp "  Trust all VS Code server executables? [Y/n]: " _ok
            [[ "${_ok,,}" =~ ^n ]] && { log_info "Cancelled."; return; }

            local _f _added=0
            for _f in "${_execs[@]}"; do
                fapolicyd-cli --add --trust-file "$_f" 2>/dev/null && _added=$(( _added + 1 )) || true
            done
            _fapolicyd_update
            log_info "Trusted $_added VS Code server executables."

            # Step 4 — restore enforcing if we switched away from it
            if [[ "$_mode_before" == "enforcing" ]]; then
                echo ""
                read -rp "  Switch back to enforcing mode now? [Y/n]: " _ok
                if [[ ! "${_ok,,}" =~ ^n ]]; then
                    sed -i "s/^permissive[[:space:]]*=.*/permissive = 0/" "$FAPOLICYD_CONF"
                    systemctl restart fapolicyd
                    log_info "fapolicyd switched back to enforcing mode."
                    echo ""
                    echo "  VS Code should now connect in enforcing mode."
                else
                    echo ""
                    echo -e "  ${YELLOW}fapolicyd is still in permissive mode. Use option 10 to re-enable enforcing.${NC}"
                fi
            fi

            echo ""
            echo -e "  ${YELLOW}Note: each time VS Code updates its server, new binaries are downloaded.${NC}"
            echo -e "  ${YELLOW}Run this option again after any VS Code extension update.${NC}"
            ;;
        4) return ;;
        *) echo "  Invalid selection." ;;
    esac
    _save_artifact
}

# =============================================================================
# Action: Remove from trust
# =============================================================================

action_remove_trust() {
    _header "Remove from Trust List"

    _require_fapolicyd || return

    echo "  Enter the full path of the binary to remove from the trust database."
    echo ""

    local _path=""
    while true; do
        read -rp "  Full path to binary: " _path
        [[ -n "$_path" ]] && break
        echo "  Path cannot be empty."
    done

    if ! fapolicyd-cli --list 2>/dev/null | grep -q "^${_path}"; then
        log_warn "'$_path' was not found in the trust database."
        return
    fi

    echo ""
    local _mode
    _mode=$(_get_mode)
    if [[ "$_mode" == "enforcing" ]]; then
        echo -e "  ${YELLOW}Warning: in enforcing mode, removing this entry will BLOCK execution of:${NC}"
        echo -e "  ${YELLOW}  $_path${NC}"
        echo ""
    fi
    read -rp "  Remove '$_path' from trust? [y/N]: " _ok
    [[ "${_ok,,}" =~ ^y ]] || { log_info "Cancelled."; return; }

    fapolicyd-cli --delete --trust-file "$_path"
    _fapolicyd_update
    log_info "'$_path' removed from trust database."
    _save_artifact
}

# =============================================================================
# Action: Sync RPM database
# =============================================================================

action_sync_rpm() {
    _header "Sync RPM Database"

    _require_fapolicyd || return

    echo "  Updates the fapolicyd trust database from the system RPM package database."
    echo "  All currently installed RPM packages will be trusted after this operation."
    echo ""
    read -rp "  Sync RPM database into fapolicyd trust? [Y/n]: " _ok
    [[ "${_ok,,}" =~ ^n ]] && { log_info "Cancelled."; return; }

    log_info "Updating trust database from RPM..."
    _fapolicyd_update
    log_info "Trust database updated from RPM database."
    _save_artifact
}

# =============================================================================
# Action: Scan for executables
# =============================================================================

action_scan_binaries() {
    _header "Scan for Executables"

    local -a _scan_paths=(/usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt /home)
    echo "  Scanning paths:"
    printf "    %s\n" "${_scan_paths[@]}"
    echo ""
    read -rp "  Add an extra path to scan? (leave blank to skip): " _extra
    [[ -n "$_extra" && -d "$_extra" ]] && _scan_paths+=("$_extra")
    echo ""

    echo "  Options:"
    echo "    1) List all executables"
    echo "    2) List executables not owned by an RPM package"
    echo "    3) Back"
    echo ""
    read -rp "  Selection [1-3, default=3]: " _sel
    echo ""

    case "${_sel:-3}" in
        1)
            echo "  All executables:"
            printf "  %s\n" "$(printf '%.0s─' {1..56})"
            find "${_scan_paths[@]}" -type f -executable 2>/dev/null \
                | sort | sed 's/^/  /' || true
            ;;
        2)
            echo "  Executables not owned by any RPM package:"
            printf "  %s\n" "$(printf '%.0s─' {1..56})"
            local _unowned=0 _bin
            while IFS= read -r _bin; do
                if ! rpm -qf "$_bin" &>/dev/null; then
                    echo "  $_bin"
                    _unowned=$(( _unowned + 1 ))
                fi
            done < <(find "${_scan_paths[@]}" -type f -executable 2>/dev/null | sort)
            echo ""
            if [[ $_unowned -eq 0 ]]; then
                echo "  (none found — all executables are owned by an RPM package)"
            else
                echo "  Total non-RPM executables: $_unowned"
                echo ""
                echo -e "  ${YELLOW}These binaries were not installed via RPM and may not be in the trust database.${NC}"
                echo -e "  ${YELLOW}Review and add legitimate ones with option 4 (Add to trust).${NC}"
            fi
            ;;
        3) return ;;
        *) echo "  Invalid selection." ;;
    esac
    echo ""
}

# =============================================================================
# Action: Find untrusted executables
# =============================================================================

action_find_untrusted() {
    _header "Find Untrusted Executables"

    _require_fapolicyd || return

    local -a _scan_paths=(/usr/local/bin /usr/local/sbin /opt /home)
    echo "  Checking executables in non-system paths against the trust database."
    echo "  Scanning: ${_scan_paths[*]}"
    echo ""
    echo "  (This may take a moment...)"
    echo ""

    local _trust_list _untrusted=0 _bin
    _trust_list=$(fapolicyd-cli --list 2>/dev/null || true)

    echo "  Untrusted executables (not found in fapolicyd trust database):"
    printf "  %s\n" "$(printf '%.0s─' {1..56})"

    while IFS= read -r _bin; do
        if ! echo "$_trust_list" | grep -qF "$_bin"; then
            echo "  $_bin"
            _untrusted=$(( _untrusted + 1 ))
        fi
    done < <(find "${_scan_paths[@]}" -type f -executable 2>/dev/null | sort)

    echo ""
    if [[ $_untrusted -eq 0 ]]; then
        echo -e "  ${GREEN}No untrusted executables found in scanned paths.${NC}"
    else
        echo "  Total untrusted: $_untrusted"
        echo ""
        echo -e "  ${YELLOW}Use option 4 (Add to trust) to allow legitimate binaries.${NC}"
    fi
    echo ""
    echo "  Note: /usr/bin and /usr/sbin are covered by the RPM trust backend"
    echo "  and are not scanned here. Use option 7 > Not RPM-owned to inspect them."
    echo ""
}

# =============================================================================
# Action: Set mode
# =============================================================================

action_set_mode() {
    _header "Set fapolicyd Mode"

    _require_fapolicyd || return

    local _current
    _current=$(_get_mode)
    printf "  %-22s %s\n" "Current mode:" "$_current"
    echo ""

    echo "  Modes:"
    echo "    1) Permissive  — log untrusted execution attempts, do not block"
    echo "    2) Enforcing   — block untrusted executables from running"
    echo "    3) Back"
    echo ""
    echo -e "  ${YELLOW}Tip: run in permissive mode first and review the audit log${NC}"
    echo -e "  ${YELLOW}before switching to enforcing to avoid locking out legitimate tools.${NC}"
    echo ""
    read -rp "  Selection [1-3, default=3]: " _sel
    echo ""

    local _new_val _new_name
    case "${_sel:-3}" in
        1) _new_val=1; _new_name="permissive" ;;
        2) _new_val=0; _new_name="enforcing"  ;;
        3) return ;;
        *) echo "  Invalid selection."; return ;;
    esac

    if [[ "$_new_name" == "enforcing" && "$_current" != "enforcing" ]]; then
        echo -e "  ${RED}╔═══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "  ${RED}║  WARNING — ENFORCING MODE                                   ║${NC}"
        echo -e "  ${RED}║  Any executable NOT in the trust database will be BLOCKED.  ║${NC}"
        echo -e "  ${RED}║  Ensure your trust list is complete before proceeding.      ║${NC}"
        echo -e "  ${RED}║  Use option 10 (View audit log) to review denials first.   ║${NC}"
        echo -e "  ${RED}╚═══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        read -rp "  Type 'enforce' to confirm: " _confirm
        [[ "$_confirm" == "enforce" ]] || { log_info "Cancelled."; return; }
    fi

    backup_file "$FAPOLICYD_CONF"
    if grep -q "^permissive[[:space:]]*=" "$FAPOLICYD_CONF" 2>/dev/null; then
        sed -i "s/^permissive[[:space:]]*=.*/permissive = ${_new_val}/" "$FAPOLICYD_CONF"
    else
        echo "permissive = ${_new_val}" >> "$FAPOLICYD_CONF"
    fi

    if _fapolicyd_running; then
        systemctl restart fapolicyd
        log_info "fapolicyd restarted in ${_new_name} mode."
    else
        log_info "Mode set to ${_new_name}. Start fapolicyd (option 2) to apply."
    fi
    _save_artifact
}

# =============================================================================
# Action: View audit log
# =============================================================================

action_view_audit_log() {
    _header "fapolicyd Audit Log"

    _require_fapolicyd || return

    local _audit_log="/var/log/audit/audit.log"
    local _has_ausearch=false
    local _has_auditlog=false
    command_exists ausearch           && _has_ausearch=true
    [[ -r "$_audit_log" ]]           && _has_auditlog=true

    echo "  deny_audit rules write to the Linux audit subsystem (auditd),"
    echo "  not the systemd journal. Denials appear in $_audit_log."
    echo ""
    echo "  Options:"
    echo "    1) Recent denials      — last 50 blocked execution attempts (audit log)"
    echo "    2) Follow live         — stream new denials in real time (Ctrl+C to stop)"
    echo "    3) Filter by path      — show denials for a specific binary path"
    echo "    4) fapolicyd service log — daemon startup and trust database messages"
    echo "    5) Back"
    echo ""
    read -rp "  Selection [1-5, default=1]: " _sel
    echo ""

    # FANOTIFY audit type = 1700. Some auditd versions log as "type=FANOTIFY",
    # others as the numeric "type=1700" — match both.
    local _fanotify_pat="type=FANOTIFY\|type=1700"

    case "${_sel:-1}" in
        1)
            echo "  Recent fapolicyd events (last 50):"
            echo "  Fields: fname = blocked binary | exe = caller | comm = command name"
            printf "  %s\n" "$(printf '%.0s─' {1..56})"
            local _denials=""
            if [[ "$_has_ausearch" == true ]]; then
                _denials=$(ausearch -m fanotify -i --start today 2>/dev/null | tail -300 || true)
            elif [[ "$_has_auditlog" == true ]]; then
                _denials=$(grep "$_fanotify_pat" "$_audit_log" 2>/dev/null | tail -50 || true)
            fi
            if [[ -z "$_denials" ]]; then
                echo "  (no fapolicyd audit entries found today)"
                if ! systemctl is-active auditd &>/dev/null; then
                    echo -e "  ${RED}auditd is not running — start it with: systemctl start auditd${NC}"
                fi
                echo "  Tip: deny_audit rules require auditd running to produce log entries."
            else
                echo "$_denials" | sed 's/^/  /'
            fi
            ;;
        2)
            local _cur_mode_live
            _cur_mode_live=$(_get_mode)
            echo "  Following fapolicyd audit events — press Ctrl+C to stop."
            echo "  Fields: fname = blocked binary | exe = caller | comm = command name"
            if [[ "$_cur_mode_live" == "permissive" ]]; then
                echo -e "  ${YELLOW}Mode: permissive — events show resp=allow even for would-be denials.${NC}"
            else
                echo -e "  ${RED}Mode: enforcing — resp=deny entries are active blocks.${NC}"
            fi
            if ! systemctl is-active auditd &>/dev/null; then
                echo -e "  ${RED}auditd is not running — no entries will appear. Start it first.${NC}"
                echo ""
                return
            fi
            echo ""
            if [[ "$_has_auditlog" == true ]]; then
                tail -f "$_audit_log" 2>/dev/null \
                    | grep --line-buffered "$_fanotify_pat" \
                    | sed 's/^/  /' || true
            else
                log_warn "Cannot read $_audit_log — ensure auditd is running and you are root."
            fi
            ;;
        3)
            local _path=""
            while true; do
                read -rp "  Binary path to filter (e.g. /tmp/mytool): " _path
                [[ -n "$_path" ]] && break
                echo "  Cannot be empty."
            done
            echo ""
            echo "  Denials for '$_path':"
            printf "  %s\n" "$(printf '%.0s─' {1..56})"
            local _filtered=""
            if [[ "$_has_ausearch" == true ]]; then
                # Show full records (all lines in the block) that contain the path
                _filtered=$(ausearch -m fanotify -i --start today 2>/dev/null \
                    | awk -v p="$_path" '
                        /^----/ { if (blk ~ p) printf "%s", blk; blk="----\n"; next }
                        { blk = blk $0 "\n" }
                        END     { if (blk ~ p) printf "%s", blk }
                    ' || true)
            elif [[ "$_has_auditlog" == true ]]; then
                _filtered=$(grep "$_fanotify_pat" "$_audit_log" 2>/dev/null \
                    | grep -F "$_path" || true)
            fi
            if [[ -z "$_filtered" ]]; then
                echo "  (no denials found for '$_path')"
            else
                echo "$_filtered" | sed 's/^/  /'
            fi
            ;;
        4)
            echo "  fapolicyd service log (last 50 entries):"
            printf "  %s\n" "$(printf '%.0s─' {1..56})"
            journalctl -u fapolicyd --no-pager -n 50 2>/dev/null | sed 's/^/  /' \
                || echo "  (no entries)"
            ;;
        5) return ;;
        *) echo "  Invalid selection." ;;
    esac
    echo ""
}

# =============================================================================
# Main TUI loop
# =============================================================================

log_section "Application Control"

while true; do
    _header "Application Control — Allow Listing via fapolicyd"
    echo ""

    # Inline status bar
    printf "  %-24s " "fapolicyd:"
    if _fapolicyd_installed; then
        if _fapolicyd_running; then
            _cur_mode=$(_get_mode)
            if [[ "$_cur_mode" == "enforcing" ]]; then
                echo -e "${RED}running — enforcing (untrusted binaries BLOCKED)${NC}"
            else
                echo -e "${YELLOW}running — permissive (logging only)${NC}"
            fi
        else
            echo -e "${RED}stopped${NC}"
        fi
    else
        echo -e "${YELLOW}not installed${NC}"
    fi
    echo ""

    echo "  ── Status ───────────────────────────────────────────────────"
    echo "    1) View status          — service state, mode, and trust summary"
    echo "    2) Enable / disable     — install, start+enable or stop+disable"
    echo "    3) Deploy default rules — install the default ruleset into rules.d/"
    echo ""
    echo "  ── Trust Management ─────────────────────────────────────────"
    echo "    4) View trust list      — list all allowed applications and binaries"
    echo "    5) Add to trust         — allow a binary or application to run"
    echo "    6) Remove from trust    — revoke trust; blocks execution in enforcing mode"
    echo "    7) Sync RPM database    — trust all currently installed RPM packages"
    echo ""
    echo "  ── Discovery ────────────────────────────────────────────────"
    echo "    8) Scan for executables — list binaries in standard system paths"
    echo "    9) Find untrusted       — show executables not in the trust database"
    echo ""
    echo "  ── Policy ───────────────────────────────────────────────────"
    echo "   10) Set mode             — permissive (log only) or enforcing (block)"
    echo "   11) View audit log       — show fapolicyd denials from journal"
    echo ""
    echo "  ─────────────────────────────────────────────────────────────"
    echo "   12) Exit"
    echo ""
    read -rp "  Selection [1-12, default=1]: " _sel
    echo ""

    case "${_sel:-1}" in
         1) action_show_status ;;
         2) action_toggle ;;
         3) _deploy_default_rules ;;
         4) action_view_trust ;;
         5) action_add_trust ;;
         6) action_remove_trust ;;
         7) action_sync_rpm ;;
         8) action_scan_binaries ;;
         9) action_find_untrusted ;;
        10) action_set_mode ;;
        11) action_view_audit_log ;;
        12) log_info "Exiting application control module."; exit 0 ;;
         *) echo "  Invalid selection." ;;
    esac

    echo ""
    read -rp "  Return to application control menu? [Y/n]: " _again
    [[ "${_again,,}" =~ ^n ]] && break
done
