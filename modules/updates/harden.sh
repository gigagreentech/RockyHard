#!/usr/bin/env bash
# =============================================================================
# Module  : updates
# Purpose : Detect pending package updates, apply them, and confirm whether
#           a reboot is required to activate installed kernel or library changes.
#
# Supports dnf (RHEL 8+/Rocky), yum (RHEL 7/CentOS), and apt (Debian/Ubuntu).
# The package manager is detected automatically at runtime.
#
# This module performs the following actions in order:
#
#   1. SYSTEM INFO SNAPSHOT
#      Logs the current OS name, kernel version, architecture, and uptime
#      before any changes are made. This provides a baseline in the log that
#      makes it easy to compare pre- and post-update state.
#
#   2. PRE-UPDATE CHECK
#      Scans for available updates and logs each pending package by name.
#      This step is informational — it does not install anything.
#        dnf/yum : uses check-update (exits 100 when updates are available)
#        apt     : uses apt-get --simulate upgrade and filters for Inst lines
#
#   3. APPLY UPDATES  (conditional on APPLY_UPDATES in config.conf)
#      Installs all available updates non-interactively.
#        dnf  : dnf upgrade -y --quiet
#        yum  : yum update -y --quiet
#        apt  : DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq
#      Set APPLY_UPDATES=no in config.conf to run this module in audit-only
#      mode — the pre- and post-checks will still run and be logged, but no
#      packages will be installed.
#
#   4. POST-UPDATE CHECK
#      Re-runs the same package scan after applying updates to confirm all
#      packages are now current. Any packages that remain (e.g. held back,
#      unresolved dependencies) will appear here and be visible in the log.
#
#   5. REBOOT CHECK
#      Determines whether a reboot is required to activate the changes.
#        dnf/yum with needs-restarting : uses needs-restarting -r (preferred)
#        dnf/yum fallback              : compares uname -r against the newest
#                                        installed kernel RPM
#        apt                           : checks for /var/run/reboot-required
#
# Configuration values read from config.conf:
#   APPLY_UPDATES = yes   (set to no to scan for updates without installing them)
#
# Files modified:
#   Package database and installed packages (if APPLY_UPDATES=yes).
#   No configuration files are modified by this module.
#
# Dependencies:
#   dnf / yum / apt-get   — one must be present (module exits if none found)
#   needs-restarting      — dnf-utils (optional; used for reboot check on RHEL)
#   rpm                   — rpm (fallback for reboot check on RHEL without dnf-utils)
#   uname, uptime         — util-linux / procps
#
# Must be run as root (enforced by check_root in master.sh).
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../config.conf"
source "$SCRIPT_DIR/../../lib/common.sh"

# Counters populated during execution and consumed by save_artifact.
UPDATES_PRE_COUNT=0
UPDATES_POST_COUNT=0
UPDATES_APPLIED=false
UPDATES_REBOOT_REQUIRED="Unknown"

# --- Detect package manager ---
detect_pkg_manager() {
    # Preference order: dnf (RHEL 8+/Rocky) → yum (RHEL 7/CentOS) → apt (Debian/Ubuntu).
    # dnf is checked first because it is also present on systems that still have yum
    # installed as a compatibility shim, so checking dnf first picks the correct tool.
    if command_exists dnf; then
        echo "dnf"
    elif command_exists yum; then
        echo "yum"
    elif command_exists apt-get; then
        echo "apt"
    else
        log_error "No supported package manager found (dnf, yum, apt-get)."
        exit 1
    fi
}

# --- Show current OS and kernel ---
print_system_info() {
    log_info "CHECK: Current system version"
    log_info "  OS     : $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')"
    log_info "  Kernel : $(uname -r)"
    log_info "  Arch   : $(uname -m)"
    # uptime -p gives human-readable output (e.g. "up 2 hours, 3 minutes") but is
    # not available on all distros; plain uptime is the universal fallback.
    log_info "  Uptime : $(uptime -p 2>/dev/null || uptime)"
}

# --- Check for available updates ---
check_available_updates() {
    local pkg_manager="$1"
    log_info "CHECK: Scanning for available updates (package manager: $pkg_manager)"

    case "$pkg_manager" in
        dnf|yum)
            # check-update exits 100 when updates are available, 0 when up to date,
            # and 1 on error. The "|| true" suppresses the exit-100 from aborting
            # the script under set -e, and we inspect the output instead.
            local update_list
            update_list=$($pkg_manager check-update --quiet 2>/dev/null || true)

            if [[ -z "$update_list" ]]; then
                log_info "  Result : All packages are up to date. No updates available."
                return 0
            fi

            # Count lines that contain a dot — each package line is in the format
            # "name.arch  version  repo", so this filters out blank lines and headers.
            local count
            count=$(echo "$update_list" | grep -c '\.' || true)
            log_warn "  Result : $count package(s) have updates available."
            log_info "  Packages pending update:"
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                log_info "    $line"
            done <<< "$update_list"
            return 1
            ;;
        apt)
            # Refresh the local package index before checking — without this,
            # apt may report stale data from the last cached fetch.
            apt-get update -qq

            # --simulate performs a dry-run upgrade and prints what would change.
            # Lines beginning with "Inst" are packages that would be installed/upgraded.
            local update_list
            update_list=$(apt-get --simulate upgrade 2>/dev/null | grep "^Inst" || true)

            if [[ -z "$update_list" ]]; then
                log_info "  Result : All packages are up to date. No updates available."
                return 0
            fi

            local count
            count=$(echo "$update_list" | wc -l)
            log_warn "  Result : $count package(s) have updates available."
            log_info "  Packages pending update:"
            while IFS= read -r line; do
                log_info "    $line"
            done <<< "$update_list"
            return 1
            ;;
    esac
}

# --- Apply updates ---
apply_updates() {
    local pkg_manager="$1"

    # APPLY_UPDATES=no allows the module to be used as a read-only audit
    # (report what needs updating without making any changes).
    if [[ "${APPLY_UPDATES:-yes}" != "yes" ]]; then
        log_info "APPLY_UPDATES is set to 'no' in config.conf — skipping update installation."
        return
    fi

    log_info "Applying updates..."

    case "$pkg_manager" in
        dnf)
            # upgrade replaces the older "update" subcommand and also handles
            # package obsoletes correctly. -y auto-confirms; --quiet reduces output.
            dnf upgrade -y --quiet
            ;;
        yum)
            yum update -y --quiet
            ;;
        apt)
            # DEBIAN_FRONTEND=noninteractive prevents apt from prompting for
            # input during package configuration (e.g. timezone, locale dialogs),
            # which would hang the script when run non-interactively.
            DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq
            ;;
    esac

    log_info "All updates applied successfully."
}

# --- Check if reboot is required ---
check_reboot_required() {
    local pkg_manager="$1"
    log_info "CHECK: Reboot requirement"

    case "$pkg_manager" in
        dnf|yum)
            if command_exists needs-restarting; then
                # needs-restarting -r exits 1 when a reboot is required (kernel or
                # core library update), 0 when no reboot is needed.
                local reboot_check
                reboot_check=$(needs-restarting -r 2>&1 || true)
                if echo "$reboot_check" | grep -qi "reboot is required"; then
                    log_warn "  Result : A REBOOT IS REQUIRED to apply kernel or core library updates."
                    log_warn "           Run: reboot"
                else
                    log_info "  Result : No reboot required."
                fi
            else
                # Fallback when needs-restarting is not installed (dnf-utils package).
                # Compare the running kernel (uname -r) against the highest-versioned
                # kernel RPM installed. A mismatch means the system booted on the old
                # kernel before the update and needs a reboot to load the new one.
                local running_kernel installed_kernel
                running_kernel=$(uname -r)
                # sort -V sorts by version number, tail -1 picks the newest
                installed_kernel=$(rpm -q kernel --qf "%{VERSION}-%{RELEASE}.%{ARCH}\n" 2>/dev/null | sort -V | tail -1 || echo "unknown")
                log_info "  Running kernel  : $running_kernel"
                log_info "  Latest installed: $installed_kernel"
                if [[ "$running_kernel" != "$installed_kernel" ]]; then
                    log_warn "  Result : Kernel was updated — a REBOOT IS REQUIRED."
                else
                    log_info "  Result : Running kernel matches latest installed. No reboot required."
                fi
            fi
            ;;
        apt)
            # apt creates this file when an update requires a reboot (e.g. kernel,
            # libc, or init). Its presence is the standard Debian/Ubuntu indicator.
            if [[ -f /var/run/reboot-required ]]; then
                log_warn "  Result : A REBOOT IS REQUIRED (/var/run/reboot-required exists)."
            else
                log_info "  Result : No reboot required."
            fi
            ;;
    esac
}

# --- Returns the number of pending updates (0 = current) ---
count_pending_updates() {
    local pkg_manager="$1" count=0 list
    case "$pkg_manager" in
        dnf|yum)
            list=$($pkg_manager check-update --quiet 2>/dev/null || true)
            count=$(echo "$list" | grep -c '\.' || true)
            ;;
        apt)
            apt-get update -qq 2>/dev/null
            list=$(apt-get --simulate upgrade 2>/dev/null | grep "^Inst" || true)
            count=$(echo "$list" | grep -c "^Inst" || true)
            ;;
    esac
    echo "$count"
}

# --- Artifact ---
save_artifact() {
    local artifact
    artifact=$(artifact_file "updates")

    local reboot_status
    case "$UPDATES_REBOOT_REQUIRED" in
        yes) reboot_status="Yes — reboot required" ;;
        no)  reboot_status="No" ;;
        *)   reboot_status="Unknown" ;;
    esac

    cat > "$artifact" <<EOF
SYSTEM UPDATES REPORT
======================
Generated  : $(date '+%Y-%m-%d %H:%M:%S')
Hostname   : $(hostname)
OS         : $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
Kernel     : $(uname -r)
Applied by : hardening/modules/updates/harden.sh

PACKAGE MANAGER
---------------
  Detected : $PKG_MANAGER

UPDATE SUMMARY
--------------
  Updates available before : $UPDATES_PRE_COUNT package(s)
  Updates applied          : $($UPDATES_APPLIED && echo "Yes (APPLY_UPDATES=yes)" || echo "No (APPLY_UPDATES=${APPLY_UPDATES:-yes})")
  Updates remaining after  : $UPDATES_POST_COUNT package(s)

REBOOT STATUS
-------------
  Reboot required : $reboot_status
EOF

    log_info "Artifact saved: $artifact"
}

# --- Main ---
log_section "System Updates"

PKG_MANAGER=$(detect_pkg_manager)
log_info "Package manager detected: $PKG_MANAGER"
echo ""

print_system_info
echo ""

UPDATES_PRE_COUNT=$(count_pending_updates "$PKG_MANAGER")
check_available_updates "$PKG_MANAGER" || true
echo ""

if [[ "${APPLY_UPDATES:-yes}" == "yes" ]]; then
    apply_updates "$PKG_MANAGER"
    UPDATES_APPLIED=true
fi
echo ""

log_info "Post-update system state:"
check_available_updates "$PKG_MANAGER" || true
UPDATES_POST_COUNT=$(count_pending_updates "$PKG_MANAGER")
echo ""

check_reboot_required "$PKG_MANAGER"

# Capture reboot status for the artifact
case "$PKG_MANAGER" in
    dnf|yum)
        if command_exists needs-restarting; then
            needs-restarting -r &>/dev/null && UPDATES_REBOOT_REQUIRED="no" || UPDATES_REBOOT_REQUIRED="yes"
        else
            running=$(uname -r)
            latest=$(rpm -q kernel --qf "%{VERSION}-%{RELEASE}.%{ARCH}\n" 2>/dev/null | sort -V | tail -1 || echo "unknown")
            [[ "$running" != "$latest" ]] && UPDATES_REBOOT_REQUIRED="yes" || UPDATES_REBOOT_REQUIRED="no"
        fi
        ;;
    apt)
        [[ -f /var/run/reboot-required ]] && UPDATES_REBOOT_REQUIRED="yes" || UPDATES_REBOOT_REQUIRED="no"
        ;;
esac
echo ""

save_artifact
log_info "Updates module complete."
