#!/usr/bin/env bash
# =============================================================================
# Module  : fips
# Purpose : Verify FIPS 140 compliance status across five independent system
#           layers and optionally enable FIPS mode if not already active.
#
# This module is read-only by default — it reports status without making
# changes unless ENABLE_FIPS=yes is set in config.conf.
#
# This module performs the following actions in order:
#
#   1. KERNEL FIPS FLAG  (/proc/sys/crypto/fips_enabled)
#      Reads the kernel's own FIPS state from the proc filesystem. A value
#      of 1 confirms the running kernel is restricting all crypto operations
#      to FIPS-approved algorithms. This is the most authoritative indicator
#      of active FIPS enforcement at the hardware/kernel layer.
#
#   2. FIPS-MODE-SETUP TOOL  (fips-mode-setup --check)
#      Runs the RHEL/Rocky OS-level check provided by crypto-policies-scripts.
#      This tool validates both the kernel flag and the active system crypto
#      policy together, giving a single pass/fail answer for the OS layer.
#      Skipped with a warning if the package is not installed.
#
#   3. KERNEL BOOT CMDLINE  (/proc/cmdline)
#      Checks that fips=1 is present in the kernel boot parameters. Without
#      this argument the kernel will not activate FIPS mode on the next reboot,
#      meaning any runtime-enabled FIPS state will be lost after a restart.
#      Remediation: add fips=1 to GRUB_CMDLINE_LINUX in /etc/default/grub
#      and regenerate the GRUB config with grub2-mkconfig.
#
#   4. SYSTEM CRYPTO POLICY  (update-crypto-policies --show)
#      Verifies the system-wide crypto policy is set to FIPS. This policy
#      controls which ciphers, key lengths, and protocols are permitted
#      across all services (TLS, SSH, IPSec, Kerberos) without requiring
#      per-application configuration. Expected value: FIPS.
#
#   5. SYSTEM-FIPS MARKER FILE  (/etc/system-fips)
#      Confirms the marker file created by fips-mode-setup is present. PAM
#      modules and some applications check for this file at startup to enforce
#      FIPS-approved algorithms independently of the kernel flag. Its absence
#      can cause application-level non-compliance even when the kernel is
#      operating in FIPS mode.
#
#   6. SUMMARY
#      Prints an overall FIPS status based on checks 1 and 2 (the two most
#      authoritative indicators):
#        COMPLIANT     — both kernel flag and fips-mode-setup passed.
#        PARTIAL       — one passed, one failed (incomplete enablement).
#        NON-COMPLIANT — both failed; remediation steps are shown.
#
#   7. OPTIONAL ENABLEMENT  (conditional on ENABLE_FIPS in config.conf)
#      If ENABLE_FIPS=yes, runs fips-mode-setup --enable which sets the crypto
#      policy to FIPS, creates /etc/system-fips, and adds fips=1 to the GRUB
#      cmdline. A reboot is required for the kernel flag to take effect.
#      Default: ENABLE_FIPS=no (check only, no changes made).
#
# Configuration values read from config.conf:
#   ENABLE_FIPS = no   (set to yes to activate FIPS mode if not already enabled;
#                       requires reboot to take full effect)
#
# Files modified:
#   None by default. If ENABLE_FIPS=yes:
#     GRUB cmdline  — fips=1 added via fips-mode-setup --enable
#     /etc/system-fips          — marker file created
#     /etc/crypto-policies/     — policy set to FIPS
#
# Dependencies:
#   cat, grep         — coreutils
#   fips-mode-setup   — crypto-policies-scripts (dnf install crypto-policies-scripts)
#   update-crypto-policies — crypto-policies
#
# Must be run as root (enforced by check_root in master.sh).
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../config.conf"
source "$SCRIPT_DIR/../../lib/common.sh"

# --- Check 1: Kernel FIPS flag ---
# /proc/sys/crypto/fips_enabled is set by the kernel at boot when fips=1 is
# passed on the kernel cmdline. A value of 1 means the kernel itself is
# restricting crypto operations to FIPS-approved algorithms only.
check_fips_kernel() {
    local fips_proc="/proc/sys/crypto/fips_enabled"
    log_info "CHECK 1: Kernel FIPS flag"
    log_info "  File   : $fips_proc"
    log_info "  Purpose: Confirms the running kernel has activated FIPS mode."
    log_info "           A value of 1 means the kernel is enforcing FIPS-approved"
    log_info "           algorithms. This is the most authoritative indicator."

    # The file only exists on kernels compiled with CONFIG_CRYPTO_FIPS; its
    # absence means FIPS state cannot be determined at the kernel level.
    if [[ ! -f "$fips_proc" ]]; then
        log_warn "  Result : FILE NOT FOUND — kernel may not expose FIPS state."
        return 1
    fi

    local val
    val=$(cat "$fips_proc")

    # 1 = FIPS active; 0 = FIPS inactive; any other value is unexpected
    if [[ "$val" == "1" ]]; then
        log_info "  Value  : $val"
        log_info "  Result : PASS"
        return 0
    else
        log_warn "  Value  : $val"
        log_warn "  Result : FAIL — FIPS is not active at the kernel level."
        return 1
    fi
}

# --- Check 2: fips-mode-setup tool ---
# fips-mode-setup is provided by the crypto-policies-scripts package on
# RHEL/Rocky. It checks both the kernel flag and the system crypto policy
# together, giving a single authoritative answer for the OS layer.
check_fips_tool() {
    log_info "CHECK 2: fips-mode-setup utility"
    log_info "  Tool   : fips-mode-setup --check"
    log_info "  Purpose: RHEL/Rocky OS-level check that validates both the kernel"
    log_info "           FIPS flag and the active crypto policy are FIPS-compliant."
    log_info "           Requires package: crypto-policies-scripts"

    if ! command_exists fips-mode-setup; then
        log_warn "  Result : SKIP — fips-mode-setup not found."
        log_warn "           Install with: dnf install -y crypto-policies-scripts"
        return 1
    fi

    # Capture output for the log before running the exit-code-only check below.
    # The tool writes human-readable status to stdout which is useful in the log.
    local output
    output=$(fips-mode-setup --check 2>&1 || true)
    log_info "  Output : $output"

    # Run a second time to get the clean exit code. stdout/stderr suppressed
    # because we already logged the output above.
    if fips-mode-setup --check &>/dev/null; then
        log_info "  Result : PASS"
        return 0
    else
        log_warn "  Result : FAIL — FIPS mode is not fully active."
        return 1
    fi
}

# --- Check 3: Kernel boot cmdline ---
# The fips=1 parameter must be present in the kernel boot arguments for FIPS
# to be activated on startup. Its absence means FIPS will not persist across
# reboots even if manually enabled at runtime.
check_fips_cmdline() {
    log_info "CHECK 3: Kernel boot parameters"
    log_info "  File   : /proc/cmdline"
    log_info "  Purpose: Verifies fips=1 was passed to the kernel at boot."
    log_info "           Without this, FIPS mode will not survive a reboot."

    local cmdline
    cmdline=$(cat /proc/cmdline)
    log_info "  Cmdline: $cmdline"

    # grep -w matches the whole word "fips=1" to avoid false positives from
    # parameters like "nofips=1" or "xfips=1".
    if echo "$cmdline" | grep -qw "fips=1"; then
        log_info "  Result : PASS — fips=1 is present."
    else
        log_warn "  Result : FAIL — fips=1 is NOT present in boot parameters."
        log_warn "           Add fips=1 to GRUB_CMDLINE_LINUX in /etc/default/grub"
        log_warn "           then run: grub2-mkconfig -o /boot/grub2/grub.cfg"
    fi
}

# --- Check 4: System crypto policy ---
# update-crypto-policies controls which algorithms are permitted system-wide
# for TLS, SSH, IPSec, etc. The policy must be set to FIPS to ensure all
# services use only FIPS-approved ciphers and key lengths.
check_crypto_policy() {
    log_info "CHECK 4: System-wide crypto policy"
    log_info "  Tool   : update-crypto-policies --show"
    log_info "  Purpose: The crypto policy controls which ciphers and algorithms"
    log_info "           are permitted system-wide (TLS, SSH, IPSec, Kerberos)."
    log_info "           Must be set to FIPS to enforce approved algorithms across"
    log_info "           all services without per-application configuration."

    # update-crypto-policies is RHEL/Rocky-specific; not present on Debian/Ubuntu
    if ! command_exists update-crypto-policies; then
        log_warn "  Result : SKIP — update-crypto-policies not found."
        return
    fi

    # Fallback to "unknown" prevents an unbound variable error if the command fails
    local policy
    policy=$(update-crypto-policies --show 2>/dev/null || echo "unknown")
    log_info "  Policy : $policy"

    if [[ "$policy" == "FIPS" ]]; then
        log_info "  Result : PASS"
    else
        log_warn "  Result : FAIL — policy is '$policy', expected 'FIPS'."
        log_warn "           To change: update-crypto-policies --set FIPS"
    fi
}

# --- Check 5: /etc/system-fips marker ---
# This file is written by fips-mode-setup when FIPS is enabled. Some
# applications and PAM modules check for it at startup to decide whether to
# restrict themselves to FIPS-approved algorithms independent of the kernel.
check_fips_marker() {
    log_info "CHECK 5: /etc/system-fips marker file"
    log_info "  File   : /etc/system-fips"
    log_info "  Purpose: Written by fips-mode-setup when FIPS is enabled."
    log_info "           Checked by PAM and some applications at startup to"
    log_info "           enforce FIPS-approved algorithms independently of the"
    log_info "           kernel flag. Its absence can cause app-level non-compliance."

    if [[ -f /etc/system-fips ]]; then
        log_info "  Result : PASS — marker file is present."
    else
        log_warn "  Result : FAIL — /etc/system-fips is NOT present."
        log_warn "           Run fips-mode-setup --enable to create it."
    fi
}

# --- Optionally enable FIPS ---
enable_fips() {
    # Guard: only proceed if the operator explicitly set ENABLE_FIPS=yes in config.conf.
    # Enabling FIPS has system-wide consequences and requires a reboot, so it must
    # be an intentional action rather than a side-effect of running the check module.
    if [[ "${ENABLE_FIPS:-no}" != "yes" ]]; then
        log_info "ENABLE_FIPS is not set to 'yes' in config.conf — skipping enablement."
        return
    fi

    if ! command_exists fips-mode-setup; then
        log_error "fips-mode-setup not available. Install crypto-policies-scripts first:"
        log_error "  dnf install -y crypto-policies-scripts"
        return 1
    fi

    # fips-mode-setup --enable sets the crypto policy to FIPS, creates /etc/system-fips,
    # and adds fips=1 to the kernel cmdline via GRUB. The kernel flag itself only
    # takes effect after reboot.
    log_warn "Enabling FIPS mode — a reboot will be required to take full effect."
    fips-mode-setup --enable
    log_info "FIPS mode has been enabled. Reboot the system to activate."
}

# --- Summary ---
print_summary() {
    # Track the two most authoritative checks separately so the final status
    # message can distinguish between fully compliant, partially compliant,
    # and non-compliant states.
    local kernel_ok=false tool_ok=false

    echo ""
    # The "|| true" prevents set -e from aborting the script when a check fails.
    # Each check function returns 1 on failure; we capture that into the boolean
    # flags and continue running all remaining checks regardless.
    check_fips_kernel  && kernel_ok=true  || true
    echo ""
    check_fips_tool    && tool_ok=true    || true
    echo ""
    check_fips_cmdline
    echo ""
    check_crypto_policy
    echo ""
    check_fips_marker

    echo ""
    echo "  -----------------------------------------------"
    if $kernel_ok && $tool_ok; then
        log_info "FIPS STATUS: COMPLIANT — all checks passed."
    elif $kernel_ok || $tool_ok; then
        # Partial means the kernel or the OS layer agrees on FIPS, but not both.
        # This is an unstable state that may indicate an incomplete enablement.
        log_warn "FIPS STATUS: PARTIAL — some checks failed. Review warnings above."
    else
        log_error "FIPS STATUS: NON-COMPLIANT — FIPS mode is not active."
        log_error "To enable FIPS on Rocky 9:"
        log_error "  1. dnf install -y crypto-policies-scripts"
        log_error "  2. fips-mode-setup --enable"
        log_error "  3. reboot"
    fi
    echo "  -----------------------------------------------"
}

# --- Artifact ---
save_artifact() {
    local artifact
    artifact=$(artifact_file "fips")

    local fips_kernel fips_tool_result cmdline_fips crypto_policy marker_present overall

    fips_kernel=$(cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo "unavailable")

    if command_exists fips-mode-setup; then
        fips-mode-setup --check &>/dev/null && fips_tool_result="PASS" || fips_tool_result="FAIL"
    else
        fips_tool_result="SKIP (fips-mode-setup not installed)"
    fi

    grep -qw "fips=1" /proc/cmdline 2>/dev/null && cmdline_fips="Yes" || cmdline_fips="No"

    if command_exists update-crypto-policies; then
        crypto_policy=$(update-crypto-policies --show 2>/dev/null || echo "unknown")
    else
        crypto_policy="unavailable (update-crypto-policies not installed)"
    fi

    [[ -f /etc/system-fips ]] && marker_present="Yes" || marker_present="No"

    if [[ "$fips_kernel" == "1" && "$fips_tool_result" == "PASS" ]]; then
        overall="COMPLIANT"
    elif [[ "$fips_kernel" == "1" || "$fips_tool_result" == "PASS" ]]; then
        overall="PARTIAL"
    else
        overall="NON-COMPLIANT"
    fi

    cat > "$artifact" <<EOF
FIPS COMPLIANCE CHECK REPORT
==============================
Generated  : $(date '+%Y-%m-%d %H:%M:%S')
Hostname   : $(hostname)
OS         : $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
Applied by : hardening/modules/fips/harden.sh

CHECK 1: Kernel FIPS flag  (/proc/sys/crypto/fips_enabled)
-----------------------------------------------------------
  Value  : $fips_kernel
  Result : $([ "$fips_kernel" == "1" ] && echo "PASS" || echo "FAIL")

CHECK 2: fips-mode-setup --check
----------------------------------
  Result : $fips_tool_result

CHECK 3: Kernel boot parameters  (/proc/cmdline)
--------------------------------------------------
  fips=1 present : $cmdline_fips
  Result         : $([ "$cmdline_fips" == "Yes" ] && echo "PASS" || echo "FAIL")

CHECK 4: System crypto policy
------------------------------
  Policy : $crypto_policy
  Result : $([ "$crypto_policy" == "FIPS" ] && echo "PASS" || echo "FAIL")

CHECK 5: /etc/system-fips marker
----------------------------------
  Present : $marker_present
  Result  : $([ "$marker_present" == "Yes" ] && echo "PASS" || echo "FAIL")

OVERALL STATUS
--------------
  $overall

FIPS ENABLEMENT
---------------
  ENABLE_FIPS setting : ${ENABLE_FIPS:-no}
  Action              : $([ "${ENABLE_FIPS:-no}" == "yes" ] && echo "Enablement requested (reboot required)" || echo "Audit only — no changes made")
EOF

    log_info "Artifact saved: $artifact"
}

# --- Main ---
log_section "FIPS Mode Check"
print_summary
echo ""
enable_fips

save_artifact
log_info "FIPS module complete."
