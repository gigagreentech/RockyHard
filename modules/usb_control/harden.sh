#!/usr/bin/env bash
# =============================================================================
# Module  : usb_control
# Purpose : Restrict USB mass storage access by either blocking all USB
#           storage devices or limiting access to an operator-approved list
#           of devices identified by Vendor ID and Product ID.
#
# Two operating modes:
#
#   Full block  — prevents the usb_storage and uas kernel modules from loading
#                 at all via modprobe.d.  No USB mass storage device can be
#                 recognised regardless of VID/PID.
#
#   Whitelist   — the USB storage driver remains available, but udev is
#                 configured to set device node permissions to 000 on any
#                 device that is not on the approved list.  Approved devices
#                 function normally; all others are inaccessible at plug-in.
#
# This module performs the following actions in order:
#
#   1. MODE SELECTION (interactive)
#      The operator selects:
#        1) Full block  — block all USB storage, no exceptions
#        2) Whitelist   — block all USB storage except approved devices
#
#   2. DEVICE APPROVAL (whitelist mode only, interactive)
#      The operator enters one or more Vendor ID:Product ID pairs
#      (e.g. 0781:5567).  If lsusb is available, connected USB devices are
#      listed as a reference.  Each entry is validated against the
#      4-hex-digit:4-hex-digit format before being accepted.  At least one
#      approved device is required to proceed in whitelist mode.
#
#   3. CONFIGURATION PREVIEW
#      The selected mode and approved device list (if any) are displayed in
#      full before any changes are made.  The operator must confirm.
#
#   4. APPLY FULL BLOCK  (full block mode)
#      Writes /etc/modprobe.d/usb-storage-block.conf with install and
#      blacklist directives for usb_storage and uas.  Using
#      'install ... /bin/false' is stronger than blacklist alone — it causes
#      modprobe to fail even when the module is requested explicitly.
#      Any existing whitelist udev rules file is removed.
#      Live unload of usb_storage and uas is attempted; a warning is shown
#      if either module is in use (reboot required to complete).
#      The initramfs is rebuilt (dracut or update-initramfs) so the block
#      persists across reboots.
#
#   5. APPLY WHITELIST  (whitelist mode)
#      The full-block modprobe config is removed if present so that the
#      usb_storage driver can load for approved devices.
#      Writes /etc/udev/rules.d/99-usb-whitelist.rules with:
#        - Early GOTO exits for non-USB, non-block, non-add events
#        - One ATTRS GOTO rule per approved VID:PID (jumps past the block rule)
#        - A default RUN rule that sets /dev/%k permissions to 000 for any
#          device not matched by an approved entry
#      udev rules are reloaded immediately (udevadm control --reload-rules).
#      The restriction applies to devices plugged in after the rules load;
#      any already-connected unauthorised device requires a replug to trigger.
#
# Files modified:
#   /etc/modprobe.d/usb-storage-block.conf   — kernel module block (full block)
#   /etc/udev/rules.d/99-usb-whitelist.rules — udev device whitelist
#
# Dependencies:
#   modprobe, lsmod      — kmod
#   udevadm              — systemd-udev
#   lsusb                — usbutils (optional, used to list connected devices)
#   dracut               — dracut (initramfs rebuild on RHEL/Rocky)
#   update-initramfs     — initramfs-tools (initramfs rebuild on Debian/Ubuntu)
#
# Must be run as root (enforced by check_root in master.sh).
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../config.conf"
source "$SCRIPT_DIR/../../lib/common.sh"

USB_MODE=""           # "block" or "whitelist"
APPROVED_DEVICES=()   # array of normalised vid:pid strings

MODPROBE_CONF="/etc/modprobe.d/usb-storage-block.conf"
UDEV_RULES="/etc/udev/rules.d/99-usb-whitelist.rules"

# --- Mode selection ---
prompt_usb_mode() {
    echo ""
    echo "  Select USB storage control mode:"
    echo ""
    echo "  1) Full block  — deny ALL USB storage devices (no exceptions)"
    echo "  2) Whitelist   — deny all USB storage EXCEPT approved devices"
    echo ""
    while true; do
        read -rp "  Enter choice [1/2]: " choice
        case "$choice" in
            1) USB_MODE="block";     break ;;
            2) USB_MODE="whitelist"; break ;;
            *) echo "  Invalid choice. Enter 1 or 2." ;;
        esac
    done
}

# --- Approved device collection (whitelist mode only) ---
validate_vid_pid() {
    # Accepts exactly 4 hex digits, colon, 4 hex digits — e.g. 0781:5567
    [[ "$1" =~ ^[0-9a-fA-F]{4}:[0-9a-fA-F]{4}$ ]]
}

prompt_approved_devices() {
    echo ""
    echo "  Enter the Vendor ID:Product ID of each approved USB device."
    echo "  Format: 4 hex digits, colon, 4 hex digits — e.g. 0781:5567"
    echo ""

    if command_exists lsusb; then
        echo "  Connected USB devices (lsusb — the ID field gives you VID:PID):"
        echo ""
        lsusb | sed 's/^/    /'
        echo ""
    else
        echo "  Tip: run 'lsusb' with the device plugged in to find its VID:PID."
        echo ""
    fi

    echo "  Type 'done' when finished. At least one device is required."
    echo ""

    while true; do
        read -rp "  Enter VID:PID (or 'done'): " entry

        if [[ "${entry,,}" == "done" ]]; then
            if [[ ${#APPROVED_DEVICES[@]} -eq 0 ]]; then
                echo "  At least one approved device is required for whitelist mode."
            else
                break
            fi
        elif validate_vid_pid "$entry"; then
            local normalised="${entry,,}"
            # Deduplicate — skip if already in the list
            local already=false
            for existing in "${APPROVED_DEVICES[@]+"${APPROVED_DEVICES[@]}"}"; do
                [[ "$existing" == "$normalised" ]] && already=true && break
            done
            if $already; then
                echo "  $normalised is already in the approved list."
            else
                APPROVED_DEVICES+=("$normalised")
                log_info "Approved device added: $normalised"
            fi
        else
            echo "  Invalid format. Use 4 hex digits : 4 hex digits (e.g. 0781:5567)."
        fi
    done
}

# --- Preview ---
preview_configuration() {
    echo ""
    log_info "Configuration preview:"
    echo ""

    if [[ "$USB_MODE" == "block" ]]; then
        echo "    Mode : Full block — all USB storage denied"
        echo ""
        echo "    $MODPROBE_CONF"
        echo "      install usb_storage /bin/false"
        echo "      blacklist usb_storage"
        echo "      install uas /bin/false"
        echo "      blacklist uas"
    else
        echo "    Mode : Whitelist — approved devices only"
        echo ""
        echo "    Approved devices:"
        for dev in "${APPROVED_DEVICES[@]}"; do
            echo "      $dev"
        done
        echo ""
        echo "    $UDEV_RULES"
        echo "      (udev rules will deny any device not in the list above)"
    fi

    echo ""
    while true; do
        read -rp "  Apply this configuration? [Y/n]: " confirm
        confirm="${confirm:-y}"
        case "${confirm,,}" in
            y|yes) break ;;
            n|no)
                log_warn "USB control not applied. Re-run the module to try again."
                exit 0
                ;;
            *) echo "  Enter y or n." ;;
        esac
    done
}

# --- Shared helper: rebuild initramfs ---
rebuild_initramfs() {
    if command_exists dracut; then
        dracut -f
        log_info "Initramfs rebuilt via dracut."
    elif command_exists update-initramfs; then
        update-initramfs -u
        log_info "Initramfs rebuilt via update-initramfs."
    else
        log_warn "Neither dracut nor update-initramfs found — initramfs not rebuilt."
        log_warn "Reboot required for the modprobe block to take full effect."
    fi
}

# --- Apply: full block ---
apply_full_block() {
    # Remove any existing whitelist rules to avoid contradictory configuration
    if [[ -f "$UDEV_RULES" ]]; then
        backup_file "$UDEV_RULES"
        rm -f "$UDEV_RULES"
        udevadm control --reload-rules 2>/dev/null || true
        log_info "Existing whitelist udev rules removed."
    fi

    backup_file "$MODPROBE_CONF"
    cat > "$MODPROBE_CONF" <<'EOF'
# Managed by hardening/modules/usb_control — do not edit manually.
# 'install ... /bin/false' prevents the module loading even when requested
# explicitly via modprobe, which is stronger than a plain blacklist entry.
install usb_storage /bin/false
blacklist usb_storage
install uas /bin/false
blacklist uas
EOF

    log_info "USB storage block written to $MODPROBE_CONF."

    # Attempt live unload — fails silently if a device is currently in use.
    # The modprobe change takes full effect after a reboot in that case.
    for mod in uas usb_storage; do
        if lsmod | grep -q "^${mod} "; then
            if modprobe -r "$mod" 2>/dev/null; then
                log_info "Kernel module '$mod' unloaded."
            else
                log_warn "Could not unload '$mod' — device likely in use. Reboot to complete."
            fi
        fi
    done

    rebuild_initramfs
    log_info "Full USB storage block applied."
}

# --- Apply: whitelist ---
apply_whitelist() {
    # Remove the full-block modprobe config if it exists — the usb_storage
    # driver must be allowed to load for whitelisted devices to be recognised.
    if [[ -f "$MODPROBE_CONF" ]]; then
        backup_file "$MODPROBE_CONF"
        rm -f "$MODPROBE_CONF"
        log_info "Full-block modprobe config removed (whitelist mode takes over)."
    fi

    backup_file "$UDEV_RULES"

    {
        printf '# Managed by hardening/modules/usb_control — do not edit manually.\n'
        printf '# Re-run the module to update the approved device list.\n\n'

        # Skip rules that do not apply to USB storage add events
        printf 'ACTION!="add",      GOTO="usb_storage_end"\n'
        printf 'SUBSYSTEM!="block", GOTO="usb_storage_end"\n'
        printf 'SUBSYSTEMS!="usb",  GOTO="usb_storage_end"\n\n'

        printf '# Approved devices — jump past the deny rule\n'
        for dev in "${APPROVED_DEVICES[@]}"; do
            local vid="${dev%%:*}"
            local pid="${dev##*:}"
            printf 'ATTRS{idVendor}=="%s", ATTRS{idProduct}=="%s", GOTO="usb_storage_end"\n' \
                "$vid" "$pid"
        done

        printf '\n# Not in approved list — deny access to the device node\n'
        printf 'RUN+="/bin/chmod 000 /dev/%%k"\n\n'

        printf 'LABEL="usb_storage_end"\n'
    } > "$UDEV_RULES"

    chmod 644 "$UDEV_RULES"
    log_info "USB whitelist rules written to $UDEV_RULES."

    udevadm control --reload-rules
    log_info "udev rules reloaded — whitelist active for newly connected devices."
    log_warn "Devices already plugged in must be replugged to trigger the new rules."
}

# --- Artifact ---
save_artifact() {
    local artifact
    artifact=$(artifact_file "usb_control")

    {
        printf 'USB STORAGE CONTROL REPORT\n'
        printf '============================\n'
        printf 'Generated  : %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
        printf 'Hostname   : %s\n' "$(hostname)"
        printf 'OS         : %s\n' "$(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')"
        printf 'Applied by : hardening/modules/usb_control/harden.sh\n\n'

        if [[ "$USB_MODE" == "block" ]]; then
            printf 'CONTROL MODE\n'
            printf '------------\n'
            printf '  Mode : Full block — all USB storage denied\n\n'
            printf 'MODPROBE CONFIGURATION  (%s)\n' "$MODPROBE_CONF"
            printf '%s\n' "$(printf '%0.s-' {1..50})"
            if [[ -f "$MODPROBE_CONF" ]]; then
                grep -v '^#' "$MODPROBE_CONF" | grep -v '^$' | sed 's/^/  /'
            else
                printf '  File not found (may require reboot to verify)\n'
            fi
            printf '\n  Modules blocked : usb_storage, uas\n'
        else
            printf 'CONTROL MODE\n'
            printf '------------\n'
            printf '  Mode : Whitelist — approved devices only\n\n'
            printf 'APPROVED DEVICES\n'
            printf '----------------\n'
            if [[ ${#APPROVED_DEVICES[@]} -gt 0 ]]; then
                for dev in "${APPROVED_DEVICES[@]}"; do
                    printf '  %s\n' "$dev"
                done
            else
                printf '  None\n'
            fi
            printf '\n  All other USB storage devices : denied (chmod 000 at plug-in)\n\n'
            printf 'UDEV RULES FILE  (%s)\n' "$UDEV_RULES"
            printf '%s\n' "$(printf '%0.s-' {1..50})"
            if [[ -f "$UDEV_RULES" ]]; then
                printf '  File present\n'
            else
                printf '  File not found\n'
            fi
        fi
    } > "$artifact"

    log_info "Artifact saved: $artifact"
}

# --- Main ---
log_section "USB Storage Control"

prompt_usb_mode
[[ "$USB_MODE" == "whitelist" ]] && prompt_approved_devices
preview_configuration

echo ""
case "$USB_MODE" in
    block)     apply_full_block ;;
    whitelist) apply_whitelist  ;;
esac

save_artifact
log_info "USB control module complete."
