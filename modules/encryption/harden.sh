#!/usr/bin/env bash
# =============================================================================
# Module  : encryption
# Purpose : OS drive FDE status, second boot passphrase, and key backup.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../lib/common.sh"
source "$SCRIPT_DIR/../../config.conf"

check_root

_ensure_cryptsetup() {
    if ! command -v cryptsetup &>/dev/null; then
        log_info "Installing cryptsetup..."
        dnf install -y cryptsetup
    fi
}

_header() {
    echo ""
    echo "  ┌─────────────────────────────────────────────────────────┐"
    printf  "  │  %-55s│\n" "$1"
    echo "  └─────────────────────────────────────────────────────────┘"
    echo ""
}

# Detect FDE by walking the ancestry of the root device (handles LVM-on-LUKS).
_fde_enabled() {
    local root_dev
    root_dev=$(findmnt -n -o SOURCE / 2>/dev/null)
    [[ -n "$root_dev" ]] && lsblk -s -o TYPE "$root_dev" 2>/dev/null | grep -q "^crypt$"
}

# Return the underlying LUKS block device backing the OS root filesystem.
# Uses -r (raw) to strip lsblk tree characters, then walks the ancestry
# to find the partition/disk immediately beneath the crypt layer.
_os_luks_device() {
    local root_dev luks_dev
    root_dev=$(findmnt -n -o SOURCE / 2>/dev/null)
    luks_dev=$(lsblk -s -r -o NAME,TYPE "$root_dev" 2>/dev/null \
        | awk '$2=="crypt"{found=1; next} found && ($2=="part" || $2=="disk"){print "/dev/"$1; exit}')
    [[ -z "$luks_dev" ]] && return 1
    echo "$luks_dev"
}

# =============================================================================
# 1) Encryption Status
# =============================================================================

menu_status() {
    _header "Encryption Status"

    _ensure_cryptsetup

    if _fde_enabled; then
        echo -e "  OS Drive FDE : ${GREEN}ENABLED${NC}  — root filesystem is encrypted"
    else
        echo -e "  OS Drive FDE : ${RED}NOT ENABLED${NC}  — OS drive is not encrypted"
        echo ""
        echo "  Root filesystem encryption must be configured at OS install time."
        echo ""
        read -rp "  Press Enter to return..."
        return
    fi

    local luks_dev
    luks_dev=$(_os_luks_device 2>/dev/null || true)

    if [[ -n "$luks_dev" ]]; then
        echo ""
        echo "  LUKS device  : $luks_dev"
        echo ""

        local ver uuid cipher keysize
        ver=$(cryptsetup luksDump "$luks_dev" 2>/dev/null | awk '/^Version/{print $2}')
        uuid=$(blkid -s UUID -o value "$luks_dev" 2>/dev/null)
        cipher=$(cryptsetup luksDump "$luks_dev" 2>/dev/null | awk '/cipher:/{print $2}' | head -1)
        keysize=$(cryptsetup luksDump "$luks_dev" 2>/dev/null | awk '/Key:/{print $2,$3}' | head -1)

        printf "  %-16s %s\n" "LUKS version:"  "LUKS${ver}"
        printf "  %-16s %s\n" "UUID:"           "$uuid"
        printf "  %-16s %s\n" "Cipher:"         "$cipher"
        printf "  %-16s %s\n" "Key size:"       "$keysize"
        echo ""

        echo "  Key slots:"
        cryptsetup luksDump "$luks_dev" 2>/dev/null \
            | awk '/^Keyslots:/,0' \
            | grep -E "^\s+[0-9]+:|ENABLED|DISABLED" \
            | sed 's/^/    /'
    fi

    echo ""
    read -rp "  Press Enter to return..."
}

# =============================================================================
# 2) Add Second Boot Passphrase
# =============================================================================

menu_add_passphrase() {
    _header "Add Second Boot Passphrase"

    echo "  Adds a second passphrase to the OS LUKS device. Either passphrase"
    echo "  can independently unlock the drive at boot. Use this to create a"
    echo "  recovery credential stored in a password manager or secure vault."
    echo ""

    if ! _fde_enabled; then
        log_warn "OS drive FDE is not enabled — nothing to add a passphrase to."
        echo ""
        read -rp "  Press Enter to return..."
        return
    fi

    _ensure_cryptsetup

    local luks_dev
    luks_dev=$(_os_luks_device 2>/dev/null || true)
    if [[ -z "$luks_dev" ]]; then
        log_error "Could not determine the OS LUKS device."
        read -rp "  Press Enter to return..."
        return
    fi

    echo "  LUKS device  : $luks_dev"
    echo ""

    local existing_pass new_pass confirm_pass
    read -rsp "  Existing boot passphrase    : " existing_pass;   echo ""
    echo ""
    while true; do
        read -rsp "  New boot passphrase         : " new_pass;     echo ""
        read -rsp "  Confirm new boot passphrase : " confirm_pass; echo ""
        [[ "$new_pass" == "$confirm_pass" ]] && break
        echo "  Passphrases do not match — try again."
        echo ""
    done

    echo ""
    log_info "Adding new boot passphrase..."
    local _tmpkey
    _tmpkey=$(mktemp)
    trap 'rm -f "$_tmpkey"' RETURN
    printf '%s' "$new_pass" > "$_tmpkey"
    printf '%s' "$existing_pass" | cryptsetup luksAddKey --key-file=- "$luks_dev" "$_tmpkey"
    echo ""
    log_info "Second boot passphrase added successfully."

    local slots
    slots=$(cryptsetup luksDump "$luks_dev" 2>/dev/null | grep -c "ENABLED" || true)
    log_info "Key slots now in use: ${slots}"

    echo ""
    echo -e "  ${YELLOW}Store this passphrase in a separate, secure location.${NC}"
    echo -e "  ${YELLOW}Do not store it on this device.${NC}"
    echo ""
    read -rp "  Press Enter to return..."
}

# =============================================================================
# 3) Backup Recovery Key (keyfile)
# =============================================================================

_email_keyfile() {
    local keyfile="$1" luks_dev="$2"

    if ! command -v msmtp &>/dev/null; then
        log_warn "msmtp is not configured — run the SMTP Relay module first."
        return
    fi

    local recipient
    read -rp "  Recipient email address: " recipient
    echo ""
    [[ -z "$recipient" ]] && { log_info "Email skipped."; return; }

    echo -e "  ${YELLOW}Warning: this keyfile can unlock the OS drive. Only send it to a${NC}"
    echo -e "  ${YELLOW}trusted, encrypted destination (e.g. a personal vault address).${NC}"
    echo ""
    read -rp "  Send to ${recipient}? [y/N]: " _confirm
    [[ "${_confirm,,}" =~ ^y ]] || { log_info "Email cancelled."; return; }

    local hostname uuid filename b64key boundary map_name
    hostname=$(hostname)
    uuid=$(blkid -s UUID -o value "$luks_dev" 2>/dev/null || echo "unknown")
    filename=$(basename "$keyfile")
    b64key=$(base64 "$keyfile")
    boundary="====LUKS_KEYFILE_$(date +%s)===="
    map_name="luks-$(basename "$luks_dev")"

    {
        printf "To: %s\n"          "$recipient"
        printf "Subject: LUKS Recovery Key — %s\n" "$hostname"
        printf "MIME-Version: 1.0\n"
        printf "Content-Type: multipart/mixed; boundary=\"%s\"\n\n" "$boundary"

        printf -- "--%s\n" "$boundary"
        printf "Content-Type: text/plain; charset=utf-8\n\n"
        printf "LUKS recovery keyfile for host : %s\n" "$hostname"
        printf "LUKS device                    : %s\n" "$luks_dev"
        printf "LUKS UUID                      : %s\n" "$uuid"
        printf "Generated                      : %s\n\n" "$(date)"
        printf "Store this keyfile securely. Anyone with access to it can unlock the encrypted volume.\n\n"
        printf "Unlock with keyfile:\n"
        printf "  cryptsetup open %s %s --key-file %s\n\n" "$luks_dev" "$map_name" "$filename"
        printf "Unlock with passphrase:\n"
        printf "  cryptsetup open %s %s\n\n" "$luks_dev" "$map_name"
        printf "Mount after unlocking:\n"
        printf "  mount /dev/mapper/%s /mnt\n\n" "$map_name"
        printf "Key contents (base64) — save to file to recover:\n"
        printf "  echo '<base64 below>' | base64 -d > %s\n\n" "$filename"
        printf "%s\n\n" "$b64key"
        printf "Key contents (hex dump):\n"
        xxd "$keyfile" 2>/dev/null | sed 's/^/  /' || printf "  (xxd not available)\n"
        printf "\n"

        printf -- "--%s\n" "$boundary"
        printf "Content-Type: application/octet-stream\n"
        printf "Content-Transfer-Encoding: base64\n"
        printf "Content-Disposition: attachment; filename=\"%s\"\n\n" "$filename"
        printf "%s\n" "$b64key"
        printf -- "--%s--\n" "$boundary"
    } | msmtp "$recipient"

    log_info "Recovery key emailed to ${recipient}."
}

menu_backup_key() {
    _header "Backup Recovery Key"

    echo "  Generates a cryptographically random keyfile and adds it as a LUKS"
    echo "  key slot on the OS drive. The keyfile can unlock the drive in place"
    echo "  of a passphrase — copy it to an encrypted USB drive, key vault, or"
    echo "  secure off-system location immediately after creation."
    echo ""
    echo "  Anyone with access to this keyfile can unlock the OS drive."
    echo ""

    if ! _fde_enabled; then
        log_warn "OS drive FDE is not enabled — nothing to generate a key for."
        echo ""
        read -rp "  Press Enter to return..."
        return
    fi

    _ensure_cryptsetup

    local luks_dev
    luks_dev=$(_os_luks_device 2>/dev/null || true)
    if [[ -z "$luks_dev" ]]; then
        log_error "Could not determine the OS LUKS device."
        read -rp "  Press Enter to return..."
        return
    fi

    echo "  LUKS device  : $luks_dev"
    echo ""

    local default_path="/root/luks-os-recovery.key"
    read -rp "  Save keyfile to [default: ${default_path}]: " keyfile_path
    keyfile_path="${keyfile_path:-$default_path}"

    if [[ -f "$keyfile_path" ]]; then
        echo ""
        log_warn "File '${keyfile_path}' already exists."
        read -rp "  Overwrite? [y/N]: " _ow
        if [[ ! "${_ow,,}" =~ ^y ]]; then
            log_info "Cancelled."
            echo ""
            read -rp "  Press Enter to return..."
            return
        fi
    fi

    dd if=/dev/urandom of="$keyfile_path" bs=512 count=1 2>/dev/null
    chmod 400 "$keyfile_path"
    chown root:root "$keyfile_path"
    log_info "Keyfile generated: ${keyfile_path} (mode 400, root:root)"

    local existing_pass
    read -rsp "  Existing boot passphrase (to authenticate): " existing_pass; echo ""

    echo ""
    log_info "Adding keyfile to LUKS device..."
    printf '%s' "$existing_pass" | cryptsetup luksAddKey --key-file=- "$luks_dev" "$keyfile_path"
    echo ""
    log_info "Keyfile added as a key slot on ${luks_dev}."

    local slots
    slots=$(cryptsetup luksDump "$luks_dev" 2>/dev/null | grep -c "ENABLED" || true)
    log_info "Key slots now in use: ${slots}"

    echo ""
    echo "  Keyfile location : ${keyfile_path}"
    echo "  Unlock command   : cryptsetup open ${luks_dev} <name> --key-file ${keyfile_path}"
    echo ""
    echo -e "  ${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "  ${RED}║  Copy this keyfile off-system immediately.                  ║${NC}"
    echo -e "  ${RED}║  Use an encrypted USB drive, password vault, or secure      ║${NC}"
    echo -e "  ${RED}║  remote location — never store it only on this machine.     ║${NC}"
    echo -e "  ${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    read -rp "  Email the keyfile to a recipient? [y/N]: " _do_email
    [[ "${_do_email,,}" =~ ^y ]] && _email_keyfile "$keyfile_path" "$luks_dev"

    echo ""
    read -rp "  Press Enter to return..."
}

# =============================================================================
# 4) Data Disk Encryption
# =============================================================================

_list_devices() {
    echo "  Available block devices:"
    echo ""
    lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT -e 7,11 | sed 's/^/    /'
    echo ""
}

_prompt_device() {
    local var_name="$1"
    local dev
    while true; do
        read -rp "  Device path (e.g. /dev/sdb, /dev/sdb1): " dev
        if [[ -z "$dev" ]]; then
            echo "  Device path cannot be empty."
        elif [[ ! -b "$dev" ]]; then
            echo "  '$dev' is not a block device."
        else
            printf -v "$var_name" '%s' "$dev"
            return
        fi
    done
}

_assert_not_mounted() {
    local dev="$1"
    if grep -qs "$dev" /proc/mounts; then
        log_error "'$dev' is currently mounted — unmount it first."
        return 1
    fi
}

_data_encrypt() {
    _header "Encrypt a Data Disk"

    echo "  Formats a block device with LUKS2 and creates a filesystem inside it."
    echo "  ALL EXISTING DATA ON THE DEVICE WILL BE PERMANENTLY DESTROYED."
    echo ""
    echo "  Use this for new disks, empty partitions, or logical volumes."
    echo "  Do not use this on a device that contains data you want to keep."
    echo ""

    _ensure_cryptsetup
    _list_devices

    local dev
    _prompt_device dev
    _assert_not_mounted "$dev" || return

    if cryptsetup isLuks "$dev" 2>/dev/null; then
        echo ""
        log_warn "'$dev' is already a LUKS device."
        read -rp "  Re-encrypting will destroy all data inside. Continue? [y/N]: " _reenc
        [[ "${_reenc,,}" =~ ^y ]] || { log_info "Cancelled."; return; }
    fi

    local default_name="luks-$(basename "$dev")"
    read -rp "  Mapper name [default: ${default_name}]: " map_name
    map_name="${map_name:-$default_name}"

    echo ""
    local pass confirm_pass
    while true; do
        read -rsp "  Encryption passphrase : " pass;         echo ""
        read -rsp "  Confirm passphrase    : " confirm_pass; echo ""
        [[ "$pass" == "$confirm_pass" ]] && break
        echo "  Passphrases do not match — try again."
        echo ""
    done

    echo ""
    echo "  Filesystem to create inside the encrypted volume:"
    echo "    1) xfs   — default on RHEL/Rocky (recommended)"
    echo "    2) ext4  — widely supported"
    echo ""
    read -rp "  Selection [1-2, default=1]: " _fs
    local fstype
    case "${_fs:-1}" in
        2) fstype="ext4" ;;
        *) fstype="xfs"  ;;
    esac

    echo ""
    read -rp "  Mount point (leave blank to skip mounting): " mount_point

    echo ""
    echo "  Summary:"
    printf "    %-22s %s\n" "Device:"       "$dev"
    printf "    %-22s %s\n" "Mapper name:"  "/dev/mapper/${map_name}"
    printf "    %-22s %s\n" "Encryption:"   "LUKS2 / AES-256-XTS"
    printf "    %-22s %s\n" "Filesystem:"   "$fstype"
    printf "    %-22s %s\n" "Mount point:"  "${mount_point:-(not mounted)}"
    echo ""
    echo -e "  ${RED}WARNING: All data on ${dev} will be permanently erased.${NC}"
    echo ""
    read -rp "  Type YES to confirm: " _final
    [[ "$_final" != "YES" ]] && { log_info "Cancelled."; return; }
    echo ""

    log_section "Formatting with LUKS2"
    echo "$pass" | cryptsetup luksFormat \
        --type luks2 \
        --cipher aes-xts-plain64 \
        --key-size 256 \
        --hash sha256 \
        --batch-mode \
        "$dev"
    log_info "LUKS2 header written to ${dev}."

    log_section "Opening volume"
    echo "$pass" | cryptsetup open "$dev" "$map_name" --key-file -
    log_info "Volume opened at /dev/mapper/${map_name}."

    log_section "Creating filesystem"
    if [[ "$fstype" == "xfs" ]]; then
        mkfs.xfs "/dev/mapper/${map_name}"
    else
        mkfs.ext4 "/dev/mapper/${map_name}"
    fi
    log_info "${fstype} filesystem created."

    if [[ -n "$mount_point" ]]; then
        mkdir -p "$mount_point"
        mount "/dev/mapper/${map_name}" "$mount_point"
        log_info "Mounted at ${mount_point}."
    fi

    echo ""
    echo "  To unlock this volume automatically at boot, entries are needed in"
    echo "  /etc/crypttab (unlock) and /etc/fstab (mount)."
    echo ""
    read -rp "  Add auto-unlock entry to /etc/crypttab? [y/N]: " _ctab
    if [[ "${_ctab,,}" =~ ^y ]]; then
        local uuid
        uuid=$(blkid -s UUID -o value "$dev")
        backup_file /etc/crypttab
        echo "${map_name}  UUID=${uuid}  none  luks" >> /etc/crypttab
        log_info "Added to /etc/crypttab: ${map_name}  UUID=${uuid}  none  luks"
        log_info "You will be prompted for the passphrase at boot."

        if [[ -n "$mount_point" ]]; then
            read -rp "  Add auto-mount entry to /etc/fstab? [y/N]: " _ftab
            if [[ "${_ftab,,}" =~ ^y ]]; then
                backup_file /etc/fstab
                echo "/dev/mapper/${map_name}  ${mount_point}  ${fstype}  defaults  0  0" >> /etc/fstab
                log_info "Added to /etc/fstab: /dev/mapper/${map_name}  ${mount_point}"
            fi
        fi
    fi

    echo ""
    log_info "Encryption complete."
    cryptsetup status "/dev/mapper/${map_name}" 2>/dev/null | sed 's/^/  /'
    echo ""
    read -rp "  Press Enter to return..."
}

_data_open() {
    _header "Open LUKS Device"

    echo "  Unlocks an existing LUKS-encrypted device and makes it accessible"
    echo "  as a decrypted block device under /dev/mapper/."
    echo ""

    _ensure_cryptsetup
    _list_devices

    local dev
    _prompt_device dev

    if ! cryptsetup isLuks "$dev" 2>/dev/null; then
        log_error "'$dev' does not appear to be a LUKS device."
        echo ""
        read -rp "  Press Enter to return..."
        return
    fi

    local default_name="luks-$(basename "$dev")"
    read -rp "  Mapper name [default: ${default_name}]: " map_name
    map_name="${map_name:-$default_name}"

    if [[ -b "/dev/mapper/${map_name}" ]]; then
        log_warn "/dev/mapper/${map_name} is already open."
        echo ""
        read -rp "  Press Enter to return..."
        return
    fi

    echo ""
    cryptsetup open "$dev" "$map_name"
    log_info "Volume opened at /dev/mapper/${map_name}."

    echo ""
    read -rp "  Mount point (leave blank to skip): " mount_point
    if [[ -n "$mount_point" ]]; then
        mkdir -p "$mount_point"
        mount "/dev/mapper/${map_name}" "$mount_point"
        log_info "Mounted at ${mount_point}."
    fi
    echo ""
    read -rp "  Press Enter to return..."
}

_data_close() {
    _header "Close LUKS Device"

    echo "  Unmounts and locks an open LUKS mapping, making the data"
    echo "  inaccessible until the passphrase is entered again."
    echo ""

    local mappings
    mappings=$(dmsetup ls --target crypt 2>/dev/null | awk '{print $1}' || true)

    if [[ -z "$mappings" ]]; then
        log_info "No active LUKS mappings found."
        echo ""
        read -rp "  Press Enter to return..."
        return
    fi

    echo "  Active LUKS mappings:"
    local i=1
    local -a map_arr
    while IFS= read -r name; do
        echo "    ${i}) /dev/mapper/${name}"
        map_arr+=("$name")
        i=$(( i + 1 ))
    done <<< "$mappings"
    echo ""

    local choice
    while true; do
        read -rp "  Select mapping to close [1-${#map_arr[@]}]: " choice
        [[ "$choice" =~ ^[0-9]+$ ]] && \
            (( choice >= 1 && choice <= ${#map_arr[@]} )) && break
        echo "  Invalid selection."
    done

    local map_name="${map_arr[$((choice - 1))]}"
    local map_path="/dev/mapper/${map_name}"

    if grep -qs "$map_path" /proc/mounts; then
        local mnt
        mnt=$(grep "$map_path" /proc/mounts | awk '{print $2}')
        umount "$map_path"
        log_info "Unmounted from ${mnt}."
    fi

    cryptsetup close "$map_name"
    log_info "/dev/mapper/${map_name} closed and locked."
    echo ""
    read -rp "  Press Enter to return..."
}

menu_data_disk() {
    while true; do
        _header "Data Disk Encryption"

        echo "  Manage LUKS2 encryption for secondary (non-OS) drives,"
        echo "  partitions, and logical volumes."
        echo ""
        echo "    1) Encrypt a device   — format a data disk with LUKS2"
        echo "    2) Open LUKS device   — unlock and map an existing LUKS device"
        echo "    3) Close LUKS device  — unmount and lock an open LUKS mapping"
        echo "    4) Back"
        echo ""
        read -rp "  Selection [1-4]: " _d
        echo ""

        case "${_d}" in
            1) _data_encrypt ;;
            2) _data_open ;;
            3) _data_close ;;
            4) return ;;
            *) echo "  Invalid selection." ;;
        esac
    done
}

# =============================================================================
# 5) FDE Installation Guide
# =============================================================================

menu_fde_guide() {
    _header "FDE Installation Guide — Rocky Linux 9"

    cat <<'GUIDE'
  Full Disk Encryption (FDE) must be enabled at OS install time. There is no
  safe way to encrypt the running OS drive after installation. This guide
  walks through a Rocky Linux 9 installation with FDE enabled.

  ── WHAT GETS ENCRYPTED ────────────────────────────────────────────────────

    /          Root filesystem — all OS files and data
    /home      User home directories
    swap       Swap space (critical — RAM can be paged here)

    NOT encrypted:
    /boot      Kernel and initramfs must be readable before LUKS unlocks.
               This is expected and unavoidable on standard BIOS/UEFI systems.

  ── STEP-BY-STEP INSTALLATION ──────────────────────────────────────────────

  1. BOOT THE INSTALLER
       Boot from Rocky Linux 9 installation media (ISO/USB).
       At the GRUB boot menu, select "Install Rocky Linux 9".

       To enable FIPS mode alongside FDE, press 'e' at the GRUB menu,
       find the line starting with 'linuxefi' and append:
         inst.fips=1
       Then press Ctrl+X to boot.

  2. REACH INSTALLATION DESTINATION
       Proceed through the installer until you reach the main summary screen.
       Click "Installation Destination".

  3. SELECT YOUR DISK
       Select the target disk. Under "Storage Configuration" choose:
         • Automatic  — simplest; the installer creates an encrypted layout
         • Custom     — full control over partition sizes

  4. ENABLE ENCRYPTION
       Check the box: "Encrypt my data"
       Click "Done".

  5. SET YOUR PASSPHRASE
       You will be prompted to enter an encryption passphrase.
       This passphrase is required at every boot to unlock the drive.

       Requirements for a strong passphrase:
         • Minimum 20 characters
         • Mix of uppercase, lowercase, numbers, and symbols
         • Not a dictionary word or pattern
         • Store it in a password manager or secure vault — if lost,
           data on the drive cannot be recovered.

  6. PARTITION LAYOUT (Custom partitioning)
       Recommended layout for a standard server:

         /boot/efi    600 MiB    EFI System Partition  (unencrypted)
         /boot        1 GiB      Boot partition         (unencrypted)
         /            20+ GiB    Root — inside LUKS
         /var         20+ GiB    Logs/data — inside LUKS (optional separate)
         /home        remainder  User data — inside LUKS
         swap         = RAM size Swap — inside LUKS

       The installer wraps everything except /boot and /boot/efi in a
       single LUKS2 container and creates an LVM volume group inside it.

  7. COMPLETE INSTALLATION
       Continue through the remaining installer steps (network, user
       accounts, etc.) and click "Begin Installation".

  8. FIRST BOOT
       After installation the system will pause at a black screen with:
         "Please enter passphrase for disk <name>:"
       Enter your FDE passphrase. The system will then boot normally.
       This prompt appears at every boot.

  ── COMBINING FDE WITH FIPS ────────────────────────────────────────────────

    Adding inst.fips=1 to the installer boot line (Step 1) configures
    the system to use only FIPS 140 approved cryptographic algorithms
    from first boot. This covers both the LUKS encryption and all
    system-level cryptography (SSH, TLS, etc.).

    This is the recommended configuration for systems requiring both
    FIPS 140 compliance and data-at-rest protection.

  ── VERIFYING FDE AFTER INSTALLATION ──────────────────────────────────────

    Run this command on the installed system to confirm FDE is active:

      lsblk -o NAME,TYPE,MOUNTPOINT,FSTYPE

    Look for TYPE=crypt entries in the ancestry of the root mount (/).
    With LVM-on-LUKS (the default layout), the crypt layer sits beneath
    an LVM volume — not directly at /. Both are valid FDE configurations.

    This hardening script's main menu and encryption module will show:
      FDE : ENABLED  — root filesystem is encrypted

  ── IMPORTANT WARNINGS ─────────────────────────────────────────────────────

    • Do not attempt to encrypt the OS drive of a running system.
      FDE must be configured at install time.

    • Loss of the FDE passphrase means permanent, unrecoverable loss of
      all data on the drive. There is no backdoor or recovery key unless
      you explicitly create one (see option 3 — Backup Recovery Key).

    • FDE protects data at rest (powered off). It does not protect a
      running system — once unlocked and booted, the drive is accessible
      as normal. Combine FDE with access controls and MFA for defence
      in depth.

GUIDE

    read -rp "  Press Enter to return..."
}

# =============================================================================
# 6) Remove Key Slot
# =============================================================================

menu_remove_keyslot() {
    _header "Remove Key Slot"

    if ! _fde_enabled; then
        log_warn "OS drive FDE is not enabled — nothing to manage."
        echo ""
        read -rp "  Press Enter to return..."
        return
    fi

    _ensure_cryptsetup

    local luks_dev
    luks_dev=$(_os_luks_device 2>/dev/null || true)
    if [[ -z "$luks_dev" ]]; then
        log_error "Could not determine the OS LUKS device."
        read -rp "  Press Enter to return..."
        return
    fi

    echo "  LUKS device : $luks_dev"
    echo ""

    # Show current slots — LUKS2 active slots appear as "N: luks2",
    # LUKS1 active slots appear as "Key Slot N: ENABLED"
    echo "  Current key slots:"
    echo ""
    local luks_ver
    luks_ver=$(cryptsetup luksDump "$luks_dev" 2>/dev/null | awk '/^Version/{print $2; exit}')

    if [[ "$luks_ver" == "2" ]]; then
        cryptsetup luksDump "$luks_dev" 2>/dev/null \
            | awk '
                /^Keyslots:/ { in_slots=1; next }
                in_slots && /^[A-Za-z]/ && !/^[[:space:]]/ { in_slots=0 }
                in_slots && /^[[:space:]]+[0-9]+: / {
                    slot=$1; gsub(/:/, "", slot)
                    type=$2
                    printf "    Slot %-3s [%s]\n", slot, type
                }
            '
    else
        cryptsetup luksDump "$luks_dev" 2>/dev/null \
            | awk '/^Key Slot [0-9]+:/ { printf "    Slot %s [%s]\n", $3, $4 }'
    fi
    echo ""

    # Count active slots — refuse if only one remains
    local active_slots
    if [[ "$luks_ver" == "2" ]]; then
        active_slots=$(cryptsetup luksDump "$luks_dev" 2>/dev/null | grep -cE "^\s+[0-9]+: luks2" || true)
    else
        active_slots=$(cryptsetup luksDump "$luks_dev" 2>/dev/null | grep -c "ENABLED" || true)
    fi
    if [[ "$active_slots" -le 1 ]]; then
        echo -e "  ${RED}Only one active key slot remains.${NC}"
        echo "  Removing it would make the drive permanently inaccessible."
        echo "  Add a second passphrase or keyfile (options 2/3) before removing this slot."
        echo ""
        read -rp "  Press Enter to return..."
        return
    fi

    local slot_num
    while true; do
        read -rp "  Slot number to remove: " slot_num
        [[ "$slot_num" =~ ^[0-9]+$ ]] && break
        echo "  Enter a numeric slot number."
    done

    echo ""
    echo -e "  ${RED}Warning: removing slot ${slot_num} is permanent and cannot be undone.${NC}"
    echo "  Ensure at least one other working slot exists before proceeding."
    echo ""
    read -rp "  Type YES to confirm removal of slot ${slot_num}: " _confirm
    [[ "$_confirm" != "YES" ]] && { log_info "Cancelled."; echo ""; read -rp "  Press Enter to return..."; return; }

    echo ""
    local auth_pass
    read -rsp "  Enter an existing passphrase to authenticate: " auth_pass; echo ""
    echo ""

    log_info "Removing key slot ${slot_num}..."
    printf '%s' "$auth_pass" | cryptsetup luksKillSlot --key-file=- "$luks_dev" "$slot_num"
    echo ""
    log_info "Slot ${slot_num} removed."

    echo ""
    echo "  Remaining key slots:"
    echo ""
    if [[ "$luks_ver" == "2" ]]; then
        cryptsetup luksDump "$luks_dev" 2>/dev/null \
            | awk '
                /^Keyslots:/ { in_slots=1; next }
                in_slots && /^[A-Za-z]/ && !/^[[:space:]]/ { in_slots=0 }
                in_slots && /^[[:space:]]+[0-9]+: / {
                    slot=$1; gsub(/:/, "", slot)
                    type=$2
                    printf "    Slot %-3s [%s]\n", slot, type
                }
            '
    else
        cryptsetup luksDump "$luks_dev" 2>/dev/null \
            | awk '/^Key Slot [0-9]+:/ { printf "    Slot %s [%s]\n", $3, $4 }'
    fi
    echo ""
    read -rp "  Press Enter to return..."
}

# =============================================================================
# 7) LUKS Recovery Guide
# =============================================================================

menu_recovery_guide() {
    _header "LUKS Recovery Guide"

    cat <<'GUIDE'
  This guide covers all methods to unlock a LUKS-encrypted drive in a recovery
  scenario — whether you have the .key file, a passphrase, or only the base64
  plaintext from a backup email.

  ── STEP 1: IDENTIFY THE ENCRYPTED DRIVE ───────────────────────────────────

    List all drives and spot the LUKS partitions (FSTYPE = crypto_LUKS):

      lsblk -f

    Or filter directly:

      lsblk -o NAME,FSTYPE,SIZE,MOUNTPOINT | grep -i crypto

    Or get the UUID (useful if the device path changed):

      sudo blkid | grep -i luks

    The device path is typically /dev/sda2, /dev/nvme0n1p3, etc.
    Replace <dev> in the commands below with your actual device path.

  ── STEP 2: CHOOSE YOUR UNLOCK METHOD ──────────────────────────────────────

    METHOD A — Unlock with the .key file
    ─────────────────────────────────────
    Use this if you have the original binary .key file on USB or copied locally.

      sudo cryptsetup open <dev> luks-recovery --key-file /path/to/recovery.key

    METHOD B — Unlock with a passphrase
    ─────────────────────────────────────
    Use this if you know the boot passphrase (set at install or via option 2).

      sudo cryptsetup open <dev> luks-recovery

    You will be prompted to enter the passphrase interactively.

    METHOD C — Recover from base64 plaintext (from backup email)
    ─────────────────────────────────────────────────────────────
    Use this if you only have the base64 text copied from the backup email.
    The base64 must be decoded back to binary before cryptsetup can use it.

    Option 1 — decode to a temp file, then unlock:

      echo 'PASTE_BASE64_HERE' | base64 -d > /tmp/recovered.key
      sudo cryptsetup open <dev> luks-recovery --key-file /tmp/recovered.key
      shred -u /tmp/recovered.key

    Option 2 — pipe directly (key never touches disk):

      echo 'PASTE_BASE64_HERE' | base64 -d | \
        sudo cryptsetup open <dev> luks-recovery --key-file -

    Note: ensure the base64 string has no extra spaces or line breaks when
    pasting. Copy the full block exactly as it appeared in the email.

  ── STEP 3: VERIFY A KEY WORKS (DRY RUN) ───────────────────────────────────

    Test any key or recovered file without actually opening the device:

      sudo cryptsetup open <dev> --test-passphrase --key-file /path/to/key

    Or for a passphrase:

      sudo cryptsetup open <dev> --test-passphrase

    No error = key is valid. Exit code 0 = success.

    To verify a round-trip (original vs re-encoded base64 are identical):

      echo 'PASTE_BASE64_HERE' | base64 -d | diff /path/to/recovery.key -

    No output = byte-for-byte match. The base64 backup is a valid copy.

  ── STEP 4: MOUNT THE DECRYPTED VOLUME ─────────────────────────────────────

    After unlocking, the decrypted device appears at /dev/mapper/luks-recovery.

      sudo mount /dev/mapper/luks-recovery /mnt

    Access your files at /mnt.

  ── STEP 5: CLOSE THE VOLUME WHEN DONE ─────────────────────────────────────

    Always close the volume after use to re-lock the drive:

      sudo umount /mnt
      sudo cryptsetup close luks-recovery

  ── BOOT / LIVE USB RECOVERY ────────────────────────────────────────────────

    If the system will not boot, perform the above steps from a live USB:

    1. Boot from Rocky Linux 9 (or any Linux) live USB.
    2. Open a terminal.
    3. Run the unlock command for your chosen method (A, B, or C above).
    4. Mount the decrypted volume and access or repair your files.
    5. If repairing the bootloader, chroot into the mounted system:

         sudo mount /dev/mapper/luks-recovery /mnt
         sudo mount /dev/sda1 /mnt/boot          # adjust to your /boot device
         sudo chroot /mnt
         grub2-mkconfig -o /boot/grub2/grub.cfg
         exit
         sudo umount -R /mnt
         sudo cryptsetup close luks-recovery

  ── TIPS ────────────────────────────────────────────────────────────────────

    • Keep the .key file on an encrypted USB drive stored off-site.
    • Test your recovery key now using --test-passphrase while the system
      is running — do not wait until an emergency to find out it is invalid.
    • If you re-generate the key (option 3 in this module), the old key is
      removed from the LUKS key slot — update your backup immediately.
    • The mapper name (luks-recovery above) is arbitrary — use any label.
      It determines the path under /dev/mapper/ while the volume is open.

GUIDE

    read -rp "  Press Enter to return..."
}

# =============================================================================
# Main loop
# =============================================================================

while true; do
    _header "Filesystem Encryption — LUKS2"

    if _fde_enabled; then
        echo -e "  OS Drive FDE : ${GREEN}ENABLED${NC}  — root filesystem is encrypted"
    else
        echo -e "  OS Drive FDE : ${RED}NOT ENABLED${NC}  — OS drive is not encrypted"
        echo ""
        echo -e "  ${YELLOW}  FDE must be configured at OS install time. Options 2 and 3${NC}"
        echo -e "  ${YELLOW}  are unavailable. See option 4 for a step-by-step setup guide.${NC}"
    fi

    echo ""
    echo "    1) Encryption status      — show LUKS device details and active key slots"
    echo "    2) Add boot passphrase    — add a second passphrase to unlock at boot"
    echo "    3) Backup recovery key    — generate a keyfile for emergency access"
    echo "    4) Data disk encryption   — encrypt, open, or close a secondary data disk"
    echo "    5) FDE setup guide        — step-by-step guide to reinstall with FDE enabled"
    echo "    6) Remove key slot        — permanently delete a key slot from the LUKS device"
    echo "    7) Recovery guide         — how to unlock a drive using key, passphrase, or base64"
    echo "    8) Exit"
    echo ""
    read -rp "  Selection [1-8, default=1]: " _main
    echo ""

    case "${_main:-1}" in
        1) menu_status ;;
        2) menu_add_passphrase ;;
        3) menu_backup_key ;;
        4) menu_data_disk ;;
        5) menu_fde_guide ;;
        6) menu_remove_keyslot ;;
        7) menu_recovery_guide ;;
        8) log_info "Exiting encryption module."; exit 0 ;;
        *) echo "  Invalid selection." ;;
    esac
done
