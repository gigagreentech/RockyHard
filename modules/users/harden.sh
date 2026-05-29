#!/usr/bin/env bash
# =============================================================================
# Module  : users
# Purpose : Interactively manage local user accounts and group memberships.
#
# Password complexity and aging policy are handled by the password_policy
# module and should be run before this module so new accounts immediately
# inherit the hardened defaults.
#
# This module presents a sub-menu with four actions:
#
#   1. CREATE USER
#      The operator selects one of three user types:
#
#        Admin    — created with home directory and bash shell, added to
#                   ADMIN_GROUP (config.conf; currently: wheel).
#                   If LOCK_ROOT=yes, root is locked via passwd -l after
#                   verifying the new user is in ADMIN_GROUP.  su is
#                   restricted to wheel via pam_wheel.so use_uid.
#
#        Standard — created with home directory and bash shell, no
#                   supplementary groups, no sudo access.
#
#        Service  — non-interactive, locked account for daemons/automation.
#                   Options prompted:
#                     - Description / GECOS comment
#                     - System account (UID < 1000, default: yes)
#                     - Working directory (default: none; /var/lib/<name>)
#                     - Login shell: /sbin/nologin (default), /bin/false,
#                       or custom
#                   After creation the operator selects from a permission
#                   menu (comma-separated, e.g. 1,2):
#                     0) None            — no additional groups (default)
#                     1) adm             — read access to /var/log
#                     2) systemd-journal — read access to systemd journal
#                     3) www-data/apache — web server file group
#                     4) ssl-cert        — TLS certificate key access
#                     5) docker          — Docker socket (root-equivalent)
#                     6) mail            — mail spool access
#                     7) Custom          — enter group names manually
#                   Password is locked (passwd -l); no interactive login
#                   is possible regardless of shell setting.
#
#      Admin/Standard: username validated; duplicate accounts offered an
#      update path.  Password entered twice, must meet MIN_PASSWORD_LENGTH,
#      applied via chpasswd.  chage -d 0 forces a reset at first login.
#
#   2. ADD USER TO GROUP(S)
#      Prompts for an existing username, shows current group memberships, then
#      prompts for one or more groups (space or comma-separated).  Missing
#      groups are offered creation via groupadd.  Applied via usermod -aG.
#
#   3. USER GROUP MEMBERSHIP
#      Prompts for a username and displays UID, primary group, and all
#      supplementary groups with GID and member list.
#
#   4. LIST ALL GROUPS
#      Reads /etc/group (sorted by GID) and displays two sections:
#        - System groups  (GID < 1000)
#        - User groups    (GID >= 1000)
#      For each group, two layers of permission information are shown:
#        Permissions — description from a built-in map of ~60 well-known
#                      groups (wheel, adm, docker, ssl-cert, kvm, etc.)
#        Sudo rules  — live-queried from /etc/sudoers and /etc/sudoers.d/
#      Groups with neither a known description nor any sudo rules are shown
#      compactly on a single line.  Groups with extra info get an indented
#      annotation block below them.
#      Members column shows supplementary membership only.
#
# Configuration values read from config.conf:
#   ADMIN_GROUP         = wheel
#   LOCK_ROOT           = yes
#   MIN_PASSWORD_LENGTH = 8
#
# Files modified:
#   /etc/pam.d/su — su restriction (admin path only, if LOCK_ROOT=yes)
#
# Dependencies:
#   useradd, usermod, groupadd, chpasswd, chage, passwd — shadow-utils
#   getent, id, groups                                  — glibc-common
#
# Must be run as root (enforced by check_root in master.sh).
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../config.conf"
source "$SCRIPT_DIR/../../lib/common.sh"

check_root

# Global state — user creation
USER_TYPE=""
NEW_USERNAME=""
NEW_PASSWORD=""

# Global state — service account creation
SVC_SYSTEM="yes"
SVC_SHELL=""
SVC_HOME_DIR=""
SVC_COMMENT=""
SERVICE_PERMISSIONS=()

# =============================================================================
# Shared helpers
# =============================================================================

# Check if a single-digit option appears in a comma-separated selection string.
# Example: _selection_has "1,3,5" "3"  → true
#          _selection_has "13"    "3"  → false  (13 is not option 3)
_selection_has() {
    [[ ",$1," == *",$2,"* ]]
}

# Return the appropriate nologin shell path for this distro.
_nologin_path() {
    if [[ -x /sbin/nologin ]]; then
        echo "/sbin/nologin"
    elif [[ -x /usr/sbin/nologin ]]; then
        echo "/usr/sbin/nologin"
    else
        echo "/bin/false"
    fi
}

# Built-in descriptions for well-known groups.
# These describe the access or capability the group grants on a standard system.
declare -A KNOWN_GROUP_PERMS
KNOWN_GROUP_PERMS=(
    # --- Privilege / admin ---
    [root]="Unrestricted system access"
    [wheel]="Full sudo access — members can run any command as any user"
    [sudo]="Full sudo access — members can run any command as any user"
    [operator]="System operator access to some admin commands"

    # --- Logging ---
    [adm]="Read access to most log files in /var/log"
    [systemd-journal]="Read access to the systemd journal (journalctl)"
    [utmp]="Write access to login records (/var/run/utmp, /var/log/wtmp)"

    # --- Security / credentials ---
    [shadow]="Read access to /etc/shadow (stores hashed passwords) — sensitive"
    [ssl-cert]="Read access to TLS/SSL certificate private keys (/etc/ssl/private)"
    [kmem]="Read access to kernel memory (/dev/mem, /dev/kmem) — dangerous"

    # --- Storage devices ---
    [disk]="Raw read/write access to block devices (/dev/sd*, /dev/nvme*) — root-equivalent"
    [tape]="Access to tape backup devices (/dev/st*, /dev/nst*)"
    [floppy]="Access to floppy drives (/dev/fd*)"
    [cdrom]="Access to optical drives (/dev/cdrom, /dev/dvd, /dev/sr*)"

    # --- Serial / comms devices ---
    [dialout]="Access to serial and modem devices (/dev/ttyS*, /dev/ttyUSB*)"
    [uucp]="UUCP serial networking devices and spool files"
    [tty]="Access to TTY character devices (/dev/tty*)"

    # --- Hardware / peripheral devices ---
    [video]="Access to video capture and GPU frame-buffer devices (/dev/video*, /dev/dri/)"
    [render]="Access to GPU render nodes (/dev/dri/renderD*)"
    [audio]="Access to audio devices (/dev/snd/)"
    [lp]="Access to printer devices (/dev/lp*)"
    [input]="Access to input event devices (/dev/input/*)"
    [rfkill]="Control RF kill switches — enable/disable WiFi and Bluetooth"
    [kvm]="Access to KVM hardware virtualisation (/dev/kvm)"
    [sgx]="Access to Intel SGX enclave driver (/dev/sgx*)"

    # --- Virtualisation / containers ---
    [libvirt]="Libvirt virtualisation management via /var/run/libvirt/libvirt-sock"
    [docker]="Docker daemon socket (/var/run/docker.sock) — root-equivalent"
    [podman]="Podman rootless container management"
    [vboxusers]="VirtualBox USB passthrough and host device access"

    # --- USB / hotplug ---
    [plugdev]="Access to hot-pluggable devices (USB mass storage, cameras)"

    # --- Network ---
    [netdev]="Network interface configuration (NetworkManager)"
    [bluetooth]="Bluetooth device sockets and management"
    [wireshark]="Raw packet capture via dumpcap without root"

    # --- System services ---
    [systemd-network]="systemd-networkd — manages network interfaces"
    [systemd-resolve]="systemd-resolved — manages DNS resolution"
    [systemd-timesync]="systemd-timesyncd — manages system clock sync"
    [polkitd]="PolicyKit authentication daemon"
    [dbus]="D-Bus system message bus"
    [cron]="Cron spool and configuration file access"
    [mail]="Access to mail spool files (/var/spool/mail)"
    [news]="Network news (NNTP) spool files"
    [backup]="Access to backup files and utilities"

    # --- Web / app services ---
    [www-data]="Web server document root and config files (/var/www)"
    [apache]="Apache httpd web server files and config"
    [nginx]="Nginx web server files and config"
    [cups]="CUPS print system socket and spool"
    [lpadmin]="CUPS printer administration"
    [sambashare]="Samba shared directory access"

    # --- Databases ---
    [mysql]="MySQL/MariaDB database files (/var/lib/mysql)"
    [postgres]="PostgreSQL database files (/var/lib/pgsql)"
    [postgresql]="PostgreSQL database files"
    [redis]="Redis data files and socket (/var/lib/redis)"
    [mongodb]="MongoDB data files (/var/lib/mongodb)"

    # --- SSH ---
    [ssh]="SSH host key storage and privilege-separation directory"
    [sshd]="SSH daemon privilege-separation chroot"

    # --- Minimal / no-privilege ---
    [users]="General unprivileged users group"
    [nogroup]="No-privilege group for isolated or namespaced processes"
    [nobody]="Minimal no-privilege group — often used by daemons"

    # --- System housekeeping ---
    [bin]="Owns standard system binaries (/bin, /usr/bin)"
    [daemon]="Generic daemon process group"
    [sys]="Owns kernel and system pseudo-files"
    [man]="Owns manual page files (/usr/share/man)"
    [games]="Game score and data files (/var/games)"
    [proxy]="HTTP proxy cache files"
)

# Return the built-in permission description for a group, or empty if not known.
_get_group_known_perms() {
    echo "${KNOWN_GROUP_PERMS[${1}]:-}"
}

# Return any sudoers rules that explicitly grant this group elevated access.
# Queries /etc/sudoers and every file in /etc/sudoers.d/.
_get_group_sudo_rules() {
    local grp="$1"
    local rules="" drop_rules=""

    if [[ -r /etc/sudoers ]]; then
        rules=$(grep -E "^[[:space:]]*%${grp}[[:space:]]" /etc/sudoers 2>/dev/null \
            | sed 's/^[[:space:]]*//' || true)
    fi

    if [[ -d /etc/sudoers.d ]]; then
        drop_rules=$(grep -rh "^[[:space:]]*%${grp}[[:space:]]" /etc/sudoers.d/ 2>/dev/null \
            | sed 's/^[[:space:]]*//' || true)
        [[ -n "$drop_rules" ]] && rules="${rules:+${rules}$'\n'}${drop_rules}"
    fi

    echo "$rules"
}

# Print indented permission annotations for a group beneath its summary line.
# Shows nothing when neither a known description nor sudo rules exist.
_print_group_perms() {
    local grp="$1"
    local known sudo_rules has_output=false

    known=$(_get_group_known_perms "$grp")
    sudo_rules=$(_get_group_sudo_rules "$grp")

    if [[ -n "$known" ]]; then
        printf "       %-12s : %s\n" "Permissions" "$known"
        has_output=true
    fi

    if [[ -n "$sudo_rules" ]]; then
        while IFS= read -r rule; do
            [[ -n "$rule" ]] && printf "       %-12s : %s\n" "Sudo rule" "$rule"
        done <<< "$sudo_rules"
        has_output=true
    fi

    # Blank line after annotated entries to visually separate them from the next
    $has_output && echo ""
}

# =============================================================================
# User creation — prompts (shared by admin/standard and service paths)
# =============================================================================

prompt_username() {
    while true; do
        read -rp "  Enter username: " NEW_USERNAME
        if [[ -z "$NEW_USERNAME" ]]; then
            echo "  Username cannot be empty."
        elif ! [[ "$NEW_USERNAME" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
            echo "  Invalid username. Use lowercase letters, digits, hyphens, or underscores."
        elif id "$NEW_USERNAME" &>/dev/null; then
            log_warn "User '$NEW_USERNAME' already exists."
            read -rp "  Update this user's password and groups? [y/N]: " cont
            [[ "$cont" =~ ^[Yy]$ ]] && break
        else
            break
        fi
    done
}

prompt_user_type() {
    echo ""
    echo "  Select user type:"
    echo "  1) Admin user       — added to $ADMIN_GROUP (full sudo access)"
    echo "  2) Standard user    — no sudo (minimum privilege)"
    echo "  3) Service account  — locked, non-interactive account for daemons and automation"
    echo ""
    while true; do
        read -rp "  Enter choice [1/2/3]: " USER_TYPE
        case "$USER_TYPE" in
            1|2|3) break ;;
            *) echo "  Invalid choice. Enter 1, 2, or 3." ;;
        esac
    done
}

prompt_password() {
    local confirm
    while true; do
        read -rsp "  Enter initial password for '$NEW_USERNAME': " NEW_PASSWORD
        echo ""
        read -rsp "  Confirm password: " confirm
        echo ""
        if [[ "$NEW_PASSWORD" != "$confirm" ]]; then
            echo "  Passwords do not match. Try again."
        elif [[ ${#NEW_PASSWORD} -lt $MIN_PASSWORD_LENGTH ]]; then
            echo "  Password too short (minimum $MIN_PASSWORD_LENGTH characters)."
        else
            break
        fi
    done
}

# =============================================================================
# User creation — apply
# =============================================================================

create_admin_user() {
    if ! id "$NEW_USERNAME" &>/dev/null; then
        useradd -m -s /bin/bash -G "$ADMIN_GROUP" "$NEW_USERNAME"
        log_info "Created admin user '$NEW_USERNAME', added to group '$ADMIN_GROUP'."
    else
        usermod -aG "$ADMIN_GROUP" "$NEW_USERNAME"
        log_info "User '$NEW_USERNAME' exists — added to group '$ADMIN_GROUP'."
    fi
    echo "$NEW_USERNAME:$NEW_PASSWORD" | chpasswd
    chage -d 0 "$NEW_USERNAME"
    log_info "Password set. '$NEW_USERNAME' must change it at first login."
}

create_standard_user() {
    if ! id "$NEW_USERNAME" &>/dev/null; then
        useradd -m -s /bin/bash "$NEW_USERNAME"
        log_info "Created standard user '$NEW_USERNAME' (no sudo access)."
    else
        log_warn "User '$NEW_USERNAME' exists — updating password only."
    fi
    echo "$NEW_USERNAME:$NEW_PASSWORD" | chpasswd
    chage -d 0 "$NEW_USERNAME"
    log_info "Password set. '$NEW_USERNAME' must change it at first login."
}

# =============================================================================
# Root lock (admin path only)
# =============================================================================

verify_sudo_access() {
    if ! groups "$NEW_USERNAME" | grep -qw "$ADMIN_GROUP"; then
        log_error "User '$NEW_USERNAME' is not in group '$ADMIN_GROUP'. Aborting root lock."
        exit 1
    fi
    if ! getent group "$ADMIN_GROUP" &>/dev/null; then
        log_error "Group '$ADMIN_GROUP' does not exist on this system."
        exit 1
    fi
    log_info "Sudo access verified for '$NEW_USERNAME'."
}

lock_root() {
    if [[ "$LOCK_ROOT" != "yes" ]]; then
        log_info "LOCK_ROOT is not enabled — skipping."
        return
    fi
    verify_sudo_access
    passwd -l root
    log_info "Root account locked."
    backup_file /etc/pam.d/su
    if ! grep -q "auth required pam_wheel.so use_uid" /etc/pam.d/su; then
        echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su
        log_info "Restricted 'su' to wheel group members only."
    fi
}

# =============================================================================
# Action 1: Create admin/standard user
# =============================================================================

action_create_user() {
    log_section "Create User"
    prompt_user_type

    if [[ "$USER_TYPE" == "3" ]]; then
        SVC_SYSTEM="yes"
        SVC_SHELL=""
        SVC_HOME_DIR=""
        SVC_COMMENT=""
        SERVICE_PERMISSIONS=()
        echo ""
        prompt_username
        _prompt_svc_options
        _prompt_svc_permissions
        _preview_svc_account
        _create_svc_account_apply
        _apply_svc_permissions
        _save_service_account_artifact
        return
    fi

    prompt_username
    prompt_password

    case "$USER_TYPE" in
        1) create_admin_user; lock_root ;;
        2) create_standard_user ;;
    esac

    _save_creation_artifact
}

_prompt_svc_options() {
    echo ""

    # Description / GECOS comment
    echo "  ── Account Options ─────────────────────────────────────────────────"
    read -rp "  Description (e.g. 'Nginx web server'): " SVC_COMMENT

    # System account (UID < 1000)?
    echo ""
    while true; do
        read -rp "  Create as system account (UID < 1000)? [Y/n] (default: Y): " ans
        ans="${ans:-y}"
        case "${ans,,}" in
            y|yes) SVC_SYSTEM="yes"; break ;;
            n|no)  SVC_SYSTEM="no";  break ;;
            *) echo "  Enter y or n." ;;
        esac
    done

    # Working directory
    echo ""
    while true; do
        read -rp "  Create a working directory for this account? [y/N] (default: N): " ans
        ans="${ans:-n}"
        case "${ans,,}" in
            y|yes)
                local default_dir="/var/lib/$NEW_USERNAME"
                read -rp "  Directory path (default: $default_dir): " ans2
                SVC_HOME_DIR="${ans2:-$default_dir}"
                break
                ;;
            n|no) SVC_HOME_DIR=""; break ;;
            *) echo "  Enter y or n." ;;
        esac
    done

    # Login shell
    local nologin
    nologin=$(_nologin_path)
    echo ""
    echo "  ── Login Shell ─────────────────────────────────────────────────────"
    echo "  1) $nologin  — returns a polite message, no interactive access (recommended)"
    echo "  2) /bin/false             — silently rejects all login attempts"
    echo "  3) Custom                 — specify a shell path"
    echo ""
    while true; do
        read -rp "  Shell [1-3, default: 1]: " ans
        ans="${ans:-1}"
        case "$ans" in
            1) SVC_SHELL="$nologin"; break ;;
            2) SVC_SHELL="/bin/false"; break ;;
            3)
                read -rp "  Shell path: " SVC_SHELL
                if [[ -z "$SVC_SHELL" ]]; then
                    echo "  Shell path cannot be empty."
                elif [[ ! -x "$SVC_SHELL" ]]; then
                    echo "  '$SVC_SHELL' not found or not executable."
                else
                    break
                fi
                ;;
            *) echo "  Enter 1, 2, or 3." ;;
        esac
    done
}

_prompt_svc_permissions() {
    echo ""
    echo "  ── Service Account Permissions ─────────────────────────────────────"
    echo "  Select permission groups to assign to '$NEW_USERNAME'."
    echo "  Enter numbers comma-separated (e.g. 1,3) or 0 for none."
    echo ""
    echo "  0) None            — no additional group memberships (recommended)"
    echo "  1) adm             — read access to log files in /var/log"
    echo "  2) systemd-journal — read access to the systemd journal"
    echo "  3) www-data/apache — web server file group (distro-appropriate)"
    echo "  4) ssl-cert        — read access to TLS certificate private keys"
    echo "  5) docker          — Docker daemon socket (warning: root-equivalent)"
    echo "  6) mail            — access to the mail spool"
    echo "  7) Custom          — enter one or more group names manually"
    echo ""

    local selections
    while true; do
        read -rp "  Permissions [default: 0]: " selections
        selections="${selections:-0}"
        selections="${selections// /}"   # strip spaces; allow commas only between digits

        if ! [[ "$selections" =~ ^[0-7,]+$ ]]; then
            echo "  Enter numbers 0-7 separated by commas."
            continue
        fi
        if _selection_has "$selections" "0" && [[ "$selections" != "0" ]]; then
            echo "  Cannot combine None (0) with other options. Enter 0 alone or choose from 1-7."
            continue
        fi
        break
    done

    if [[ "$selections" == "0" ]]; then
        log_info "No additional permissions selected."
        return
    fi

    # adm — log file access
    _selection_has "$selections" "1" && SERVICE_PERMISSIONS+=("adm") || true

    # systemd-journal
    _selection_has "$selections" "2" && SERVICE_PERMISSIONS+=("systemd-journal") || true

    # www-data / apache (distro-appropriate)
    if _selection_has "$selections" "3"; then
        if getent group www-data &>/dev/null; then
            SERVICE_PERMISSIONS+=("www-data")
        elif getent group apache &>/dev/null; then
            SERVICE_PERMISSIONS+=("apache")
        else
            log_warn "Neither 'www-data' nor 'apache' group found — skipping option 3."
        fi
    fi

    # ssl-cert
    if _selection_has "$selections" "4"; then
        if getent group ssl-cert &>/dev/null; then
            SERVICE_PERMISSIONS+=("ssl-cert")
        else
            log_warn "Group 'ssl-cert' not found on this system — skipping option 4."
        fi
    fi

    # docker — warn loudly: membership grants root-equivalent access
    if _selection_has "$selections" "5"; then
        echo ""
        echo -e "  ${YELLOW}  Warning: docker group membership grants effective root-equivalent access."
        echo "  Any process running as '$NEW_USERNAME' could trivially escalate to root"
        echo -e "  via 'docker run --rm -v /:/mnt ...'. Only assign if strictly required.${NC}"
        echo ""
        read -rp "  Confirm docker group access for '$NEW_USERNAME'? [y/N]: " confirm_docker
        if [[ "${confirm_docker,,}" =~ ^y ]]; then
            if getent group docker &>/dev/null; then
                SERVICE_PERMISSIONS+=("docker")
            else
                log_warn "Group 'docker' not found — is Docker installed? Skipping option 5."
            fi
        else
            log_info "Docker group access declined."
        fi
    fi

    # mail
    _selection_has "$selections" "6" && SERVICE_PERMISSIONS+=("mail") || true

    # custom groups
    _selection_has "$selections" "7" && _prompt_custom_svc_groups || true
}

_prompt_custom_svc_groups() {
    echo ""
    echo "  ── Custom Groups ───────────────────────────────────────────────────"
    echo "  Enter group name(s) — space or comma-separated."
    local custom_input
    read -rp "  Groups: " custom_input
    [[ -z "$custom_input" ]] && return

    local normalised="${custom_input//,/ }"
    local grp
    for grp in $normalised; do
        [[ -z "$grp" ]] && continue
        if getent group "$grp" &>/dev/null; then
            SERVICE_PERMISSIONS+=("$grp")
            log_info "Group '$grp' found."
        else
            echo ""
            log_warn "Group '$grp' does not exist."
            read -rp "  Create group '$grp'? [y/N]: " create_grp
            if [[ "${create_grp,,}" =~ ^y ]]; then
                groupadd "$grp"
                log_info "Group '$grp' created."
                SERVICE_PERMISSIONS+=("$grp")
            else
                log_info "Skipping group '$grp'."
            fi
        fi
    done
}

_preview_svc_account() {
    echo ""
    log_info "Service account configuration preview:"
    echo ""
    printf "    %-22s : %s\n" "Username"         "$NEW_USERNAME"
    printf "    %-22s : %s\n" "Description"      "${SVC_COMMENT:-(none)}"
    printf "    %-22s : %s\n" "System account"   "$SVC_SYSTEM  (UID < 1000)"
    printf "    %-22s : %s\n" "Working directory" "${SVC_HOME_DIR:-(none)}"
    printf "    %-22s : %s\n" "Login shell"      "$SVC_SHELL"
    printf "    %-22s : %s\n" "Password"         "locked (no interactive login)"
    if [[ ${#SERVICE_PERMISSIONS[@]} -gt 0 ]]; then
        printf "    %-22s : %s\n" "Permission groups" "${SERVICE_PERMISSIONS[*]}"
    else
        printf "    %-22s : %s\n" "Permission groups" "(none)"
    fi
    echo ""
    while true; do
        read -rp "  Create this service account? [Y/n]: " confirm
        confirm="${confirm:-y}"
        case "${confirm,,}" in
            y|yes) break ;;
            n|no)
                log_warn "Service account creation cancelled."
                return 1
                ;;
            *) echo "  Enter y or n." ;;
        esac
    done
}

_create_svc_account_apply() {
    local useradd_args=()

    # System account: -r implies no home directory; we add -m -d only when wanted
    [[ "$SVC_SYSTEM" == "yes" ]] && useradd_args+=("-r")

    useradd_args+=("-s" "$SVC_SHELL")

    [[ -n "$SVC_COMMENT" ]] && useradd_args+=("-c" "$SVC_COMMENT")

    if [[ -n "$SVC_HOME_DIR" ]]; then
        useradd_args+=("-m" "-d" "$SVC_HOME_DIR")
    elif [[ "$SVC_SYSTEM" != "yes" ]]; then
        useradd_args+=("-M")   # non-system accounts don't get a home dir unless requested
    fi

    if ! id "$NEW_USERNAME" &>/dev/null; then
        useradd "${useradd_args[@]}" "$NEW_USERNAME"
        log_info "Service account '$NEW_USERNAME' created."
    else
        log_warn "Account '$NEW_USERNAME' already exists — updating shell and comment."
        usermod -s "$SVC_SHELL" "$NEW_USERNAME"
        [[ -n "$SVC_COMMENT" ]] && usermod -c "$SVC_COMMENT" "$NEW_USERNAME" || true
    fi

    # Lock password — the account must never be used for interactive login
    passwd -l "$NEW_USERNAME"
    log_info "Password locked for '$NEW_USERNAME' — no interactive login possible."
}

_apply_svc_permissions() {
    if [[ ${#SERVICE_PERMISSIONS[@]} -eq 0 ]]; then
        log_info "No additional permission groups to apply."
        return
    fi

    local groups_csv
    groups_csv=$(
        IFS=,
        echo "${SERVICE_PERMISSIONS[*]}"
    )
    usermod -aG "$groups_csv" "$NEW_USERNAME"
    log_info "Assigned permission groups to '$NEW_USERNAME': $groups_csv"
}

# =============================================================================
# Action 2: Change user password
# =============================================================================

action_change_password() {
    log_section "Change User Password"
    echo ""

    local target_user=""
    while true; do
        read -rp "  Username: " target_user
        if [[ -z "$target_user" ]]; then
            echo "  Username cannot be empty."
        elif ! id "$target_user" &>/dev/null; then
            echo "  User '$target_user' does not exist."
        else
            break
        fi
    done

    local uid primary_group
    uid=$(id -u "$target_user")
    primary_group=$(id -gn "$target_user")
    echo ""
    log_info "Account: $target_user (UID $uid, primary group: $primary_group)"
    echo ""

    local new_pass confirm_pass
    while true; do
        read -rsp "  New password for '$target_user': " new_pass
        echo ""
        read -rsp "  Confirm password: " confirm_pass
        echo ""
        if [[ "$new_pass" != "$confirm_pass" ]]; then
            echo "  Passwords do not match. Try again."
        elif [[ ${#new_pass} -lt $MIN_PASSWORD_LENGTH ]]; then
            echo "  Password too short (minimum $MIN_PASSWORD_LENGTH characters)."
        else
            break
        fi
    done

    echo "$target_user:$new_pass" | chpasswd
    log_info "Password updated for '$target_user'."

    echo ""
    read -rp "  Force password reset at next login? [y/N]: " _reset
    if [[ "${_reset,,}" =~ ^y ]]; then
        chage -d 0 "$target_user"
        log_info "'$target_user' will be prompted to set a new password at next login."
    fi

    _save_password_change_artifact "$target_user"
}

# =============================================================================
# Action 4: Create group
# =============================================================================

action_create_group() {
    log_section "Create Group"
    echo ""

    local grp_name=""
    while true; do
        read -rp "  Group name: " grp_name
        if [[ -z "$grp_name" ]]; then
            echo "  Group name cannot be empty."
        elif ! [[ "$grp_name" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
            echo "  Invalid name. Use lowercase letters, digits, hyphens, or underscores."
        elif getent group "$grp_name" &>/dev/null; then
            log_warn "Group '$grp_name' already exists."
            getent group "$grp_name" | awk -F: '{printf "  GID: %s   Members: %s\n", $3, ($4=="" ? "(none)" : $4)}'
            return
        else
            break
        fi
    done

    local groupadd_args=()

    echo ""
    read -rp "  Create as system group (GID < 1000)? [y/N]: " _sys
    if [[ "${_sys,,}" =~ ^y ]]; then
        groupadd_args+=("-r")
    fi

    echo ""
    read -rp "  Assign a specific GID? Leave blank to auto-assign: " _gid
    if [[ -n "$_gid" ]]; then
        if ! [[ "$_gid" =~ ^[0-9]+$ ]]; then
            log_warn "Invalid GID '$_gid' — auto-assigning."
        elif getent group "$_gid" &>/dev/null; then
            log_warn "GID $_gid is already in use — auto-assigning."
        else
            groupadd_args+=("-g" "$_gid")
        fi
    fi

    echo ""
    groupadd "${groupadd_args[@]}" "$grp_name"
    local final_gid
    final_gid=$(getent group "$grp_name" | cut -d: -f3)
    log_info "Group '$grp_name' created (GID $final_gid)."

    echo ""
    read -rp "  Add users to '$grp_name' now? [y/N]: " _add_users
    if [[ "${_add_users,,}" =~ ^y ]]; then
        echo "  Enter username(s) to add — space or comma-separated."
        local users_input
        read -rp "  Users: " users_input
        if [[ -n "$users_input" ]]; then
            local normalised="${users_input//,/ }"
            local u
            for u in $normalised; do
                [[ -z "$u" ]] && continue
                if id "$u" &>/dev/null; then
                    usermod -aG "$grp_name" "$u"
                    log_info "Added '$u' to '$grp_name'."
                else
                    log_warn "User '$u' does not exist — skipping."
                fi
            done
        fi
    fi

    _save_create_group_artifact "$grp_name" "$final_gid"
}

# =============================================================================
# Action 3: Add existing user to group(s)
# =============================================================================

action_add_to_groups() {
    log_section "Add User to Group(s)"
    echo ""

    local target_user=""
    while true; do
        read -rp "  Username: " target_user
        if [[ -z "$target_user" ]]; then
            echo "  Username cannot be empty."
        elif ! id "$target_user" &>/dev/null; then
            echo "  User '$target_user' does not exist on this system."
        else
            break
        fi
    done

    local current_groups
    current_groups=$(id -Gn "$target_user")
    echo ""
    log_info "Current groups for '$target_user': $current_groups"
    echo ""

    echo "  Enter group(s) to add '$target_user' to."
    echo "  Space or comma-separated (e.g. docker,developers or docker developers)."
    echo ""
    local groups_input
    read -rp "  Groups: " groups_input

    if [[ -z "$groups_input" ]]; then
        log_warn "No groups entered — nothing to do."
        return
    fi

    local normalised="${groups_input//,/ }"
    local groups_to_add=()
    read -r -a groups_to_add <<< "$normalised"

    local valid_groups=() grp
    for grp in "${groups_to_add[@]}"; do
        [[ -z "$grp" ]] && continue
        if getent group "$grp" &>/dev/null; then
            valid_groups+=("$grp")
            log_info "Group '$grp' found."
        else
            echo ""
            log_warn "Group '$grp' does not exist."
            read -rp "  Create group '$grp'? [y/N]: " create_grp
            if [[ "${create_grp,,}" =~ ^y ]]; then
                groupadd "$grp"
                log_info "Group '$grp' created."
                valid_groups+=("$grp")
            else
                log_info "Skipping group '$grp'."
            fi
        fi
    done

    if [[ ${#valid_groups[@]} -eq 0 ]]; then
        log_warn "No valid groups to add — nothing done."
        return
    fi

    local groups_csv
    groups_csv=$(
        IFS=,
        echo "${valid_groups[*]}"
    )
    usermod -aG "$groups_csv" "$target_user"
    log_info "Added '$target_user' to: $groups_csv"

    local updated_groups
    updated_groups=$(id -Gn "$target_user")
    log_info "Updated group memberships for '$target_user': $updated_groups"

    _save_group_change_artifact "$target_user" "${valid_groups[*]}" "$updated_groups"
}

# =============================================================================
# Action 4: Show user group memberships
# =============================================================================

action_user_memberships() {
    log_section "User Group Membership"
    echo ""

    local target_user=""
    while true; do
        read -rp "  Username: " target_user
        if [[ -z "$target_user" ]]; then
            echo "  Username cannot be empty."
        elif ! id "$target_user" &>/dev/null; then
            echo "  User '$target_user' does not exist."
        else
            break
        fi
    done

    local uid primary_gid primary_group all_groups
    uid=$(id -u "$target_user")
    primary_gid=$(id -g "$target_user")
    primary_group=$(id -gn "$target_user")
    all_groups=$(id -Gn "$target_user")

    echo ""
    echo "  ── $target_user ────────────────────────────────────────────────────"
    printf "  %-20s : %s\n"              "Username"      "$target_user"
    printf "  %-20s : %s\n"              "UID"           "$uid"
    printf "  %-20s : %s (GID %s)\n"    "Primary group" "$primary_group" "$primary_gid"
    echo ""
    printf "  %-25s %-8s %s\n" "Group" "GID" "Supplementary members"
    printf "  %s\n" "$(printf '%0.s─' {1..60})"

    local grp gid members
    for grp in $all_groups; do
        gid=$(getent group "$grp" | cut -d: -f3)
        members=$(getent group "$grp" | cut -d: -f4)
        printf "  %-25s %-8s %s\n" "$grp" "$gid" "${members:-(none listed)}"
        _print_group_perms "$grp"
    done
    echo ""

    _save_membership_artifact "$target_user" "$uid" "$primary_group" "$primary_gid" "$all_groups"
}

# =============================================================================
# Action 5: List all groups
# =============================================================================

action_list_groups() {
    log_section "All System Groups"

    local sys_count=0 user_count=0

    echo ""
    echo "  Note: Members column shows supplementary members only."
    echo "  Users whose primary group is listed here appear in /etc/passwd, not /etc/group."
    echo "  Permissions and Sudo rules are shown where known."
    echo ""

    echo "  SYSTEM GROUPS  (GID < 1000)"
    printf "  %s\n" "$(printf '%0.s─' {1..60})"
    printf "  %-25s %-8s %s\n" "Group" "GID" "Members"
    printf "  %s\n" "$(printf '%0.s─' {1..60})"

    local grp_name grp_gid grp_members
    while IFS=: read -r grp_name _ grp_gid grp_members; do
        if (( grp_gid < 1000 )); then
            printf "  %-25s %-8s %s\n" "$grp_name" "$grp_gid" "${grp_members:-(none)}"
            _print_group_perms "$grp_name"
            sys_count=$(( sys_count + 1 ))
        fi
    done < <(sort -t: -k3 -n /etc/group)

    echo ""
    echo "  USER GROUPS  (GID >= 1000)"
    printf "  %s\n" "$(printf '%0.s─' {1..60})"
    printf "  %-25s %-8s %s\n" "Group" "GID" "Members"
    printf "  %s\n" "$(printf '%0.s─' {1..60})"

    while IFS=: read -r grp_name _ grp_gid grp_members; do
        if (( grp_gid >= 1000 )); then
            printf "  %-25s %-8s %s\n" "$grp_name" "$grp_gid" "${grp_members:-(none)}"
            _print_group_perms "$grp_name"
            user_count=$(( user_count + 1 ))
        fi
    done < <(sort -t: -k3 -n /etc/group)

    echo ""
    log_info "Total: $sys_count system group(s), $user_count user group(s)."

    _save_groups_list_artifact "$sys_count" "$user_count"
}

# =============================================================================
# Artifacts
# =============================================================================

_save_creation_artifact() {
    local artifact
    artifact=$(artifact_file "users")

    local user_type_label groups_list root_locked su_restricted
    [[ "$USER_TYPE" == "1" ]] \
        && user_type_label="Admin (${ADMIN_GROUP}/sudo)" \
        || user_type_label="Standard (no sudo)"
    groups_list=$(id -Gn "$NEW_USERNAME" 2>/dev/null || echo "unavailable")

    if passwd -S root 2>/dev/null | awk '{print $2}' | grep -q "^L$"; then
        root_locked="Yes"
    else
        root_locked="No"
    fi

    if grep -q "pam_wheel.so use_uid" /etc/pam.d/su 2>/dev/null; then
        su_restricted="Yes (pam_wheel.so use_uid)"
    else
        su_restricted="No"
    fi

    cat > "$artifact" <<EOF
USER ACCOUNT CONFIGURATION REPORT
====================================
Generated  : $(date '+%Y-%m-%d %H:%M:%S')
Hostname   : $(hostname)
OS         : $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
Applied by : hardening/modules/users/harden.sh

ACCOUNT CREATED
---------------
  Username   : $NEW_USERNAME
  Type       : $user_type_label
  Groups     : $groups_list
  Home dir   : $(getent passwd "$NEW_USERNAME" | cut -d: -f6)
  Shell      : $(getent passwd "$NEW_USERNAME" | cut -d: -f7)

SECURITY SETTINGS
-----------------
  Password reset at first login : Yes (chage -d 0 applied)
  Root account locked           : $root_locked
  su restricted to wheel group  : $su_restricted
EOF

    log_info "Artifact saved: $artifact"
}

_save_service_account_artifact() {
    local artifact
    artifact=$(artifact_file "users")

    local final_groups
    final_groups=$(id -Gn "$NEW_USERNAME" 2>/dev/null || echo "unavailable")

    local passwd_status
    passwd_status=$(passwd -S "$NEW_USERNAME" 2>/dev/null | awk '{print $2}' || echo "unknown")

    {
        cat <<EOF
SERVICE ACCOUNT CONFIGURATION REPORT
======================================
Generated  : $(date '+%Y-%m-%d %H:%M:%S')
Hostname   : $(hostname)
OS         : $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
Applied by : hardening/modules/users/harden.sh

ACCOUNT CREATED
---------------
  Username          : $NEW_USERNAME
  UID               : $(id -u "$NEW_USERNAME" 2>/dev/null || echo "unavailable")
  Description       : ${SVC_COMMENT:-(none)}
  System account    : $SVC_SYSTEM
  Working directory : ${SVC_HOME_DIR:-(none)}
  Login shell       : $SVC_SHELL
  Password status   : $passwd_status  (L = locked)

PERMISSIONS
-----------
  All groups        : $final_groups
EOF
        if [[ ${#SERVICE_PERMISSIONS[@]} -gt 0 ]]; then
            echo "  Assigned groups   : ${SERVICE_PERMISSIONS[*]}"
        else
            echo "  Assigned groups   : (none — minimal access)"
        fi
    } > "$artifact"

    log_info "Artifact saved: $artifact"
}

_save_group_change_artifact() {
    local target_user="$1" groups_added="$2" final_groups="$3"
    local artifact
    artifact=$(artifact_file "users")

    cat > "$artifact" <<EOF
GROUP CHANGE REPORT
====================
Generated  : $(date '+%Y-%m-%d %H:%M:%S')
Hostname   : $(hostname)
OS         : $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
Applied by : hardening/modules/users/harden.sh

ACTION
------
  User              : $target_user
  Groups added      : $groups_added

RESULTING MEMBERSHIPS
---------------------
  All groups        : $final_groups
EOF

    log_info "Artifact saved: $artifact"
}

_save_membership_artifact() {
    local target_user="$1" uid="$2" primary_group="$3" primary_gid="$4" all_groups="$5"
    local artifact
    artifact=$(artifact_file "users")

    {
        cat <<EOF
GROUP MEMBERSHIP REPORT
========================
Generated  : $(date '+%Y-%m-%d %H:%M:%S')
Hostname   : $(hostname)
OS         : $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
Applied by : hardening/modules/users/harden.sh

USER
----
  Username      : $target_user
  UID           : $uid
  Primary group : $primary_group (GID $primary_gid)

GROUP DETAILS
-------------
$(printf "  %-25s %-8s %s\n" "Group" "GID" "Supplementary members")
$(printf "  %s\n" "$(printf '%0.s─' {1..60})")
EOF
        local grp gid members known sudo_rules
        for grp in $all_groups; do
            gid=$(getent group "$grp" | cut -d: -f3)
            members=$(getent group "$grp" | cut -d: -f4)
            printf "  %-25s %-8s %s\n" "$grp" "$gid" "${members:-(none listed)}"
            known=$(_get_group_known_perms "$grp")
            sudo_rules=$(_get_group_sudo_rules "$grp")
            [[ -n "$known" ]] && printf "    %-12s : %s\n" "Permissions" "$known"
            if [[ -n "$sudo_rules" ]]; then
                while IFS= read -r rule; do
                    [[ -n "$rule" ]] && printf "    %-12s : %s\n" "Sudo rule" "$rule"
                done <<< "$sudo_rules"
            fi
        done
    } > "$artifact"

    log_info "Artifact saved: $artifact"
}

_save_password_change_artifact() {
    local target_user="$1"
    local artifact
    artifact=$(artifact_file "users")

    cat > "$artifact" <<EOF
PASSWORD CHANGE REPORT
=======================
Generated  : $(date '+%Y-%m-%d %H:%M:%S')
Hostname   : $(hostname)
OS         : $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
Applied by : hardening/modules/users/harden.sh

ACTION
------
  User              : $target_user
  Password changed  : Yes
  Force reset       : $(chage -l "$target_user" 2>/dev/null | grep "Last password change" | grep -q "password must be changed" && echo "Yes" || echo "No")
EOF

    log_info "Artifact saved: $artifact"
}

_save_create_group_artifact() {
    local grp_name="$1" gid="$2"
    local artifact
    artifact=$(artifact_file "users")
    local members
    members=$(getent group "$grp_name" | cut -d: -f4)

    cat > "$artifact" <<EOF
GROUP CREATION REPORT
======================
Generated  : $(date '+%Y-%m-%d %H:%M:%S')
Hostname   : $(hostname)
OS         : $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
Applied by : hardening/modules/users/harden.sh

GROUP CREATED
-------------
  Name    : $grp_name
  GID     : $gid
  Members : ${members:-(none)}
EOF

    log_info "Artifact saved: $artifact"
}

_save_groups_list_artifact() {
    local sys_count="$1" user_count="$2"
    local artifact
    artifact=$(artifact_file "users")

    {
        cat <<EOF
ALL GROUPS REPORT
==================
Generated  : $(date '+%Y-%m-%d %H:%M:%S')
Hostname   : $(hostname)
OS         : $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
Applied by : hardening/modules/users/harden.sh

Note: Members column shows supplementary members only.

SYSTEM GROUPS  (GID < 1000)
$(printf '%s\n' "$(printf '%0.s─' {1..60})")
$(printf "%-25s %-8s %s\n" "Group" "GID" "Members")
$(printf '%s\n' "$(printf '%0.s─' {1..60})")
EOF
        local grp_name grp_gid grp_members known sudo_rules
        while IFS=: read -r grp_name _ grp_gid grp_members; do
            if (( grp_gid < 1000 )); then
                printf "%-25s %-8s %s\n" "$grp_name" "$grp_gid" "${grp_members:-(none)}"
                known=$(_get_group_known_perms "$grp_name")
                sudo_rules=$(_get_group_sudo_rules "$grp_name")
                [[ -n "$known" ]] && printf "  %-12s : %s\n" "Permissions" "$known"
                if [[ -n "$sudo_rules" ]]; then
                    while IFS= read -r rule; do
                        [[ -n "$rule" ]] && printf "  %-12s : %s\n" "Sudo rule" "$rule"
                    done <<< "$sudo_rules"
                fi
            fi
        done < <(sort -t: -k3 -n /etc/group)

        cat <<EOF

USER GROUPS  (GID >= 1000)
$(printf '%s\n' "$(printf '%0.s─' {1..60})")
$(printf "%-25s %-8s %s\n" "Group" "GID" "Members")
$(printf '%s\n' "$(printf '%0.s─' {1..60})")
EOF
        while IFS=: read -r grp_name _ grp_gid grp_members; do
            if (( grp_gid >= 1000 )); then
                printf "%-25s %-8s %s\n" "$grp_name" "$grp_gid" "${grp_members:-(none)}"
                known=$(_get_group_known_perms "$grp_name")
                sudo_rules=$(_get_group_sudo_rules "$grp_name")
                [[ -n "$known" ]] && printf "  %-12s : %s\n" "Permissions" "$known"
                if [[ -n "$sudo_rules" ]]; then
                    while IFS= read -r rule; do
                        [[ -n "$rule" ]] && printf "  %-12s : %s\n" "Sudo rule" "$rule"
                    done <<< "$sudo_rules"
                fi
            fi
        done < <(sort -t: -k3 -n /etc/group)

        cat <<EOF

SUMMARY
-------
  System groups : $sys_count
  User groups   : $user_count
  Total         : $(( sys_count + user_count ))
EOF
    } > "$artifact"

    log_info "Artifact saved: $artifact"
}

# =============================================================================
# Main
# =============================================================================

log_section "User Administration"

while true; do
    echo ""
    echo "  ── User Administration ─────────────────────────────────────────────"
    echo ""
    echo "  1) Create user           — admin, standard, or service account"
    echo "  2) Change user password  — reset a user's password as root"
    echo "  3) Add to group(s)       — add an existing user to one or more groups"
    echo "  4) Create group          — create a new group and optionally add members"
    echo "  5) User group membership — display all groups a user belongs to"
    echo "  6) List all groups       — show every group on the system with members"
    echo "  7) Exit module"
    echo ""
    read -rp "  Enter choice [1-7]: " action

    case "$action" in
        1) action_create_user ;;
        2) action_change_password ;;
        3) action_add_to_groups ;;
        4) action_create_group ;;
        5) action_user_memberships ;;
        6) action_list_groups ;;
        7) break ;;
        *) echo "  Invalid choice. Enter 1-7."; continue ;;
    esac

    echo ""
    read -rp "  Return to User Administration menu? [Y/n]: " again
    [[ "$again" =~ ^[Nn]$ ]] && break
done

log_info "Users module complete."
