#!/usr/bin/env bash
# =============================================================================
# Module  : password_policy_and_account_lockout
# Purpose : Enforce system-wide password complexity, aging, account lockout,
#           and password reuse prevention.
#
# This module configures four independent controls.  Run before the users
# module so that any account created there immediately inherits the hardened
# defaults.
#
# This module performs the following actions in order:
#
#   1. POLICY SELECTION (interactive)
#      The operator chooses one of two modes:
#        1) Default — applies the recommended values defined in config.conf
#                     and the hardcoded defaults below.
#        2) Custom  — prompts for every configurable value individually;
#                     pressing Enter at any prompt accepts the shown default.
#
#   2. PASSWORD COMPLEXITY  (/etc/security/pwquality.conf)
#      PAM reads this file via pam_pwquality.so whenever a password is set or
#      changed.  The following values are written:
#        minlen   — minimum total character length (default: MIN_PASSWORD_LENGTH = 8).
#        dcredit  — set to -1 to require at least one digit, 0 to make optional.
#        ucredit  — set to -1 to require at least one uppercase letter (A–Z).
#        lcredit  — set to -1 to require at least one lowercase letter (a–z).
#        ocredit  — set to -1 to require at least one special character.
#      A timestamped backup of pwquality.conf is taken before any change.
#
#   3. PASSWORD AGING  (/etc/login.defs)
#      useradd and passwd read these defaults when creating or modifying
#      accounts.  The following values are written:
#        PASS_MAX_DAYS — password must be changed after this many days (default: 90).
#        PASS_MIN_DAYS — minimum days before a change is allowed (default: 1).
#        PASS_WARN_AGE — days before expiry that the user is warned (default: 14).
#      IMPORTANT: these are defaults for new accounts only.  Existing accounts
#      retain their current chage values and must be updated individually.
#      A timestamped backup of /etc/login.defs is taken before any change.
#
#   4. ACCOUNT LOCKOUT  (/etc/security/faillock.conf)
#      pam_faillock.so counts consecutive authentication failures and
#      temporarily locks the account when the threshold is reached.
#        deny         — failed attempts before lockout (default: 5).
#        fail_interval— window in seconds over which failures are counted (default: 900).
#        unlock_time  — seconds before automatic unlock (default: 900 = 15 min).
#      pam_faillock must already be wired into the PAM auth and account stacks
#      (authselect handles this automatically on RHEL/Rocky 9).  If authselect
#      is present and the with-faillock feature is not yet enabled, this module
#      enables it.  On systems without authselect the PAM files are edited
#      directly with a backup taken first.
#      A timestamped backup of faillock.conf is taken before any change.
#
#   5. PASSWORD HISTORY  (PAM pam_pwhistory.so)
#      Prevents users from reusing recent passwords.
#        remember     — number of previous passwords stored and rejected (default: 5).
#      If authselect is present and the with-pwhistory feature is not yet
#      enabled, this module enables it.  On systems without authselect the
#      pam_pwhistory line is inserted into the password stack of
#      /etc/pam.d/system-auth directly, with a backup taken first.
#
#   6. POLICY ARTIFACT  (hardening/artifacts/)
#      After applying all controls, the module reads the live values back from
#      every file and writes a timestamped report to:
#        hardening/artifacts/password_policy_<hostname>_<YYYYMMDD_HHMMSS>.txt
#      The artifact records actual on-disk state with a plain-English
#      interpretation of each value.
#
# Configuration values read from config.conf:
#   MIN_PASSWORD_LENGTH = 8   (default minlen; also enforced in the users module)
#
# Files modified:
#   /etc/security/pwquality.conf   — PAM password complexity rules
#   /etc/login.defs                — system-wide password aging defaults
#   /etc/security/faillock.conf    — account lockout thresholds
#   /etc/pam.d/system-auth         — pwhistory / faillock PAM wiring (if no authselect)
#   /etc/pam.d/password-auth       — faillock PAM wiring (if no authselect)
#
# Artifacts written:
#   hardening/artifacts/password_policy_<hostname>_<timestamp>.txt
#
# Dependencies:
#   sed, grep, awk          — coreutils / util-linux
#   pam_pwquality           — libpwquality (must be wired into PAM)
#   pam_faillock            — pam (included in RHEL/Rocky 9 base install)
#   pam_pwhistory           — pam (included in RHEL/Rocky 9 base install)
#   authselect (optional)   — preferred PAM manager on RHEL/Rocky 9
#
# Must be run as root (enforced by check_root in master.sh).
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../config.conf"
source "$SCRIPT_DIR/../../lib/common.sh"

ARTIFACTS_DIR="$SCRIPT_DIR/../../artifacts/password_policy"

# Policy variables are initialised to safe defaults here. The operator may
# override them via the custom prompt; the default path leaves them unchanged.
POLICY_MINLEN="$MIN_PASSWORD_LENGTH"
POLICY_DCREDIT="-1"
POLICY_UCREDIT="-1"
POLICY_LCREDIT="-1"
POLICY_OCREDIT="-1"
POLICY_MAX_DAYS="90"
POLICY_MIN_DAYS="1"
POLICY_WARN_AGE="14"
POLICY_FAILLOCK_DENY="5"
POLICY_FAILLOCK_FAIL_INTERVAL="900"
POLICY_FAILLOCK_UNLOCK_TIME="900"
POLICY_PWHISTORY_REMEMBER="5"

# --- Policy selection ---
prompt_policy_choice() {
    echo ""
    echo "  Select password policy mode:"
    echo ""
    printf "  1) Default  —  minlen=%-2s | digit, upper, lower, special all required\n" "$POLICY_MINLEN"
    echo "                 max age: 90 days  |  min age: 1 day  |  warn: 14 days"
    echo "                 lockout after 5 failed attempts (unlock after 15 min)"
    echo "                 remember last 5 passwords"
    echo ""
    echo "  2) Custom   —  configure each value interactively"
    echo ""
    while true; do
        read -rp "  Enter choice [1/2]: " choice
        case "$choice" in
            1) break ;;
            2) prompt_custom_policy; break ;;
            *) echo "  Invalid choice. Enter 1 or 2." ;;
        esac
    done
}

# Sets the named variable to -1 (character class required) or 0 (optional).
# A negative credit value in pwquality means the class is mandatory; zero
# means it contributes positively to the score but is not enforced.
prompt_required() {
    local label="$1" varname="$2"
    while true; do
        read -rp "  Require $label? [Y/n]: " ans
        ans="${ans:-y}"
        # ${ans,,} converts the input to lowercase, accepting Y/y/YES/yes uniformly.
        case "${ans,,}" in
            y|yes) printf -v "$varname" "%s" "-1"; break ;;
            n|no)  printf -v "$varname" "%s"  "0"; break ;;
            *) echo "  Enter y or n." ;;
        esac
    done
}

# Generic integer prompt with a minimum value guard. Uses printf -v to write
# the validated result directly into the named variable without a subshell.
prompt_int() {
    local prompt="$1" varname="$2" default="$3" min="${4:-0}"
    while true; do
        read -rp "  $prompt [$default]: " val
        # Empty input accepts the default shown in brackets.
        val="${val:-$default}"
        if [[ "$val" =~ ^[0-9]+$ ]] && (( val >= min )); then
            printf -v "$varname" "%s" "$val"; break
        else
            echo "  Must be an integer >= $min."
        fi
    done
}

prompt_custom_policy() {
    echo ""
    log_info "--- Password Complexity ---"
    prompt_int "Minimum password length"   POLICY_MINLEN  "$POLICY_MINLEN"  1
    prompt_required "a digit (0–9)"        POLICY_DCREDIT
    prompt_required "an uppercase letter"  POLICY_UCREDIT
    prompt_required "a lowercase letter"   POLICY_LCREDIT
    prompt_required "a special character"  POLICY_OCREDIT

    echo ""
    log_info "--- Password Aging ---"
    prompt_int "Maximum password age in days"          POLICY_MAX_DAYS "$POLICY_MAX_DAYS" 1
    prompt_int "Minimum days between password changes" POLICY_MIN_DAYS "$POLICY_MIN_DAYS" 0
    prompt_int "Days warning before expiry"            POLICY_WARN_AGE "$POLICY_WARN_AGE" 0

    echo ""
    log_info "--- Account Lockout (faillock) ---"
    # fail_interval and unlock_time are typically set equal so that the failure
    # window resets cleanly when an account unlocks. See module header for detail.
    prompt_int "Failed attempts before lockout"                     POLICY_FAILLOCK_DENY          "$POLICY_FAILLOCK_DENY"          1
    prompt_int "Failure counting window in seconds (fail_interval)" POLICY_FAILLOCK_FAIL_INTERVAL "$POLICY_FAILLOCK_FAIL_INTERVAL" 1
    prompt_int "Unlock time in seconds (0 = manual unlock only)"    POLICY_FAILLOCK_UNLOCK_TIME   "$POLICY_FAILLOCK_UNLOCK_TIME"   0

    echo ""
    log_info "--- Password History ---"
    prompt_int "Number of previous passwords to remember" POLICY_PWHISTORY_REMEMBER "$POLICY_PWHISTORY_REMEMBER" 1
}

# --- Apply complexity ---
configure_password_policy() {
    local pwquality_conf="/etc/security/pwquality.conf"

    if [[ ! -f "$pwquality_conf" ]]; then
        log_warn "pwquality.conf not found — skipping password complexity policy."
        log_warn "Install libpwquality and ensure pam_pwquality is wired into PAM."
        return
    fi

    backup_file "$pwquality_conf"

    # Each sed expression matches both commented-out (#minlen = ...) and active
    # (minlen = ...) lines, replacing them with the new value. This ensures the
    # setting is always active regardless of the file's prior state.
    sed -i "s/^#*\s*minlen\s*=.*/minlen = ${POLICY_MINLEN}/"    "$pwquality_conf"
    sed -i "s/^#*\s*dcredit\s*=.*/dcredit = ${POLICY_DCREDIT}/" "$pwquality_conf"
    sed -i "s/^#*\s*ucredit\s*=.*/ucredit = ${POLICY_UCREDIT}/" "$pwquality_conf"
    sed -i "s/^#*\s*lcredit\s*=.*/lcredit = ${POLICY_LCREDIT}/" "$pwquality_conf"
    sed -i "s/^#*\s*ocredit\s*=.*/ocredit = ${POLICY_OCREDIT}/" "$pwquality_conf"

    log_info "Password complexity configured:"
    log_info "  minlen=$POLICY_MINLEN  dcredit=$POLICY_DCREDIT  ucredit=$POLICY_UCREDIT  lcredit=$POLICY_LCREDIT  ocredit=$POLICY_OCREDIT"
}

# --- Apply aging ---
configure_password_aging() {
    backup_file /etc/login.defs

    # These sed expressions match the exact key at the start of the line
    # (no leading whitespace) to avoid accidentally replacing commented examples.
    sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   ${POLICY_MAX_DAYS}/" /etc/login.defs
    sed -i "s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   ${POLICY_MIN_DAYS}/" /etc/login.defs
    sed -i "s/^PASS_WARN_AGE.*/PASS_WARN_AGE   ${POLICY_WARN_AGE}/" /etc/login.defs

    log_info "Password aging configured:"
    log_info "  PASS_MAX_DAYS=$POLICY_MAX_DAYS  PASS_MIN_DAYS=$POLICY_MIN_DAYS  PASS_WARN_AGE=$POLICY_WARN_AGE"
}

# --- Apply faillock ---
configure_faillock() {
    local faillock_conf="/etc/security/faillock.conf"

    # faillock.conf may not exist on minimal installs; create it so pam_faillock
    # has a file to read. Without it the module falls back to PAM inline args.
    if [[ ! -f "$faillock_conf" ]]; then
        log_warn "faillock.conf not found — creating it."
        touch "$faillock_conf"
    fi

    backup_file "$faillock_conf"

    # For each key=value pair: if the key already exists (commented or active),
    # replace the entire line; otherwise append it. This handles both fresh
    # installs and systems where faillock was previously configured.
    for key_val in \
        "deny = ${POLICY_FAILLOCK_DENY}" \
        "fail_interval = ${POLICY_FAILLOCK_FAIL_INTERVAL}" \
        "unlock_time = ${POLICY_FAILLOCK_UNLOCK_TIME}"
    do
        # Strip everything from " =" onward to isolate the key name for the grep.
        local key="${key_val%% =*}"
        if grep -qE "^\s*${key}\s*=" "$faillock_conf"; then
            sed -i "s|^\s*${key}\s*=.*|${key_val}|" "$faillock_conf"
        else
            echo "$key_val" >> "$faillock_conf"
        fi
    done

    log_info "faillock configured:"
    log_info "  deny=$POLICY_FAILLOCK_DENY  fail_interval=${POLICY_FAILLOCK_FAIL_INTERVAL}s  unlock_time=${POLICY_FAILLOCK_UNLOCK_TIME}s"

    # Wire pam_faillock into the PAM stack.
    if command_exists authselect; then
        # authselect is the recommended PAM manager on RHEL/Rocky 9. It manages
        # /etc/pam.d/ files via profiles and features — direct edits are overwritten
        # by authselect apply-changes, so we use its API instead.
        if ! authselect current 2>/dev/null | grep -q "with-faillock"; then
            authselect enable-feature with-faillock
            log_info "authselect: with-faillock feature enabled."
        else
            log_info "authselect: with-faillock already enabled."
        fi
    else
        # Without authselect, insert pam_faillock lines directly into both PAM
        # config files. Two lines are needed in the auth stack:
        #   preauth  — runs before password verification to check if already locked
        #   authfail — runs after a failed attempt to increment the failure counter
        # The account line denies access to locked accounts during session setup.
        for pam_file in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
            [[ -f "$pam_file" ]] || continue
            backup_file "$pam_file"

            if ! grep -q "pam_faillock.so preauth" "$pam_file"; then
                sed -i '/^auth.*pam_unix\.so/i auth        required      pam_faillock.so preauth' "$pam_file"
                sed -i '/^auth.*pam_unix\.so/a auth        required      pam_faillock.so authfail' "$pam_file"
                log_info "faillock auth lines inserted into $pam_file"
            fi

            if ! grep -q "pam_faillock.so" "$pam_file" | grep -q "account"; then
                sed -i '/^account.*pam_unix\.so/i account     required      pam_faillock.so' "$pam_file"
                log_info "faillock account line inserted into $pam_file"
            fi
        done
    fi
}

# --- Apply password history ---
configure_pwhistory() {
    log_info "Password history: remember last $POLICY_PWHISTORY_REMEMBER password(s)."

    if command_exists authselect; then
        if ! authselect current 2>/dev/null | grep -q "with-pwhistory"; then
            authselect enable-feature with-pwhistory
            log_info "authselect: with-pwhistory feature enabled."
        else
            log_info "authselect: with-pwhistory already enabled."
        fi

        # On RHEL 9, authselect wires pam_pwhistory but the remember count is
        # controlled by a separate config file rather than a PAM inline argument.
        local pwhistory_conf="/etc/security/pwhistory.conf"
        if [[ -f "$pwhistory_conf" ]]; then
            backup_file "$pwhistory_conf"
            if grep -qE "^\s*remember\s*=" "$pwhistory_conf"; then
                sed -i "s|^\s*remember\s*=.*|remember = ${POLICY_PWHISTORY_REMEMBER}|" "$pwhistory_conf"
            else
                echo "remember = ${POLICY_PWHISTORY_REMEMBER}" >> "$pwhistory_conf"
            fi
            log_info "pwhistory.conf: remember=${POLICY_PWHISTORY_REMEMBER}"
        fi
    else
        # Insert the pam_pwhistory line before pam_unix.so in the password stack
        # so that history is checked before the new password is actually set.
        # use_authtok tells pam_pwhistory to use the password already collected by
        # pam_pwquality rather than prompting for it a second time.
        local pam_file="/etc/pam.d/system-auth"
        if [[ -f "$pam_file" ]]; then
            backup_file "$pam_file"
            if ! grep -q "pam_pwhistory.so" "$pam_file"; then
                sed -i "/^password.*pam_unix\.so/i password    required      pam_pwhistory.so remember=${POLICY_PWHISTORY_REMEMBER} use_authtok" "$pam_file"
                log_info "pam_pwhistory line inserted into $pam_file (remember=${POLICY_PWHISTORY_REMEMBER})"
            else
                # Line exists — update the remember count in place.
                sed -i "s|pam_pwhistory\.so.*|pam_pwhistory.so remember=${POLICY_PWHISTORY_REMEMBER} use_authtok|" "$pam_file"
                log_info "pam_pwhistory updated in $pam_file (remember=${POLICY_PWHISTORY_REMEMBER})"
            fi
        else
            log_warn "$pam_file not found — skipping pwhistory PAM wiring."
        fi
    fi
}

# --- Artifact ---
save_artifact() {
    mkdir -p "$ARTIFACTS_DIR"
    local artifact="${ARTIFACTS_DIR}/password_policy_$(hostname)_$(date +%Y%m%d_%H%M%S).txt"
    local pwquality_conf="/etc/security/pwquality.conf"
    local faillock_conf="/etc/security/faillock.conf"
    local pwhistory_conf="/etc/security/pwhistory.conf"

    # Read live values back from the actual files on disk rather than echoing
    # the variables set earlier. This ensures the artifact reflects reality —
    # e.g. if a sed substitution silently failed, the artifact will show it.
    local minlen dcredit ucredit lcredit ocredit
    local max_days min_days warn_age
    local fl_deny fl_interval fl_unlock
    local pw_remember authselect_info

    minlen=$(    grep -E "^\s*minlen\s*="          "$pwquality_conf" 2>/dev/null | awk -F= '{gsub(/ /,"",$2); print $2}' || echo "not set")
    dcredit=$(   grep -E "^\s*dcredit\s*="         "$pwquality_conf" 2>/dev/null | awk -F= '{gsub(/ /,"",$2); print $2}' || echo "not set")
    ucredit=$(   grep -E "^\s*ucredit\s*="         "$pwquality_conf" 2>/dev/null | awk -F= '{gsub(/ /,"",$2); print $2}' || echo "not set")
    lcredit=$(   grep -E "^\s*lcredit\s*="         "$pwquality_conf" 2>/dev/null | awk -F= '{gsub(/ /,"",$2); print $2}' || echo "not set")
    ocredit=$(   grep -E "^\s*ocredit\s*="         "$pwquality_conf" 2>/dev/null | awk -F= '{gsub(/ /,"",$2); print $2}' || echo "not set")
    max_days=$(  grep -E "^PASS_MAX_DAYS"          /etc/login.defs   2>/dev/null | awk '{print $2}'                       || echo "not set")
    min_days=$(  grep -E "^PASS_MIN_DAYS"          /etc/login.defs   2>/dev/null | awk '{print $2}'                       || echo "not set")
    warn_age=$(  grep -E "^PASS_WARN_AGE"          /etc/login.defs   2>/dev/null | awk '{print $2}'                       || echo "not set")
    fl_deny=$(   grep -E "^\s*deny\s*="            "$faillock_conf"  2>/dev/null | awk -F= '{gsub(/ /,"",$2); print $2}' || echo "not set")
    fl_interval=$(grep -E "^\s*fail_interval\s*=" "$faillock_conf"  2>/dev/null | awk -F= '{gsub(/ /,"",$2); print $2}' || echo "not set")
    fl_unlock=$( grep -E "^\s*unlock_time\s*="    "$faillock_conf"  2>/dev/null | awk -F= '{gsub(/ /,"",$2); print $2}' || echo "not set")

    # pwhistory remember count may live in pwhistory.conf (RHEL 9 with authselect)
    # or inline in system-auth (older/manual PAM config). Check both.
    if [[ -f "$pwhistory_conf" ]]; then
        pw_remember=$(grep -E "^\s*remember\s*=" "$pwhistory_conf" 2>/dev/null | awk -F= '{gsub(/ /,"",$2); print $2}' || echo "not set")
    else
        pw_remember=$(grep -oP "(?<=remember=)\d+" /etc/pam.d/system-auth 2>/dev/null || echo "not set")
    fi

    if command_exists authselect; then
        authselect_info=$(authselect current 2>/dev/null || echo "not configured")
    else
        authselect_info="not available"
    fi

    # Helper functions defined locally so they can be used inside the heredoc
    # via command substitution. Heredocs do not expand function calls directly.
    credit_desc() { [[ "$1" == "-1" ]] && echo "required" || echo "optional"; }
    unlock_desc()  { [[ "$1" == "0"  ]] && echo "manual unlock only" || echo "auto-unlock after ${1}s"; }

    cat > "$artifact" <<EOF
PASSWORD POLICY CONFIGURATION REPORT
======================================
Generated    : $(date '+%Y-%m-%d %H:%M:%S')
Hostname     : $(hostname)
OS           : $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
Applied by   : hardening/modules/password_policy/harden.sh
PAM manager  : $authselect_info

PASSWORD COMPLEXITY  (/etc/security/pwquality.conf)
-----------------------------------------------------
  minlen  = $minlen
            Passwords must be at least $minlen character(s) long.

  dcredit = $dcredit
            Digits (0–9)            : $(credit_desc "$dcredit")

  ucredit = $ucredit
            Uppercase letters (A–Z) : $(credit_desc "$ucredit")

  lcredit = $lcredit
            Lowercase letters (a–z) : $(credit_desc "$lcredit")

  ocredit = $ocredit
            Special characters      : $(credit_desc "$ocredit")

PASSWORD AGING  (/etc/login.defs)
-----------------------------------
  PASS_MAX_DAYS = $max_days
                  Passwords expire after $max_days day(s) and must be changed.

  PASS_MIN_DAYS = $min_days
                  At least $min_days day(s) must pass before a password can be changed again.

  PASS_WARN_AGE = $warn_age
                  Users are warned $warn_age day(s) before their password expires.

  NOTE: Aging defaults apply to new accounts only.
        To apply to existing accounts: chage -M $max_days -m $min_days -W $warn_age <username>

ACCOUNT LOCKOUT  (/etc/security/faillock.conf)
------------------------------------------------
  deny          = $fl_deny
                  Account is locked after $fl_deny consecutive failed login attempt(s).

  fail_interval = $fl_interval
                  Failed attempts are counted within a ${fl_interval}-second window.

  unlock_time   = $fl_unlock
                  $(unlock_desc "$fl_unlock")

  To view locked accounts  : faillock
  To manually unlock       : faillock --user <username> --reset

PASSWORD HISTORY  (pam_pwhistory.so)
--------------------------------------
  remember = $pw_remember
             The last $pw_remember password(s) are stored and cannot be reused.

  History file : /etc/security/opasswd
EOF

    log_info "Policy artifact saved: $artifact"
}

# --- Main ---
log_section "Password Policy"

prompt_policy_choice
echo ""

configure_password_policy
echo ""

configure_password_aging
echo ""

configure_faillock
echo ""

configure_pwhistory
echo ""

save_artifact

log_info "Password policy module complete."
