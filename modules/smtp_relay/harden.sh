#!/usr/bin/env bash
# =============================================================================
# Module  : smtp_relay
# Purpose : Install and configure msmtp as an outbound SMTP relay.
#
# msmtp is a lightweight sendmail replacement that forwards all outgoing mail
# through an upstream smarthost. It requires no daemon, no mail queue, and no
# database maps — the entire configuration is a single file.
#
# The config is written to /etc/msmtprc (mode 600, root:root). msmtp-mta
# installs a sendmail symlink so cron, scripts, and system tools work
# without any changes.
#
# Note: msmtp has no mail queue. If the relay is unreachable when mail is
# sent the message is lost rather than retried. For guaranteed delivery use
# Postfix instead.
#
# Menu:
#   1) Install / Configure relay   — install msmtp, set relay host and creds
#   2) Send test email             — send a message to verify delivery
#   3) Show current configuration  — display active relay settings
#   4) Exit
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../lib/common.sh"
source "$SCRIPT_DIR/../../config.conf"

check_root

MSMTP_CONF="/etc/msmtprc"
MSMTP_LOG="/var/log/msmtp.log"

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

_current_host() {
    grep -E "^host[[:space:]]" "$MSMTP_CONF" 2>/dev/null \
        | awk '{print $2}' || true
}

# =============================================================================
# Preset relay profiles
# =============================================================================

_pick_relay_preset() {
    echo "  Select your mail provider or enter a custom relay:"
    echo ""
    echo "    1) Office 365           — smtp.office365.com:587    (STARTTLS)"
    echo "    2) Office 365 GCC High  — smtp.office365.us:587     (STARTTLS, GCCH tenants)"
    echo "    3) Gmail                — smtp.gmail.com:587         (STARTTLS)"
    echo "    4) SendGrid             — smtp.sendgrid.net:587      (STARTTLS)"
    echo "    5) Amazon SES           — email-smtp.<region>.amazonaws.com:587"
    echo "    6) Custom               — enter hostname and port manually"
    echo ""
    read -rp "  Selection [1-6, default=6]: " _preset
    echo ""

    case "${_preset:-6}" in
        1) RELAY_HOST="smtp.office365.com"; RELAY_PORT="587"; RELAY_TLS="starttls" ;;
        2) RELAY_HOST="smtp.office365.us";  RELAY_PORT="587"; RELAY_TLS="starttls" ;;
        3) RELAY_HOST="smtp.gmail.com";     RELAY_PORT="587"; RELAY_TLS="starttls" ;;
        4) RELAY_HOST="smtp.sendgrid.net";  RELAY_PORT="587"; RELAY_TLS="starttls" ;;
        5)
            read -rp "  AWS SES region (e.g. us-east-1): " _region
            RELAY_HOST="email-smtp.${_region}.amazonaws.com"
            RELAY_PORT="587"
            RELAY_TLS="starttls"
            ;;
        6|*)
            while true; do
                read -rp "  Relay hostname (e.g. mail.example.com): " RELAY_HOST
                [[ -n "$RELAY_HOST" ]] && break
                echo "  Hostname cannot be empty."
            done
            echo ""
            echo "  Common ports:"
            echo "    587 — STARTTLS (recommended)"
            echo "    465 — SMTPS (implicit TLS)"
            echo "    25  — unencrypted (not recommended)"
            echo ""
            read -rp "  Port [default=587]: " RELAY_PORT
            RELAY_PORT="${RELAY_PORT:-587}"
            echo ""
            echo "  TLS mode:"
            echo "    1) STARTTLS — upgrade plain connection to TLS (recommended for 587)"
            echo "    2) SMTPS    — TLS from the start (port 465)"
            echo "    3) None     — no encryption (not recommended)"
            echo ""
            read -rp "  Selection [1-3, default=1]: " _tls
            case "${_tls:-1}" in
                2) RELAY_TLS="smtps" ;;
                3) RELAY_TLS="none" ;;
                *) RELAY_TLS="starttls" ;;
            esac
            ;;
    esac
}

# =============================================================================
# Menu: Install / Configure
# =============================================================================

menu_install() {
    _header "Install / Configure SMTP Relay"

    echo "  Configures msmtp to forward all outbound mail through an upstream"
    echo "  SMTP relay. Credentials are stored in ${MSMTP_CONF} (mode 600)."
    echo "  msmtp-mta provides a sendmail symlink so existing scripts and"
    echo "  cron jobs work without modification."
    echo ""

    # -- Package -----------------------------------------------------------------
    log_section "Install msmtp"

    if ! rpm -q epel-release &>/dev/null; then
        log_info "Installing EPEL repository..."
        dnf install -y epel-release
    fi

    if ! rpm -q msmtp &>/dev/null; then
        log_info "Installing msmtp..."
        dnf install -y msmtp
    else
        log_info "msmtp already installed."
    fi

    # Register msmtp as the sendmail provider and force it active.
    # --install adds it to the alternatives list; --set makes it win
    # regardless of what other MTAs (e.g. Postfix) are registered.
    if [[ -x /usr/bin/msmtp ]]; then
        alternatives --install /usr/sbin/sendmail mta /usr/bin/msmtp 10 \
            2>/dev/null || true
        alternatives --set mta /usr/bin/msmtp
        log_info "msmtp set as active sendmail provider."
    fi

    # -- Relay host --------------------------------------------------------------
    log_section "Relay Host"

    local RELAY_HOST RELAY_PORT RELAY_TLS
    _pick_relay_preset

    log_info "Relay: ${RELAY_HOST}:${RELAY_PORT} (${RELAY_TLS})"

    # -- Credentials -------------------------------------------------------------
    log_section "Authentication"

    echo "  Enter the credentials used to authenticate with ${RELAY_HOST}."
    echo "  For Office 365 this is typically your full email address."
    echo "  For SendGrid use 'apikey' as the username and your API key as the password."
    echo ""

    local RELAY_USER RELAY_PASS confirm_pass
    while true; do
        read -rp "  Username: " RELAY_USER
        [[ -n "$RELAY_USER" ]] && break
        echo "  Username cannot be empty."
    done

    while true; do
        read -rsp "  Password: " RELAY_PASS; echo ""
        read -rsp "  Confirm:  " confirm_pass; echo ""
        [[ "$RELAY_PASS" == "$confirm_pass" ]] && break
        echo "  Passwords do not match."
    done

    # -- Sender address ----------------------------------------------------------
    log_section "Sender Address"

    echo "  The From address used on outgoing mail."
    echo "  For Office 365 this must be a licensed mailbox on your tenant."
    echo ""
    read -rp "  From address [default: ${RELAY_USER}]: " MAIL_FROM
    MAIL_FROM="${MAIL_FROM:-$RELAY_USER}"

    # -- Write config ------------------------------------------------------------
    log_section "Writing configuration"

    local ca_file
    if [[ -f /etc/pki/tls/certs/ca-bundle.crt ]]; then
        ca_file="/etc/pki/tls/certs/ca-bundle.crt"
    else
        ca_file="/etc/ssl/certs/ca-bundle.crt"
    fi

    local starttls_val="on"
    local tls_val="on"
    case "$RELAY_TLS" in
        smtps)    starttls_val="off" ;;
        none)     tls_val="off"; starttls_val="off" ;;
    esac

    [[ -f "$MSMTP_CONF" ]] && backup_file "$MSMTP_CONF"

    cat > "$MSMTP_CONF" <<EOF
# msmtp system-wide relay configuration
# Managed by hardening/modules/smtp_relay — do not edit manually.

defaults
tls             ${tls_val}
tls_starttls    ${starttls_val}
tls_trust_file  ${ca_file}
logfile         ${MSMTP_LOG}

account default
host        ${RELAY_HOST}
port        ${RELAY_PORT}
auth        on
user        ${RELAY_USER}
password    ${RELAY_PASS}
from        ${MAIL_FROM}
EOF

    chmod 600 "$MSMTP_CONF"
    chown root:root "$MSMTP_CONF"

    touch "$MSMTP_LOG"
    chmod 640 "$MSMTP_LOG"

    log_info "Configuration written to ${MSMTP_CONF}"

    # -- Verify ------------------------------------------------------------------
    log_section "Verify"

    if msmtp --serverinfo --account=default &>/dev/null; then
        log_info "Successfully connected to ${RELAY_HOST}:${RELAY_PORT}."
    else
        log_warn "Could not reach relay — check hostname, port, and credentials."
        log_warn "You can still send a test email to get a detailed error."
    fi

    echo ""
    read -rp "  Send a test email now? [y/N]: " _test
    [[ "${_test,,}" =~ ^y ]] && menu_test_email
}

# =============================================================================
# Menu: Send test email
# =============================================================================

menu_test_email() {
    _header "Send Test Email"

    echo "  Sends a test message through the configured relay to verify"
    echo "  that authentication and delivery are working correctly."
    echo ""

    if [[ ! -f "$MSMTP_CONF" ]]; then
        log_warn "No configuration found at ${MSMTP_CONF}. Run Install / Configure first."
        return
    fi

    local to_addr from_addr
    while true; do
        read -rp "  Send test email to: " to_addr
        [[ -n "$to_addr" ]] && break
        echo "  Address cannot be empty."
    done

    from_addr=$(grep -E "^from[[:space:]]" "$MSMTP_CONF" 2>/dev/null | awk '{print $2}' || echo "root@$(hostname)")
    local relay_host
    relay_host=$(_current_host)

    echo ""
    log_info "Sending test email to ${to_addr} via ${relay_host}..."

    local subject="SMTP Relay Test — $(hostname) — $(date '+%Y-%m-%d %H:%M:%S')"

    if sendmail "$to_addr" <<MAIL
From: ${from_addr}
To: ${to_addr}
Subject: ${subject}

This is an automated test message from the Linux Hardening Script.

Host     : $(hostname)
OS       : $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
Relay    : ${relay_host}
Sent at  : $(date)

If you received this message your SMTP relay is configured correctly.
MAIL
    then
        log_info "Message accepted. Check ${to_addr} for delivery."
        log_info "Delivery log: tail ${MSMTP_LOG}"
    else
        log_error "Delivery failed. Check ${MSMTP_LOG} for details."
    fi
    echo ""
}

# =============================================================================
# Menu: Show current configuration
# =============================================================================

menu_show_config() {
    _header "Current SMTP Relay Configuration"

    if [[ ! -f "$MSMTP_CONF" ]]; then
        log_warn "No configuration found at ${MSMTP_CONF}. Run Install / Configure first."
        return
    fi

    echo "  Configuration file: ${MSMTP_CONF} (mode $(stat -c '%a' "$MSMTP_CONF"))"
    echo ""

    # Print config with password redacted.
    sed 's/^\(password[[:space:]]\+\).*/\1<hidden>/' "$MSMTP_CONF" | sed 's/^/    /'

    echo ""
    if [[ -f "$MSMTP_LOG" ]]; then
        echo "  Last 5 log entries (${MSMTP_LOG}):"
        tail -5 "$MSMTP_LOG" 2>/dev/null | sed 's/^/    /' || echo "    (empty)"
    fi
    echo ""
}

# =============================================================================
# Main landing page
# =============================================================================

while true; do
    _header "SMTP Relay — Outbound Mail via msmtp"
    echo "  Configures msmtp as an outbound SMTP relay. Mail sent from this"
    echo "  system (alerts, reports, cron output) is forwarded through an"
    echo "  upstream smarthost using authenticated TLS."
    echo ""
    echo "    1) Install / Configure relay  — set relay host, credentials, and TLS"
    echo "    2) Send test email            — verify delivery through the relay"
    echo "    3) Show current configuration — display active relay settings"
    echo "    4) Exit"
    echo ""
    read -rp "  Selection [1-4, default=1]: " _main
    echo ""

    case "${_main:-1}" in
        1) menu_install ;;
        2) menu_test_email ;;
        3) menu_show_config ;;
        4) log_info "Exiting SMTP relay module."; exit 0 ;;
        *) echo "  Invalid selection." ;;
    esac
done
