#!/usr/bin/env bash
# /etc/profile.d/mfa_reminder.sh
# Remind users to enroll in MFA if they have not yet done so.
# Runs for every interactive login shell (SSH, GUI terminal, console).

# Only run in interactive shells attached to a terminal.
[[ -t 1 ]] || return 0

GA_FILE="${HOME}/.google_authenticator"

if [[ ! -f "$GA_FILE" ]]; then
    echo ""
    echo "  ╔══════════════════════════════════════════════════════════╗"
    echo "  ║              ACTION REQUIRED: Enroll in MFA              ║"
    echo "  ╠══════════════════════════════════════════════════════════╣"
    echo "  ║  Multi-factor authentication is required on this system. ║"
    echo "  ║  You have not yet registered your authenticator app.     ║"
    echo "  ║                                                          ║"
    echo "  ║  Run the following command to enroll:                    ║"
    echo "  ║                                                          ║"
    echo "  ║      google-authenticator                                ║"
    echo "  ║                                                          ║"
    echo "  ║  You will need Google Authenticator, Authy, or any      ║"
    echo "  ║  TOTP-compatible app installed on your mobile device.   ║"
    echo "  ╚══════════════════════════════════════════════════════════╝"
    echo ""
fi
