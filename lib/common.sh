#!/usr/bin/env bash

# --- Colours ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

LOG_FILE="${LOG_FILE:-/var/log/hardening.log}"

# --- Logging ---
log_info()    { echo -e "${GREEN}[INFO]${NC}  $*" | tee -a "$LOG_FILE"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*" | tee -a "$LOG_FILE"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG_FILE"; }
log_section() { echo -e "\n${BLUE}========== $* ==========${NC}" | tee -a "$LOG_FILE"; }

# --- Guards ---
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root."
        exit 1
    fi
}

command_exists() {
    command -v "$1" &>/dev/null
}

# --- Artifact helpers ---
# Returns a timestamped artifact path and creates the directory.
# Usage: local f; f=$(artifact_file <module_name>)
artifact_file() {
    local module="$1"
    local hardening_root
    hardening_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    local artifact_dir="${hardening_root}/artifacts/${module}"
    mkdir -p "$artifact_dir"
    echo "${artifact_dir}/${module}_$(hostname)_$(date +%Y%m%d_%H%M%S).txt"
}

# --- Backup a file before modifying ---
backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        cp "$file" "${file}.bak.$(date +%Y%m%d%H%M%S)"
        log_info "Backed up $file"
    fi
}
