# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

A modular, interactive Bash hardening toolkit for Rocky Linux 9 (RHEL-based). It applies CIS/CMMC-aligned security controls via a TUI menu system and is deployed to target hosts over SSH.

## Running the script

```bash
# Run locally (must be root)
sudo bash master.sh

# Deploy to a remote host and run
bash deploy.sh [user@host]        # defaults to root@172.26.124.219
ssh root@<target>
sudo bash /opt/hardening/master.sh
```

`deploy.sh` uses `rsync` to push the working directory to `/opt/hardening/` on the remote host, strips Windows line endings from all `.sh`/`.conf` files, and sets execute permissions.

## Architecture

```
master.sh          — entry point: TUI menu, category/module dispatch
config.conf        — feature flags (MODULE_<NAME>=yes/no) and all module parameters
lib/common.sh      — shared helpers: colour variables, log_info/warn/error/section,
                     check_root, command_exists, artifact_file, backup_file
modules/<name>/
  harden.sh        — self-contained module; sources ../../lib/common.sh and
                     ../../config.conf; implements its own interactive TUI loop
  *.sh             — supporting scripts sourced or called by harden.sh (e.g. clamav.sh, mde.sh)
artifacts/<name>/  — timestamped evidence files written by modules via artifact_file()
backups/           — point-in-time snapshots of the full script directory
logs/              — /var/log/hardening.log is the primary log (tee'd by all log_* calls)
MDE/               — Microsoft Defender onboarding Python script
```

### Control flow

`master.sh` presents a **category menu** → user picks a category → **module sub-menu** shows modules in that category with enabled/disabled status → user picks a module → `run_module()` executes `modules/<name>/harden.sh` via `bash`. Each module runs its own interactive loop and exits back to the caller.

### Module enable/disable

Modules are toggled by `MODULE_<NAME>=yes|no` in `config.conf`. Disabled modules can still be run interactively for the current session (the menu prompts). `master.sh` reads the flags at startup; module scripts re-source `config.conf` to access their own parameters.

### FIPS / FDE compliance checks

`master.sh` detects FIPS mode (`/proc/sys/crypto/fips_enabled`) and FDE (walks `lsblk` ancestry of `/` looking for a `crypt` layer). If either is missing, a red compliance warning is shown before entering any category, and the operator must confirm to continue.

## Adding a new module

1. Create `modules/<name>/harden.sh` — source `../../lib/common.sh` and `../../config.conf`, call `check_root`, implement a `while true` menu loop, exit cleanly.
2. Add `MODULE_<NAME>=yes|no` and a comment to `config.conf`.
3. Register the module in `master.sh`:
   - Append `<name>` to the appropriate `CATEGORY_MODULES_<key>` variable.
   - Add a `MODULE_DESC[<name>]="..."` entry.

## Key conventions

- **`backup_file <path>`** — call before modifying any system file; creates `<file>.bak.<timestamp>`.
- **`artifact_file <module>`** — returns a path like `artifacts/<module>/<module>_<hostname>_<timestamp>.txt`; use to save evidence after a module completes.
- **Idempotency** — modules check whether a change is already applied before making it (e.g. `grep -q` before `sed -i` or `echo >>`).
- **SELinux awareness** — Rocky Linux 9 has SELinux enforcing by default; modules account for this (e.g. MFA uses `--allow-reuse --no-rate-limit` and sets `authlogin_yubikey` boolean; encryption uses `restorecon`).
- **`set -euo pipefail`** — all scripts use strict mode; local variables must be declared before use in error-prone paths.
- **OpenSSH version detection** — MFA and SSH modules detect the OpenSSH major version to choose between `KbdInteractiveAuthentication` (≥8) and `ChallengeResponseAuthentication` (<8).
