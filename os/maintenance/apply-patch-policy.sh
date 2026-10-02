#!/usr/bin/env bash
#
# HappyMining OS — put the scheduled-patching policy files in place on an
# EXISTING server (machines installed from the HappyMining OS image already
# have them). Opt-in and separate from install.sh on purpose: install.sh never
# changes the configuration of the host's package manager.
#
#   sudo ./apply-patch-policy.sh [--dry-run] [--root DIR]
#
# It copies two files and nothing else:
#   /etc/apt/apt.conf.d/52happymining-unattended-upgrades
#   /etc/needrestart/conf.d/50-happymining.conf
# It does not upgrade, hold or remove any package and does not restart
# anything. Existing files with these names are kept as *.bak-<timestamp>.

set -euo pipefail
umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
HM_PROG="apply-patch-policy.sh"
if [[ -f "$SCRIPT_DIR/lib.sh" ]]; then
    # shellcheck source=os/install/lib.sh
    . "$SCRIPT_DIR/lib.sh"
else
    # shellcheck source=os/install/lib.sh
    . "$SCRIPT_DIR/../install/lib.sh"
fi

usage() {
    cat <<'USAGE'
Usage: sudo ./apply-patch-policy.sh [--dry-run] [--root DIR]

Copies the HappyMining unattended-upgrades and needrestart policy files into
/etc. Changes no package and restarts nothing.

  --dry-run    show what would be copied; change nothing.
  --root DIR   operate on the system tree under DIR (tests, images).

Exit codes: 0 done, 1 failure, 2 usage, 5 refused.
USAGE
}

ROOT=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) HM_DRY_RUN=1; shift ;;
        --root) ROOT="${2:-}"; shift 2 || hm_die "$HM_EXIT_USAGE" "--root needs a value" ;;
        -h | --help) usage; exit 0 ;;
        *) usage >&2; hm_die "$HM_EXIT_USAGE" "unknown argument: $1" ;;
    esac
done
if [[ -n "$ROOT" ]]; then
    [[ -d "$ROOT" ]] || hm_die "$HM_EXIT_USAGE" "--root directory not found: $ROOT"
    ROOT="$(cd -- "$ROOT" && pwd)"
    [[ "$ROOT" != "/" ]] || ROOT=""
fi
if ! hm_is_root && [[ "$HM_DRY_RUN" != "1" ]]; then
    hm_die "$HM_EXIT_REFUSED" "this script must run as root (use sudo). Use --dry-run to preview without privileges."
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
copy_policy() {
    local src="$1" dst="$2"
    [[ -f "$src" ]] || hm_die "$HM_EXIT_FAIL" "missing $src"
    if [[ -f "$dst" ]] && cmp -s -- "$src" "$dst"; then
        hm_log "already in place: $dst"
        return 0
    fi
    if [[ -e "$dst" ]]; then
        hm_run cp -p -- "$dst" "$dst.bak-$stamp"
    fi
    hm_run install -D -m 0644 -- "$src" "$dst"
}

copy_policy "$SCRIPT_DIR/52happymining-unattended-upgrades" "$ROOT/etc/apt/apt.conf.d/52happymining-unattended-upgrades"
copy_policy "$SCRIPT_DIR/needrestart-happymining.conf" "$ROOT/etc/needrestart/conf.d/50-happymining.conf"

if [[ "$HM_DRY_RUN" == "1" ]]; then
    hm_log "DRY RUN complete: nothing was changed"
else
    hm_log "done. No package was changed and nothing was restarted."
    hm_log "Check the effective policy with: apt-config dump | grep -i unattended-upgrade"
fi
