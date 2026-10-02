#!/usr/bin/env bash
#
# HappyMining agent — take the agent package off this machine. Only that.
#
#   sudo ./uninstall.sh [--erase-config] [--dry-run] [--yes]
#
# Docker, the Vast host software, NVIDIA drivers, kernels, disks, network and
# firewall are left exactly as they are, and the machine is not restarted.
# Vast hosting keeps running: the HappyMining agent is not in the rental data
# path.

set -euo pipefail
umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
HM_PROG="uninstall.sh"
# shellcheck source=os/install/lib.sh
. "$SCRIPT_DIR/lib.sh"

usage() {
    cat <<'USAGE'
Usage: sudo ./uninstall.sh [options]

  --erase-config   also erase the package's configuration files (dpkg -P).
                   Without it, configuration and the device identity stay on
                   disk so that the same package can be added again later.
  --dry-run        show what would be done. Changes nothing.
  --yes            do not ask for confirmation.
  --root DIR       operate on the system tree under DIR (tests, images).
  -h, --help       this text.

Only the happymining-agent package is touched. Docker, the Vast host software
and NVIDIA drivers are never touched by this script.

Exit codes: 0 done, 1 failure, 2 usage, 5 refused, 77 skipped.
USAGE
}

ERASE_CONFIG=0
ASSUME_YES=0
ROOT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --erase-config) ERASE_CONFIG=1; shift ;;
        --dry-run) HM_DRY_RUN=1; shift ;;
        --yes) ASSUME_YES=1; shift ;;
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

hm_load_versions
hm_need_tools dpkg dpkg-query sha256sum awk grep stat diff

hm_self_guard "${BASH_SOURCE[0]}"

if ! hm_is_root; then
    if [[ "$HM_DRY_RUN" == "1" ]]; then
        hm_warn "not running as root: this dry run can only show what a privileged run would do"
    else
        hm_die "$HM_EXIT_REFUSED" "this script must run as root (use sudo). Use --dry-run to preview without privileges."
    fi
fi

LOG_DIR="$ROOT/var/log/happymining"
if [[ "$HM_DRY_RUN" != "1" ]]; then
    mkdir -p -- "$LOG_DIR"
    HM_LOG_FILE="$LOG_DIR/install.log"
    hm_log "---- uninstall started; erase-config=$ERASE_CONFIG root=${ROOT:-/}"
else
    hm_log "DRY RUN: nothing on this machine will be changed"
fi

installed_version="$(hm_pkg_version "$ROOT" "$AGENT_PACKAGE")"
if [[ -z "$installed_version" ]]; then
    hm_log "$AGENT_PACKAGE is not present on this machine; nothing to do"
    exit 0
fi

state_before="$(hm_host_state "$ROOT")"
hm_host_summary "$ROOT" "$state_before"

DPKG=(dpkg)
# With an alternate root, dpkg's own log must go into that root as well: the
# "log" setting in /etc/dpkg/dpkg.cfg is an absolute path on the host.
[[ -z "$ROOT" ]] || DPKG=(dpkg "--root=$ROOT" "--log=$ROOT/var/log/dpkg.log")
if [[ "$ERASE_CONFIG" == "1" ]]; then
    action=(-P)
else
    action=(-r)
fi

hm_log "plan: $(hm_quote_cmd "${DPKG[@]}" "${action[@]}" "$AGENT_PACKAGE")  (version $installed_version)"
hm_log "  nothing else: Docker, the Vast host software, NVIDIA drivers, kernels, disks and network stay as they are"
if [[ -f "$ROOT/var/lib/happymining/credential.json" ]]; then
    hm_warn "this machine is paired. Run 'sudo happyminingctl unpair' first if the device should also be revoked on the HappyMining side."
fi

if [[ "$HM_DRY_RUN" != "1" && "$ASSUME_YES" != "1" ]]; then
    hm_confirm "Take $AGENT_PACKAGE $installed_version off this machine?" ||
        hm_die "$HM_EXIT_REFUSED" "not confirmed; nothing was changed"
fi

hm_run "${DPKG[@]}" "${action[@]}" "$AGENT_PACKAGE"

state_after="$(hm_host_state "$ROOT")"
if ! hm_assert_host_unchanged "$state_before" "$state_after"; then
    exit "$HM_EXIT_FAIL"
fi

if [[ "$HM_DRY_RUN" == "1" ]]; then
    hm_log "DRY RUN complete: nothing was changed"
    exit 0
fi
hm_log "done: $AGENT_PACKAGE is no longer on this machine"
hm_log "Docker, the Vast host software and NVIDIA drivers were not touched; Vast hosting continues to run."
hm_log "Cached packages remain in $ROOT/var/cache/happymining and logs in $LOG_DIR; delete them by hand if wanted."
