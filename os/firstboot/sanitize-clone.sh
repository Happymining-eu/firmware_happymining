#!/usr/bin/env bash
#
# HappyMining OS — make an installed system safe to CLONE.
#
# A machine installed from the HappyMining OS image gets its own machine-id,
# SSH host keys and HappyMining device identity. If the installed DISK is then
# copied to other machines, every copy would share them. Run this on the image
# that is about to be cloned (offline with --root, or on the source machine
# immediately before it is shut down for imaging). On the next boot each clone
# creates new values and must be paired again.
#
#   sudo ./sanitize-clone.sh --root /mnt/image [--dry-run]
#   sudo ./sanitize-clone.sh --i-am-preparing-a-clone-image [--yes] [--dry-run]
#
# What it clears:
#   /etc/machine-id                 truncated (systemd creates a new one at boot)
#   /var/lib/dbus/machine-id        removed
#   /etc/ssh/ssh_host_*             removed; a small unit recreates them at boot
#   /var/lib/happymining/**         every file removed: device identity, device
#                                   credential, operation journal, telemetry
#                                   spool (directories are kept)
#   /var/lib/cloud/{instance,instances,data,sem}   cloud-init instance state
#   /var/lib/systemd/random-seed    removed
#
# What it never touches: Docker data, the Vast host software and its machine
# identity, NVIDIA drivers, user accounts, network configuration, disks.

set -euo pipefail
umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OS_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
HM_PROG="sanitize-clone.sh"
# The library sits in ../install in the repository and next to this script in
# the install-scripts bundle.
if [[ -f "$SCRIPT_DIR/lib.sh" ]]; then
    # shellcheck source=os/install/lib.sh
    . "$SCRIPT_DIR/lib.sh"
else
    # shellcheck source=os/install/lib.sh
    . "$OS_DIR/install/lib.sh"
fi

usage() {
    cat <<'USAGE'
Usage: sudo ./sanitize-clone.sh [--root DIR] [options]

  --root DIR      sanitize the system tree mounted at DIR (an image that is not
                  running). Without --root the RUNNING system is sanitized.
  --i-am-preparing-a-clone-image
                  required when the target is PAIRED with HappyMining (a
                  running production machine, or the mounted disk of one).
                  It loses its identity and credential and must be paired again.
  --allow-vast-present
                  continue although the Vast host software is on the image.
                  Its files are still not touched; clones of such an image
                  share Vast's host-local machine identity. Prepare clone
                  images BEFORE Vast enrolment instead.
  --yes           do not ask for confirmation.
  --dry-run       list what would be removed; change nothing.
  -h, --help      this text.

Exit codes: 0 done, 1 failure, 2 usage, 5 refused.
USAGE
}

ROOT=""
ROOT_GIVEN=0
CLONE_ACK=0
ALLOW_VAST=0
ASSUME_YES=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --root) ROOT="${2:-}"; ROOT_GIVEN=1; shift 2 || hm_die "$HM_EXIT_USAGE" "--root needs a value" ;;
        --i-am-preparing-a-clone-image) CLONE_ACK=1; shift ;;
        --allow-vast-present) ALLOW_VAST=1; shift ;;
        --yes) ASSUME_YES=1; shift ;;
        --dry-run) HM_DRY_RUN=1; shift ;;
        -h | --help) usage; exit 0 ;;
        *) usage >&2; hm_die "$HM_EXIT_USAGE" "unknown argument: $1" ;;
    esac
done

LIVE=1
if [[ "$ROOT_GIVEN" == "1" ]]; then
    [[ -n "$ROOT" && -d "$ROOT" ]] || hm_die "$HM_EXIT_USAGE" "--root directory not found: $ROOT"
    ROOT="$(cd -- "$ROOT" && pwd)"
    if [[ "$ROOT" == "/" ]]; then
        ROOT=""
    else
        LIVE=0
        [[ -d "$ROOT/etc" && -d "$ROOT/var" ]] ||
            hm_die "$HM_EXIT_USAGE" "$ROOT does not look like a system tree (no etc/ and var/)"
    fi
fi

if ! hm_is_root && [[ "$HM_DRY_RUN" != "1" ]]; then
    hm_die "$HM_EXIT_REFUSED" "this script must run as root (use sudo). Use --dry-run to preview without privileges."
fi

STATE_DIR="$ROOT/var/lib/happymining"
target_desc="${ROOT:-the RUNNING system (/)}"

# ----- refusals ---------------------------------------------------------------
paired=0
[[ -e "$STATE_DIR/credential.json" ]] && paired=1

if [[ "$paired" == "1" && "$CLONE_ACK" != "1" ]]; then
    if [[ "$LIVE" == "1" ]]; then
        hm_err "this is a RUNNING machine that is PAIRED with HappyMining."
    else
        hm_err "the system tree at $ROOT is PAIRED with HappyMining (it holds a device credential)."
    fi
    hm_err "Sanitizing it deletes its device identity and credential, its SSH host keys and its machine-id."
    hm_err "It would drop out of the fleet and would have to be paired again."
    hm_die "$HM_EXIT_REFUSED" "refusing. If this really is the source of a clone image, repeat with --i-am-preparing-a-clone-image"
fi

if [[ -d "$ROOT/var/lib/vastai_kaalia" || -e "$ROOT/etc/systemd/system/vastai.service" ]]; then
    if [[ "$ALLOW_VAST" != "1" ]]; then
        hm_err "the Vast host software is present on $target_desc."
        hm_err "A clone of this disk would carry the same Vast host-local machine identity."
        hm_err "This script never modifies Vast's files. Make clone images BEFORE Vast enrolment."
        hm_die "$HM_EXIT_REFUSED" "refusing. To sanitize everything else anyway, repeat with --allow-vast-present"
    fi
    hm_banner "The Vast host software is present and is NOT sanitized." \
        "Clones of this image share Vast's host-local machine identity." \
        "Do not boot two of them on Vast at the same time."
fi

# ----- what will be removed -----------------------------------------------------
to_remove=()
add_if_exists() {
    local p
    for p in "$@"; do
        if [[ -e "$p" || -L "$p" ]]; then
            to_remove+=("$p")
        fi
    done
}
add_if_exists "$ROOT/var/lib/dbus/machine-id"
add_if_exists "$ROOT"/etc/ssh/ssh_host_*_key "$ROOT"/etc/ssh/ssh_host_*_key.pub "$ROOT"/etc/ssh/ssh_host_*_key-cert.pub
# Agent state: every file goes; the directories (for example spool/) stay,
# with their owner and mode, because the package created them.
if [[ -d "$STATE_DIR" && ! -L "$STATE_DIR" ]]; then
    while IFS= read -r -d '' p; do
        to_remove+=("$p")
    done < <(find "$STATE_DIR" -mindepth 1 ! -type d -print0 | LC_ALL=C sort -z)
fi
add_if_exists "$ROOT/var/lib/cloud/instance"
for d in instances data sem; do
    if [[ -d "$ROOT/var/lib/cloud/$d" && ! -L "$ROOT/var/lib/cloud/$d" ]]; then
        while IFS= read -r -d '' p; do
            to_remove+=("$p")
        done < <(find "$ROOT/var/lib/cloud/$d" -mindepth 1 -maxdepth 1 -print0 | LC_ALL=C sort -z)
    fi
done
add_if_exists "$ROOT/var/lib/systemd/random-seed"

UNIT_SRC="$SCRIPT_DIR/happymining-regen-ssh-hostkeys.service"
UNIT_DST="$ROOT/etc/systemd/system/happymining-regen-ssh-hostkeys.service"
UNIT_LINK="$ROOT/etc/systemd/system/multi-user.target.wants/happymining-regen-ssh-hostkeys.service"
[[ -f "$UNIT_SRC" ]] || hm_die "$HM_EXIT_FAIL" "missing $UNIT_SRC (needed so that clones get new SSH host keys)"

hm_log "target: $target_desc"
hm_log "will truncate: $ROOT/etc/machine-id"
for p in "${to_remove[@]}"; do
    hm_log "will remove:   $p"
done
hm_log "will install:  $UNIT_DST (creates new SSH host keys on the next boot)"
hm_log "not touched:   Docker data, Vast host software, NVIDIA drivers, accounts, network configuration, disks"

if [[ "$HM_DRY_RUN" == "1" ]]; then
    hm_log "DRY RUN complete: nothing was changed"
    exit 0
fi

if [[ "$LIVE" == "1" && "$ASSUME_YES" != "1" ]]; then
    hm_confirm "Sanitize the RUNNING system? SSH host keys and the machine identity are deleted now." ||
        hm_die "$HM_EXIT_REFUSED" "not confirmed; nothing was changed"
fi

# ----- do it ------------------------------------------------------------------------
: >"$ROOT/etc/machine-id"
chmod 0444 -- "$ROOT/etc/machine-id"
for p in "${to_remove[@]}"; do
    # Every entry was built from a fixed sub-path of the target tree above.
    case "$p" in
        "$ROOT"/etc/ssh/ssh_host_* | "$ROOT"/var/lib/dbus/machine-id | "$STATE_DIR"/* | \
            "$ROOT"/var/lib/cloud/instance | "$ROOT"/var/lib/cloud/instances/* | "$ROOT"/var/lib/cloud/data/* | \
            "$ROOT"/var/lib/cloud/sem/* | "$ROOT"/var/lib/systemd/random-seed)
            rm -rf -- "$p"
            ;;
        *) hm_die "$HM_EXIT_FAIL" "internal error: unexpected path $p" ;;
    esac
done
mkdir -p -- "$(dirname -- "$UNIT_LINK")"
install -m 0644 -- "$UNIT_SRC" "$UNIT_DST"
ln -sfn -- ../happymining-regen-ssh-hostkeys.service "$UNIT_LINK"

hm_log "done. Shut this system down now (do not let it run on) and take the image."
hm_log "Each clone gets a new machine-id, new SSH host keys and no HappyMining identity or credential."
hm_log "On each clone: check 'happyminingctl status' (run 'sudo happyminingctl identity init' if no identity was created), then 'sudo happyminingctl pair'."
