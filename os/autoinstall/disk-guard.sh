#!/usr/bin/env bash
#
# HappyMining OS - disk guard for the per-machine unattended seed.
#
# render-seed.sh embeds this file in the seed's early-commands. It runs in the
# Ubuntu installer environment, as soon as the installer starts and before it
# probes block devices. It only READS; it never writes to a disk. Any non-zero
# exit aborts the installation before anything is erased.
#
#   disk-guard.sh --firmware uefi --disk BY_ID SERIAL MIN_BYTES [--disk BY_ID SERIAL MIN_BYTES]...
#
# For every --disk it requires that:
#   * /dev/disk/by-id/<name> exists on THIS machine;
#   * it resolves to a whole disk (not a partition, not the installation medium);
#   * the udev property ID_SERIAL of that disk equals SERIAL exactly - this is
#     the value the seed's storage section matches on ("match: {serial: ...}");
#   * exactly one disk in the machine has that ID_SERIAL;
#   * the disk is at least MIN_BYTES large;
# and that no two --disk arguments resolve to the same device.

set -euo pipefail

fail() {
    printf '\nHAPPYMINING DISK GUARD: REFUSING TO INSTALL - %s\n' "$*" >&2
    printf 'Nothing has been written to any disk.\n\n' >&2
    exit 1
}

udev_prop() {
    # udev_prop DEVICE KEY - value of one udev property, empty if unset.
    udevadm info --query=property --name="$1" 2>/dev/null | sed -n "s/^$2=//p" | head -n 1
}

firmware=""
ids=()
serials=()
mins=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --firmware)
            firmware="${2:-}"
            shift 2 || fail "--firmware needs a value"
            ;;
        --disk)
            [[ $# -ge 4 ]] || fail "--disk needs BY_ID SERIAL MIN_BYTES"
            ids+=("$2")
            serials+=("$3")
            mins+=("$4")
            shift 4
            ;;
        *) fail "unknown argument: $1" ;;
    esac
done
[[ ${#ids[@]} -ge 1 ]] || fail "no --disk given"

if [[ "$firmware" == "uefi" ]]; then
    [[ -d /sys/firmware/efi ]] ||
        fail "this seed creates a UEFI layout (EFI system partition), but the installer was not booted in UEFI mode"
elif [[ -n "$firmware" ]]; then
    fail "unsupported --firmware value: $firmware"
fi

resolved=()
for i in "${!ids[@]}"; do
    by_id="${ids[$i]}"
    want_serial="${serials[$i]}"
    min_bytes="${mins[$i]}"

    [[ "$by_id" == /dev/disk/by-id/* ]] || fail "$by_id is not a /dev/disk/by-id/ name"
    [[ "$min_bytes" =~ ^[0-9]+$ ]] || fail "minimum size for $by_id is not a number"
    # readlink -e fails when the name (or any link on the way) does not exist.
    real="$(readlink -e -- "$by_id" 2>/dev/null)" ||
        fail "$by_id does not exist on this machine. This seed was rendered for a different machine or disk."
    dev_type="$(lsblk -dno TYPE -- "$real" 2>/dev/null | head -n 1 | tr -d '[:space:]')"
    [[ "$dev_type" == "disk" ]] ||
        fail "$by_id resolves to $real, which is a '${dev_type:-unknown}' and not a whole disk"

    got_serial="$(udev_prop "$real" ID_SERIAL)"
    [[ -n "$got_serial" ]] || fail "$real has no udev ID_SERIAL; it cannot be matched safely"
    [[ "$got_serial" == "$want_serial" ]] ||
        fail "$by_id has ID_SERIAL '$got_serial' but the seed expects '$want_serial'"

    same=0
    while IFS= read -r name; do
        [[ -n "$name" ]] || continue
        if [[ "$(udev_prop "/dev/$name" ID_SERIAL)" == "$want_serial" ]]; then
            same=$((same + 1))
        fi
    done < <(lsblk -dno NAME,TYPE 2>/dev/null | awk '$2 == "disk" { print $1 }')
    [[ "$same" == "1" ]] ||
        fail "$same disks report ID_SERIAL '$want_serial' (expected exactly 1; multipath and duplicate serials are not supported by this seed)"

    # The installation medium must never be the target.
    while IFS= read -r mp; do
        case "$mp" in
            /cdrom | /cdrom/* | /run/live/medium | /media/cdrom)
                fail "$by_id ($real) carries the installation medium (mounted at $mp)"
                ;;
        esac
    done < <(lsblk -no MOUNTPOINT -- "$real" 2>/dev/null)

    size="$(blockdev --getsize64 "$real" 2>/dev/null || echo 0)"
    [[ "$size" =~ ^[0-9]+$ ]] || size=0
    if ((size < min_bytes)); then
        fail "$by_id is $size bytes, smaller than the $min_bytes bytes this seed's partition plan needs"
    fi

    for other in "${resolved[@]}"; do
        [[ "$other" != "$real" ]] || fail "two --disk arguments resolve to the same device $real"
    done
    resolved+=("$real")
    printf 'HappyMining disk guard: OK %s -> %s (ID_SERIAL %s, %s bytes)\n' "$by_id" "$real" "$got_serial" "$size"
done

printf 'HappyMining disk guard: all checks passed; the installer will now ask for confirmation unless it was pre-confirmed on the kernel command line.\n'
