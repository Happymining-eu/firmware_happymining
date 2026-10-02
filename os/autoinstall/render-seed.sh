#!/usr/bin/env bash
#
# HappyMining OS — render a PER-MACHINE unattended installation seed.
#
# A rendered seed ERASES one explicitly named disk (and, optionally, a second
# dedicated data disk). This script never touches a disk itself: it only writes
# two small text files (user-data, meta-data) for the Ubuntu installer.
#
# Safety rules implemented here:
#   * the target must be given as /dev/disk/by-id/<name>; kernel names such as
#     /dev/sda or /dev/nvme0n1, by-path, by-uuid, "first", "largest" are refused;
#   * the same by-id string must be typed again with --confirm-erase;
#   * the partition plan and the exact identifier that will be ERASED are
#     printed before anything is written;
#   * unless --yes-i-have-read-the-plan is given, the by-id name must be typed
#     once more interactively;
#   * the only account credential is the operator's own SSH PUBLIC key; a
#     private key file is refused; there is never a password;
#   * the output directory is 0700 and the files 0600, and it may not be placed
#     inside the trees that feed the distributed image (os/, dist/).

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OS_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_DIR="$(cd -- "$OS_DIR/.." && pwd)"
HM_PROG="render-seed.sh"
# shellcheck source=os/install/lib.sh
. "$OS_DIR/install/lib.sh"
hm_load_versions

TEMPLATE="$SCRIPT_DIR/user-data.unattended.yaml.tmpl"
GUARD="$SCRIPT_DIR/disk-guard.sh"

usage() {
    cat <<USAGE
Usage: render-seed.sh --disk-by-id /dev/disk/by-id/NAME --disk-serial SERIAL \\
                      --confirm-erase /dev/disk/by-id/NAME \\
                      --ssh-authorized-key-file FILE.pub --hostname NAME --out DIR [options]

Required:
  --disk-by-id PATH        the disk to ERASE, as /dev/disk/by-id/<name>
                           (ata-..., nvme-<model>_<serial>, scsi-..., virtio-...).
  --disk-serial SERIAL     the udev ID_SERIAL of that disk. The installer matches
                           the disk on this value (Subiquity "match: serial"). The
                           by-id name must be "<bus>-<SERIAL>". On the target:
                             udevadm info --query=property --name=/dev/disk/by-id/NAME | grep '^ID_SERIAL='
  --confirm-erase PATH     the same by-id string, typed again.
  --ssh-authorized-key-file FILE
                           the operator's own SSH PUBLIC key file (one key per
                           line). Vast asks for a unique key pair per machine.
  --hostname NAME          hostname of the machine (lower case letters, digits, '-').
  --out DIR                directory to create for this machine's seed.

Partition plan (defaults come from os/versions.env and cite Vast's documentation):
  --root-size SIZE         size of the root filesystem (default 100G).
  --data-fs FS             filesystem for Docker/Vast instance storage
                           (default ${VAST_DOCKER_DATA_FS}; xfs or ext4).
  --data-mount PATH        its mount point (default ${VAST_DOCKER_DATA_MOUNT}).
  --data-mount-options O   its mount options (default ${VAST_DOCKER_DATA_MOUNT_OPTIONS} for xfs).
  --min-data-size SIZE     smallest acceptable data filesystem; the installer
                           refuses a disk that is too small (default ${VAST_MIN_DOCKER_STORAGE_GB}G).
  --data-disk-by-id PATH, --data-disk-serial SERIAL, --confirm-erase-data-disk PATH
                           put the data filesystem on a second, dedicated disk
                           (also ERASED) instead of a partition of the first one.

Other:
  --username NAME          account to create (default hmadmin). Key login only,
                           locked password, sudo without password.
  --timezone TZ            default Etc/UTC.
  --yes-i-have-read-the-plan
                           skip the interactive typed confirmation.
  --force                  write into an existing, non-empty --out directory.
  --dry-run                print the plan and the rendered seed; write nothing.
  -h, --help               this text.

Sizes are whole numbers followed by M or G (for example 100G).
Exit codes: 0 done, 1 failure, 2 usage, 5 refused, 77 skipped (prerequisite missing).
USAGE
}

DISK_BY_ID=""
DISK_SERIAL=""
CONFIRM_ERASE=""
KEY_FILE=""
HOSTNAME_ARG=""
OUT_DIR=""
ROOT_SIZE="100G"
DATA_FS="$VAST_DOCKER_DATA_FS"
DATA_MOUNT="$VAST_DOCKER_DATA_MOUNT"
DATA_MOUNT_OPTIONS=""
MIN_DATA_SIZE="${VAST_MIN_DOCKER_STORAGE_GB}G"
DATA_DISK_BY_ID=""
DATA_DISK_SERIAL=""
CONFIRM_ERASE_DATA=""
USERNAME="hmadmin"
TIMEZONE="Etc/UTC"
PLAN_ACK=0
FORCE=0

need_value() {
    [[ $# -ge 2 ]] || hm_die "$HM_EXIT_USAGE" "$1 needs a value"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --disk-by-id) need_value "$@"; DISK_BY_ID="$2"; shift 2 ;;
        --disk-serial) need_value "$@"; DISK_SERIAL="$2"; shift 2 ;;
        --confirm-erase) need_value "$@"; CONFIRM_ERASE="$2"; shift 2 ;;
        --ssh-authorized-key-file) need_value "$@"; KEY_FILE="$2"; shift 2 ;;
        --hostname) need_value "$@"; HOSTNAME_ARG="$2"; shift 2 ;;
        --out) need_value "$@"; OUT_DIR="$2"; shift 2 ;;
        --root-size) need_value "$@"; ROOT_SIZE="$2"; shift 2 ;;
        --data-fs) need_value "$@"; DATA_FS="$2"; shift 2 ;;
        --data-mount) need_value "$@"; DATA_MOUNT="$2"; shift 2 ;;
        --data-mount-options) need_value "$@"; DATA_MOUNT_OPTIONS="$2"; shift 2 ;;
        --min-data-size) need_value "$@"; MIN_DATA_SIZE="$2"; shift 2 ;;
        --data-disk-by-id) need_value "$@"; DATA_DISK_BY_ID="$2"; shift 2 ;;
        --data-disk-serial) need_value "$@"; DATA_DISK_SERIAL="$2"; shift 2 ;;
        --confirm-erase-data-disk) need_value "$@"; CONFIRM_ERASE_DATA="$2"; shift 2 ;;
        --username) need_value "$@"; USERNAME="$2"; shift 2 ;;
        --timezone) need_value "$@"; TIMEZONE="$2"; shift 2 ;;
        --yes-i-have-read-the-plan) PLAN_ACK=1; shift ;;
        --force) FORCE=1; shift ;;
        --dry-run) HM_DRY_RUN=1; shift ;;
        -h | --help) usage; exit 0 ;;
        *) usage >&2; hm_die "$HM_EXIT_USAGE" "unknown argument: $1" ;;
    esac
done

# ---------------------------------------------------------------------------
# Validation. Nothing is written until every check below has passed.
# ---------------------------------------------------------------------------
refuse_disk() {
    hm_err "$1"
    hm_err "A destructive install needs an explicit, stable disk identity:"
    hm_err "  --disk-by-id /dev/disk/by-id/<bus>-<serial>   (list them on the target with: ls -l /dev/disk/by-id/)"
    hm_err "Kernel names (/dev/sda, /dev/nvme0n1, /dev/vda), by-path, by-uuid and choices such as"
    hm_err "'first' or 'largest' are never accepted, because they can point at a different disk on the next boot."
    exit "$HM_EXIT_REFUSED"
}

validate_by_id() {
    # validate_by_id OPTION VALUE SERIAL
    local opt="$1" value="$2" serial="$3" base bus
    [[ -n "$value" ]] || refuse_disk "$opt is required and must not be empty"
    case "$value" in
        /dev/disk/by-id/*) ;;
        /dev/disk/by-path/* | /dev/disk/by-uuid/* | /dev/disk/by-partuuid/* | /dev/disk/by-label/* | /dev/disk/by-partlabel/*)
            refuse_disk "$opt: '$value' is not a /dev/disk/by-id/ name"
            ;;
        /dev/*) refuse_disk "$opt: '$value' is a kernel device name, not a /dev/disk/by-id/ name" ;;
        *) refuse_disk "$opt: '$value' is not a disk identifier; it must start with /dev/disk/by-id/" ;;
    esac
    base="${value#/dev/disk/by-id/}"
    [[ "$base" =~ ^[A-Za-z0-9][A-Za-z0-9._:+=@-]*$ ]] ||
        refuse_disk "$opt: '$value' has an empty or unexpected name after /dev/disk/by-id/"
    [[ ! "$base" =~ -part[0-9]+$ ]] ||
        refuse_disk "$opt: '$value' is a partition; give the whole disk"
    case "$base" in
        wwn-* | nvme-eui.* | nvme-nvme.* | nvme-uuid.*)
            refuse_disk "$opt: '$value' is a WWN/EUI name. The installer matches on udev ID_SERIAL, which this name does not contain; use the ata-, nvme-<model>_<serial>, scsi- or virtio- name of the same disk"
            ;;
        dm-* | md-* | lvm-* | usb-* | mmc-* | raid-*)
            refuse_disk "$opt: '$value' is not a plain internal disk (device-mapper, RAID, USB and MMC names are not supported by this seed)"
            ;;
    esac
    bus="${base%%-*}"
    case "$bus" in
        ata | nvme | scsi | virtio) ;;
        *) refuse_disk "$opt: unsupported by-id prefix '$bus-' (supported: ata-, nvme-, scsi-, virtio-)" ;;
    esac
    [[ -n "$serial" ]] ||
        hm_die "$HM_EXIT_USAGE" "the serial option that belongs to $opt is required (udev ID_SERIAL of that disk)"
    [[ "$serial" =~ ^[A-Za-z0-9][A-Za-z0-9._:+=@-]*$ && ${#serial} -le 128 ]] ||
        hm_die "$HM_EXIT_REFUSED" "serial '$serial' contains characters that are not allowed (wildcards such as * ? [ ] are never accepted: the match must be exact)"
    [[ "$base" == "$bus-$serial" ]] ||
        hm_die "$HM_EXIT_REFUSED" "$opt '$value' and serial '$serial' do not describe the same disk: the by-id name must be exactly '$bus-<ID_SERIAL>' (expected /dev/disk/by-id/$bus-$serial)"
}

size_to_bytes() {
    local size="$1" n unit
    [[ "$size" =~ ^([1-9][0-9]*)([MG])$ ]] || return 1
    n="${BASH_REMATCH[1]}"
    unit="${BASH_REMATCH[2]}"
    if [[ "$unit" == "G" ]]; then
        printf '%s\n' "$((n * 1024 * 1024 * 1024))"
    else
        printf '%s\n' "$((n * 1024 * 1024))"
    fi
}

validate_by_id "--disk-by-id" "$DISK_BY_ID" "$DISK_SERIAL"
[[ -n "$CONFIRM_ERASE" ]] ||
    hm_die "$HM_EXIT_REFUSED" "--confirm-erase is required: type the --disk-by-id value again to confirm that this disk may be ERASED"
[[ "$CONFIRM_ERASE" == "$DISK_BY_ID" ]] ||
    hm_die "$HM_EXIT_REFUSED" "--confirm-erase does not match --disk-by-id exactly ('$CONFIRM_ERASE' vs '$DISK_BY_ID'); nothing was written"

USE_DATA_DISK=0
if [[ -n "$DATA_DISK_BY_ID" || -n "$DATA_DISK_SERIAL" || -n "$CONFIRM_ERASE_DATA" ]]; then
    USE_DATA_DISK=1
    validate_by_id "--data-disk-by-id" "$DATA_DISK_BY_ID" "$DATA_DISK_SERIAL"
    [[ "$CONFIRM_ERASE_DATA" == "$DATA_DISK_BY_ID" ]] ||
        hm_die "$HM_EXIT_REFUSED" "--confirm-erase-data-disk does not match --data-disk-by-id exactly; nothing was written"
    [[ "$DATA_DISK_BY_ID" != "$DISK_BY_ID" && "$DATA_DISK_SERIAL" != "$DISK_SERIAL" ]] ||
        hm_die "$HM_EXIT_REFUSED" "the data disk must be a different disk from the system disk"
fi

[[ -n "$HOSTNAME_ARG" ]] || hm_die "$HM_EXIT_USAGE" "--hostname is required"
[[ "$HOSTNAME_ARG" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] ||
    hm_die "$HM_EXIT_USAGE" "--hostname must be 1-63 characters: lower case letters, digits and '-', not starting or ending with '-'"
[[ "$USERNAME" =~ ^[a-z][a-z0-9_-]{0,30}$ && "$USERNAME" != "root" && "$USERNAME" != "happymining" ]] ||
    hm_die "$HM_EXIT_USAGE" "--username must be a normal login name (not root, not the agent's system user)"
[[ "$TIMEZONE" =~ ^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+){0,2}$ ]] ||
    hm_die "$HM_EXIT_USAGE" "--timezone must look like Etc/UTC or Europe/Paris"

case "$DATA_FS" in
    xfs | ext4) ;;
    *) hm_die "$HM_EXIT_USAGE" "--data-fs must be xfs or ext4" ;;
esac
[[ "$DATA_MOUNT" =~ ^/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$ ]] ||
    hm_die "$HM_EXIT_USAGE" "--data-mount must be an absolute path"
case "$DATA_MOUNT" in
    /boot | /boot/* | /etc | /etc/* | /usr | /usr/* | /dev | /dev/* | /proc | /proc/* | /sys | /sys/* | /run | /run/* | /bin | /sbin | /lib | /lib64)
        hm_die "$HM_EXIT_USAGE" "--data-mount $DATA_MOUNT is not a place for a data filesystem"
        ;;
esac
if [[ -z "$DATA_MOUNT_OPTIONS" ]]; then
    if [[ "$DATA_FS" == "$VAST_DOCKER_DATA_FS" ]]; then
        DATA_MOUNT_OPTIONS="$VAST_DOCKER_DATA_MOUNT_OPTIONS"
    else
        hm_die "$HM_EXIT_USAGE" "--data-mount-options is required when --data-fs is not $VAST_DOCKER_DATA_FS (there is no verified default for $DATA_FS)"
    fi
fi
[[ "$DATA_MOUNT_OPTIONS" =~ ^[A-Za-z0-9_=.-]+(,[A-Za-z0-9_=.-]+)*$ ]] ||
    hm_die "$HM_EXIT_USAGE" "--data-mount-options must be a comma-separated list of mount options"

ESP_BYTES="$((1024 * 1024 * 1024))"
ROOT_BYTES="$(size_to_bytes "$ROOT_SIZE")" || hm_die "$HM_EXIT_USAGE" "--root-size must look like 100G or 51200M"
MIN_DATA_BYTES="$(size_to_bytes "$MIN_DATA_SIZE")" || hm_die "$HM_EXIT_USAGE" "--min-data-size must look like 200G"
MIN_ROOT_BYTES="$(((VAST_MIN_ROOT_FREE_GB + 12) * 1024 * 1024 * 1024))"
if ((ROOT_BYTES < MIN_ROOT_BYTES)); then
    hm_warn "--root-size $ROOT_SIZE is small: Vast asks for ${VAST_MIN_ROOT_FREE_GB} GB FREE on the root partition, and the system itself needs about 12 GB"
fi
if ((MIN_DATA_BYTES < VAST_MIN_DOCKER_STORAGE_GB * 1024 * 1024 * 1024)); then
    hm_warn "--min-data-size $MIN_DATA_SIZE is below Vast's documented minimum of ${VAST_MIN_DOCKER_STORAGE_GB} GB for Docker container storage"
fi
# One extra GiB covers partition alignment and the backup GPT.
SLACK_BYTES="$((1024 * 1024 * 1024))"
if [[ "$USE_DATA_DISK" == "1" ]]; then
    DISK_MIN_BYTES="$((ESP_BYTES + ROOT_BYTES + SLACK_BYTES))"
    DATA_DISK_MIN_BYTES="$((MIN_DATA_BYTES + SLACK_BYTES))"
else
    DISK_MIN_BYTES="$((ESP_BYTES + ROOT_BYTES + MIN_DATA_BYTES + SLACK_BYTES))"
    DATA_DISK_MIN_BYTES=0
fi

[[ -n "$KEY_FILE" ]] || hm_die "$HM_EXIT_USAGE" "--ssh-authorized-key-file is required (the operator's own PUBLIC key)"
[[ -f "$KEY_FILE" && -r "$KEY_FILE" ]] || hm_die "$HM_EXIT_USAGE" "public key file not found or not readable: $KEY_FILE"
[[ -n "$OUT_DIR" ]] || hm_die "$HM_EXIT_USAGE" "--out DIR is required"

hm_need_tools python3

# The key file is parsed by a small Python program: private keys are refused,
# every line must be a well-formed public key whose base64 body names the same
# key type as its first field. Output: "<SHA256 fingerprint>\t<key line>".
KEY_REPORT="$(
    python3 - "$KEY_FILE" <<'PYEOF'
import base64
import hashlib
import re
import struct
import sys

ALLOWED = {
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
}
path = sys.argv[1]
try:
    with open(path, "rb") as fh:
        raw = fh.read(1024 * 1024)
except OSError as exc:
    sys.exit(f"cannot read {path}: {exc}")
try:
    text = raw.decode("utf-8")
except UnicodeDecodeError:
    sys.exit("the file is not text; an SSH public key file is expected")
if "PRIVATE KEY" in text or "PuTTY-User-Key-File" in text:
    sys.exit("this file contains a PRIVATE key. Never put a private key in a seed; "
             "pass the matching PUBLIC key file (usually the same name with .pub)")
keys = []
for lineno, line in enumerate(text.splitlines(), start=1):
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    parts = line.split(None, 2)
    if len(parts) < 2 or parts[0] not in ALLOWED:
        sys.exit(f"line {lineno}: not an accepted SSH public key (accepted types: {', '.join(sorted(ALLOWED))}; "
                 "options before the key type are not accepted)")
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", parts[1]):
        sys.exit(f"line {lineno}: the key body is not base64")
    try:
        blob = base64.b64decode(parts[1], validate=True)
        (length,) = struct.unpack(">I", blob[:4])
        inner = blob[4:4 + length].decode("ascii")
    except Exception:
        sys.exit(f"line {lineno}: the key body cannot be decoded")
    if inner != parts[0]:
        sys.exit(f"line {lineno}: key type '{parts[0]}' does not match the key body ('{inner}')")
    comment = parts[2] if len(parts) == 3 else ""
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in comment) or len(line) > 8192:
        sys.exit(f"line {lineno}: unexpected characters or length")
    fp = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    keys.append((f"SHA256:{fp}", line))
if not keys:
    sys.exit("no public key found in the file")
for fp, line in keys:
    print(f"{fp}\t{line}")
PYEOF
)" || hm_die "$HM_EXIT_REFUSED" "--ssh-authorized-key-file $KEY_FILE was refused (see the message above); nothing was written"

SSH_KEYS=()
SSH_FPRS=()
while IFS=$'\t' read -r fpr keyline; do
    [[ -n "$fpr" ]] || continue
    SSH_FPRS+=("$fpr")
    SSH_KEYS+=("$keyline")
done <<<"$KEY_REPORT"

# Output location: never inside the trees that feed the distributed image.
out_parent="$(dirname -- "$OUT_DIR")"
[[ -d "$out_parent" ]] || hm_die "$HM_EXIT_USAGE" "the parent directory of --out does not exist: $out_parent"
OUT_ABS="$(cd -- "$out_parent" && pwd)/$(basename -- "$OUT_DIR")"
case "$OUT_ABS/" in
    "$OS_DIR"/* | "$REPO_DIR/dist"/* | "$REPO_DIR/agent"/*)
        hm_die "$HM_EXIT_REFUSED" "--out $OUT_ABS is inside the source or distribution tree. A per-machine seed must never be placed where it could end up in the generic image; choose a directory outside os/ and dist/"
        ;;
esac
if [[ -e "$OUT_ABS" ]]; then
    [[ -d "$OUT_ABS" && ! -L "$OUT_ABS" ]] || hm_die "$HM_EXIT_REFUSED" "--out $OUT_ABS exists and is not a directory"
    if [[ -n "$(ls -A -- "$OUT_ABS")" && "$FORCE" != "1" ]]; then
        hm_die "$HM_EXIT_REFUSED" "--out $OUT_ABS is not empty (use --force to overwrite user-data and meta-data in it)"
    fi
fi

# ---------------------------------------------------------------------------
# The plan. Printed before anything is written.
# ---------------------------------------------------------------------------
print_plan() {
    local n
    cat <<PLAN

==================== HAPPYMINING OS — DESTRUCTIVE INSTALL PLAN ====================
Machine hostname ........ $HOSTNAME_ARG
Boot firmware ........... UEFI only (the installer refuses to continue otherwise)

DISK THAT WILL BE ERASED:
    $DISK_BY_ID
    matched in the installer by udev ID_SERIAL = $DISK_SERIAL (exact, no wildcards)
    the existing partition table and ALL data on this disk are destroyed

Partition plan (GPT) on $DISK_BY_ID:
    #  size        filesystem  mount point        purpose
    1  1G          fat32       /boot/efi          EFI system partition (ESP)
    -  (no separate /boot: the root filesystem is a plain partition, no LVM, no encryption)
    2  $(printf '%-10s' "$ROOT_SIZE")  ext4        /                  operating system
PLAN
    if [[ "$USE_DATA_DISK" == "1" ]]; then
        cat <<PLAN
    (the rest of this disk stays unallocated)

SECOND DISK THAT WILL BE ERASED (dedicated data disk):
    $DATA_DISK_BY_ID
    matched in the installer by udev ID_SERIAL = $DATA_DISK_SERIAL (exact, no wildcards)

Partition plan (GPT) on $DATA_DISK_BY_ID:
    #  size        filesystem  mount point        purpose
    1  whole disk  $(printf '%-10s' "$DATA_FS")  $(printf '%-17s' "$DATA_MOUNT")  Docker / Vast instance storage
PLAN
    else
        cat <<PLAN
    3  remainder   $(printf '%-10s' "$DATA_FS")  $(printf '%-17s' "$DATA_MOUNT")  Docker / Vast instance storage
PLAN
    fi
    cat <<PLAN
    data filesystem mount options: $DATA_MOUNT_OPTIONS
    swap: none

Why this data filesystem: Vast's host installer expects $VAST_DOCKER_DATA_MOUNT on
$VAST_DOCKER_DATA_FS mounted with project quota ($VAST_DOCKER_DATA_MOUNT_OPTIONS) and reuses such a mount
when it finds it in the filesystem table; Vast's verification requirements ask
for at least ${VAST_MIN_DOCKER_STORAGE_GB} GB of SSD storage for Docker ("Dedicated drive for Docker
container storage") and ${VAST_MIN_ROOT_FREE_GB} GB free on the root partition. Sources: os/README.md.

Checks the installer runs BEFORE it erases anything (disk-guard.sh):
    * it was booted in UEFI mode;
    * $DISK_BY_ID exists on that machine, is a whole disk,
      has exactly this ID_SERIAL, is the only disk with it,
      and is at least $DISK_MIN_BYTES bytes;
PLAN
    if [[ "$USE_DATA_DISK" == "1" ]]; then
        cat <<PLAN
    * the same for $DATA_DISK_BY_ID (at least $DATA_DISK_MIN_BYTES bytes);
PLAN
    fi
    cat <<PLAN
    * the installation medium is not the target.
All other disks in the machine are left untouched by this seed.

Account ................. $USERNAME (SSH key login only, password locked, sudo without password)
SSH password login ...... disabled
SSH public key(s) .......
PLAN
    for n in "${!SSH_FPRS[@]}"; do
        printf '    %s\n' "${SSH_FPRS[$n]}"
    done
    cat <<PLAN
Not in the seed ......... no password, no private key, no pairing code, no API or Vast credential
Output .................. $OUT_ABS/user-data and $OUT_ABS/meta-data (directory 0700, files 0600)
===================================================================================

PLAN
}

print_plan
if [[ "$USE_DATA_DISK" != "1" ]]; then
    hm_warn "Vast's requirements speak of a DEDICATED DRIVE for Docker storage. This plan puts it on a partition of the system disk. If the machine has a second SSD, consider --data-disk-by-id."
fi

# ---------------------------------------------------------------------------
# Typed confirmation.
# ---------------------------------------------------------------------------
if [[ "$HM_DRY_RUN" == "1" ]]; then
    hm_log "DRY RUN: no confirmation asked and nothing will be written"
elif [[ "$PLAN_ACK" != "1" ]]; then
    printf 'To confirm that %s will be ERASED, type its full by-id path again: ' "$DISK_BY_ID" >&2
    reply=""
    IFS= read -r reply || true
    if [[ "$reply" != "$DISK_BY_ID" ]]; then
        printf '\n' >&2
        hm_die "$HM_EXIT_REFUSED" "confirmation did not match; nothing was written"
    fi
    if [[ "$USE_DATA_DISK" == "1" ]]; then
        printf 'To confirm that %s will ALSO be ERASED, type its full by-id path again: ' "$DATA_DISK_BY_ID" >&2
        reply=""
        IFS= read -r reply || true
        if [[ "$reply" != "$DATA_DISK_BY_ID" ]]; then
            printf '\n' >&2
            hm_die "$HM_EXIT_REFUSED" "confirmation for the data disk did not match; nothing was written"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Render (in memory), validate, then write.
# ---------------------------------------------------------------------------
render_args=(
    --template "$TEMPLATE"
    --block-file "DISK_GUARD=$GUARD"
    --set "DISK_BY_ID=$DISK_BY_ID"
    --set "DISK_SERIAL=$DISK_SERIAL"
    --set "DISK_MIN_BYTES=$DISK_MIN_BYTES"
    --set "ROOT_SIZE=$ROOT_SIZE"
    --set "DATA_FS=$DATA_FS"
    --set "DATA_MOUNT=$DATA_MOUNT"
    --set "DATA_MOUNT_OPTIONS=$DATA_MOUNT_OPTIONS"
    --set "HOSTNAME=$HOSTNAME_ARG"
    --set "USERNAME=$USERNAME"
    --set "TIMEZONE=$TIMEZONE"
)
if [[ "$USE_DATA_DISK" == "1" ]]; then
    render_args+=(
        --enable DATA_DISK
        --set "DATA_DISK_BY_ID=$DATA_DISK_BY_ID"
        --set "DATA_DISK_SERIAL=$DATA_DISK_SERIAL"
        --set "DATA_DISK_MIN_BYTES=$DATA_DISK_MIN_BYTES"
    )
else
    render_args+=(--enable DATA_ON_ROOT_DISK)
fi
for key in "${SSH_KEYS[@]}"; do
    render_args+=(--list-item "SSH_AUTHORIZED_KEYS=$key")
done

RENDERED="$(python3 "$SCRIPT_DIR/render_template.py" "${render_args[@]}")" ||
    hm_die "$HM_EXIT_FAIL" "rendering the seed failed; nothing was written"

if ! printf '%s\n' "$RENDERED" | python3 "$SCRIPT_DIR/validate.py" --kind unattended --rendered - >&2; then
    hm_die "$HM_EXIT_FAIL" "the rendered seed did not pass validate.py; nothing was written"
fi

META_DATA="instance-id: happymining-seed-$HOSTNAME_ARG"

if [[ "$HM_DRY_RUN" == "1" ]]; then
    printf 'DRY-RUN would create directory (mode 0700): %s\n' "$OUT_ABS"
    printf 'DRY-RUN would write (mode 0600): %s/meta-data with content:\n%s\n' "$OUT_ABS" "$META_DATA"
    printf 'DRY-RUN would write (mode 0600): %s/user-data with content:\n' "$OUT_ABS"
    printf -- '----- begin user-data -----\n%s\n----- end user-data -----\n' "$RENDERED"
    hm_log "DRY RUN complete: nothing was written"
    exit 0
fi

if [[ ! -d "$OUT_ABS" ]]; then
    mkdir -m 0700 -- "$OUT_ABS"
fi
chmod 0700 -- "$OUT_ABS"
printf '%s\n' "$RENDERED" >"$OUT_ABS/user-data"
printf '%s\n' "$META_DATA" >"$OUT_ABS/meta-data"
chmod 0600 -- "$OUT_ABS/user-data" "$OUT_ABS/meta-data"

hm_log "wrote $OUT_ABS/user-data and $OUT_ABS/meta-data"
cat <<NEXT

Next steps:
  1. Put the seed on a volume labelled CIDATA (a small USB stick or a second
     virtual drive):
         os/autoinstall/make-seed-volume.sh --seed-dir $OUT_ABS --out /path/to/seed-$HOSTNAME_ARG.iso
  2. Boot the machine from the HappyMining OS installation medium with the seed
     volume attached and choose
         "Install HappyMining OS with a per-machine seed volume (CIDATA)".
  3. The installer asks "Continue with autoinstall? (yes|no)" before it erases
     the disk. Answer yes on the console.
  4. Keep this directory private and delete it when the machine is installed.
NEXT
