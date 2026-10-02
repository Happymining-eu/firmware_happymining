#!/usr/bin/env bash
#
# HappyMining OS — pack a rendered per-machine seed into a volume image
# labelled CIDATA (ISO 9660 with Joliet and Rock Ridge), the form in which
# cloud-init's NoCloud data source finds "user-data" and "meta-data" on an
# attached drive.
#
#   make-seed-volume.sh --seed-dir DIR --out FILE.iso [--dry-run]
#
# The result is a regular file. Writing it to a USB stick is a separate,
# manual step that this script deliberately does not perform.

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OS_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_DIR="$(cd -- "$OS_DIR/.." && pwd)"
HM_PROG="make-seed-volume.sh"
# shellcheck source=os/install/lib.sh
. "$OS_DIR/install/lib.sh"

usage() {
    cat <<'USAGE'
Usage: make-seed-volume.sh --seed-dir DIR --out FILE.iso [--dry-run]

  --seed-dir DIR   directory written by render-seed.sh (user-data, meta-data).
  --out FILE.iso   image file to create (mode 0600). Must not exist, and must
                   not be inside os/ or dist/.
  --dry-run        print the command that would be run; write nothing.

Needs one of: xorriso, genisoimage, cloud-localds. Exit code 77 when none is
installed.
USAGE
}

SEED_DIR=""
OUT=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --seed-dir) SEED_DIR="${2:-}"; shift 2 || hm_die "$HM_EXIT_USAGE" "--seed-dir needs a value" ;;
        --out) OUT="${2:-}"; shift 2 || hm_die "$HM_EXIT_USAGE" "--out needs a value" ;;
        --dry-run) HM_DRY_RUN=1; shift ;;
        -h | --help) usage; exit 0 ;;
        *) usage >&2; hm_die "$HM_EXIT_USAGE" "unknown argument: $1" ;;
    esac
done

[[ -n "$SEED_DIR" && -n "$OUT" ]] || { usage >&2; hm_die "$HM_EXIT_USAGE" "--seed-dir and --out are required"; }
[[ -f "$SEED_DIR/user-data" && -f "$SEED_DIR/meta-data" ]] ||
    hm_die "$HM_EXIT_USAGE" "$SEED_DIR does not contain user-data and meta-data"
out_parent="$(dirname -- "$OUT")"
[[ -d "$out_parent" ]] || hm_die "$HM_EXIT_USAGE" "the parent directory of --out does not exist: $out_parent"
OUT_ABS="$(cd -- "$out_parent" && pwd)/$(basename -- "$OUT")"
case "$OUT_ABS" in
    "$OS_DIR"/* | "$REPO_DIR/dist"/*)
        hm_die "$HM_EXIT_REFUSED" "--out is inside os/ or dist/: a per-machine seed must never sit next to the generic image"
        ;;
esac
[[ ! -e "$OUT_ABS" ]] || hm_die "$HM_EXIT_REFUSED" "$OUT_ABS already exists"

if hm_have xorriso; then
    cmd=(xorriso -as mkisofs -volid CIDATA -joliet -rock -output "$OUT_ABS" "$SEED_DIR/user-data" "$SEED_DIR/meta-data")
elif hm_have genisoimage; then
    cmd=(genisoimage -output "$OUT_ABS" -volid CIDATA -joliet -rock "$SEED_DIR/user-data" "$SEED_DIR/meta-data")
elif hm_have cloud-localds; then
    cmd=(cloud-localds "$OUT_ABS" "$SEED_DIR/user-data" "$SEED_DIR/meta-data")
elif [[ "$HM_DRY_RUN" == "1" ]]; then
    hm_warn "none of xorriso, genisoimage, cloud-localds is installed; showing the xorriso form"
    cmd=(xorriso -as mkisofs -volid CIDATA -joliet -rock -output "$OUT_ABS" "$SEED_DIR/user-data" "$SEED_DIR/meta-data")
else
    hm_err "prerequisite not available: one of xorriso, genisoimage or cloud-localds is needed"
    hm_err "skipped: prerequisite not available (exit $HM_EXIT_SKIP)"
    exit "$HM_EXIT_SKIP"
fi

hm_run "${cmd[@]}"
if [[ "$HM_DRY_RUN" != "1" ]]; then
    chmod 0600 -- "$OUT_ABS"
    hm_log "wrote $OUT_ABS (volume label CIDATA). Attach it to the machine together with the HappyMining OS installation medium."
fi
