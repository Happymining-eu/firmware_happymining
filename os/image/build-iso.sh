#!/usr/bin/env bash
#
# HappyMining OS — build the branded installation ISO.
#
# Method: xorriso repack of the OFFICIAL Ubuntu Server live ISO. The squashfs
# and every Ubuntu file stay byte-identical; the boot setup (El Torito BIOS +
# EFI, GPT/MBR system area) is carried over with "-boot_image any replay".
# Added or replaced:
#   /happymining/                 agent .deb, generic seed, banner, patch policy,
#                                 SHA256SUMS (+ SHA256SUMS.gpg)
#   /boot/grub/grub.cfg           two extra menu entries (never with the
#                                 keyword that pre-confirms an installation)
#   /md5sum.txt                   entries for the files above
#
# Trust: the base ISO is accepted only if it matches Ubuntu's SHA256SUMS, and
# SHA256SUMS only if its detached signature is from the pinned Ubuntu CD image
# signing key (os/versions.env). No ISO hash is stored in this repository.
#
# This script needs a normal build host (xorriso, gpgv, network or a local
# copy of the ISO). It exits 77 when a prerequisite is not available.

set -euo pipefail
umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OS_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_DIR="$(cd -- "$OS_DIR/.." && pwd)"
HM_PROG="build-iso.sh"
# shellcheck source=os/install/lib.sh
. "$OS_DIR/install/lib.sh"
hm_load_versions

usage() {
    cat <<USAGE
Usage: build-iso.sh [options]

Base image (verified against Ubuntu's signed SHA256SUMS in every case):
  --base-iso FILE          use this copy of ${UBUNTU_ISO_FILENAME}
  --download               download it from ${UBUNTU_RELEASE_URL}/
                           into the cache directory when it is not there yet
  --cache-dir DIR          download cache (default: <dist>/cache)
  --ubuntu-sums-dir DIR    take SHA256SUMS and SHA256SUMS.gpg from DIR instead
                           of downloading them (offline builds; still verified)
  --ubuntu-keyring FILE    keyring holding the Ubuntu CD image signing key
                           (default: ${UBUNTU_KEYRING_DEFAULT}).
                           The signer must be ${UBUNTU_CDIMAGE_KEY_FPR}.

Payload:
  --agent-deb FILE         agent package (default: <dist>/${AGENT_DEB_FILENAME})
  --signing-key-home DIR   GnuPG home with the release signing key; signs the
                           SHA256SUMS placed on the medium
  --signing-key FPR        which secret key to use when the home holds several
  --allow-unsigned-dev     build without that signature (development only)

Output:
  --dist DIR               output directory (default: <repo>/dist)
  --out FILE               ISO file (default:
                           <dist>/happymining-os-${AGENT_VERSION}-ubuntu-${UBUNTU_POINT_RELEASE}-${UBUNTU_ARCH}.iso)
  --stage-only DIR         only assemble and check the /happymining payload tree
                           in DIR (must not exist); no base ISO or xorriso needed
  --dry-run                print every step and command; build nothing
  -h, --help               this text

Exit codes: 0 built, 1 failure, 2 usage, 3 verification failed,
77 skipped: a prerequisite (tool, base ISO, agent package, signing key) is not available.
USAGE
}

BASE_ISO=""
DOWNLOAD=0
CACHE_DIR=""
SUMS_DIR=""
UBUNTU_KEYRING="$UBUNTU_KEYRING_DEFAULT"
AGENT_DEB=""
SIGN_HOME=""
SIGN_KEY=""
ALLOW_UNSIGNED=0
DIST_DIR="$REPO_DIR/dist"
OUT=""
STAGE_ONLY=""

need_value() { [[ $# -ge 2 ]] || hm_die "$HM_EXIT_USAGE" "$1 needs a value"; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        --base-iso) need_value "$@"; BASE_ISO="$2"; shift 2 ;;
        --download) DOWNLOAD=1; shift ;;
        --cache-dir) need_value "$@"; CACHE_DIR="$2"; shift 2 ;;
        --ubuntu-sums-dir) need_value "$@"; SUMS_DIR="$2"; shift 2 ;;
        --ubuntu-keyring) need_value "$@"; UBUNTU_KEYRING="$2"; shift 2 ;;
        --agent-deb) need_value "$@"; AGENT_DEB="$2"; shift 2 ;;
        --signing-key-home) need_value "$@"; SIGN_HOME="$2"; shift 2 ;;
        --signing-key) need_value "$@"; SIGN_KEY="$2"; shift 2 ;;
        --allow-unsigned-dev) ALLOW_UNSIGNED=1; shift ;;
        --dist) need_value "$@"; DIST_DIR="$2"; shift 2 ;;
        --out) need_value "$@"; OUT="$2"; shift 2 ;;
        --stage-only) need_value "$@"; STAGE_ONLY="$2"; shift 2 ;;
        --dry-run) HM_DRY_RUN=1; shift ;;
        -h | --help) usage; exit 0 ;;
        *) usage >&2; hm_die "$HM_EXIT_USAGE" "unknown argument: $1" ;;
    esac
done

[[ -n "$CACHE_DIR" ]] || CACHE_DIR="$DIST_DIR/cache"
[[ -n "$AGENT_DEB" ]] || AGENT_DEB="$DIST_DIR/$AGENT_DEB_FILENAME"
[[ -n "$OUT" ]] || OUT="$DIST_DIR/happymining-os-${AGENT_VERSION}-ubuntu-${UBUNTU_POINT_RELEASE}-${UBUNTU_ARCH}.iso"
if [[ -n "$SIGN_HOME" && "$ALLOW_UNSIGNED" == "1" ]]; then
    hm_die "$HM_EXIT_USAGE" "--signing-key-home and --allow-unsigned-dev cannot be combined"
fi

GENERIC_SEED="$OS_DIR/autoinstall/user-data.generic.yaml"
GENERIC_META="$OS_DIR/autoinstall/meta-data.generic"
GRUB_ENTRIES="$SCRIPT_DIR/branding/grub-entries.cfg.in"
ISSUE_FILE="$SCRIPT_DIR/branding/issue"
POLICY_DIR="$OS_DIR/maintenance"

# ---------------------------------------------------------------------------
# Payload staging (shared by the real build and --stage-only)
# ---------------------------------------------------------------------------
stage_payload() {
    # stage_payload DIR — DIR becomes the /happymining directory of the medium.
    local dir="$1" f
    mkdir -p -- "$dir/seed" "$dir/maintenance"
    cp -- "$AGENT_DEB" "$dir/$AGENT_DEB_FILENAME"
    cp -- "$GENERIC_SEED" "$dir/seed/user-data"
    cp -- "$GENERIC_META" "$dir/seed/meta-data"
    cp -- "$ISSUE_FILE" "$dir/issue"
    cp -- "$POLICY_DIR/52happymining-unattended-upgrades" "$dir/maintenance/52happymining-unattended-upgrades"
    cp -- "$POLICY_DIR/needrestart-happymining.conf" "$dir/maintenance/needrestart-happymining.conf"
    cat >"$dir/README.txt" <<README
HappyMining OS payload ${AGENT_VERSION} for Ubuntu Server ${UBUNTU_POINT_RELEASE} (${UBUNTU_ARCH}).

  ${AGENT_DEB_FILENAME}   HappyMining agent package
  seed/                   generic installer seed (asks for disk and account)
  issue                   console banner
  maintenance/            scheduled-patching policy files
  SHA256SUMS[.gpg]        checksums of this directory (and their signature)

This directory contains no password, no SSH key, no pairing code and no API or
Vast credential. Everything else on this medium is the unmodified Ubuntu
Server installer.
README
    find "$dir" -type d -exec chmod 0755 {} +
    find "$dir" -type f -exec chmod 0644 {} +
    local sums_tmp
    sums_tmp="$(mktemp "${dir%/}.sums.XXXXXXXX")"
    (
        cd -- "$dir"
        find . -type f -printf '%P\n' | LC_ALL=C sort |
            while IFS= read -r f; do sha256sum -- "$f"; done
    ) >"$sums_tmp"
    mv -- "$sums_tmp" "$dir/SHA256SUMS"
    chmod 0644 -- "$dir/SHA256SUMS"
    if [[ -n "$SIGN_HOME" ]]; then
        hm_gpg_sign_detached "$SIGN_HOME" "$dir/SHA256SUMS" "$dir/SHA256SUMS.gpg" "$SIGN_KEY" ||
            hm_die "$HM_EXIT_FAIL" "could not sign the payload checksums"
        chmod 0644 -- "$dir/SHA256SUMS.gpg"
        hm_log "payload SHA256SUMS signed by $HM_SIGNER_FPR"
    else
        hm_banner "UNSIGNED DEVELOPMENT BUILD: the payload SHA256SUMS on the medium is not signed." \
            "Do not distribute this image."
    fi
}

check_agent_deb() {
    local name version arch
    if [[ ! -f "$AGENT_DEB" ]]; then
        hm_err "prerequisite not available: agent package $AGENT_DEB (build it with: make build-agent)"
        hm_err "skipped: prerequisite not available (exit $HM_EXIT_SKIP)"
        exit "$HM_EXIT_SKIP"
    fi
    if hm_have dpkg-deb; then
        name="$(dpkg-deb -f "$AGENT_DEB" Package 2>/dev/null || true)"
        version="$(dpkg-deb -f "$AGENT_DEB" Version 2>/dev/null || true)"
        arch="$(dpkg-deb -f "$AGENT_DEB" Architecture 2>/dev/null || true)"
        [[ "$name" == "$AGENT_PACKAGE" && "$version" == "$AGENT_VERSION" && "$arch" == "$AGENT_ARCH" ]] ||
            hm_die "$HM_EXIT_FAIL" "$AGENT_DEB is '$name $version $arch'; versions.env expects '$AGENT_PACKAGE $AGENT_VERSION $AGENT_ARCH'"
    fi
}

scan_agent_package_contents() {
    # scan_agent_package_contents SCRATCH_DIR — the .deb is a compressed
    # archive, so scanning the staged tree does not look inside it. Unpack it
    # (files and maintainer scripts) and scan that too.
    local dir="$1"
    if ! hm_have dpkg-deb; then
        hm_warn "dpkg-deb is not available: the CONTENTS of the agent package were not scanned for secrets"
        return 0
    fi
    mkdir -p -- "$dir"
    dpkg-deb -x "$AGENT_DEB" "$dir/data"
    dpkg-deb -e "$AGENT_DEB" "$dir/control"
    python3 "$SCRIPT_DIR/secret_scan.py" --quiet "$dir" ||
        hm_die "$HM_EXIT_FAIL" "secrets found inside the agent package $AGENT_DEB; refusing"
    rm -rf -- "$dir"
    hm_log "agent package contents scanned: no secrets found"
}

check_signing_choice() {
    if [[ -z "$SIGN_HOME" && "$ALLOW_UNSIGNED" != "1" ]]; then
        hm_err "prerequisite not available: no release signing key (--signing-key-home DIR)"
        hm_err "for a development build create one with os/release/gen-dev-signing-key.sh, or pass --allow-unsigned-dev"
        hm_err "skipped: prerequisite not available (exit $HM_EXIT_SKIP)"
        exit "$HM_EXIT_SKIP"
    fi
    if [[ -n "$SIGN_HOME" && ! -d "$SIGN_HOME" ]]; then
        hm_die "$HM_EXIT_USAGE" "signing key home not found: $SIGN_HOME"
    fi
}

# ---------------------------------------------------------------------------
# Dry run: describe the build, run nothing.
# ---------------------------------------------------------------------------
if [[ "$HM_DRY_RUN" == "1" ]]; then
    hm_log "DRY RUN: nothing is downloaded, built or written"
    for tool in xorriso gpgv sha256sum python3 curl; do
        hm_have "$tool" || hm_warn "prerequisite not available on this host: $tool (a real build would exit $HM_EXIT_SKIP)"
    done
    [[ -f "$AGENT_DEB" ]] || hm_warn "agent package not present: $AGENT_DEB (a real build would exit $HM_EXIT_SKIP)"
    W='<work>'
    if [[ -n "$STAGE_ONLY" ]]; then
        printf 'DRY-RUN would stage the payload tree in %s and scan it for secrets\n' "$STAGE_ONLY"
        exit 0
    fi
    cat <<PLAN
Steps of a real build:
 1. Ubuntu checksums: $(if [[ -n "$SUMS_DIR" ]]; then echo "use $SUMS_DIR/SHA256SUMS and SHA256SUMS.gpg"; else echo "download"; fi)
PLAN
    if [[ -z "$SUMS_DIR" ]]; then
        printf 'DRY-RUN would run: %s\n' "$(hm_quote_cmd curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 --output "$CACHE_DIR/ubuntu-$UBUNTU_POINT_RELEASE/SHA256SUMS" "$UBUNTU_SUMS_URL")"
        printf 'DRY-RUN would run: %s\n' "$(hm_quote_cmd curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 --output "$CACHE_DIR/ubuntu-$UBUNTU_POINT_RELEASE/SHA256SUMS.gpg" "$UBUNTU_SUMS_SIG_URL")"
    fi
    cat <<PLAN
 2. Verify the signature on SHA256SUMS with gpgv and keyring $UBUNTU_KEYRING;
    the signer must be $UBUNTU_CDIMAGE_KEY_FPR.
 3. Base ISO: $(if [[ -n "$BASE_ISO" ]]; then echo "$BASE_ISO"; else echo "$CACHE_DIR/$UBUNTU_ISO_FILENAME$([[ "$DOWNLOAD" == "1" ]] && echo " (downloaded from $UBUNTU_ISO_URL if absent)")"; fi)
    Verify its sha256 against the entry '$UBUNTU_ISO_FILENAME' of the signed SHA256SUMS.
 4. Validate the autoinstall files: python3 $OS_DIR/autoinstall/validate.py
 5. Stage /happymining (agent package, generic seed, banner, patch policy,
    SHA256SUMS$([[ -n "$SIGN_HOME" ]] && echo ", SHA256SUMS.gpg signed with the key in $SIGN_HOME" || echo "; UNSIGNED development build")).
 6. Take grub.cfg and md5sum.txt out of the base ISO and add the menu entries:
PLAN
    printf 'DRY-RUN would run: %s\n' "$(hm_quote_cmd xorriso -osirrox on -indev "${BASE_ISO:-$CACHE_DIR/$UBUNTU_ISO_FILENAME}" -extract /boot/grub/grub.cfg "$W/orig/grub.cfg" -extract /md5sum.txt "$W/orig/md5sum.txt")"
    printf 'DRY-RUN would run: %s\n' "$(hm_quote_cmd python3 "$SCRIPT_DIR/patch_grub.py" grub --in "$W/orig/grub.cfg" --entries "$GRUB_ENTRIES" --out "$W/new/grub.cfg")"
    printf 'DRY-RUN would run: %s\n' "$(hm_quote_cmd python3 "$OS_DIR/autoinstall/validate.py" --grub-cfg "$W/new/grub.cfg")"
    cat <<PLAN
 7. Scan the staged tree, and the unpacked contents of the agent package, for secrets:
    python3 $SCRIPT_DIR/secret_scan.py $W/tree
 8. Repack:
PLAN
    printf 'DRY-RUN would run: %s\n' "$(hm_quote_cmd xorriso -indev "${BASE_ISO:-$CACHE_DIR/$UBUNTU_ISO_FILENAME}" -outdev "$OUT.partial" -boot_image any replay -map "$W/tree/happymining" /happymining -map "$W/new/grub.cfg" /boot/grub/grub.cfg -map "$W/new/md5sum.txt" /md5sum.txt -chown_r 0 /happymining -- -chgrp_r 0 /happymining --)"
    cat <<PLAN
 9. Read the result back: compare /happymining and grub.cfg with what was staged,
    scan them for secrets again, check that no kernel line pre-confirms an
    installation, compare the El Torito boot entries with the base ISO.
10. Move $OUT.partial to $OUT and write $OUT.buildinfo
Afterwards: os/release/make-checksums.sh signs dist/SHA256SUMS over all artifacts.
PLAN
    exit 0
fi

# ---------------------------------------------------------------------------
# --stage-only: payload tree for inspection and tests
# ---------------------------------------------------------------------------
if [[ -n "$STAGE_ONLY" ]]; then
    hm_need_tools sha256sum python3 find
    [[ ! -e "$STAGE_ONLY" ]] || hm_die "$HM_EXIT_REFUSED" "--stage-only target already exists: $STAGE_ONLY"
    check_agent_deb
    check_signing_choice
    python3 "$OS_DIR/autoinstall/validate.py" || hm_die "$HM_EXIT_FAIL" "the autoinstall files are not valid"
    SCAN_TMP="$(mktemp -d "${TMPDIR:-/tmp}/hm-stage-scan.XXXXXXXX")"
    # shellcheck disable=SC2329  # invoked through the EXIT trap
    cleanup_scan() { rm -rf -- "$SCAN_TMP"; }
    trap cleanup_scan EXIT
    scan_agent_package_contents "$SCAN_TMP/agent-package"
    mkdir -p -- "$STAGE_ONLY"
    stage_payload "$STAGE_ONLY/happymining"
    python3 "$SCRIPT_DIR/secret_scan.py" "$STAGE_ONLY" ||
        hm_die "$HM_EXIT_FAIL" "secrets found in the staged payload"
    hm_log "payload staged in $STAGE_ONLY/happymining (no ISO was built)"
    exit 0
fi

# ---------------------------------------------------------------------------
# Real build
# ---------------------------------------------------------------------------
hm_need_tools xorriso gpgv sha256sum python3 find diff awk
check_agent_deb
check_signing_choice
if [[ ! -r "$UBUNTU_KEYRING" ]]; then
    hm_err "prerequisite not available: Ubuntu keyring $UBUNTU_KEYRING (package ubuntu-keyring, or --ubuntu-keyring FILE)"
    hm_err "skipped: prerequisite not available (exit $HM_EXIT_SKIP)"
    exit "$HM_EXIT_SKIP"
fi

mkdir -p -- "$DIST_DIR" "$CACHE_DIR"
WORK="$(mktemp -d "$DIST_DIR/.work-iso.XXXXXXXX")"
cleanup() {
    rm -rf -- "$WORK"
    rm -f -- "$OUT.partial"
}
trap cleanup EXIT

fetch() {
    # fetch URL DEST — https only, fail on HTTP errors.
    hm_need_tools curl
    hm_log "downloading $1"
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 \
        --output "$2.part" "$1" || {
        rm -f -- "$2.part"
        hm_die "$HM_EXIT_FAIL" "download failed: $1"
    }
    mv -- "$2.part" "$2"
}

# 1-2. Ubuntu's checksum list and its signature.
if [[ -n "$SUMS_DIR" ]]; then
    SUMS="$SUMS_DIR/SHA256SUMS"
    SUMS_SIG="$SUMS_DIR/SHA256SUMS.gpg"
    [[ -f "$SUMS" && -f "$SUMS_SIG" ]] || hm_die "$HM_EXIT_USAGE" "$SUMS_DIR must contain SHA256SUMS and SHA256SUMS.gpg"
else
    mkdir -p -- "$CACHE_DIR/ubuntu-$UBUNTU_POINT_RELEASE"
    SUMS="$CACHE_DIR/ubuntu-$UBUNTU_POINT_RELEASE/SHA256SUMS"
    SUMS_SIG="$CACHE_DIR/ubuntu-$UBUNTU_POINT_RELEASE/SHA256SUMS.gpg"
    fetch "$UBUNTU_SUMS_URL" "$SUMS"
    fetch "$UBUNTU_SUMS_SIG_URL" "$SUMS_SIG"
fi
if ! hm_verify_detached "$UBUNTU_KEYRING" "$SUMS_SIG" "$SUMS" "$UBUNTU_CDIMAGE_KEY_FPR"; then
    hm_die "$HM_EXIT_VERIFY" "Ubuntu's SHA256SUMS is not signed by the pinned CD image key $UBUNTU_CDIMAGE_KEY_FPR; refusing"
fi
hm_log "Ubuntu SHA256SUMS: good signature from $HM_SIG_FPR"
if ! hm_sums_lookup "$SUMS" "$UBUNTU_ISO_FILENAME" >/dev/null; then
    hm_err "the signed SHA256SUMS has no entry for $UBUNTU_ISO_FILENAME."
    hm_err "Canonical has probably published a newer point release in $UBUNTU_RELEASE_URL/ ."
    hm_die "$HM_EXIT_VERIFY" "update UBUNTU_POINT_RELEASE in os/versions.env deliberately, or pass --ubuntu-sums-dir with the checksum files of $UBUNTU_POINT_RELEASE"
fi

# 3. The base ISO.
if [[ -z "$BASE_ISO" ]]; then
    BASE_ISO="$CACHE_DIR/$UBUNTU_ISO_FILENAME"
    if [[ ! -f "$BASE_ISO" ]]; then
        if [[ "$DOWNLOAD" == "1" ]]; then
            fetch "$UBUNTU_ISO_URL" "$BASE_ISO"
        else
            hm_err "prerequisite not available: base ISO $BASE_ISO"
            hm_err "pass --base-iso FILE, or --download to fetch $UBUNTU_ISO_URL"
            hm_err "skipped: prerequisite not available (exit $HM_EXIT_SKIP)"
            exit "$HM_EXIT_SKIP"
        fi
    fi
fi
[[ -f "$BASE_ISO" ]] || hm_die "$HM_EXIT_USAGE" "base ISO not found: $BASE_ISO"
hm_log "checking the base ISO against the signed SHA256SUMS (this reads the whole file)"
if ! hm_verify_sums_entry "$SUMS" "$BASE_ISO" "$UBUNTU_ISO_FILENAME"; then
    hm_die "$HM_EXIT_VERIFY" "the base ISO is not the official $UBUNTU_ISO_FILENAME; refusing"
fi
BASE_SHA256="$(hm_sums_lookup "$SUMS" "$UBUNTU_ISO_FILENAME")"
hm_log "base ISO verified: $UBUNTU_ISO_FILENAME sha256 $BASE_SHA256"

# 4. Autoinstall files.
python3 "$OS_DIR/autoinstall/validate.py" || hm_die "$HM_EXIT_FAIL" "the autoinstall files are not valid"

# 5. Payload.
mkdir -p -- "$WORK/tree" "$WORK/orig" "$WORK/new" "$WORK/readback"
stage_payload "$WORK/tree/happymining"

# 6. GRUB configuration and md5sum.txt.
xorriso -osirrox on -indev "$BASE_ISO" -extract /boot/grub/grub.cfg "$WORK/orig/grub.cfg" >"$WORK/xorriso-extract.log" 2>&1 ||
    hm_die "$HM_EXIT_FAIL" "could not read /boot/grub/grub.cfg from the base ISO (see $WORK/xorriso-extract.log)"
chmod u+w -- "$WORK/orig/grub.cfg"
python3 "$SCRIPT_DIR/patch_grub.py" grub --in "$WORK/orig/grub.cfg" --entries "$GRUB_ENTRIES" --out "$WORK/new/grub.cfg" ||
    hm_die "$HM_EXIT_FAIL" "could not add the HappyMining entries to grub.cfg"
python3 "$OS_DIR/autoinstall/validate.py" --grub-cfg "$WORK/new/grub.cfg" ||
    hm_die "$HM_EXIT_FAIL" "the new grub.cfg failed validation"

map_args=(-map "$WORK/tree/happymining" /happymining -map "$WORK/new/grub.cfg" /boot/grub/grub.cfg)
mkdir -p -- "$WORK/tree/boot/grub"
cp -- "$WORK/new/grub.cfg" "$WORK/tree/boot/grub/grub.cfg"
if xorriso -osirrox on -indev "$BASE_ISO" -extract /md5sum.txt "$WORK/orig/md5sum.txt" >>"$WORK/xorriso-extract.log" 2>&1; then
    chmod u+w -- "$WORK/orig/md5sum.txt"
    mapfile -t payload_files < <(cd -- "$WORK/tree" && find happymining boot -type f | LC_ALL=C sort)
    python3 "$SCRIPT_DIR/patch_grub.py" md5 --in "$WORK/orig/md5sum.txt" --root "$WORK/tree" --out "$WORK/new/md5sum.txt" "${payload_files[@]}" ||
        hm_die "$HM_EXIT_FAIL" "could not update md5sum.txt"
    map_args+=(-map "$WORK/new/md5sum.txt" /md5sum.txt)
else
    hm_warn "the base ISO has no /md5sum.txt; the live system's integrity self-check list is not updated"
fi

# 7. Nothing secret may go onto the medium.
python3 "$SCRIPT_DIR/secret_scan.py" "$WORK/tree" || hm_die "$HM_EXIT_FAIL" "secrets found in the files staged for the ISO; refusing to build"
scan_agent_package_contents "$WORK/agent-package"

# 8. Repack.
mkdir -p -- "$(dirname -- "$OUT")"
rm -f -- "$OUT.partial"
hm_log "repacking with xorriso (boot setup replayed from the base ISO)"
xorriso -indev "$BASE_ISO" -outdev "$OUT.partial" \
    -boot_image any replay \
    "${map_args[@]}" \
    -chown_r 0 /happymining -- \
    -chgrp_r 0 /happymining -- \
    >"$WORK/xorriso-build.log" 2>&1 || {
    tail -n 40 -- "$WORK/xorriso-build.log" >&2
    hm_die "$HM_EXIT_FAIL" "xorriso failed"
}

# 9. Read the result back and check it.
xorriso -osirrox on -indev "$OUT.partial" \
    -extract /happymining "$WORK/readback/happymining" \
    -extract /boot/grub/grub.cfg "$WORK/readback/grub.cfg" >"$WORK/xorriso-readback.log" 2>&1 ||
    hm_die "$HM_EXIT_FAIL" "could not read the new ISO back"
chmod -R u+w -- "$WORK/readback"
diff -r -- "$WORK/tree/happymining" "$WORK/readback/happymining" >/dev/null ||
    hm_die "$HM_EXIT_FAIL" "/happymining in the new ISO differs from what was staged"
diff -- "$WORK/new/grub.cfg" "$WORK/readback/grub.cfg" >/dev/null ||
    hm_die "$HM_EXIT_FAIL" "grub.cfg in the new ISO differs from what was staged"
python3 "$SCRIPT_DIR/secret_scan.py" "$WORK/readback" || hm_die "$HM_EXIT_FAIL" "secrets found in the built ISO; refusing"
python3 "$OS_DIR/autoinstall/validate.py" --grub-cfg "$WORK/readback/grub.cfg" ||
    hm_die "$HM_EXIT_FAIL" "the built ISO's grub.cfg failed validation"
python3 "$OS_DIR/autoinstall/validate.py" --kind generic --file "$WORK/readback/happymining/seed/user-data" ||
    hm_die "$HM_EXIT_FAIL" "the seed inside the built ISO failed validation"
# No configuration may sit where the installer would pick it up on its own
# (root of the medium). The test is "could the file be extracted", which does
# not depend on xorriso's exit code conventions.
for stray in autoinstall.yaml user-data meta-data; do
    xorriso -osirrox on -indev "$OUT.partial" -extract "/$stray" "$WORK/readback/stray-$stray" >/dev/null 2>&1 || true
    if [[ -e "$WORK/readback/stray-$stray" ]]; then
        hm_die "$HM_EXIT_FAIL" "unexpected /$stray in the root of the ISO"
    fi
done
base_boot="$(xorriso -indev "$BASE_ISO" -report_el_torito plain 2>/dev/null | grep -c '^El Torito boot img' || true)"
new_boot="$(xorriso -indev "$OUT.partial" -report_el_torito plain 2>/dev/null | grep -c '^El Torito boot img' || true)"
if [[ "$base_boot" == "0" || "$base_boot" != "$new_boot" ]]; then
    hm_die "$HM_EXIT_FAIL" "boot setup was not carried over (El Torito boot images: base $base_boot, new $new_boot)"
fi
hm_log "boot setup carried over: $new_boot El Torito boot image(s), as in the base ISO"

# 10. Publish.
mv -- "$OUT.partial" "$OUT"
{
    printf 'artifact: %s\n' "$(basename -- "$OUT")"
    printf 'built-utc: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'base-iso: %s\n' "$UBUNTU_ISO_FILENAME"
    printf 'base-iso-sha256: %s\n' "$BASE_SHA256"
    printf 'base-iso-sums-signer: %s\n' "$UBUNTU_CDIMAGE_KEY_FPR"
    printf 'agent-package: %s\n' "$AGENT_DEB_FILENAME"
    printf 'agent-package-sha256: %s\n' "$(hm_sha256 "$AGENT_DEB")"
    printf 'payload-signed-by: %s\n' "${HM_SIGNER_FPR:-UNSIGNED-DEVELOPMENT-BUILD}"
    printf 'xorriso: %s\n' "$(xorriso -version 2>/dev/null | head -n 1)"
} >"$OUT.buildinfo"
hm_log "built $OUT"
hm_log "next: os/release/make-checksums.sh --signing-key-home DIR   (signs dist/SHA256SUMS over all artifacts)"
hm_log "then: os/smoke/qemu-smoke.sh   (VM smoke test)"
