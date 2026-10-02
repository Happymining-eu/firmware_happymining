#!/usr/bin/env bash
#
# HappyMining OS — single entry point for "make build-installer".
#
#   1. validates the autoinstall files (always);
#   2. builds dist/happymining-seed-generic.tar.gz (always possible);
#   3. builds dist/happymining-install-scripts-<version>.tar.gz (always possible);
#   4. builds the installation ISO through build-iso.sh WHEN xorriso, a base
#      ISO, the agent package and a signing choice are available.
#
# When the ISO cannot be built, the script says exactly which artifacts were
# and were not produced and exits 77 — or 0 only when --allow-partial was
# given. It never reports an ISO that was not built.

set -euo pipefail
umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OS_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_DIR="$(cd -- "$OS_DIR/.." && pwd)"
HM_PROG="build-installer.sh"
# shellcheck source=os/install/lib.sh
. "$OS_DIR/install/lib.sh"
hm_load_versions

usage() {
    cat <<USAGE
Usage: build-installer.sh [options]

  --allow-partial          exit 0 even when the ISO could not be built
                           (the seed and install-scripts bundles are still made)
  --base-iso FILE          verified copy source of ${UBUNTU_ISO_FILENAME}
  --download               allow build-iso.sh to download the base ISO
  --ubuntu-sums-dir DIR    passed to build-iso.sh
  --ubuntu-keyring FILE    passed to build-iso.sh
  --agent-deb FILE         agent package (default: <dist>/${AGENT_DEB_FILENAME})
  --signing-key-home DIR   release signing key home, passed to build-iso.sh
  --allow-unsigned-dev     development build without a signed payload
  --dist DIR               output directory (default: <repo>/dist)
  --dry-run                show what would be done; write nothing
  -h, --help               this text

Exit codes: 0 everything requested was built (or partial with --allow-partial),
1 failure, 2 usage, 3 verification failed, 77 ISO skipped: prerequisite not available.
USAGE
}

ALLOW_PARTIAL=0
BASE_ISO=""
DOWNLOAD=0
SUMS_DIR=""
UBUNTU_KEYRING=""
AGENT_DEB=""
SIGN_HOME=""
ALLOW_UNSIGNED=0
DIST_DIR="$REPO_DIR/dist"

need_value() { [[ $# -ge 2 ]] || hm_die "$HM_EXIT_USAGE" "$1 needs a value"; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        --allow-partial) ALLOW_PARTIAL=1; shift ;;
        --base-iso) need_value "$@"; BASE_ISO="$2"; shift 2 ;;
        --download) DOWNLOAD=1; shift ;;
        --ubuntu-sums-dir) need_value "$@"; SUMS_DIR="$2"; shift 2 ;;
        --ubuntu-keyring) need_value "$@"; UBUNTU_KEYRING="$2"; shift 2 ;;
        --agent-deb) need_value "$@"; AGENT_DEB="$2"; shift 2 ;;
        --signing-key-home) need_value "$@"; SIGN_HOME="$2"; shift 2 ;;
        --allow-unsigned-dev) ALLOW_UNSIGNED=1; shift ;;
        --dist) need_value "$@"; DIST_DIR="$2"; shift 2 ;;
        --dry-run) HM_DRY_RUN=1; shift ;;
        -h | --help) usage; exit 0 ;;
        *) usage >&2; hm_die "$HM_EXIT_USAGE" "unknown argument: $1" ;;
    esac
done
[[ -n "$AGENT_DEB" ]] || AGENT_DEB="$DIST_DIR/$AGENT_DEB_FILENAME"

SEED_BUNDLE="$DIST_DIR/happymining-seed-generic.tar.gz"
SCRIPTS_BUNDLE="$DIST_DIR/happymining-install-scripts-${AGENT_VERSION}.tar.gz"
ISO_OUT="$DIST_DIR/happymining-os-${AGENT_VERSION}-ubuntu-${UBUNTU_POINT_RELEASE}-${UBUNTU_ARCH}.iso"

produced=()
not_produced=()

hm_need_tools python3 tar gzip sha256sum find

# ----- 1. validation ---------------------------------------------------------------
hm_log "validating the autoinstall files"
python3 "$OS_DIR/autoinstall/validate.py" || hm_die "$HM_EXIT_FAIL" "the autoinstall files are not valid; nothing was built"

if [[ "$HM_DRY_RUN" == "1" ]]; then
    hm_log "DRY RUN: nothing is written"
    printf 'DRY-RUN would write: %s (user-data, meta-data, README.txt of the generic seed)\n' "$SEED_BUNDLE"
    printf 'DRY-RUN would write: %s (install.sh, upgrade.sh, uninstall.sh, lib.sh, forbidden-commands.txt, nvidia-driver-plan.sh, sanitize-clone.sh, patch policy, versions.env)\n' "$SCRIPTS_BUNDLE"
fi

pack() {
    # pack STAGING_PARENT TOP_DIR OUTPUT — reproducible tar.gz of TOP_DIR.
    tar --sort=name --mtime="@${SOURCE_DATE_EPOCH:-0}" --owner=0 --group=0 --numeric-owner \
        -C "$1" -cf - "$2" | gzip -n -9 >"$3.partial"
    mv -- "$3.partial" "$3"
}

WORK=""
# shellcheck disable=SC2329  # invoked through the EXIT trap
cleanup() { [[ -z "$WORK" ]] || rm -rf -- "$WORK"; }
trap cleanup EXIT

if [[ "$HM_DRY_RUN" != "1" ]]; then
    mkdir -p -- "$DIST_DIR"
    WORK="$(mktemp -d "$DIST_DIR/.work-installer.XXXXXXXX")"

    # ----- 2. generic seed bundle ---------------------------------------------------
    seed_top="happymining-seed-generic"
    mkdir -p -- "$WORK/seed/$seed_top"
    cp -- "$OS_DIR/autoinstall/user-data.generic.yaml" "$WORK/seed/$seed_top/user-data"
    cp -- "$OS_DIR/autoinstall/meta-data.generic" "$WORK/seed/$seed_top/meta-data"
    cat >"$WORK/seed/$seed_top/README.txt" <<README
HappyMining OS generic installer seed (agent ${AGENT_VERSION}, Ubuntu Server ${UBUNTU_POINT_RELEASE}).

user-data and meta-data form a cloud-init NoCloud seed for the Ubuntu Server
installer. The seed makes the installer ask for the disk and for the account
(interactive sections) and adds the HappyMining agent from /cdrom/happymining
at the end of the installation. It contains no password, no SSH key, no pairing
code and no credential. It selects no disk.

It is the same seed that build-iso.sh places at /happymining/seed/ on the
HappyMining OS installation medium; on its own it expects that medium.
README
    find "$WORK/seed" -type d -exec chmod 0755 {} +
    find "$WORK/seed" -type f -exec chmod 0644 {} +
    python3 "$SCRIPT_DIR/secret_scan.py" --quiet "$WORK/seed" ||
        hm_die "$HM_EXIT_FAIL" "secrets found in the generic seed; refusing to package it"
    python3 "$OS_DIR/autoinstall/validate.py" --kind generic --file "$WORK/seed/$seed_top/user-data" >/dev/null ||
        hm_die "$HM_EXIT_FAIL" "the staged generic seed is not valid"
    pack "$WORK/seed" "$seed_top" "$SEED_BUNDLE"
    produced+=("$SEED_BUNDLE")
    hm_log "built $SEED_BUNDLE"

    # ----- 3. install scripts bundle ------------------------------------------------
    scripts_top="happymining-install-scripts-${AGENT_VERSION}"
    mkdir -p -- "$WORK/scripts/$scripts_top"
    for f in install.sh upgrade.sh uninstall.sh lib.sh forbidden-commands.txt nvidia-driver-plan.sh; do
        cp -- "$OS_DIR/install/$f" "$WORK/scripts/$scripts_top/$f"
    done
    cp -- "$OS_DIR/versions.env" "$WORK/scripts/$scripts_top/versions.env"
    cp -- "$OS_DIR/firstboot/sanitize-clone.sh" "$OS_DIR/firstboot/happymining-regen-ssh-hostkeys.service" "$WORK/scripts/$scripts_top/"
    cp -- "$OS_DIR/maintenance/apply-patch-policy.sh" "$OS_DIR/maintenance/52happymining-unattended-upgrades" \
        "$OS_DIR/maintenance/needrestart-happymining.conf" "$WORK/scripts/$scripts_top/"
    find "$WORK/scripts" -type d -exec chmod 0755 {} +
    find "$WORK/scripts" -type f -exec chmod 0644 {} +
    chmod 0755 -- "$WORK/scripts/$scripts_top"/*.sh
    python3 "$SCRIPT_DIR/secret_scan.py" --quiet "$WORK/scripts" ||
        hm_die "$HM_EXIT_FAIL" "secrets found in the install scripts; refusing to package them"
    pack "$WORK/scripts" "$scripts_top" "$SCRIPTS_BUNDLE"
    produced+=("$SCRIPTS_BUNDLE")
    hm_log "built $SCRIPTS_BUNDLE"
fi

# ----- 4. ISO, when possible ------------------------------------------------------------
iso_reasons=()
hm_have xorriso || iso_reasons+=("xorriso is not installed")
hm_have gpgv || iso_reasons+=("gpgv is not installed")
if [[ -n "$BASE_ISO" ]]; then
    [[ -f "$BASE_ISO" ]] || iso_reasons+=("base ISO not found: $BASE_ISO")
elif [[ ! -f "$DIST_DIR/cache/$UBUNTU_ISO_FILENAME" && "$DOWNLOAD" != "1" ]]; then
    iso_reasons+=("no base ISO: pass --base-iso FILE or --download ($UBUNTU_ISO_FILENAME)")
fi
[[ -f "$AGENT_DEB" ]] || iso_reasons+=("agent package not found: $AGENT_DEB (make build-agent)")
if [[ -z "$SIGN_HOME" && "$ALLOW_UNSIGNED" != "1" ]]; then
    iso_reasons+=("no signing choice: pass --signing-key-home DIR (or --allow-unsigned-dev for a development build)")
fi

iso_rc=0
if [[ ${#iso_reasons[@]} -eq 0 ]]; then
    iso_args=(--dist "$DIST_DIR" --agent-deb "$AGENT_DEB" --out "$ISO_OUT")
    [[ -z "$BASE_ISO" ]] || iso_args+=(--base-iso "$BASE_ISO")
    [[ "$DOWNLOAD" != "1" ]] || iso_args+=(--download)
    [[ -z "$SUMS_DIR" ]] || iso_args+=(--ubuntu-sums-dir "$SUMS_DIR")
    [[ -z "$UBUNTU_KEYRING" ]] || iso_args+=(--ubuntu-keyring "$UBUNTU_KEYRING")
    [[ -z "$SIGN_HOME" ]] || iso_args+=(--signing-key-home "$SIGN_HOME")
    [[ "$ALLOW_UNSIGNED" != "1" ]] || iso_args+=(--allow-unsigned-dev)
    [[ "$HM_DRY_RUN" != "1" ]] || iso_args+=(--dry-run)
    "$SCRIPT_DIR/build-iso.sh" "${iso_args[@]}" || iso_rc=$?
    if [[ "$HM_DRY_RUN" == "1" ]]; then
        :
    elif [[ "$iso_rc" == "0" && -f "$ISO_OUT" ]]; then
        produced+=("$ISO_OUT")
    else
        not_produced+=("$ISO_OUT  (build-iso.sh exit code $iso_rc)")
    fi
else
    iso_rc="$HM_EXIT_SKIP"
    reason_text="$(printf '%s; ' "${iso_reasons[@]}")"
    not_produced+=("$ISO_OUT  (not attempted: ${reason_text%; })")
fi

# ----- summary ------------------------------------------------------------------------------
printf '\n===== build-installer summary =====\n'
if [[ "$HM_DRY_RUN" == "1" ]]; then
    printf 'DRY RUN: no artifact was produced.\n'
fi
printf 'PRODUCED:\n'
if [[ ${#produced[@]} -eq 0 ]]; then
    printf '  (nothing)\n'
else
    for a in "${produced[@]}"; do printf '  %s\n' "$a"; done
fi
printf 'NOT PRODUCED:\n'
if [[ ${#not_produced[@]} -eq 0 ]]; then
    printf '  (nothing)\n'
else
    for a in "${not_produced[@]}"; do printf '  %s\n' "$a"; done
fi
printf '===================================\n'

if [[ ${#not_produced[@]} -eq 0 ]]; then
    exit 0
fi
case "$iso_rc" in
    "$HM_EXIT_SKIP")
        if [[ "$ALLOW_PARTIAL" == "1" ]]; then
            hm_warn "the installation ISO was NOT built (prerequisites missing); exiting 0 because --allow-partial was given"
            exit 0
        fi
        hm_err "the installation ISO was NOT built: prerequisite not available (exit $HM_EXIT_SKIP; use --allow-partial to accept the partial result)"
        exit "$HM_EXIT_SKIP"
        ;;
    *)
        hm_err "the installation ISO build FAILED (exit code $iso_rc)"
        exit "$iso_rc"
        ;;
esac
