#!/usr/bin/env bash
#
# HappyMining agent — upgrade (or roll back) the agent package ONLY.
#
#   sudo ./upgrade.sh --deb PATH --keyring FILE [--dry-run] [--yes]
#   sudo ./upgrade.sh --rollback [--dry-run] [--yes]
#
# Same guarantees as install.sh: no partition, filesystem, driver, kernel,
# Docker, Vast, network or firewall change, and no machine restart.
#
# Credentials are preserved: the device identity and credential under
# /var/lib/happymining and /etc/happymining/agent.env are fingerprinted and
# copied aside before the package is replaced, compared afterwards, and put
# back if the package changed or lost them.
#
# ROLLBACK SCOPE. --rollback puts the previous agent package back (the copy
# kept in /var/cache/happymining/). That is ALL it does. It does NOT roll back
# NVIDIA drivers, kernels, Docker, the Vast host software, firmware settings or
# any filesystem change. Those are handled by the maintenance procedure in
# docs/os-maintenance.md and cannot be undone by reinstalling a .deb.

set -euo pipefail
umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
HM_PROG="upgrade.sh"
# shellcheck source=os/install/lib.sh
. "$SCRIPT_DIR/lib.sh"

usage() {
    cat <<'USAGE'
Usage: sudo ./upgrade.sh --deb PATH --keyring FILE [options]
       sudo ./upgrade.sh --rollback [options]

  --deb PATH              the newer happymining-agent .deb (SHA256SUMS and
                          SHA256SUMS.gpg next to it).
  --keyring FILE          OpenPGP public key(s) of the HappyMining release signer.
  --expect-fingerprint F  require this signer fingerprint (40 hex digits).
  --rollback              put back the previous agent package kept in
                          /var/cache/happymining/. Agent package only: drivers,
                          kernels and filesystem changes are NOT rolled back.
  --allow-downgrade       accept a --deb older than the present version.
  --dry-run               verify, run the read-only checks, print what would change.
  --yes                   do not ask for confirmation.
  --force-preflight       continue although the preflight reported FAIL (logged).
  --allow-unsigned-dev    developer builds only: accept an unsigned package.
  --root DIR              operate on the system tree under DIR (tests, images).
  -h, --help              this text.

Exit codes: 0 done, 1 failure, 2 usage, 3 verification failed, 4 preflight FAIL,
5 refused, 77 skipped (a prerequisite is not available).
USAGE
}

DEB=""
KEYRING=""
EXPECT_FPR=""
ROLLBACK=0
ALLOW_DOWNGRADE=0
ASSUME_YES=0
FORCE_PREFLIGHT=0
ALLOW_UNSIGNED=0
ROOT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --deb) DEB="${2:-}"; shift 2 || hm_die "$HM_EXIT_USAGE" "--deb needs a value" ;;
        --keyring) KEYRING="${2:-}"; shift 2 || hm_die "$HM_EXIT_USAGE" "--keyring needs a value" ;;
        --expect-fingerprint) EXPECT_FPR="${2:-}"; shift 2 || hm_die "$HM_EXIT_USAGE" "--expect-fingerprint needs a value" ;;
        --root) ROOT="${2:-}"; shift 2 || hm_die "$HM_EXIT_USAGE" "--root needs a value" ;;
        --rollback) ROLLBACK=1; shift ;;
        --allow-downgrade) ALLOW_DOWNGRADE=1; shift ;;
        --dry-run) HM_DRY_RUN=1; shift ;;
        --yes) ASSUME_YES=1; shift ;;
        --force-preflight) FORCE_PREFLIGHT=1; shift ;;
        --allow-unsigned-dev) ALLOW_UNSIGNED=1; shift ;;
        -h | --help) usage; exit 0 ;;
        *) usage >&2; hm_die "$HM_EXIT_USAGE" "unknown argument: $1" ;;
    esac
done

if [[ "$ROLLBACK" == "1" && -n "$DEB" ]]; then
    hm_die "$HM_EXIT_USAGE" "--rollback and --deb cannot be combined"
fi
if [[ "$ROLLBACK" != "1" ]]; then
    [[ -n "$DEB" ]] || { usage >&2; hm_die "$HM_EXIT_USAGE" "--deb PATH (or --rollback) is required"; }
    [[ -f "$DEB" ]] || hm_die "$HM_EXIT_USAGE" "package file not found: $DEB"
fi
if [[ -n "$KEYRING" && ! -f "$KEYRING" ]]; then
    hm_die "$HM_EXIT_USAGE" "keyring file not found: $KEYRING"
fi
if [[ -n "$EXPECT_FPR" && ! "${EXPECT_FPR// /}" =~ ^[0-9A-Fa-f]{40}$ ]]; then
    hm_die "$HM_EXIT_USAGE" "--expect-fingerprint must be 40 hexadecimal digits"
fi
if [[ -n "$ROOT" ]]; then
    [[ -d "$ROOT" ]] || hm_die "$HM_EXIT_USAGE" "--root directory not found: $ROOT"
    ROOT="$(cd -- "$ROOT" && pwd)"
    [[ "$ROOT" != "/" ]] || ROOT=""
fi

hm_load_versions
hm_need_tools dpkg dpkg-deb dpkg-query sha256sum awk grep stat mktemp find diff

STATE_DIR="$ROOT/var/lib/happymining"
ENV_FILE="$ROOT/etc/happymining/agent.env"
CACHE_DIR="$ROOT/var/cache/happymining"
LOG_DIR="$ROOT/var/log/happymining"
# Files that must survive an upgrade byte for byte.
PRESERVE=("$STATE_DIR/identity" "$STATE_DIR/credential.json" "$ENV_FILE")

hm_self_guard "${BASH_SOURCE[0]}"

if ! hm_is_root; then
    if [[ "$HM_DRY_RUN" == "1" ]]; then
        hm_warn "not running as root: this dry run can only show what a privileged run would do"
    else
        hm_die "$HM_EXIT_REFUSED" "this script must run as root (use sudo). Use --dry-run to preview without privileges."
    fi
fi

if [[ "$HM_DRY_RUN" != "1" ]]; then
    mkdir -p -- "$LOG_DIR"
    chmod 0750 -- "$LOG_DIR"
    HM_LOG_FILE="$LOG_DIR/install.log"
    hm_log "---- upgrade started; rollback=$ROLLBACK deb=${DEB:-none} force-preflight=$FORCE_PREFLIGHT allow-unsigned-dev=$ALLOW_UNSIGNED allow-downgrade=$ALLOW_DOWNGRADE root=${ROOT:-/}"
else
    hm_log "DRY RUN: nothing on this machine will be changed"
fi

# Private scratch directory (mode 0700, owned by the caller). The copies of
# the credential files are kept here, never inside /var/lib/happymining,
# which belongs to the unprivileged agent user.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/hm-upgrade.XXXXXXXX")"
BACKUP_DIR="$WORK/preserve"
cleanup() { rm -rf -- "$WORK"; }
trap cleanup EXIT

installed_version="$(hm_pkg_version "$ROOT" "$AGENT_PACKAGE")"
[[ -n "$installed_version" ]] ||
    hm_die "$HM_EXIT_REFUSED" "$AGENT_PACKAGE is not present on this machine; use install.sh"

current_name=""
[[ -f "$CACHE_DIR/current" ]] && current_name="$(head -n 1 -- "$CACHE_DIR/current")"

# ----- choose and authenticate the package ----------------------------------
if [[ "$ROLLBACK" == "1" ]]; then
    [[ -f "$CACHE_DIR/previous" ]] ||
        hm_die "$HM_EXIT_REFUSED" "no previous package is recorded in $CACHE_DIR; nothing to roll back to"
    hm_require_root_owned "$CACHE_DIR" "$CACHE_DIR/previous" ||
        hm_die "$HM_EXIT_REFUSED" "the rollback store is not exclusively root-writable; refusing to use it"
    prev_name="$(head -n 1 -- "$CACHE_DIR/previous")"
    [[ "$prev_name" =~ ^[A-Za-z0-9][A-Za-z0-9._+~-]*\.deb$ ]] ||
        hm_die "$HM_EXIT_FAIL" "unexpected content in $CACHE_DIR/previous"
    DEB="$CACHE_DIR/$prev_name"
    [[ -f "$DEB" && -f "$DEB.sha256" ]] ||
        hm_die "$HM_EXIT_FAIL" "the previous package or its recorded checksum is missing: $DEB"
    hm_require_root_owned "$DEB" "$DEB.sha256" ||
        hm_die "$HM_EXIT_REFUSED" "the cached previous package is not exclusively root-writable; refusing to use it"
    # The copy was authenticated when it was first used and its sha256 was
    # recorded in this root-owned directory; check it is still that file.
    if ! hm_verify_sums_entry "$DEB.sha256" "$DEB"; then
        hm_die "$HM_EXIT_VERIFY" "the cached previous package no longer matches its recorded checksum; refusing"
    fi
    hm_banner "ROLLBACK OF THE AGENT PACKAGE ONLY." \
        "NVIDIA drivers, kernels, Docker, the Vast host software and any filesystem" \
        "change are NOT rolled back by this command. See docs/os-maintenance.md."
else
    verify_rc=0
    hm_verify_release_file "$DEB" "$KEYRING" "$ALLOW_UNSIGNED" "$EXPECT_FPR" || verify_rc=$?
    if [[ "$verify_rc" != "0" ]]; then
        hm_err "package verification failed; nothing was changed"
        exit "$HM_EXIT_VERIFY"
    fi
fi

pkg_name="$(dpkg-deb -f "$DEB" Package 2>/dev/null || true)"
pkg_version="$(dpkg-deb -f "$DEB" Version 2>/dev/null || true)"
pkg_arch="$(dpkg-deb -f "$DEB" Architecture 2>/dev/null || true)"
[[ "$pkg_name" == "$AGENT_PACKAGE" ]] ||
    hm_die "$HM_EXIT_REFUSED" "$DEB is package '${pkg_name:-unreadable}', not '$AGENT_PACKAGE'; this script changes the HappyMining agent and nothing else"
host_arch="$(dpkg --print-architecture)"
if [[ "$pkg_arch" != "$host_arch" && "$pkg_arch" != "all" ]]; then
    hm_die "$HM_EXIT_REFUSED" "package architecture '$pkg_arch' does not match this machine ('$host_arch')"
fi

hm_log "present version: $installed_version; package offered: $pkg_version"
if dpkg --compare-versions "$pkg_version" eq "$installed_version"; then
    hm_log "version $pkg_version is already present; nothing to do"
    exit 0
fi
if dpkg --compare-versions "$pkg_version" lt "$installed_version"; then
    if [[ "$ROLLBACK" != "1" && "$ALLOW_DOWNGRADE" != "1" ]]; then
        hm_die "$HM_EXIT_REFUSED" "$pkg_version is older than the present $installed_version; use --rollback or --allow-downgrade"
    fi
    hm_warn "going back from $installed_version to $pkg_version (agent package only)"
fi

# ----- inventory -------------------------------------------------------------
state_before="$(hm_host_state "$ROOT")"
hm_host_summary "$ROOT" "$state_before"

declare -A preserve_before=()
for f in "${PRESERVE[@]}"; do
    preserve_before["$f"]="$(hm_file_fingerprint "$f")"
done

# ----- preflight from the unpacked package (nothing changed yet) -------------
mkdir -m 0700 -- "$WORK/pkg"
dpkg-deb -x "$DEB" "$WORK/pkg"
CTL="$(find "$WORK/pkg" -type f -name happyminingctl -perm -u+x | LC_ALL=C sort | head -n 1)"
[[ -n "$CTL" ]] || hm_die "$HM_EXIT_FAIL" "the package does not contain an executable happyminingctl; cannot run the preflight"
hm_log "running preflight from the unpacked package: happyminingctl preflight"
preflight_rc=0
"$CTL" preflight || preflight_rc=$?
case "$preflight_rc" in
    0) hm_log "preflight: no FAIL" ;;
    1)
        if [[ "$FORCE_PREFLIGHT" == "1" ]]; then
            hm_banner "PREFLIGHT REPORTED FAIL — continuing because --force-preflight was given." \
                "This override is recorded in ${HM_LOG_FILE:-the log}."
            hm_log "OVERRIDE: --force-preflight used; preflight exit code 1 (FAIL) was ignored by operator request"
        else
            hm_err "preflight reported at least one FAIL; nothing was changed"
            exit "$HM_EXIT_PREFLIGHT"
        fi
        ;;
    *) hm_die "$HM_EXIT_FAIL" "happyminingctl preflight did not run correctly (exit code $preflight_rc); nothing was changed" ;;
esac

# ----- plan and confirmation ---------------------------------------------------
# --force-confold/--force-confdef: dpkg never stops to ask about a configuration
# file; /etc/happymining/agent.env as the administrator left it is kept.
DPKG=(dpkg --force-confold --force-confdef)
# With an alternate root, dpkg's own log must go into that root as well: the
# "log" setting in /etc/dpkg/dpkg.cfg is an absolute path on the host.
[[ -z "$ROOT" ]] || DPKG+=("--root=$ROOT" "--log=$ROOT/var/log/dpkg.log")
deb_base="$(basename -- "$DEB")"

hm_log "plan:"
hm_log "  replace package: $(hm_quote_cmd "${DPKG[@]}" -i "$DEB")"
hm_log "  keep $deb_base in $CACHE_DIR and remember '${current_name:-none}' as the previous package"
hm_log "  preserve: ${PRESERVE[*]}"
hm_log "  nothing else: no partition, filesystem, driver, kernel, Docker, Vast, network or firewall change, no machine restart"

if [[ "$HM_DRY_RUN" != "1" && "$ASSUME_YES" != "1" ]]; then
    hm_confirm "Replace $AGENT_PACKAGE $installed_version with $pkg_version?" ||
        hm_die "$HM_EXIT_REFUSED" "not confirmed; nothing was changed"
fi

# ----- copy credentials aside ---------------------------------------------------
if [[ "$HM_DRY_RUN" == "1" ]]; then
    printf 'DRY-RUN would copy aside (mode preserved, root-only directory): %s\n' "${PRESERVE[*]}"
else
    mkdir -m 0700 -- "$BACKUP_DIR"
    i=0
    for f in "${PRESERVE[@]}"; do
        if [[ -e "$f" ]]; then
            cp -p -- "$f" "$BACKUP_DIR/$i"
        fi
        i=$((i + 1))
    done
fi

# ----- cache bookkeeping and package ---------------------------------------------
hm_run mkdir -p -- "$CACHE_DIR"
if [[ "$HM_DRY_RUN" != "1" ]]; then
    hm_require_root_owned "$CACHE_DIR" ||
        hm_die "$HM_EXIT_REFUSED" "$CACHE_DIR is not exclusively root-writable; refusing to keep packages in it"
fi
if [[ "$ROLLBACK" != "1" ]]; then
    hm_run cp -- "$DEB" "$CACHE_DIR/$deb_base"
fi
if [[ "$HM_DRY_RUN" == "1" ]]; then
    printf 'DRY-RUN would record: current=%s previous=%s in %s\n' "$deb_base" "${current_name:-none}" "$CACHE_DIR"
else
    if [[ "$ROLLBACK" != "1" ]]; then
        printf '%s  %s\n' "$(hm_sha256 "$DEB")" "$deb_base" >"$CACHE_DIR/$deb_base.sha256"
    fi
    if [[ -n "$current_name" && "$current_name" != "$deb_base" ]]; then
        printf '%s\n' "$current_name" >"$CACHE_DIR/previous"
    fi
    printf '%s\n' "$deb_base" >"$CACHE_DIR/current"
fi
hm_run "${DPKG[@]}" -i "$DEB"

# ----- credentials must be untouched ------------------------------------------------
if [[ "$HM_DRY_RUN" != "1" ]]; then
    i=0
    restored=0
    for f in "${PRESERVE[@]}"; do
        after="$(hm_file_fingerprint "$f")"
        if [[ "$after" != "${preserve_before[$f]}" ]]; then
            if [[ -e "$BACKUP_DIR/$i" ]]; then
                hm_warn "$f was changed or lost by the package; putting the previous copy back"
                # --remove-destination unlinks whatever is at the destination
                # (never writes through a symbolic link) before copying.
                mkdir -p -- "$(dirname -- "$f")"
                cp -p --remove-destination -- "$BACKUP_DIR/$i" "$f"
                restored=1
            else
                hm_log "$f did not exist before and exists now (created by the package)"
            fi
        fi
        i=$((i + 1))
    done
    if [[ "$restored" == "1" ]]; then
        hm_warn "one or more credential files had to be put back; report this as a packaging bug"
    else
        hm_log "verified: device identity, credential and agent.env are unchanged"
    fi
fi

# ----- service ------------------------------------------------------------------------
if [[ -z "$ROOT" && -d /run/systemd/system ]]; then
    hm_run systemctl try-restart happymining-agent.service
elif [[ "$HM_DRY_RUN" == "1" ]]; then
    printf 'DRY-RUN would run (on a machine booted with systemd): systemctl try-restart happymining-agent.service\n'
fi

state_after="$(hm_host_state "$ROOT")"
if ! hm_assert_host_unchanged "$state_before" "$state_after"; then
    exit "$HM_EXIT_FAIL"
fi

if [[ "$HM_DRY_RUN" == "1" ]]; then
    hm_log "DRY RUN complete: nothing was changed"
    exit 0
fi

hm_log "done: $AGENT_PACKAGE is now $pkg_version (was $installed_version)"
cat <<NOTE

To go back to the previous agent package:   sudo ./upgrade.sh --rollback

Reminder: that rollback covers the HappyMining agent package only. It does not
roll back NVIDIA drivers, kernels, Docker, the Vast host software or filesystem
changes. Driver and kernel work follows docs/os-maintenance.md.
NOTE
