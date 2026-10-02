#!/usr/bin/env bash
#
# HappyMining agent — NON-DESTRUCTIVE installation on an existing, supported
# Ubuntu server.
#
#   sudo ./install.sh --deb PATH --keyring FILE [--api-url URL] [--dry-run] [--yes]
#
# What it does, in this order:
#   1. self-guard: refuses to start if this script or lib.sh contains a command
#      from forbidden-commands.txt;
#   2. refuses when not root (a --dry-run may run unprivileged);
#   3. checks that this is Ubuntu;
#   4. verifies the package: sha256 against the SHA256SUMS file next to it and
#      the detached signature SHA256SUMS.gpg against --keyring; only then reads
#      the package fields and refuses anything that is not the agent package
#      for this machine's architecture;
#   5. takes a read-only inventory of Docker, the Vast host software, NVIDIA
#      drivers, kernels, mounts and network files;
#   6. runs the preflight from a copy of happyminingctl unpacked into a
#      temporary directory, so that nothing on the machine has changed when the
#      checks run; stops on FAIL unless --force-preflight;
#   7. installs the one package with dpkg;
#   8. writes HM_API_URL only if --api-url was given and the key was unset
#      before this run (a value the operator set earlier is never replaced);
#   9. enables the HappyMining services;
#  10. compares the inventory of step 5 again and fails loudly on any change.
#
# What it never does: change partitions, filesystems, mount points or the
# filesystem table; add, replace or drop Docker, NVIDIA drivers, kernels or the
# Vast host software; change network or firewall configuration; restart the
# machine. See os/README.md.

set -euo pipefail
umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
HM_PROG="install.sh"
# shellcheck source=os/install/lib.sh
. "$SCRIPT_DIR/lib.sh"

usage() {
    cat <<'USAGE'
Usage: sudo ./install.sh --deb PATH --keyring FILE [options]

Required:
  --deb PATH              the happymining-agent .deb to add to this machine.
                          SHA256SUMS and SHA256SUMS.gpg must sit next to it.
  --keyring FILE          OpenPGP public key(s) of the HappyMining release
                          signer (binary or ASCII-armoured export).

Options:
  --expect-fingerprint F  additionally require the signer's primary key
                          fingerprint to be exactly F (40 hex digits).
  --api-url URL           write HM_API_URL=URL to /etc/happymining/agent.env,
                          only when that key was not set before this run (the
                          default that ships in the package is replaced; a value
                          an operator set earlier is kept). https only (http is
                          accepted for loopback addresses).
  --dry-run               verify and run the read-only checks, then print the
                          commands that would change the machine. Changes nothing.
  --yes                   do not ask for the final confirmation.
  --force-preflight       continue although the preflight reported FAIL.
                          Recorded in the log.
  --allow-unsigned-dev    developer builds only: accept a package without a
                          verified signature. Prints a loud warning.
  --root DIR              operate on the system tree under DIR instead of /
                          (image preparation and tests; services are not started).
  -h, --help              this text.

Exit codes: 0 done, 1 failure, 2 usage, 3 verification failed, 4 preflight FAIL,
5 refused, 77 skipped (a prerequisite is not available).
USAGE
}

DEB=""
KEYRING=""
EXPECT_FPR=""
API_URL=""
ASSUME_YES=0
FORCE_PREFLIGHT=0
ALLOW_UNSIGNED=0
ROOT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --deb) DEB="${2:-}"; shift 2 || hm_die "$HM_EXIT_USAGE" "--deb needs a value" ;;
        --keyring) KEYRING="${2:-}"; shift 2 || hm_die "$HM_EXIT_USAGE" "--keyring needs a value" ;;
        --expect-fingerprint) EXPECT_FPR="${2:-}"; shift 2 || hm_die "$HM_EXIT_USAGE" "--expect-fingerprint needs a value" ;;
        --api-url) API_URL="${2:-}"; shift 2 || hm_die "$HM_EXIT_USAGE" "--api-url needs a value" ;;
        --root) ROOT="${2:-}"; shift 2 || hm_die "$HM_EXIT_USAGE" "--root needs a value" ;;
        --dry-run) HM_DRY_RUN=1; shift ;;
        --yes) ASSUME_YES=1; shift ;;
        --force-preflight) FORCE_PREFLIGHT=1; shift ;;
        --allow-unsigned-dev) ALLOW_UNSIGNED=1; shift ;;
        -h | --help) usage; exit 0 ;;
        *) usage >&2; hm_die "$HM_EXIT_USAGE" "unknown argument: $1" ;;
    esac
done

# ----- argument validation (no side effects) -------------------------------
[[ -n "$DEB" ]] || { usage >&2; hm_die "$HM_EXIT_USAGE" "--deb PATH is required"; }
[[ -f "$DEB" ]] || hm_die "$HM_EXIT_USAGE" "package file not found: $DEB"
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
if [[ -n "$API_URL" ]]; then
    https_re='^https://[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$'
    loopback_re='^http://(127\.0\.0\.1|localhost|\[::1\])(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$'
    if [[ "$API_URL" =~ $https_re ]]; then
        :
    elif [[ "$API_URL" =~ $loopback_re ]]; then
        hm_warn "--api-url uses plain http on a loopback address; this is for local development only"
    else
        hm_die "$HM_EXIT_USAGE" "--api-url must be an https:// URL (http is accepted only for loopback addresses)"
    fi
fi

hm_load_versions
hm_need_tools dpkg dpkg-deb dpkg-query sha256sum awk grep stat mktemp find

ETC_DIR="$ROOT/etc/happymining"
ENV_FILE="$ETC_DIR/agent.env"
CACHE_DIR="$ROOT/var/cache/happymining"
LOG_DIR="$ROOT/var/log/happymining"

# ----- 1. self-guard -------------------------------------------------------
hm_self_guard "${BASH_SOURCE[0]}"

# ----- 2. privileges -------------------------------------------------------
if ! hm_is_root; then
    if [[ "$HM_DRY_RUN" == "1" ]]; then
        hm_warn "not running as root: this dry run can only show what a privileged run would do"
    else
        hm_die "$HM_EXIT_REFUSED" "this installer must run as root (use sudo). Use --dry-run to preview without privileges."
    fi
fi

if [[ "$HM_DRY_RUN" != "1" ]]; then
    mkdir -p -- "$LOG_DIR"
    chmod 0750 -- "$LOG_DIR"
    HM_LOG_FILE="$LOG_DIR/install.log"
    hm_log "---- install started; arguments recorded: deb=$DEB dry-run=0 yes=$ASSUME_YES force-preflight=$FORCE_PREFLIGHT allow-unsigned-dev=$ALLOW_UNSIGNED root=${ROOT:-/}"
else
    hm_log "DRY RUN: nothing on this machine will be changed"
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/hm-install.XXXXXXXX")"
cleanup() { rm -rf -- "$WORK"; }
trap cleanup EXIT

# ----- 3. platform ---------------------------------------------------------
os_release_file="$ROOT/etc/os-release"
os_id=""
os_version=""
if [[ -r "$os_release_file" ]]; then
    os_id="$(awk -F= '$1 == "ID" { gsub(/"/, "", $2); print $2 }' "$os_release_file")"
    os_version="$(awk -F= '$1 == "VERSION_ID" { gsub(/"/, "", $2); print $2 }' "$os_release_file")"
fi
if [[ "$os_id" != "ubuntu" ]]; then
    hm_die "$HM_EXIT_REFUSED" "this is not Ubuntu (ID='${os_id:-unknown}' in $os_release_file); HappyMining OS supports Ubuntu Server ${SUPPORTED_UBUNTU_VERSIONS// / and } only"
fi
version_supported=0
for v in $SUPPORTED_UBUNTU_VERSIONS; do
    [[ "$os_version" == "$v" ]] && version_supported=1
done

# ----- 4. authenticity of the package --------------------------------------
verify_rc=0
hm_verify_release_file "$DEB" "$KEYRING" "$ALLOW_UNSIGNED" "$EXPECT_FPR" || verify_rc=$?
if [[ "$verify_rc" != "0" ]]; then
    hm_err "package verification failed; nothing was changed"
    hm_err "(developer builds only: --allow-unsigned-dev skips the signature requirement)"
    exit "$HM_EXIT_VERIFY"
fi

# Only now is the package itself opened: its fields are read after the
# checksum and the signature were verified, never before.
pkg_name="$(dpkg-deb -f "$DEB" Package 2>/dev/null || true)"
pkg_version="$(dpkg-deb -f "$DEB" Version 2>/dev/null || true)"
pkg_arch="$(dpkg-deb -f "$DEB" Architecture 2>/dev/null || true)"
if [[ "$pkg_name" != "$AGENT_PACKAGE" ]]; then
    hm_die "$HM_EXIT_REFUSED" "$DEB is package '${pkg_name:-unreadable}', not '$AGENT_PACKAGE'; this installer adds the HappyMining agent and nothing else"
fi
host_arch="$(dpkg --print-architecture)"
if [[ "$pkg_arch" != "$host_arch" && "$pkg_arch" != "all" ]]; then
    hm_die "$HM_EXIT_REFUSED" "package architecture '$pkg_arch' does not match this machine ('$host_arch')"
fi
hm_log "package: $pkg_name $pkg_version ($pkg_arch); system: Ubuntu ${os_version:-unknown}"

# ----- 5. inventory of what must not change --------------------------------
state_before="$(hm_host_state "$ROOT")"
hm_host_summary "$ROOT" "$state_before"
installed_version="$(hm_pkg_version "$ROOT" "$AGENT_PACKAGE")"
if [[ -n "$installed_version" ]]; then
    hm_log "$AGENT_PACKAGE $installed_version is already present; for a version change prefer upgrade.sh (it keeps a rollback copy)"
fi

# ----- 6. preflight, before anything is changed ----------------------------
# The package is unpacked with dpkg-deb -x into a private temporary directory
# and the happyminingctl found there is executed. The alternative — a first
# dpkg -i followed by the installed happyminingctl — would already have changed
# the machine (files, system user, units) before the checks had passed.
mkdir -m 0700 -- "$WORK/pkg"
dpkg-deb -x "$DEB" "$WORK/pkg"
CTL="$(find "$WORK/pkg" -type f -name happyminingctl -perm -u+x | LC_ALL=C sort | head -n 1)"
[[ -n "$CTL" ]] || hm_die "$HM_EXIT_FAIL" "the package does not contain an executable happyminingctl; cannot run the preflight"

if [[ "$version_supported" != "1" ]]; then
    hm_warn "FAIL os: Ubuntu ${os_version:-unknown} is not in the supported list ($SUPPORTED_UBUNTU_VERSIONS)"
fi
hm_log "running preflight from the unpacked package (nothing is installed yet): happyminingctl preflight"
preflight_rc=0
"$CTL" preflight || preflight_rc=$?
if [[ "$version_supported" != "1" && "$preflight_rc" == "0" ]]; then
    preflight_rc=1
fi
case "$preflight_rc" in
    0)
        hm_log "preflight: no FAIL"
        ;;
    1)
        if [[ "$FORCE_PREFLIGHT" == "1" ]]; then
            hm_banner "PREFLIGHT REPORTED FAIL — continuing because --force-preflight was given." \
                "This override is recorded in ${HM_LOG_FILE:-the log}."
            hm_log "OVERRIDE: --force-preflight used; preflight exit code 1 (FAIL) was ignored by operator request"
        else
            hm_err "preflight reported at least one FAIL; nothing was changed"
            hm_err "fix the FAIL lines above, or repeat with --force-preflight (recorded in the log)"
            exit "$HM_EXIT_PREFLIGHT"
        fi
        ;;
    *)
        hm_die "$HM_EXIT_FAIL" "happyminingctl preflight did not run correctly (exit code $preflight_rc); nothing was changed"
        ;;
esac

# ----- plan and confirmation ------------------------------------------------
# --force-confold/--force-confdef: dpkg never stops to ask about a configuration
# file; a file the administrator changed is kept as it is.
DPKG=(dpkg --force-confold --force-confdef)
# With an alternate root, dpkg's own log must go into that root as well: the
# "log" setting in /etc/dpkg/dpkg.cfg is an absolute path on the host.
[[ -z "$ROOT" ]] || DPKG+=("--root=$ROOT" "--log=$ROOT/var/log/dpkg.log")
deb_base="$(basename -- "$DEB")"

# "Unset" is judged BEFORE the package is added: the package ships a default
# HM_API_URL, and that default is not an operator's choice.
api_url_preexisting=0
if [[ -f "$ENV_FILE" ]] && grep -Eq '^[[:space:]]*HM_API_URL=[^[:space:]]' -- "$ENV_FILE"; then
    api_url_preexisting=1
fi

hm_log "plan:"
hm_log "  keep a copy of the package in $CACHE_DIR (used by upgrade.sh --rollback)"
hm_log "  add package: $(hm_quote_cmd "${DPKG[@]}" -i "$DEB")"
if [[ -n "$API_URL" ]]; then
    hm_log "  set HM_API_URL in $ENV_FILE unless an operator already set it"
fi
hm_log "  enable happymining-firstboot.service and happymining-agent.service"
hm_log "  nothing else: no partition, filesystem, driver, kernel, Docker, Vast, network or firewall change, no machine restart"

if [[ "$HM_DRY_RUN" != "1" && "$ASSUME_YES" != "1" ]]; then
    hm_confirm "Add $pkg_name $pkg_version to this machine?" ||
        hm_die "$HM_EXIT_REFUSED" "not confirmed; nothing was changed"
fi

# ----- 7. cache copy and package -------------------------------------------
hm_run mkdir -p -- "$CACHE_DIR"
if [[ "$HM_DRY_RUN" != "1" ]]; then
    hm_require_root_owned "$CACHE_DIR" ||
        hm_die "$HM_EXIT_REFUSED" "$CACHE_DIR is not exclusively root-writable; refusing to keep packages in it"
fi
hm_run cp -- "$DEB" "$CACHE_DIR/$deb_base"
if [[ "$HM_DRY_RUN" == "1" ]]; then
    printf 'DRY-RUN would write: %s (sha256 of the verified package) and %s\n' "$CACHE_DIR/$deb_base.sha256" "$CACHE_DIR/current"
else
    printf '%s  %s\n' "$(hm_sha256 "$DEB")" "$deb_base" >"$CACHE_DIR/$deb_base.sha256"
    printf '%s\n' "$deb_base" >"$CACHE_DIR/current"
    chmod 0644 -- "$CACHE_DIR/$deb_base" "$CACHE_DIR/$deb_base.sha256" "$CACHE_DIR/current"
fi
hm_run "${DPKG[@]}" -i "$DEB"

# ----- 8. API URL, only when asked and only when it was unset -----------------
env_changed=0
if [[ -n "$API_URL" ]]; then
    if [[ "$api_url_preexisting" == "1" ]]; then
        hm_log "HM_API_URL was already set in $ENV_FILE before this run; leaving it unchanged (--api-url ignored)"
    elif [[ "$HM_DRY_RUN" == "1" ]]; then
        printf 'DRY-RUN would set in %s: HM_API_URL=%s\n' "$ENV_FILE" "$API_URL"
    else
        mkdir -p -- "$ETC_DIR"
        if [[ ! -e "$ENV_FILE" ]]; then
            : >"$ENV_FILE"
        fi
        if grep -Fxq -- "HM_API_URL=$API_URL" "$ENV_FILE"; then
            hm_log "HM_API_URL in $ENV_FILE already has the requested value"
        elif grep -Eq '^[[:space:]]*HM_API_URL=' -- "$ENV_FILE"; then
            # Replace the default that came with the package, in place, keeping
            # every other line, the owner and the mode of the file.
            awk -v url="$API_URL" '
                /^[[:space:]]*HM_API_URL=/ { if (!done) { print "HM_API_URL=" url; done = 1 }; next }
                { print }' "$ENV_FILE" >"$WORK/agent.env.new"
            cat -- "$WORK/agent.env.new" >"$ENV_FILE"
            env_changed=1
            hm_log "set HM_API_URL in $ENV_FILE (replaced the package default)"
        else
            printf 'HM_API_URL=%s\n' "$API_URL" >>"$ENV_FILE"
            env_changed=1
            hm_log "wrote HM_API_URL to $ENV_FILE"
        fi
    fi
fi

# ----- 9. services ----------------------------------------------------------
if [[ -z "$ROOT" && -d /run/systemd/system ]]; then
    hm_run systemctl enable happymining-firstboot.service happymining-agent.service
    hm_run systemctl start happymining-firstboot.service
    if [[ "$env_changed" == "1" ]]; then
        hm_run systemctl restart happymining-agent.service
    else
        hm_run systemctl start happymining-agent.service
    fi
elif [[ "$HM_DRY_RUN" == "1" ]]; then
    printf 'DRY-RUN would run (on a machine booted with systemd): systemctl enable happymining-firstboot.service happymining-agent.service\n'
else
    hm_warn "systemd is not managing this tree; services were not started here (the package enables them for the next boot)"
fi

# ----- 10. prove nothing else changed ---------------------------------------
state_after="$(hm_host_state "$ROOT")"
if ! hm_assert_host_unchanged "$state_before" "$state_after"; then
    exit "$HM_EXIT_FAIL"
fi

if [[ "$HM_DRY_RUN" == "1" ]]; then
    hm_log "DRY RUN complete: nothing was changed"
    exit 0
fi

hm_log "done: $pkg_name $pkg_version is on this machine"
cat <<NEXT

Next steps (run them on this machine):

  1. Ask your HappyMining administrator for a pairing code, then:
         sudo happyminingctl pair
  2. Enrol the machine with Vast.ai yourself, as the local operator:
         happyminingctl vast-enroll-help
     HappyMining never runs the Vast installer for you and never stores your
     Vast account key on this machine.
  3. Check the result:
         happyminingctl status

This installer did not touch disks, drivers, kernels, Docker, the Vast host
software, the network or the firewall, and did not restart the machine.
NEXT
