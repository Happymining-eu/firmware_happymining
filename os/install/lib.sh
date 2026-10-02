#!/usr/bin/env bash
# shellcheck shell=bash
#
# HappyMining OS — shared shell helpers.
#
# This file is SOURCED by the scripts in os/ (install, upgrade, uninstall,
# image build, release). It is never executed on its own and has no side
# effects when sourced.

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "lib.sh is a library; source it from another script." >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Exit codes (documented in os/README.md)
# ---------------------------------------------------------------------------
# shellcheck disable=SC2034  # used by the scripts that source this file
readonly \
    HM_EXIT_OK=0 \
    HM_EXIT_FAIL=1 \
    HM_EXIT_USAGE=2 \
    HM_EXIT_VERIFY=3 \
    HM_EXIT_PREFLIGHT=4 \
    HM_EXIT_REFUSED=5 \
    HM_EXIT_SKIP=77
# 0 done | 1 generic failure | 2 bad arguments | 3 signature or checksum
# verification failed | 4 preflight reported FAIL | 5 safety refusal (not root,
# wrong OS, no confirmation ...) | 77 skipped: prerequisite not available

HM_LIB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly HM_LIB_DIR

# Set by the calling script.
HM_DRY_RUN="${HM_DRY_RUN:-0}"
HM_LOG_FILE="${HM_LOG_FILE:-}"
HM_PROG="${HM_PROG:-$(basename -- "$0")}"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
hm__emit() {
    # $1 = level, rest = message. Goes to stdout (INFO) or stderr (WARN/ERROR)
    # and, when HM_LOG_FILE is set and this is not a dry run, to the log file.
    local level="$1"
    shift
    local line
    line="$(printf '%s [%s] %s' "$HM_PROG" "$level" "$*")"
    if [[ "$level" == "INFO" ]]; then
        printf '%s\n' "$line"
    else
        printf '%s\n' "$line" >&2
    fi
    if [[ -n "$HM_LOG_FILE" && "$HM_DRY_RUN" != "1" ]]; then
        printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$line" >>"$HM_LOG_FILE" 2>/dev/null || true
    fi
}
hm_log() { hm__emit INFO "$@"; }
hm_warn() { hm__emit WARN "$@"; }
hm_err() { hm__emit ERROR "$@"; }

hm_die() {
    # hm_die EXIT_CODE MESSAGE...
    local code="$1"
    shift
    hm_err "$@"
    exit "$code"
}

hm_banner() {
    # Loud multi-line warning on stderr.
    local line
    printf '\n%s\n' '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!' >&2
    for line in "$@"; do
        printf '!! %s\n' "$line" >&2
    done
    printf '%s\n\n' '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!' >&2
    if [[ -n "$HM_LOG_FILE" && "$HM_DRY_RUN" != "1" ]]; then
        for line in "$@"; do
            printf '%s %s [WARN] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$HM_PROG" "$line" >>"$HM_LOG_FILE" 2>/dev/null || true
        done
    fi
}

# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
hm_have() { command -v -- "$1" >/dev/null 2>&1; }

hm_need_tools() {
    # hm_need_tools TOOL... — exit 77 (skipped: prerequisite not available)
    # with one clear line per missing tool.
    local missing=0 tool
    for tool in "$@"; do
        if ! hm_have "$tool"; then
            hm_err "prerequisite not available: '$tool' is not installed or not on PATH"
            missing=1
        fi
    done
    if [[ "$missing" == "1" ]]; then
        hm_err "skipped: prerequisite not available (exit $HM_EXIT_SKIP)"
        exit "$HM_EXIT_SKIP"
    fi
}

hm_quote_cmd() {
    # Print a command line that can be pasted into a shell, for dry-run output
    # and logs. Plain words are printed as they are; anything else is put in
    # single quotes.
    local out="" arg
    for arg in "$@"; do
        if [[ "$arg" =~ ^[A-Za-z0-9_@%+=:,./-]+$ ]]; then
            out+="$arg "
        else
            out+="'${arg//\'/\'\\\'\'}' "
        fi
    done
    printf '%s' "${out% }"
}

hm_run() {
    # Run a state-changing command, or print it in dry-run mode.
    if [[ "$HM_DRY_RUN" == "1" ]]; then
        printf 'DRY-RUN would run: %s\n' "$(hm_quote_cmd "$@")"
        return 0
    fi
    hm_log "run: $(hm_quote_cmd "$@")"
    "$@"
}

# ---------------------------------------------------------------------------
# versions.env
# ---------------------------------------------------------------------------
hm_load_versions() {
    # Looks next to the calling script first (install-scripts bundle), then in
    # the repository layout (os/versions.env).
    local candidate
    for candidate in "${HM_VERSIONS_FILE:-}" "$HM_LIB_DIR/versions.env" "$HM_LIB_DIR/../versions.env"; do
        if [[ -n "$candidate" && -f "$candidate" ]]; then
            # shellcheck source=os/versions.env
            . "$candidate"
            HM_VERSIONS_FILE="$candidate"
            return 0
        fi
    done
    hm_die "$HM_EXIT_FAIL" "versions.env not found next to $HM_LIB_DIR or in its parent directory"
}

# ---------------------------------------------------------------------------
# Forbidden-command self guard
# ---------------------------------------------------------------------------
hm_forbidden_patterns_file() { printf '%s\n' "$HM_LIB_DIR/forbidden-commands.txt"; }

hm_forbidden_scan() {
    # hm_forbidden_scan FILE... — prints "file:line:text" for every line that
    # matches a forbidden pattern. Returns 0 when the files are clean, 1 when a
    # match was found, 2 when the scan itself could not be performed.
    local list patterns rc=0 file
    list="$(hm_forbidden_patterns_file)"
    if [[ ! -r "$list" ]]; then
        hm_err "forbidden-command list is missing: $list"
        return 2
    fi
    patterns="$(grep -vE '^[[:space:]]*(#|$)' -- "$list" || true)"
    if [[ -z "$patterns" ]]; then
        hm_err "forbidden-command list is empty: $list"
        return 2
    fi
    for file in "$@"; do
        if [[ ! -r "$file" ]]; then
            hm_err "cannot read $file for the forbidden-command scan"
            return 2
        fi
        if grep -nHE -e "$patterns" -- "$file"; then
            rc=1
        fi
    done
    return "$rc"
}

hm_self_guard() {
    # Refuse to run when the calling script or this library contains a command
    # from the forbidden list (partitioning, formatting, package removal,
    # firewall changes, machine restart ...). Fails closed: a missing list is a
    # refusal, not a pass.
    local rc=0
    hm_forbidden_scan "$@" "${BASH_SOURCE[0]}" >&2 || rc=$?
    if [[ "$rc" != "0" ]]; then
        hm_die "$HM_EXIT_REFUSED" "self-guard: forbidden command pattern found (or the scan failed); refusing to run"
    fi
}

# ---------------------------------------------------------------------------
# Checksums and signatures
# ---------------------------------------------------------------------------
hm_sha256() {
    local out
    out="$(sha256sum -- "$1")" || return 1
    printf '%s\n' "${out%% *}"
}

hm_sums_lookup() {
    # hm_sums_lookup SUMSFILE NAME — print the hash recorded for NAME.
    # Fails unless there is exactly one entry for NAME. Accepts the text
    # ("hash  name") and binary ("hash *name") forms of sha256sum output.
    local sums="$1" name="$2"
    awk -v want="$name" '
        {
            hash = $1
            file = $0
            sub(/^[0-9A-Fa-f]+[ \t]+\*?/, "", file)
            if (file == want || file == "./" want) { n++; found = hash }
        }
        END {
            if (n == 1 && found ~ /^[0-9A-Fa-f]{64}$/) { print tolower(found); exit 0 }
            exit 1
        }' "$sums"
}

hm_verify_sums_entry() {
    # hm_verify_sums_entry SUMSFILE FILE [NAME]
    # Verifies FILE against the entry NAME (default: basename of FILE).
    local sums="$1" file="$2" name="${3:-}" want got
    [[ -n "$name" ]] || name="$(basename -- "$file")"
    if ! want="$(hm_sums_lookup "$sums" "$name")"; then
        hm_err "no unique sha256 entry for '$name' in $sums"
        return 1
    fi
    got="$(hm_sha256 "$file")" || return 1
    if [[ "$want" != "$got" ]]; then
        hm_err "sha256 MISMATCH for $file"
        hm_err "  expected (from $sums): $want"
        hm_err "  actual:                $got"
        return 1
    fi
    return 0
}

# Set by hm_verify_detached on success: primary-key fingerprint of the signer.
HM_SIG_FPR=""

hm_verify_detached() {
    # hm_verify_detached KEYRING SIGNATURE DATA [EXPECTED_FINGERPRINT]
    #
    # Verifies a detached OpenPGP signature with gpgv against the public keys
    # in KEYRING (binary keyring/exported key, or ASCII-armoured export).
    # The decision is taken from gpgv's machine-readable status lines, not from
    # its exit code: a signature counts only when there is a GOODSIG and a
    # VALIDSIG for the same key and no BADSIG; expired or revoked keys and
    # expired signatures never count. When EXPECTED_FINGERPRINT is given, the
    # primary-key fingerprint of a good signature must equal it.
    local keyring="$1" sig="$2" data="$3" want_fpr="${4:-}"
    local tmp kr status f
    HM_SIG_FPR=""
    for f in "$keyring" "$sig" "$data"; do
        if [[ ! -r "$f" ]]; then
            hm_err "cannot read $f"
            return 1
        fi
    done
    if ! hm_have gpgv; then
        hm_err "gpgv is required to verify signatures and is not installed"
        return 1
    fi
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/hm-verify.XXXXXXXX")" || return 1
    kr="$tmp/keyring.gpg"
    if head -c 64 -- "$keyring" | grep -q -- '-----BEGIN PGP PUBLIC KEY BLOCK-----'; then
        if ! hm_have gpg; then
            rm -rf -- "$tmp"
            hm_err "the keyring is ASCII-armoured and gpg is not available to convert it"
            return 1
        fi
        if ! gpg --homedir "$tmp" --no-options --batch --quiet --dearmor <"$keyring" >"$kr" 2>/dev/null; then
            rm -rf -- "$tmp"
            hm_err "could not read the ASCII-armoured keyring $keyring"
            return 1
        fi
    else
        cp -- "$keyring" "$kr"
    fi
    want_fpr="${want_fpr// /}"
    want_fpr="${want_fpr^^}"
    status="$(gpgv --homedir "$tmp" --keyring "$kr" --status-fd 1 -- "$sig" "$data" 2>"$tmp/gpgv.stderr" || true)"
    rm -rf -- "$tmp"

    if grep -q '^\[GNUPG:\] BADSIG ' <<<"$status"; then
        hm_err "BAD signature on $data"
        return 1
    fi
    local good_ids line fields sub_fpr prim_fpr found=""
    good_ids="$(awk '$1 == "[GNUPG:]" && $2 == "GOODSIG" { print toupper($3) }' <<<"$status")"
    while IFS= read -r line; do
        [[ "$line" == "[GNUPG:] VALIDSIG "* ]] || continue
        read -r -a fields <<<"$line"
        sub_fpr="${fields[2]^^}"
        prim_fpr="${fields[${#fields[@]} - 1]^^}"
        # GOODSIG carries the long key id of the signing (sub)key.
        if ! grep -qx -- "${sub_fpr: -16}" <<<"$good_ids"; then
            continue
        fi
        if [[ -n "$want_fpr" && "$prim_fpr" != "$want_fpr" ]]; then
            continue
        fi
        found="$prim_fpr"
        break
    done <<<"$status"
    if [[ -z "$found" ]]; then
        if [[ -n "$want_fpr" ]]; then
            hm_err "no good signature from the expected key $want_fpr on $data"
        else
            hm_err "no good signature from a key in $keyring on $data"
        fi
        return 1
    fi
    HM_SIG_FPR="$found"
    return 0
}

hm_verify_release_file() {
    # hm_verify_release_file FILE KEYRING ALLOW_UNSIGNED [EXPECTED_FINGERPRINT]
    #
    # Release-artifact check used by install.sh and upgrade.sh:
    #   1. SHA256SUMS next to FILE must list FILE with the right hash;
    #   2. SHA256SUMS.gpg next to it must be a good detached signature of
    #      SHA256SUMS made by a key in KEYRING.
    # ALLOW_UNSIGNED=1 (developer builds only) downgrades a missing signature,
    # keyring or SHA256SUMS to a loud warning. A checksum MISMATCH or a BAD
    # signature is fatal in every mode.
    local file="$1" keyring="$2" allow_unsigned="$3" want_fpr="${4:-}"
    local dir sums sig
    dir="$(cd -- "$(dirname -- "$file")" && pwd)"
    sums="$dir/SHA256SUMS"
    sig="$dir/SHA256SUMS.gpg"

    if [[ -f "$sums" ]]; then
        if ! hm_verify_sums_entry "$sums" "$file"; then
            hm_err "refusing: $file does not match $sums"
            return "$HM_EXIT_VERIFY"
        fi
        hm_log "sha256 of $(basename -- "$file") matches $sums"
    elif [[ "$allow_unsigned" == "1" ]]; then
        hm_banner "UNSIGNED DEVELOPMENT INSTALL" \
            "No SHA256SUMS file next to $file." \
            "Nothing proves where this package came from. Never do this on a customer machine."
        return 0
    else
        hm_err "refusing: no SHA256SUMS file next to $file"
        return "$HM_EXIT_VERIFY"
    fi

    if [[ -f "$sig" && -n "$keyring" ]]; then
        if ! hm_verify_detached "$keyring" "$sig" "$sums" "$want_fpr"; then
            hm_err "refusing: the signature on $sums could not be verified with $keyring"
            return "$HM_EXIT_VERIFY"
        fi
        hm_log "good signature on SHA256SUMS from key $HM_SIG_FPR"
        return 0
    fi

    if [[ "$allow_unsigned" == "1" ]]; then
        hm_banner "UNSIGNED DEVELOPMENT INSTALL" \
            "The checksum matches, but the signature was NOT verified" \
            "(SHA256SUMS.gpg present: $([[ -f "$sig" ]] && echo yes || echo no); --keyring given: $([[ -n "$keyring" ]] && echo yes || echo no))." \
            "Nothing proves where this package came from. Never do this on a customer machine."
        return 0
    fi
    if [[ ! -f "$sig" ]]; then
        hm_err "refusing: no SHA256SUMS.gpg next to $sums (unsigned package)"
    else
        hm_err "refusing: --keyring FILE is required to verify $sig"
    fi
    return "$HM_EXIT_VERIFY"
}

# ---------------------------------------------------------------------------
# Small helpers shared by install / upgrade / uninstall
# ---------------------------------------------------------------------------
hm_confirm() {
    # hm_confirm PROMPT — returns 0 only when the operator types "yes".
    local reply=""
    printf '%s [type yes to continue] ' "$1" >&2
    if ! IFS= read -r reply; then
        printf '\n' >&2
        return 1
    fi
    [[ "$reply" == "yes" ]]
}

hm_is_root() { [[ "$(id -u)" == "0" ]]; }

hm_require_root_owned() {
    # hm_require_root_owned PATH... — every path must exist, be owned by uid 0
    # and not be writable by group or others. Used for the rollback store: a
    # package taken from a directory that an unprivileged user can write to
    # must never be handed to dpkg by root.
    local p owner mode
    for p in "$@"; do
        if [[ ! -e "$p" || -L "$p" ]]; then
            hm_err "$p is missing or is a symbolic link"
            return 1
        fi
        owner="$(stat -c '%u' -- "$p")"
        mode="$(stat -c '%a' -- "$p")"
        if [[ "$owner" != "0" ]]; then
            hm_err "$p is owned by uid $owner, expected root"
            return 1
        fi
        if (((8#$mode & 8#022) != 0)); then
            hm_err "$p is writable by group or others (mode $mode)"
            return 1
        fi
    done
    return 0
}

hm_file_fingerprint() {
    # "sha256 mode uid:gid" for an existing file, "absent" otherwise.
    local f="$1"
    if [[ -e "$f" || -L "$f" ]]; then
        printf '%s %s\n' "$(sha256sum -- "$f" 2>/dev/null | cut -d' ' -f1 || echo unreadable)" "$(stat -c '%a %u:%g' -- "$f")"
    else
        printf 'absent\n'
    fi
}

# ---------------------------------------------------------------------------
# Host inventory: software and configuration that the HappyMining scripts must
# leave exactly as they found it. Read-only.
# ---------------------------------------------------------------------------
hm_dpkg_query() {
    # hm_dpkg_query ROOT ARGS... — dpkg-query against the package database of ROOT.
    local root="$1"
    shift
    if [[ -n "$root" ]]; then
        dpkg-query --admindir="$root/var/lib/dpkg" "$@"
    else
        dpkg-query "$@"
    fi
}

hm_pkg_version() {
    # Print the version of an installed package, or nothing when it is not
    # fully installed ("install ok installed").
    local root="$1" pkg="$2" out
    # shellcheck disable=SC2016  # dpkg-query format string, not a shell expansion
    out="$(hm_dpkg_query "$root" -W -f='${db:Status-Abbrev}|${Version}\n' -- "$pkg" 2>/dev/null || true)"
    if [[ "$out" == "ii "* ]]; then
        printf '%s\n' "${out#*|}"
    fi
}

hm_host_state() {
    # hm_host_state ROOT — one line per fact about Docker, the Vast host
    # software, NVIDIA drivers, kernels, mounts and network configuration.
    # The output is compared before and after an install / upgrade / removal:
    # any difference is reported as an error.
    local root="$1" f rel
    for rel in etc/fstab etc/docker/daemon.json etc/systemd/system/vastai.service \
        etc/apt/preferences.d/vast-packages etc/default/grub; do
        printf 'file /%s: %s\n' "$rel" "$(hm_file_fingerprint "$root/$rel")"
    done
    for f in "$root"/etc/netplan/*; do
        [[ -e "$f" ]] || continue
        printf 'file %s: %s\n' "${f#"$root"}" "$(hm_file_fingerprint "$f")"
    done
    for rel in var/lib/docker var/lib/vastai_kaalia var/lib/containerd; do
        if [[ -d "$root/$rel" ]]; then
            printf 'dir /%s: present %s\n' "$rel" "$(stat -c '%a %u:%g' -- "$root/$rel")"
        else
            printf 'dir /%s: absent\n' "$rel"
        fi
    done
    printf 'packages:\n'
    # shellcheck disable=SC2016  # dpkg-query format string, not a shell expansion
    hm_dpkg_query "$root" -W -f='  ${Package} ${Version} ${db:Status-Abbrev}\n' \
        'docker*' 'containerd*' 'nvidia*' 'libnvidia*' 'linux-image*' 'linux-modules*' \
        'linux-headers*' 'linux-generic*' 2>/dev/null | LC_ALL=C sort || true
    printf 'holds:\n'
    # shellcheck disable=SC2016  # dpkg-query format string, not a shell expansion
    hm_dpkg_query "$root" -W -f='${db:Status-Want} ${Package}\n' 2>/dev/null |
        awk '$1 == "hold" { print "  " $2 }' | LC_ALL=C sort || true
    if [[ -z "$root" ]]; then
        if [[ -r /proc/driver/nvidia/version ]]; then
            printf 'nvidia kernel module: %s\n' "$(head -n 1 /proc/driver/nvidia/version)"
        else
            printf 'nvidia kernel module: not loaded\n'
        fi
        printf 'running kernel: %s\n' "$(uname -r)"
        if [[ -r /proc/self/mounts ]]; then
            printf 'mounts: %s\n' "$(awk '{ print $1, $2, $3, $4 }' /proc/self/mounts | grep -vE ' (/run|/proc|/sys|/dev)(/| )' | LC_ALL=C sort | sha256sum | cut -d' ' -f1)"
        fi
    fi
}

hm_host_summary() {
    # Human-readable summary of what was found (derived from hm_host_state).
    local root="$1" state="$2" line
    if grep -q '^  docker' <<<"$state" || [[ -d "$root/var/lib/docker" ]]; then
        hm_log "existing Docker installation detected — it will be left exactly as it is:"
        while IFS= read -r line; do hm_log "   $line"; done < <(grep -E '^  (docker|containerd)' <<<"$state" || true)
        [[ -d "$root/var/lib/docker" ]] && hm_log "   /var/lib/docker is present"
        [[ -f "$root/etc/docker/daemon.json" ]] && hm_log "   /etc/docker/daemon.json is present"
    else
        hm_log "no Docker installation detected (none will be installed by this script)"
    fi
    if [[ -d "$root/var/lib/vastai_kaalia" || -f "$root/etc/systemd/system/vastai.service" ]]; then
        hm_log "existing Vast host software detected — it will be left exactly as it is"
    else
        hm_log "no Vast host software detected (it is installed later by the local operator, never by this script)"
    fi
    if grep -qE '^  (nvidia|libnvidia)' <<<"$state"; then
        hm_log "NVIDIA packages detected — they will be left exactly as they are:"
        while IFS= read -r line; do hm_log "   $line"; done < <(grep -E '^  nvidia-(driver|headless)' <<<"$state" || true)
    else
        hm_log "no NVIDIA driver packages detected (drivers are never installed by this script)"
    fi
}

hm_assert_host_unchanged() {
    # hm_assert_host_unchanged BEFORE AFTER
    local before="$1" after="$2"
    if [[ "$before" == "$after" ]]; then
        hm_log "verified: Docker, Vast software, NVIDIA drivers, kernels, mounts and network files are unchanged"
        return 0
    fi
    hm_err "HOST STATE CHANGED during this operation. This must never happen. Differences:"
    diff <(printf '%s\n' "$before") <(printf '%s\n' "$after") >&2 || true
    return 1
}

# ---------------------------------------------------------------------------
# GnuPG home directories (release tooling)
# ---------------------------------------------------------------------------
hm_gpg_home() {
    # hm_gpg_home DIR — print the path to pass to gpg --homedir for DIR.
    # gpg-agent creates its socket inside the home directory and UNIX socket
    # paths are limited to about 107 bytes, so a signing home under a long
    # path makes every secret-key operation fail with "can't connect to the
    # gpg-agent". For a long DIR this returns a short symbolic link to it;
    # the caller removes the link with hm_gpg_home_release.
    local dir="$1" base link
    if ((${#dir} <= 60)); then
        printf '%s\n' "$dir"
        return 0
    fi
    for base in "${XDG_RUNTIME_DIR:-}" /tmp /dev/shm; do
        [[ -n "$base" && -d "$base" && -w "$base" ]] || continue
        link="$(mktemp -u "$base/hmgpg.XXXXXXXX")"
        if ln -s -- "$dir" "$link" 2>/dev/null; then
            printf '%s\n' "$link"
            return 0
        fi
    done
    printf '%s\n' "$dir"
}

hm_gpg_home_release() {
    # hm_gpg_home_release HOME_AS_USED REAL_DIR — stop the agent that gpg
    # started for this home and remove the short link, if one was made.
    local used="$1" real="$2"
    if hm_have gpgconf; then
        gpgconf --homedir "$used" --kill all >/dev/null 2>&1 || true
    fi
    if [[ "$used" != "$real" && -L "$used" ]]; then
        rm -f -- "$used"
    fi
}

hm_gpg_sign_detached() {
    # hm_gpg_sign_detached SIGNING_HOME FILE OUT_SIGNATURE [KEY_FINGERPRINT]
    #
    # Writes an ASCII-armoured detached signature of FILE. The signing home
    # must contain exactly one secret key unless KEY_FINGERPRINT is given.
    # The fingerprint of the key that was used is left in HM_SIGNER_FPR.
    local real_home="$1" file="$2" out="$3" key="${4:-}"
    local home keys count rc=0
    HM_SIGNER_FPR=""
    if [[ ! -d "$real_home" ]]; then
        hm_err "signing key home not found: $real_home"
        return 1
    fi
    real_home="$(cd -- "$real_home" && pwd)"
    home="$(hm_gpg_home "$real_home")"
    keys="$(gpg --homedir "$home" --batch --with-colons --list-secret-keys 2>/dev/null |
        awk -F: '$1 == "sec" { want = 1; next } want && $1 == "fpr" { print $10; want = 0 }')"
    count="$(grep -c . <<<"$keys" || true)"
    if [[ -z "$key" ]]; then
        if [[ "$count" != "1" ]]; then
            hm_gpg_home_release "$home" "$real_home"
            hm_err "expected exactly one secret key in $real_home, found $count (choose one with --signing-key FINGERPRINT)"
            return 1
        fi
        key="$keys"
    elif ! grep -qx -- "${key^^}" <<<"$keys"; then
        hm_gpg_home_release "$home" "$real_home"
        hm_err "no secret key $key in $real_home"
        return 1
    fi
    gpg --homedir "$home" --batch --yes --local-user "$key" \
        --armor --detach-sign --output "$out" -- "$file" || rc=$?
    hm_gpg_home_release "$home" "$real_home"
    if [[ "$rc" != "0" ]]; then
        hm_err "gpg could not sign $file"
        return 1
    fi
    # shellcheck disable=SC2034  # read by the calling script
    HM_SIGNER_FPR="${key^^}"
    return 0
}
