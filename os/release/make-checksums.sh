#!/usr/bin/env bash
#
# HappyMining OS — write dist/SHA256SUMS over all release artifacts and sign it.
#
#   os/release/make-checksums.sh --signing-key-home DIR [--dist DIR] [--dry-run]
#
# Output: <dist>/SHA256SUMS and <dist>/SHA256SUMS.gpg (ASCII-armoured detached
# signature). install.sh and upgrade.sh verify exactly this pair.

set -euo pipefail
umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OS_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_DIR="$(cd -- "$OS_DIR/.." && pwd)"
HM_PROG="make-checksums.sh"
# shellcheck source=os/install/lib.sh
. "$OS_DIR/install/lib.sh"

DIST_DIR="$REPO_DIR/dist"
SIGN_HOME=""
SIGN_KEY=""

usage() {
    cat <<'USAGE'
Usage: make-checksums.sh --signing-key-home DIR [options]

  --signing-key-home DIR   GnuPG home that holds the release signing key
  --signing-key FPR        which secret key to use when DIR holds several
  --dist DIR               artifact directory (default: <repo>/dist)
  --dry-run                list the artifacts and commands; write nothing
  -h, --help               this text

Covered: every regular file directly in DIR and in its sub-directories, except
SHA256SUMS, SHA256SUMS.gpg, *.partial, hidden files and directories, and cache/.
Exit codes: 0 done, 1 failure, 2 usage, 3 verification of the new signature
failed, 77 gpg not available.
USAGE
}

need_value() { [[ $# -ge 2 ]] || hm_die "$HM_EXIT_USAGE" "$1 needs a value"; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        --signing-key-home) need_value "$@"; SIGN_HOME="$2"; shift 2 ;;
        --signing-key) need_value "$@"; SIGN_KEY="$2"; shift 2 ;;
        --dist) need_value "$@"; DIST_DIR="$2"; shift 2 ;;
        --dry-run) HM_DRY_RUN=1; shift ;;
        -h | --help) usage; exit 0 ;;
        *) usage >&2; hm_die "$HM_EXIT_USAGE" "unknown argument: $1" ;;
    esac
done

[[ -n "$SIGN_HOME" ]] || { usage >&2; hm_die "$HM_EXIT_USAGE" "--signing-key-home DIR is required"; }
[[ -d "$DIST_DIR" ]] || hm_die "$HM_EXIT_USAGE" "artifact directory not found: $DIST_DIR"
DIST_DIR="$(cd -- "$DIST_DIR" && pwd)"

mapfile -t artifacts < <(
    cd -- "$DIST_DIR" &&
        find . -type f \
            ! -path './.*' ! -path '*/.*' ! -path './cache/*' \
            ! -name SHA256SUMS ! -name SHA256SUMS.gpg ! -name '*.partial' \
            -printf '%P\n' | LC_ALL=C sort
)
[[ ${#artifacts[@]} -gt 0 ]] || hm_die "$HM_EXIT_FAIL" "no artifacts found in $DIST_DIR"

if [[ "$HM_DRY_RUN" == "1" ]]; then
    hm_have gpg || hm_warn "prerequisite not available on this host: gpg (a real run would exit $HM_EXIT_SKIP)"
    printf 'DRY-RUN would write %s with sha256 of:\n' "$DIST_DIR/SHA256SUMS"
    printf '  %s\n' "${artifacts[@]}"
    printf 'DRY-RUN would run: %s\n' "$(hm_quote_cmd gpg --homedir "$SIGN_HOME" --batch --yes --local-user '<the one secret key>' --armor --detach-sign --output "$DIST_DIR/SHA256SUMS.gpg" -- "$DIST_DIR/SHA256SUMS")"
    exit 0
fi

hm_need_tools gpg gpgv gpgconf sha256sum
[[ -d "$SIGN_HOME" ]] || hm_die "$HM_EXIT_USAGE" "signing key home not found: $SIGN_HOME"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/hm-sums.XXXXXXXX")"
# shellcheck disable=SC2329  # invoked through the EXIT trap
cleanup() { rm -rf -- "$WORK"; }
trap cleanup EXIT

(
    cd -- "$DIST_DIR"
    for f in "${artifacts[@]}"; do
        sha256sum -- "$f"
    done
) >"$WORK/SHA256SUMS"

hm_gpg_sign_detached "$SIGN_HOME" "$WORK/SHA256SUMS" "$WORK/SHA256SUMS.gpg" "$SIGN_KEY" ||
    hm_die "$HM_EXIT_FAIL" "signing failed; $DIST_DIR/SHA256SUMS was not changed"
signer="$HM_SIGNER_FPR"

# Verify what was just produced, with the public key only, the same way
# install.sh will.
real_home="$(cd -- "$SIGN_HOME" && pwd)"
home="$(hm_gpg_home "$real_home")"
gpg --homedir "$home" --batch --export "$signer" >"$WORK/pub.gpg"
hm_gpg_home_release "$home" "$real_home"
hm_verify_detached "$WORK/pub.gpg" "$WORK/SHA256SUMS.gpg" "$WORK/SHA256SUMS" "$signer" ||
    hm_die "$HM_EXIT_VERIFY" "the new signature does not verify; nothing was published"

install -m 0644 -- "$WORK/SHA256SUMS" "$DIST_DIR/SHA256SUMS"
install -m 0644 -- "$WORK/SHA256SUMS.gpg" "$DIST_DIR/SHA256SUMS.gpg"

hm_log "wrote $DIST_DIR/SHA256SUMS (${#artifacts[@]} artifact(s)) and SHA256SUMS.gpg"
hm_log "signed by $signer"
if gpg --homedir "$real_home" --batch --with-colons --list-keys "$signer" 2>/dev/null | grep -q 'NOT FOR PRODUCTION'; then
    hm_banner "Signed with a DEVELOPMENT key (NOT FOR PRODUCTION)." \
        "These artifacts must not be shipped to customers."
fi
