#!/usr/bin/env bash
#
# HappyMining OS — create a local DEVELOPMENT release-signing key.
#
#   os/release/gen-dev-signing-key.sh [--signing-key-home DIR] [--out-pub FILE] [--dry-run]
#
# The key is generated on this machine, has no passphrase, expires after 90
# days and is labelled as a development key in its user ID. It is for local
# builds and tests only. It lives in .signing/ at the repository root, which is
# excluded from version control, and must never be used for a release that
# reaches a customer. Production key custody is described in docs/trust-chain.md.

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OS_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_DIR="$(cd -- "$OS_DIR/.." && pwd)"
HM_PROG="gen-dev-signing-key.sh"
# shellcheck source=os/install/lib.sh
. "$OS_DIR/install/lib.sh"

DEV_UID="HappyMining DEVELOPMENT release signing key (NOT FOR PRODUCTION) <dev-release@happymining.invalid>"
SIGN_HOME="$REPO_DIR/.signing"
OUT_PUB="$REPO_DIR/dist/happymining-dev-release.pub.asc"
EXPIRE="90d"

usage() {
    cat <<USAGE
Usage: gen-dev-signing-key.sh [options]

  --signing-key-home DIR   GnuPG home to create (default: <repo>/.signing)
  --out-pub FILE           where to export the public key
                           (default: <repo>/dist/happymining-dev-release.pub.asc)
  --dry-run                print what would be done; create nothing
  -h, --help               this text

Refuses to run when DIR already holds a secret key.
Exit codes: 0 done, 1 failure, 2 usage, 5 refused, 77 gpg not available.
USAGE
}

need_value() { [[ $# -ge 2 ]] || hm_die "$HM_EXIT_USAGE" "$1 needs a value"; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        --signing-key-home) need_value "$@"; SIGN_HOME="$2"; shift 2 ;;
        --out-pub) need_value "$@"; OUT_PUB="$2"; shift 2 ;;
        --dry-run) HM_DRY_RUN=1; shift ;;
        -h | --help) usage; exit 0 ;;
        *) usage >&2; hm_die "$HM_EXIT_USAGE" "unknown argument: $1" ;;
    esac
done

if [[ "$HM_DRY_RUN" == "1" ]]; then
    hm_have gpg || hm_warn "prerequisite not available on this host: gpg (a real run would exit $HM_EXIT_SKIP)"
    printf 'DRY-RUN would create GnuPG home (mode 0700): %s\n' "$SIGN_HOME"
    printf 'DRY-RUN would run: %s\n' "$(hm_quote_cmd gpg --homedir "$SIGN_HOME" --batch --pinentry-mode loopback --passphrase '' --quick-generate-key "$DEV_UID" ed25519 sign "$EXPIRE")"
    printf 'DRY-RUN would export the public key to: %s\n' "$OUT_PUB"
    exit 0
fi

hm_need_tools gpg gpgconf

if [[ -d "$SIGN_HOME" ]] && [[ -n "$(ls -A -- "$SIGN_HOME" 2>/dev/null)" ]]; then
    hm_die "$HM_EXIT_REFUSED" "$SIGN_HOME already exists and is not empty; refusing to touch an existing signing home"
fi
mkdir -p -- "$SIGN_HOME"
chmod 0700 -- "$SIGN_HOME"
SIGN_HOME="$(cd -- "$SIGN_HOME" && pwd)"
mkdir -p -- "$(dirname -- "$OUT_PUB")"

home="$(hm_gpg_home "$SIGN_HOME")"
# shellcheck disable=SC2329  # invoked through the EXIT trap
cleanup() { hm_gpg_home_release "$home" "$SIGN_HOME"; }
trap cleanup EXIT

gpg --homedir "$home" --batch --quiet --pinentry-mode loopback --passphrase '' \
    --quick-generate-key "$DEV_UID" ed25519 sign "$EXPIRE" ||
    hm_die "$HM_EXIT_FAIL" "gpg could not generate the development key"
fpr="$(gpg --homedir "$home" --batch --with-colons --list-secret-keys |
    awk -F: '$1 == "sec" { want = 1; next } want && $1 == "fpr" { print $10; exit }')"
[[ -n "$fpr" ]] || hm_die "$HM_EXIT_FAIL" "the new key could not be found in $SIGN_HOME"
(umask 022 && gpg --homedir "$home" --batch --armor --export "$fpr" >"$OUT_PUB")

cat >"$SIGN_HOME/README.txt" <<README
DEVELOPMENT signing key. Not for production. Never commit this directory.
Fingerprint: $fpr
Created by os/release/gen-dev-signing-key.sh; expires after $EXPIRE.
README

hm_log "development signing key created"
hm_log "  fingerprint: $fpr"
hm_log "  user ID:     $DEV_UID"
hm_log "  secret key:  $SIGN_HOME (mode 0700; excluded from version control)"
hm_log "  public key:  $OUT_PUB"
hm_banner "This is a DEVELOPMENT key without a passphrase." \
    "Artifacts signed with it prove nothing to a customer. See docs/trust-chain.md for production key custody."
