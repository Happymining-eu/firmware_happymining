#!/usr/bin/env bash
# Back up the HappyMining database to a compressed custom-format dump with a
# SHA-256 checksum next to it.
#
#   backup.sh --host HOST --user USER --database DB --out-dir DIR [--port 5432]
#
# The password comes from PGPASSWORD or ~/.pgpass, never from the command line.
# With Docker Compose:  docker compose -f deploy/docker-compose.yml --env-file deploy/.env run --rm backup
#
# A backup you have not restored is not a backup: see scripts/restore-verify.sh.
set -euo pipefail

HOST="" PORT="5432" USER_NAME="" DATABASE="" OUT_DIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --user) USER_NAME="$2"; shift 2 ;;
    --database) DATABASE="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$HOST" ] && [ -n "$USER_NAME" ] && [ -n "$DATABASE" ] && [ -n "$OUT_DIR" ] || {
  echo "usage: $0 --host HOST --user USER --database DB --out-dir DIR [--port PORT]" >&2; exit 2; }

PG_DUMP="${PG_DUMP:-pg_dump}"
command -v "$PG_DUMP" >/dev/null 2>&1 || { echo "pg_dump not found" >&2; exit 1; }

umask 077
mkdir -p "$OUT_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
FILE="$OUT_DIR/happymining-${STAMP}.dump"
TMP="$FILE.partial"

"$PG_DUMP" --host "$HOST" --port "$PORT" --username "$USER_NAME" --dbname "$DATABASE" \
  --format=custom --compress=6 --no-owner --no-privileges --file "$TMP"
mv "$TMP" "$FILE"
( cd "$OUT_DIR" && sha256sum "$(basename "$FILE")" > "$(basename "$FILE").sha256" )
echo "$FILE"
