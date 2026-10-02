#!/usr/bin/env bash
# Restore a backup into a scratch database and verify it. This is the tested
# restoration procedure: run it regularly, not only after an incident.
#
#   restore-verify.sh --dump FILE --host HOST --user USER --scratch-db NAME [--port 5432] [--keep]
#
# It never touches the production database: it creates NAME (which must not
# exist), restores into it, checks that the schema is at the expected revision,
# recomputes the ledger and the audit hash chain, prints row counts, and drops
# NAME again unless --keep is given.
#
# To actually recover production, restore the same way into a fresh database
# and point HM_DATABASE_URL at it (docs/operations.md, "Disaster recovery").
set -euo pipefail

DUMP="" HOST="" PORT="5432" USER_NAME="" SCRATCH="" KEEP=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dump) DUMP="$2"; shift 2 ;;
    --host) HOST="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --user) USER_NAME="$2"; shift 2 ;;
    --scratch-db) SCRATCH="$2"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$DUMP" ] && [ -n "$HOST" ] && [ -n "$USER_NAME" ] && [ -n "$SCRATCH" ] || {
  echo "usage: $0 --dump FILE --host HOST --user USER --scratch-db NAME [--port PORT] [--keep]" >&2; exit 2; }
case "$SCRATCH" in
  *[!a-z0-9_]*|"") echo "scratch database name must be lower-case letters, digits and underscores" >&2; exit 2 ;;
  happymining) echo "refusing to use the production database name as the scratch database" >&2; exit 2 ;;
esac
[ -f "$DUMP" ] || { echo "dump file not found: $DUMP" >&2; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${HM_PYTHON:-$ROOT/api/.venv/bin/python}"
PSQL=(psql --host "$HOST" --port "$PORT" --username "$USER_NAME" --no-psqlrc --set ON_ERROR_STOP=1 --quiet)

if [ -f "$DUMP.sha256" ]; then
  ( cd "$(dirname "$DUMP")" && sha256sum --check --quiet "$(basename "$DUMP").sha256" )
  echo "checksum ok"
else
  echo "WARNING: no checksum file next to the dump; integrity of the file was not checked" >&2
fi

if [ "$("${PSQL[@]}" --dbname postgres --tuples-only --no-align \
      --command "SELECT count(*) FROM pg_database WHERE datname = '$SCRATCH'")" != "0" ]; then
  echo "database $SCRATCH already exists; choose another scratch name" >&2
  exit 1
fi
"${PSQL[@]}" --dbname postgres --command "CREATE DATABASE $SCRATCH"
cleanup() {
  if [ -z "$KEEP" ]; then
    "${PSQL[@]}" --dbname postgres --command "DROP DATABASE IF EXISTS $SCRATCH WITH (FORCE)" || true
  fi
}
trap cleanup EXIT

pg_restore --host "$HOST" --port "$PORT" --username "$USER_NAME" --dbname "$SCRATCH" \
  --no-owner --no-privileges --exit-on-error "$DUMP"
echo "restored into $SCRATCH"

"${PSQL[@]}" --dbname "$SCRATCH" --tuples-only --no-align --command \
  "SELECT 'schema revision: ' || version_num FROM alembic_version;
   SELECT 'journal entries: ' || count(*) FROM journal_entries;
   SELECT 'journal lines:   ' || count(*) FROM journal_lines;
   SELECT 'audit rows:      ' || count(*) FROM audit_log;
   SELECT 'triggers:        ' || count(*) FROM pg_trigger WHERE NOT tgisinternal;"

# Recompute the ledger and the audit chain from the restored data.
export HM_DATABASE_URL="postgresql+psycopg://${USER_NAME}@${HOST}:${PORT}/${SCRATCH}"
if [ -n "${PGPASSWORD:-}" ]; then
  export HM_DATABASE_URL="postgresql+psycopg://${USER_NAME}:${PGPASSWORD}@${HOST}:${PORT}/${SCRATCH}"
fi
PYTHONPATH="$ROOT/api" "$PY" -m happymining.cli verify
echo "restore verified"
