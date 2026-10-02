#!/usr/bin/env bash
# Run the acceptance demo end to end on this machine. DEMO mode, synthetic data.
#
# Starts a throwaway PostgreSQL, creates a fresh "happymining_demo" database,
# migrates and seeds it, starts the API on a loopback port, runs
# scripts/acceptance_demo.py against it over HTTP with the simulator binary,
# then stops the API. Set HM_DEMO_KEEP=1 to leave the API running afterwards.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${HM_DEMO_PORT:-8765}"
SIMULATOR="$ROOT/dist/bin/hm-simulator"
PY="${HM_PYTHON:-$ROOT/api/.venv/bin/python}"

[ -x "$SIMULATOR" ] || { echo "missing $SIMULATOR; run: make build-agent" >&2; exit 2; }
[ -x "$PY" ] || { echo "missing $PY; run: make setup" >&2; exit 2; }

if [ "$(id -u)" -eq 0 ] && [ -z "${HM_DEV_PG_DIR:-}" ] && [ -d /var/lib/postgresql ]; then
  export HM_DEV_PG_DIR=/var/lib/postgresql/hm-dev
fi
BASE_URL="$("$ROOT/scripts/dev-postgres.sh" start | tail -n 1)"
DEMO_URL="${BASE_URL%/*}/happymining_demo"

"$PY" - "$BASE_URL" <<'PY'
import sys
from sqlalchemy import create_engine, text
engine = create_engine(sys.argv[1], isolation_level="AUTOCOMMIT")
with engine.connect() as conn:
    conn.execute(text("DROP DATABASE IF EXISTS happymining_demo WITH (FORCE)"))
    conn.execute(text("CREATE DATABASE happymining_demo"))
PY

export HM_MODE=demo
export HM_PROVIDER=fake
export HM_DATABASE_URL="$DEMO_URL"
# Published demo values. LIVE mode refuses to start with either of them.
export HM_SECRET_KEY="demo-secret-key-demo-secret-key-demo-secret-key"
export HM_FIELD_ENCRYPTION_KEY="ZGVtby1maWVsZC1lbmNyeXB0aW9uLWtleS0wMDAwMDA="
export HM_DEMO_LOGIN_ENABLED=true
export HM_COOKIE_SECURE=false
export HM_PAYOUTS_ENABLED=true
export HM_PAYOUT_PROVIDER=mock
export HM_PUBLIC_BASE_URL="http://127.0.0.1:${PORT}"
export HM_ALLOWED_HOSTS="127.0.0.1,localhost"
# The simulator sends a sample every 40 ms; a real agent sends one a minute.
export HM_DEVICE_HEARTBEAT_RATE_LIMIT_PER_MINUTE=100000
export HM_DEVICE_REQUEST_RATE_LIMIT_PER_MINUTE=100000
export HM_LOG_LEVEL=WARNING
export PYTHONPATH="$ROOT/api"

cd "$ROOT"
"$PY" -m happymining.cli migrate
"$PY" -m happymining.cli seed-demo >/dev/null

"$PY" -m uvicorn happymining.main:app_factory --factory --host 127.0.0.1 --port "$PORT" --log-level warning &
API_PID=$!
cleanup() { if [ -z "${HM_DEMO_KEEP:-}" ]; then kill "$API_PID" 2>/dev/null || true; wait "$API_PID" 2>/dev/null || true; fi; }
trap cleanup EXIT

for _ in $(seq 1 60); do
  if "$PY" -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:${PORT}/readyz', timeout=1)" 2>/dev/null; then break; fi
  sleep 0.25
done

"$PY" "$ROOT/scripts/acceptance_demo.py" --api-url "http://127.0.0.1:${PORT}" --simulator "$SIMULATOR"

if [ -n "${HM_DEMO_KEEP:-}" ]; then
  echo
  echo "API left running (pid $API_PID): http://127.0.0.1:${PORT}/login  — use a demo account."
  trap - EXIT
fi
