#!/usr/bin/env bash
# Throwaway PostgreSQL for development and tests.
#
#   scripts/dev-postgres.sh start   start (or reuse) a database and print its URL
#   scripts/dev-postgres.sh stop    stop it and delete its data
#   scripts/dev-postgres.sh url     print the URL
#
# Uses Docker when a daemon is reachable, otherwise local PostgreSQL binaries
# (initdb/pg_ctl) in a temporary directory. The data is disposable either way.
# Nothing here is for production: see deploy/ for that.
set -euo pipefail

PORT="${HM_DEV_PG_PORT:-54329}"
NAME="happymining-dev-pg"
STATE_DIR="${HM_DEV_PG_DIR:-${TMPDIR:-/tmp}/happymining-dev-pg}"
PASSWORD="happymining_dev"
URL="postgresql+psycopg://happymining:${PASSWORD}@127.0.0.1:${PORT}/happymining"

have_docker() { command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; }

pg_bin() {
  local candidate
  for candidate in "$(command -v pg_ctl 2>/dev/null || true)" /usr/lib/postgresql/*/bin/pg_ctl; do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then dirname "$candidate"; return 0; fi
  done
  return 1
}

# PostgreSQL refuses to run as root; drop to the postgres user when we are root.
as_pg() {
  if [ "$(id -u)" -eq 0 ]; then
    if command -v runuser >/dev/null 2>&1; then runuser -u postgres -- "$@"; else su postgres -s /bin/sh -c "$(printf '%q ' "$@")"; fi
  else
    "$@"
  fi
}

wait_ready() {
  local _
  for _ in $(seq 1 60); do
    if "$1" -h 127.0.0.1 -p "$PORT" -q >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  echo "PostgreSQL did not become ready on port $PORT" >&2
  return 1
}

start_local() {
  local bin
  bin="$(pg_bin)" || { echo "No Docker daemon and no local PostgreSQL binaries found." >&2; exit 1; }
  if [ -f "$STATE_DIR/data/postmaster.pid" ] && "$bin/pg_isready" -h 127.0.0.1 -p "$PORT" -q; then
    echo "$URL"; return 0
  fi
  rm -rf "$STATE_DIR"
  mkdir -p "$STATE_DIR"
  if [ "$(id -u)" -eq 0 ]; then chown postgres "$STATE_DIR"; fi
  printf '%s\n' "$PASSWORD" > "$STATE_DIR/pw"
  if [ "$(id -u)" -eq 0 ]; then chown postgres "$STATE_DIR/pw"; fi
  as_pg "$bin/initdb" -D "$STATE_DIR/data" -U happymining --pwfile="$STATE_DIR/pw" --auth=scram-sha-256 \
    --encoding=UTF8 --locale=C >/dev/null
  as_pg "$bin/pg_ctl" -D "$STATE_DIR/data" -l "$STATE_DIR/log" -w \
    -o "-p $PORT -c listen_addresses=127.0.0.1 -c unix_socket_directories=$STATE_DIR -c fsync=off -c max_connections=200" \
    start >/dev/null
  wait_ready "$bin/pg_isready"
  PGPASSWORD="$PASSWORD" "$bin/createdb" -h 127.0.0.1 -p "$PORT" -U happymining happymining
  echo "$URL"
}

start_docker() {
  if ! docker ps --format '{{.Names}}' | grep -qx "$NAME"; then
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker run -d --name "$NAME" -e POSTGRES_USER=happymining -e POSTGRES_PASSWORD="$PASSWORD" \
      -e POSTGRES_DB=happymining -p "127.0.0.1:${PORT}:5432" postgres:16 >/dev/null
  fi
  local _
  for _ in $(seq 1 60); do
    if docker exec "$NAME" pg_isready -U happymining -q >/dev/null 2>&1; then echo "$URL"; return 0; fi
    sleep 0.5
  done
  echo "PostgreSQL container did not become ready" >&2
  exit 1
}

case "${1:-}" in
  start)
    if have_docker; then start_docker; else start_local; fi
    ;;
  stop)
    if have_docker; then docker rm -f "$NAME" >/dev/null 2>&1 || true; fi
    if [ -d "$STATE_DIR/data" ]; then
      bin="$(pg_bin)" && as_pg "$bin/pg_ctl" -D "$STATE_DIR/data" -m immediate stop >/dev/null 2>&1 || true
      rm -rf "$STATE_DIR"
    fi
    ;;
  url)
    echo "$URL"
    ;;
  *)
    echo "usage: $0 start|stop|url" >&2
    exit 2
    ;;
esac
