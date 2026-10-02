"""Command line: `python -m hm_vectorizer serve | sync | status | healthcheck | selfcheck`.

Exit codes (README.md, "Command line"):

- `serve`: 0 stopped by SIGTERM/SIGINT; 2 configuration, token or state
  directory refused (nothing started).
- `sync`: 0 the run finished with state `idle` (files that failed are counted
  in the status, they do not make the run fail); 1 the run ended with state
  `error` (see `detail`); 2 configuration refused or state directory missing
  or not writable (nothing indexed); 3 another sync holds the lock (nothing
  ran).
- `status`: 0, the status printed as JSON.
- `healthcheck`: 0 the local API answers `/healthz`; 1 otherwise.
- `selfcheck`: 0 Docling parses offline; 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import threading
from pathlib import Path

from . import status as status_mod
from .answer import Answerer
from .config import API_KEY_ENV, CLOUD_PROVIDERS, NAS_ROOT, Config, ConfigError, load_config, take_api_key
from .http_client import HttpError, JsonHttpClient
from .logs import setup_logging
from .server import App, SyncLauncher, TokenSource, VectorizerServer
from .sync import SyncBusy, run_sync

log = logging.getLogger("hm_vectorizer")

DEFAULT_PORT = 8765
CONFIG_NAME = "vectorizer.json"
TOKEN_NAME = "token"  # noqa: S105 - a file name


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hm_vectorizer", description="HappyMining NAS vectorizer")
    parser.add_argument("--version", action="version", version="hm_vectorizer 1")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--config-dir", type=Path, default=Path("/config"))
        p.add_argument("--state-dir", type=Path, default=Path("/state"))
        p.add_argument("--nas-root", default=NAS_ROOT, help="where the sources are mounted (for tests)")

    serve = sub.add_parser("serve", help="run the HTTP API")
    common(serve)
    serve.add_argument("--host", default="0.0.0.0")  # noqa: S104 - a container port, published by Compose
    serve.add_argument("--port", type=int, default=DEFAULT_PORT)

    sync = sub.add_parser("sync", help="run one sync and wait for it")
    common(sync)
    sync.add_argument("--lock-fd", type=int, default=None, help=argparse.SUPPRESS)

    status = sub.add_parser("status", help="print the status as JSON")
    status.add_argument("--state-dir", type=Path, default=Path("/state"))

    health = sub.add_parser("healthcheck", help="exit 0 when the API answers on this machine")
    health.add_argument("--port", type=int, default=DEFAULT_PORT)

    sub.add_parser("selfcheck", help="exit 0 when Docling can parse documents with the files it has")
    return parser


def _load(args: argparse.Namespace) -> Config | None:
    try:
        return load_config(args.config_dir / CONFIG_NAME, nas_root=args.nas_root)
    except ConfigError as exc:
        print(f"configuration refused: {exc}", file=sys.stderr)
        return None


def _state_dir_ok(state_dir: Path) -> bool:
    if state_dir.is_dir() and os.access(state_dir, os.W_OK | os.X_OK):
        return True
    print("state directory missing or not writable", file=sys.stderr)
    return False


def _serve(args: argparse.Namespace) -> int:
    api_key = take_api_key(os.environ)
    token = TokenSource(args.config_dir / TOKEN_NAME)
    setup_logging(lambda: (token.last_loaded(), api_key.reveal() if api_key else None))
    cfg = _load(args)
    if cfg is None or not _state_dir_ok(args.state_dir):
        return 2
    if token.current() is None:
        print(
            "token refused: missing, unreadable, or not one line of 16 to 512 printable characters",
            file=sys.stderr,
        )
        return 2
    try:
        status_mod.repair_status(args.state_dir)
    except OSError:
        print("state directory not writable", file=sys.stderr)
        return 2

    launcher = SyncLauncher(config_dir=args.config_dir, state_dir=args.state_dir, nas_root=args.nas_root)
    app = App(
        cfg,
        state_dir=args.state_dir,
        token=token,
        answerer=Answerer(cfg, api_key),
        launcher=launcher,
    )
    server = VectorizerServer((args.host, args.port), app)
    if cfg.answer.provider in CLOUD_PROVIDERS and api_key is None:
        log.warning(
            "answer provider %s configured without a usable API key: /v1/ask will answer 503",
            cfg.answer.provider,
        )
    log.info(
        "serving on port %d: sources=%d answer_provider=%s ocr=%s",
        server.server_address[1],
        len(cfg.sources),
        cfg.answer.provider,
        cfg.ocr,
    )

    def stop(signum: int, frame: object) -> None:
        # shutdown() waits for serve_forever(), which runs in this thread: call it from another.
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        launcher.stop()
    log.info("stopped")
    return 0


def _sync(args: argparse.Namespace) -> int:
    # The run has no use for the cloud key, and the parsers it loads must not see it.
    os.environ.pop(API_KEY_ENV, None)
    setup_logging(lambda: ())
    cfg = _load(args)
    if cfg is None or not _state_dir_ok(args.state_dir):
        return 2
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda signum, frame: stop.set())
    try:
        result = run_sync(cfg, args.state_dir, lock_fd=args.lock_fd, should_stop=stop.is_set)
    except SyncBusy:
        print("a sync is already running", file=sys.stderr)
        return 3
    except OSError as exc:
        # The lock or status.json cannot be written: nothing was indexed.
        print(f"state directory not writable ({exc.__class__.__name__})", file=sys.stderr)
        return 2
    return 0 if result.status.get("state") == "idle" else 1


def _status(args: argparse.Namespace) -> int:
    print(json.dumps(status_mod.read_status(args.state_dir)))
    return 0


def _healthcheck(args: argparse.Namespace) -> int:
    try:
        answer = JsonHttpClient(max_response_bytes=4096).request(
            "GET", f"http://127.0.0.1:{args.port}/healthz", timeout=5.0
        )
    except HttpError:
        return 1
    return 0 if isinstance(answer, dict) and answer.get("status") == "ok" else 1


def _selfcheck(args: argparse.Namespace) -> int:
    from .selfcheck import run

    return run()


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    handlers = {
        "serve": _serve,
        "sync": _sync,
        "status": _status,
        "healthcheck": _healthcheck,
        "selfcheck": _selfcheck,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
