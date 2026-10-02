"""The HTTP API, on the standard library's threading server.

    GET  /healthz     no authentication, no detail
    POST /v1/search   {"query": "...", "limit": 8}
    POST /v1/ask      {"question": "..."}          501 when the provider is none
    GET  /v1/status
    POST /v1/sync     starts a run; 409 when one is running

Everything but /healthz needs `Authorization: Bearer <token>`. The index has
one access level: whoever holds the token can search everything indexed.

Requests and answers are JSON. A request body is at most 64 KiB and must
come with a Content-Length. Errors are `{"error": "<code>"}`; no stack trace,
no upstream error text. Wrong tokens are counted per client address and
further attempts are refused for a while.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import logging
import os
import subprocess
import sys
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from . import status as status_mod
from .answer import Answerer, AnswerError
from .config import Config, ConfigError, load_token
from .embedder import EmbedderError, OllamaEmbedder
from .state import read_summary
from .store import Passage, QdrantStore, StoreError
from .sync import decode_counts

log = logging.getLogger(__name__)

MAX_BODY_BYTES = 64 * 1024
MAX_QUERY_CHARS = 2000
SEARCH_LIMIT_DEFAULT = 8
SEARCH_LIMIT_MAX = 50
ASK_PASSAGES_DEFAULT = 6
ASK_PASSAGES_MAX = 20
MAX_CONCURRENT_REQUESTS = 32
SOCKET_TIMEOUT_S = 30.0
AUTH_MAX_FAILURES = 10
AUTH_WINDOW_S = 60.0
AUTH_MAX_CLIENTS = 4096
QUERY_EMBED_TIMEOUT_S = 60.0


class ApiError(Exception):
    def __init__(self, status: int, code: str, headers: dict[str, str] | None = None) -> None:
        self.status = status
        self.code = code
        self.headers = headers or {}
        super().__init__(code)


class TokenSource:
    """The bearer token, read again whenever the file changes.

    A token replaced on disk stops being accepted at the next request, without
    a restart. If the file becomes unreadable or invalid, nothing is accepted.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._stamp: tuple[int, int, int] | None = None
        self._digest: bytes | None = None
        self._value: str | None = None

    def _refresh(self) -> None:
        try:
            info = os.stat(self._path)
            stamp = (info.st_mtime_ns, info.st_size, info.st_ino)
        except OSError:
            self._stamp, self._digest, self._value = None, None, None
            return
        if stamp == self._stamp:
            return
        try:
            token = load_token(self._path)
        except ConfigError:
            self._stamp, self._digest, self._value = stamp, None, None
            return
        self._stamp, self._value = stamp, token
        self._digest = hashlib.sha256(token.encode("ascii")).digest()

    def check(self, presented: str) -> bool:
        with self._lock:
            self._refresh()
            expected = self._digest
        if expected is None:
            return False
        # Hashing both sides first makes the comparison independent of their lengths.
        given = hashlib.sha256(presented.encode("utf-8", errors="surrogateescape")).digest()
        return hmac.compare_digest(given, expected)

    def current(self) -> str | None:
        with self._lock:
            self._refresh()
            return self._value

    def last_loaded(self) -> str | None:
        """The token as last read, without looking at the file (for log redaction)."""
        return self._value


class AuthThrottle:
    """Limits wrong tokens per client address: 10 in 60 seconds, then refusal
    until the oldest of them is 60 seconds old."""

    def __init__(
        self,
        *,
        max_failures: int = AUTH_MAX_FAILURES,
        window_s: float = AUTH_WINDOW_S,
        max_clients: int = AUTH_MAX_CLIENTS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._max = max_failures
        self._window = window_s
        self._max_clients = max_clients
        self._clock = clock
        self._lock = threading.Lock()
        self._failures: OrderedDict[str, deque[float]] = OrderedDict()

    def retry_after(self, client: str) -> int:
        """0 when the client may try; otherwise the seconds to wait."""
        now = self._clock()
        with self._lock:
            times = self._failures.get(client)
            if times is None:
                return 0
            while times and now - times[0] >= self._window:
                times.popleft()
            if not times:
                del self._failures[client]
                return 0
            if len(times) < self._max:
                return 0
            return max(1, int(self._window - (now - times[0])) + 1)

    def record_failure(self, client: str) -> None:
        now = self._clock()
        with self._lock:
            times = self._failures.get(client)
            if times is None:
                times = deque(maxlen=self._max)
                self._failures[client] = times
                while len(self._failures) > self._max_clients:
                    self._failures.popitem(last=False)
            else:
                self._failures.move_to_end(client)
            times.append(now)


class SyncLauncher:
    """Starts a sync as a separate process.

    The run lock is taken here and handed to the child with its descriptor, so
    "is a run in progress" has one answer at any time. A separate process keeps
    the document parsers (and their memory) out of the server, and a parser
    that crashes takes down the run, not the API.
    """

    def __init__(self, *, config_dir: Path, state_dir: Path, nas_root: str) -> None:
        self._config_dir = config_dir
        self._state_dir = state_dir
        self._nas_root = nas_root
        self._mutex = threading.Lock()
        self._child: subprocess.Popen[bytes] | None = None

    def start(self) -> bool:
        """True when a run was started, False when one is already in progress."""
        with self._mutex:
            if self._child is not None and self._child.poll() is None:
                return False
            lock_fd = None
            for _ in range(4):
                lock_fd = status_mod.try_lock(self._state_dir)
                if lock_fd is not None:
                    break
                time.sleep(0.05)  # a status probe holds the lock for an instant
            if lock_fd is None:
                return False
            try:
                package_parent = str(Path(__file__).resolve().parent.parent)
                env = dict(os.environ)
                env["PYTHONPATH"] = os.pathsep.join(
                    p for p in (package_parent, env.get("PYTHONPATH", "")) if p
                )
                argv = [
                    sys.executable,
                    "-m",
                    "hm_vectorizer",
                    "sync",
                    "--config-dir",
                    str(self._config_dir),
                    "--state-dir",
                    str(self._state_dir),
                    "--nas-root",
                    self._nas_root,
                    "--lock-fd",
                    str(lock_fd),
                ]
                # No shell; the arguments are this process's own start-up values.
                child = subprocess.Popen(argv, pass_fds=(lock_fd,), stdin=subprocess.DEVNULL, env=env)  # noqa: S603
            finally:
                os.close(lock_fd)  # the child's copy keeps the lock
            self._child = child
            threading.Thread(target=self._reap, args=(child,), name="sync-reaper", daemon=True).start()
            return True

    def _reap(self, child: subprocess.Popen[bytes]) -> None:
        code = child.wait()
        if code != 0:
            log.warning("sync process ended with code %d", code)
        try:
            status_mod.repair_status(self._state_dir)
        except OSError:
            log.error("status file could not be repaired")

    def stop(self, timeout: float = 8.0) -> None:
        with self._mutex:
            child = self._child
        if child is None or child.poll() is not None:
            return
        child.terminate()
        try:
            child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            child.kill()


class App:
    """What the routes do. No HTTP in here."""

    def __init__(
        self,
        cfg: Config,
        *,
        state_dir: Path,
        token: TokenSource,
        answerer: Answerer,
        launcher: Any,
        embedder: OllamaEmbedder | None = None,
        store: QdrantStore | None = None,
        throttle: AuthThrottle | None = None,
    ) -> None:
        self.cfg = cfg
        self.state_dir = state_dir
        self.token = token
        self.answerer = answerer
        self.launcher = launcher
        self.embedder = embedder or OllamaEmbedder(
            cfg.ollama_url, cfg.embedding_model, timeout=QUERY_EMBED_TIMEOUT_S, retry_delays=()
        )
        self.store = store or QdrantStore(cfg.qdrant_url, cfg.collection)
        self.throttle = throttle or AuthThrottle()

    def retrieve(self, query: str, limit: int) -> list[Passage]:
        try:
            if not self.store.exists():
                return []
            vector = self.embedder.embed([query])[0]
            return self.store.search(vector, limit)
        except EmbedderError as exc:
            raise ApiError(503, exc.code) from None
        except StoreError as exc:
            raise ApiError(503, exc.code) from None

    def search(self, body: dict[str, Any]) -> dict[str, Any]:
        _only_keys(body, {"query", "limit"})
        query = _text(body, "query")
        limit = _limit(body, SEARCH_LIMIT_DEFAULT, SEARCH_LIMIT_MAX)
        return {"results": [_passage_json(p) for p in self.retrieve(query, limit)]}

    def ask(self, body: dict[str, Any]) -> dict[str, Any]:
        if self.answerer.provider == "none":
            raise ApiError(501, "answer_provider_none")
        _only_keys(body, {"question", "limit"})
        question = _text(body, "question")
        limit = _limit(body, ASK_PASSAGES_DEFAULT, ASK_PASSAGES_MAX)
        passages = self.retrieve(question, limit)
        if not passages:
            # Nothing was retrieved: nothing is sent to the provider.
            return {"answer": "", "sources": []}
        try:
            answer = self.answerer.answer(question, passages)
        except AnswerError as exc:
            raise ApiError(exc.http_status, exc.code) from None
        sources = [{"n": n, **_passage_json(p)} for n, p in enumerate(passages, start=1)]
        return {"answer": answer, "sources": sources}

    def status(self) -> dict[str, Any]:
        out = status_mod.read_status(self.state_dir)
        failed, skipped_text = read_summary(self.state_dir)
        skipped = decode_counts(skipped_text)
        out["failed_by_reason"] = failed
        out["skipped_by_reason"] = skipped
        out["answer_provider"] = self.answerer.provider
        return out

    def sync(self) -> dict[str, Any]:
        if not self.launcher.start():
            raise ApiError(409, "sync_running")
        return {"started": True}


def _only_keys(body: dict[str, Any], allowed: set[str]) -> None:
    if set(body) - allowed:
        raise ApiError(400, "unknown_field")


def _text(body: dict[str, Any], key: str) -> str:
    value = body.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ApiError(400, f"{key}_required")
    if len(value) > MAX_QUERY_CHARS:
        raise ApiError(400, f"{key}_too_long")
    return value.strip()


def _limit(body: dict[str, Any], default: int, maximum: int) -> int:
    value = body.get("limit", default)
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
        raise ApiError(400, "limit_invalid")
    return value


def _passage_json(passage: Passage) -> dict[str, Any]:
    return {
        "score": passage.score,
        "source": passage.source,
        "path": passage.path,
        "page": passage.page,
        "headings": list(passage.headings),
        "text": passage.text,
    }


_ROUTES: dict[str, tuple[str, bool]] = {
    # path -> (method, needs a JSON body)
    "/v1/search": ("POST", True),
    "/v1/ask": ("POST", True),
    "/v1/status": ("GET", False),
    "/v1/sync": ("POST", False),
}


class Handler(BaseHTTPRequestHandler):
    server_version = "hm-vectorizer"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = SOCKET_TIMEOUT_S
    server: VectorizerServer

    # -- plumbing -------------------------------------------------------------

    def version_string(self) -> str:
        return "hm-vectorizer"

    def log_message(self, format: str, *args: Any) -> None:
        # The default writes the raw request line to stderr. Requests are logged in _handle.
        return

    def _send(self, status: int, payload: dict[str, Any], headers: dict[str, str] | None = None) -> None:
        if self.request_version == "HTTP/0.9":
            # The base class answers an HTTP/0.9 request, and on some Python
            # versions a malformed request line, without status line or headers.
            # This service speaks HTTP/1.x only: every answer carries both.
            self.request_version = ""
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)
        self.close_connection = True

    def _route(self) -> str:
        path = self.path.split("?", 1)[0]
        return path if path == "/healthz" or path in _ROUTES else "other"

    def _handle(self) -> None:
        started = time.monotonic()
        route = self._route()
        status = 500
        try:
            status, payload, headers = self._dispatch(route)
        except ApiError as exc:
            status, payload, headers = exc.status, {"error": exc.code}, exc.headers
        except Exception as exc:
            log.error("request failed: %s", exc.__class__.__name__)
            log.debug("request failure", exc_info=True)
            status, payload, headers = 500, {"error": "internal"}, {}
        with contextlib.suppress(OSError):
            self._send(status, payload, headers)
        log.info("%s %s -> %d (%.0f ms)", self.command, route, status, (time.monotonic() - started) * 1000)

    def _dispatch(self, route: str) -> tuple[int, dict[str, Any], dict[str, str]]:
        app = self.server.app
        if route == "/healthz":
            if self.command != "GET":
                raise ApiError(405, "method_not_allowed", {"Allow": "GET"})
            return 200, {"status": "ok"}, {}
        if route == "other":
            raise ApiError(404, "not_found")
        method, has_body = _ROUTES[route]
        if self.command != method:
            raise ApiError(405, "method_not_allowed", {"Allow": method})

        self._authenticate()
        body = self._read_json() if has_body else self._no_body()
        if route == "/v1/search":
            return 200, app.search(body), {}
        if route == "/v1/ask":
            return 200, app.ask(body), {}
        if route == "/v1/status":
            return 200, app.status(), {}
        return 202, app.sync(), {}

    def _authenticate(self) -> None:
        app = self.server.app
        client = self.client_address[0]
        wait = app.throttle.retry_after(client)
        if wait:
            raise ApiError(429, "too_many_failed_authentications", {"Retry-After": str(wait)})
        header = self.headers.get("Authorization", "")
        scheme, _, presented = header.partition(" ")
        if scheme.lower() != "bearer" or not presented.strip():
            raise ApiError(401, "unauthorized", {"WWW-Authenticate": "Bearer"})
        if not app.token.check(presented.strip()):
            app.throttle.record_failure(client)
            raise ApiError(401, "unauthorized", {"WWW-Authenticate": "Bearer"})

    def _content_length(self) -> int:
        if self.headers.get("Transfer-Encoding"):
            raise ApiError(411, "length_required")
        raw = self.headers.get("Content-Length")
        if raw is None:
            raise ApiError(411, "length_required")
        if not raw.isascii() or not raw.isdigit():
            raise ApiError(400, "bad_content_length")
        return int(raw)

    def _no_body(self) -> dict[str, Any]:
        """A route that takes no body. A request without Content-Length and
        without Transfer-Encoding has an empty body (RFC 9112, 6.3): accepted.
        Whatever body is sent is not read; the connection is closed after the answer."""
        if self.command != "POST":
            return {}
        if self.headers.get("Content-Length") is None and not self.headers.get("Transfer-Encoding"):
            return {}
        if self._content_length() > MAX_BODY_BYTES:
            raise ApiError(413, "body_too_large")
        return {}

    def _read_json(self) -> dict[str, Any]:
        length = self._content_length()
        if length > MAX_BODY_BYTES:
            raise ApiError(413, "body_too_large")
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise ApiError(415, "json_required")
        try:
            raw = self.rfile.read(length)
        except OSError:
            raise ApiError(408, "body_not_received") from None
        if len(raw) != length:
            raise ApiError(400, "body_incomplete")
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise ApiError(400, "bad_json") from None
        if not isinstance(body, dict):
            raise ApiError(400, "json_object_required")
        return body

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_DELETE = _handle
    do_PATCH = _handle
    do_HEAD = _handle
    do_OPTIONS = _handle

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        # Malformed requests are answered by the base class through here: keep it JSON, without detail.
        with contextlib.suppress(OSError):
            self._send(code, {"error": "bad_request"})


class VectorizerServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, address: tuple[str, int], app: App) -> None:
        super().__init__(address, Handler)
        self.app = app
        self._slots = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            # Too many requests at once: drop the connection instead of piling up threads.
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request: Any, client_address: Any) -> None:
        # The default prints a traceback to stderr.
        log.debug("connection error", exc_info=True)
