"""In-process fake HTTP servers for the vectorizer tests.

They record every request (method, path, query, headers, decoded body) and
answer in the shapes of the real APIs as documented by their vendors:

- FakeOllama: `POST /api/embed`, `POST /api/chat` (ollama/ollama docs/api.md)
- FakeQdrant: the collection, index, points, delete and query endpoints of
  Qdrant's OpenAPI specification. It refuses request shapes the real server
  would refuse (unknown filter keys, wrong vector size, a point id that is
  neither an unsigned integer nor a UUID), so a drift in the client's request
  shape fails the tests.
- FakeLLM: an OpenAI-compatible `/chat/completions` and Anthropic's
  `/v1/messages`, over HTTPS with a throw-away certificate.

They are fakes: they prove the client sends what the documentation
describes, not that a real server accepts it.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import ssl
import threading
import time
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

EMBED_DIM = 32


@dataclass
class Recorded:
    method: str
    path: str
    query: dict[str, list[str]]
    headers: dict[str, str]
    body: Any
    raw: bytes = b""


class Reply(Exception):
    """Raised by a fake to answer with this status and JSON body."""

    def __init__(self, status: int, body: Any, headers: dict[str, str] | None = None) -> None:
        self.status = status
        self.body = body
        self.headers = headers or {}
        super().__init__(status)


class FakeServer:
    def __init__(self, tls: tuple[str, str] | None = None) -> None:
        self.requests: list[Recorded] = []
        self._lock = threading.Lock()
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def _serve(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                try:
                    body = json.loads(raw.decode("utf-8")) if raw else None
                except ValueError:
                    body = None
                parts = urlsplit(self.path)
                recorded = Recorded(
                    method=self.command,
                    path=parts.path,
                    query=parse_qs(parts.query),
                    headers={k.lower(): v for k, v in self.headers.items()},
                    body=body,
                    raw=raw,
                )
                with fake._lock:
                    fake.requests.append(recorded)
                try:
                    status, payload, headers = 200, fake.handle(recorded), {}
                except Reply as reply:
                    status, payload, headers = reply.status, reply.body, reply.headers
                data = b"" if payload is None else json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Connection", "close")
                for name, value in headers.items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(data)
                self.close_connection = True

            do_GET = do_POST = do_PUT = do_DELETE = _serve

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.scheme = "http"
        if tls is not None:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=tls[0], keyfile=tls[1])
            self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)
            self.scheme = "https"
        self._thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05})
        self._thread.daemon = True
        self._thread.start()

    @property
    def url(self) -> str:
        return f"{self.scheme}://127.0.0.1:{self.httpd.server_address[1]}"

    def handle(self, request: Recorded) -> Any:
        raise Reply(404, {"error": "not found"})

    def calls(self, method: str, path: str) -> list[Recorded]:
        with self._lock:
            return [r for r in self.requests if r.method == method and r.path == path]

    def clear(self) -> None:
        with self._lock:
            self.requests.clear()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self._thread.join(timeout=5)


# --------------------------------------------------------------------------- Ollama


def fake_embedding(text: str, dim: int = EMBED_DIM) -> list[float]:
    """A deterministic bag-of-words vector: texts sharing words are close."""
    vector = [0.0] * dim
    for word in re.findall(r"[a-z0-9]+", text.lower()):
        slot = int.from_bytes(hashlib.sha256(word.encode()).digest()[:4], "big") % dim
        vector[slot] += 1.0
    norm = math.sqrt(sum(v * v for v in vector))
    if norm == 0:
        vector[0] = 1.0
        norm = 1.0
    return [v / norm for v in vector]


class FakeOllama(FakeServer):
    def __init__(self, models: tuple[str, ...] = ("bge-m3", "hermes3:8b"), dim: int = EMBED_DIM) -> None:
        self.models = set(models)
        self.dim = dim
        self.chat_answer = "The pump reference is HM-PUMP-7731 [1]."
        self.fail_embed_after: int | None = None  # after this many successful embed calls, answer 500
        self.embed_ok_calls = 0
        self.gate: threading.Event | None = None  # when set to an Event, embed calls wait for it
        self.gate_entered = threading.Event()
        super().__init__()

    def embedded_texts(self) -> list[str]:
        """Every text sent for embedding, the dimension probe excluded."""
        out: list[str] = []
        for request in self.calls("POST", "/api/embed"):
            inputs = request.body["input"]
            out.extend(t for t in inputs if t != "dimension probe")
        return out

    def handle(self, request: Recorded) -> Any:
        if request.method == "POST" and request.path == "/api/embed":
            return self._embed(request)
        if request.method == "POST" and request.path == "/api/chat":
            return self._chat(request)
        raise Reply(404, {"error": "not found"})

    def _embed(self, request: Recorded) -> Any:
        body = request.body
        if not isinstance(body, dict) or set(body) - {
            "model",
            "input",
            "truncate",
            "options",
            "keep_alive",
            "dimensions",
        }:
            raise Reply(400, {"error": "invalid request"})
        if body.get("model") not in self.models:
            raise Reply(404, {"error": f'model "{body.get("model")}" not found, try pulling it first'})
        inputs = body.get("input")
        if isinstance(inputs, str):
            inputs = [inputs]
        if not isinstance(inputs, list) or not all(isinstance(t, str) for t in inputs):
            raise Reply(400, {"error": "invalid input type"})
        probe = inputs == ["dimension probe"]
        if self.gate is not None and not probe:
            self.gate_entered.set()
            self.gate.wait(timeout=60)
        if self.fail_embed_after is not None and not probe:
            if self.embed_ok_calls >= self.fail_embed_after:
                raise Reply(500, {"error": "llama runner process has terminated"})
            self.embed_ok_calls += 1
        return {
            "model": body["model"],
            "embeddings": [fake_embedding(t, self.dim) for t in inputs],
            "total_duration": 14143917,
            "load_duration": 1019500,
            "prompt_eval_count": 8,
        }

    def _chat(self, request: Recorded) -> Any:
        body = request.body
        if not isinstance(body, dict) or body.get("stream") is not False:
            # The real endpoint streams unless "stream" is false; the client must ask for one object.
            raise Reply(400, {"error": "this fake only answers non-streaming requests"})
        if body.get("model") not in self.models:
            raise Reply(404, {"error": "model not found"})
        options = body.get("options", {})
        if not isinstance(options, dict) or any(
            not isinstance(v, int | float) or isinstance(v, bool) for v in options.values()
        ):
            raise Reply(400, {"error": "invalid options"})
        messages = body.get("messages")
        if not isinstance(messages, list) or not all(
            isinstance(m, dict) and m.get("role") in ("system", "user", "assistant", "tool") for m in messages
        ):
            raise Reply(400, {"error": "invalid messages"})
        return {
            "model": body["model"],
            "created_at": "2026-10-02T12:00:00.000000Z",
            "message": {"role": "assistant", "content": self.chat_answer},
            "done": True,
            "total_duration": 5191566416,
            "eval_count": 298,
        }


# --------------------------------------------------------------------------- Qdrant


@dataclass
class FakeCollection:
    size: int
    distance: str
    points: dict[str, dict[str, Any]] = field(default_factory=dict)
    indexes: dict[str, str] = field(default_factory=dict)


def _ok(result: Any) -> dict[str, Any]:
    return {"result": result, "status": "ok", "time": 0.001}


def _bad(message: str) -> Reply:
    return Reply(400, {"status": {"error": message}, "time": 0.0})


class FakeQdrant(FakeServer):
    def __init__(self) -> None:
        self.collections: dict[str, FakeCollection] = {}
        self.fail_upserts = False
        super().__init__()

    # -- helpers for assertions ------------------------------------------------

    def payloads(self, collection: str) -> list[dict[str, Any]]:
        return [p["payload"] for p in self.collections[collection].points.values()]

    def texts(self, collection: str) -> list[str]:
        return sorted(p["text"] for p in self.payloads(collection))

    def paths(self, collection: str) -> set[str]:
        return {p["path"] for p in self.payloads(collection)}

    # -- request handling ------------------------------------------------------

    def handle(self, request: Recorded) -> Any:
        match = re.fullmatch(r"/collections/([^/]+)(/.*)?", request.path)
        if match is None:
            raise Reply(404, {"status": {"error": "not found"}})
        name, rest = match.group(1), match.group(2) or ""
        method = request.method
        if rest == "/exists" and method == "GET":
            return _ok({"exists": name in self.collections})
        if rest == "" and method == "PUT":
            return self._create(name, request.body)
        if rest == "" and method == "GET":
            return self._info(name)
        if rest == "" and method == "DELETE":
            return _ok(self.collections.pop(name, None) is not None)
        collection = self.collections.get(name)
        if collection is None:
            raise Reply(404, {"status": {"error": f"Not found: Collection `{name}` doesn't exist!"}})
        wait = request.query.get("wait") == ["true"]
        status = "completed" if wait else "acknowledged"
        if rest == "/index" and method == "PUT":
            body = request.body
            if (
                not isinstance(body, dict)
                or set(body) - {"field_name", "field_schema"}
                or "field_name" not in body
            ):
                raise _bad("bad index request")
            if body.get("field_schema") not in (
                "keyword",
                "integer",
                "float",
                "geo",
                "text",
                "bool",
                "datetime",
                "uuid",
            ):
                raise _bad("bad field schema")
            collection.indexes[body["field_name"]] = body["field_schema"]
            return _ok({"operation_id": 1, "status": status})
        if rest == "/points" and method == "PUT":
            return _ok({"operation_id": 2, "status": self._upsert(collection, request.body, status)})
        if rest == "/points/delete" and method == "POST":
            return _ok({"operation_id": 3, "status": self._delete(collection, request.body, status)})
        if rest == "/points/query" and method == "POST":
            return _ok(self._query(collection, request.body))
        raise Reply(404, {"status": {"error": "not found"}})

    def _create(self, name: str, body: Any) -> Any:
        if not isinstance(body, dict) or not isinstance(body.get("vectors"), dict):
            raise _bad("vectors required")
        vectors = body["vectors"]
        if set(vectors) - {"size", "distance", "on_disk", "hnsw_config", "quantization_config", "datatype"}:
            raise _bad("unknown vector params")
        size, distance = vectors.get("size"), vectors.get("distance")
        if not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= 65536:
            raise _bad("bad size")
        if distance not in ("Cosine", "Euclid", "Dot", "Manhattan"):
            raise _bad("bad distance")
        if name in self.collections:
            raise Reply(409, {"status": {"error": f"Wrong input: Collection `{name}` already exists!"}})
        self.collections[name] = FakeCollection(size=size, distance=distance)
        return _ok(True)

    def _info(self, name: str) -> Any:
        collection = self.collections.get(name)
        if collection is None:
            raise Reply(404, {"status": {"error": f"Not found: Collection `{name}` doesn't exist!"}})
        return _ok(
            {
                "status": "green",
                "optimizer_status": "ok",
                "points_count": len(collection.points),
                "segments_count": 1,
                "config": {
                    "params": {"vectors": {"size": collection.size, "distance": collection.distance}},
                    "hnsw_config": {},
                    "optimizer_config": {},
                },
                "payload_schema": {k: {"data_type": v, "points": 0} for k, v in collection.indexes.items()},
            }
        )

    def _upsert(self, collection: FakeCollection, body: Any, status: str) -> str:
        if self.fail_upserts:
            raise Reply(500, {"status": {"error": "Service internal error"}})
        if not isinstance(body, dict) or set(body) - {"points"} or not isinstance(body.get("points"), list):
            raise _bad("points required")
        for point in body["points"]:
            if not isinstance(point, dict) or set(point) - {"id", "vector", "payload"}:
                raise _bad("bad point")
            pid = point.get("id")
            if isinstance(pid, str):
                try:
                    uuid.UUID(pid)
                except ValueError:
                    raise _bad("point id is not a UUID") from None
            elif not isinstance(pid, int) or isinstance(pid, bool) or pid < 0:
                raise _bad("bad point id")
            vector = point.get("vector")
            if not isinstance(vector, list) or len(vector) != collection.size:
                raise _bad(f"Wrong input: Vector dimension error: expected dim: {collection.size}")
            if not all(isinstance(v, int | float) and not isinstance(v, bool) for v in vector):
                raise _bad("bad vector")
            payload = point.get("payload")
            if payload is not None and not isinstance(payload, dict):
                raise _bad("bad payload")
            collection.points[str(pid)] = {"vector": [float(v) for v in vector], "payload": payload or {}}
        return status

    def _delete(self, collection: FakeCollection, body: Any, status: str) -> str:
        if not isinstance(body, dict) or set(body) - {"filter", "points"}:
            raise _bad("bad selector")
        if "points" in body:
            for pid in body["points"]:
                collection.points.pop(str(pid), None)
            return status
        flt = body.get("filter")
        if not isinstance(flt, dict):
            raise _bad("filter required")
        doomed = [pid for pid, p in collection.points.items() if _filter_matches(p["payload"], flt)]
        for pid in doomed:
            del collection.points[pid]
        return status

    def _query(self, collection: FakeCollection, body: Any) -> Any:
        allowed = {
            "query",
            "limit",
            "with_payload",
            "with_vector",
            "filter",
            "offset",
            "score_threshold",
            "using",
            "params",
        }
        if not isinstance(body, dict) or set(body) - allowed:
            raise _bad("bad query request")
        query = body.get("query")
        if not isinstance(query, list) or len(query) != collection.size:
            raise _bad("Wrong input: Vector dimension error")
        limit = body.get("limit", 10)
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise _bad("bad limit")
        scored = []
        for pid, point in collection.points.items():
            if "filter" in body and not _filter_matches(point["payload"], body["filter"]):
                continue
            scored.append((_cosine(query, point["vector"]), pid, point))
        scored.sort(key=lambda item: (-item[0], item[1]))
        points = []
        for score, pid, point in scored[:limit]:
            entry: dict[str, Any] = {"id": pid, "version": 3, "score": score}
            # The real default is no payload: the client must ask for it.
            if body.get("with_payload") is True:
                entry["payload"] = point["payload"]
            points.append(entry)
        return {"points": points}


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


def _condition_matches(payload: dict[str, Any], condition: Any) -> bool:
    if not isinstance(condition, dict) or "key" not in condition:
        raise _bad("bad condition")
    if set(condition) - {"key", "match", "range"}:
        raise _bad("unknown condition field")
    value = payload.get(condition["key"])
    if "match" in condition:
        match = condition["match"]
        if not isinstance(match, dict) or set(match) != {"value"}:
            raise _bad("bad match")
        return value == match["value"]
    if "range" in condition:
        bounds = condition["range"]
        if not isinstance(bounds, dict) or set(bounds) - {"lt", "gt", "gte", "lte"}:
            raise _bad("bad range")
        if not isinstance(value, int | float) or isinstance(value, bool):
            return False
        return (
            ("gte" not in bounds or value >= bounds["gte"])
            and ("gt" not in bounds or value > bounds["gt"])
            and ("lte" not in bounds or value <= bounds["lte"])
            and ("lt" not in bounds or value < bounds["lt"])
        )
    raise _bad("condition without a test")


def _filter_matches(payload: dict[str, Any], flt: Any) -> bool:
    # Qdrant's Filter schema has additionalProperties: false.
    if not isinstance(flt, dict) or set(flt) - {"must", "must_not", "should", "min_should"}:
        raise _bad("unknown filter field")
    must = flt.get("must") or []
    must_not = flt.get("must_not") or []
    if not isinstance(must, list) or not isinstance(must_not, list):
        raise _bad("bad filter")
    return all(_condition_matches(payload, c) for c in must) and not any(
        _condition_matches(payload, c) for c in must_not
    )


# --------------------------------------------------------------------------- cloud LLMs


class FakeLLM(FakeServer):
    """An OpenAI-compatible server and Anthropic's Messages API, over HTTPS."""

    def __init__(self, tls: tuple[str, str]) -> None:
        self.answer = "According to the handbook the reference is HM-PUMP-7731 [1]."
        self.redirect_to: str | None = None
        self.error_status: int | None = None
        self.error_echoes_credentials = False
        self.delay_s = 0.0
        super().__init__(tls=tls)

    def handle(self, request: Recorded) -> Any:
        if self.delay_s:
            time.sleep(self.delay_s)
        if self.redirect_to is not None:
            raise Reply(307, {"note": "moved"}, {"Location": self.redirect_to + request.path})
        if self.error_status is not None:
            echoed = ""
            if self.error_echoes_credentials:
                echoed = request.headers.get("authorization", "") + request.headers.get("x-api-key", "")
            raise Reply(
                self.error_status,
                {
                    "error": {
                        "message": f"Incorrect API key provided: {echoed}",
                        "type": "invalid_request_error",
                    }
                },
            )
        if request.method == "POST" and request.path.endswith("/chat/completions"):
            return self._openai(request)
        if request.method == "POST" and request.path == "/v1/messages":
            return self._anthropic(request)
        raise Reply(404, {"error": {"message": "not found"}})

    def _openai(self, request: Recorded) -> Any:
        if not request.headers.get("authorization", "").startswith("Bearer "):
            raise Reply(401, {"error": {"message": "You didn't provide an API key."}})
        body = request.body
        if not isinstance(body, dict) or not isinstance(body.get("model"), str):
            raise Reply(400, {"error": {"message": "you must provide a model parameter"}})
        messages = body.get("messages")
        if not isinstance(messages, list) or not messages:
            raise Reply(400, {"error": {"message": "messages required"}})
        if body.get("stream"):
            raise Reply(400, {"error": {"message": "this fake does not stream"}})
        return {
            "id": "chatcmpl-123",
            "object": "chat.completion",
            "created": 1790000000,
            "model": body["model"],
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": self.answer},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20},
        }

    def _anthropic(self, request: Recorded) -> Any:
        if not request.headers.get("x-api-key"):
            raise Reply(
                401,
                {
                    "type": "error",
                    "error": {"type": "authentication_error", "message": "x-api-key header is required"},
                },
            )
        if not request.headers.get("anthropic-version"):
            raise Reply(
                400,
                {
                    "type": "error",
                    "error": {
                        "type": "invalid_request_error",
                        "message": "anthropic-version header is required",
                    },
                },
            )
        body = request.body
        if not isinstance(body, dict):
            raise Reply(400, {"type": "error", "error": {"type": "invalid_request_error", "message": "body"}})
        for required in ("model", "max_tokens", "messages"):
            if required not in body:
                raise Reply(
                    400,
                    {
                        "type": "error",
                        "error": {"type": "invalid_request_error", "message": f"{required}: Field required"},
                    },
                )
        if "temperature" in body:
            # The client sends no sampling parameter (the current SDK's create
            # parameters do not list one); refusing it here makes adding one fail a test.
            raise Reply(
                400,
                {
                    "type": "error",
                    "error": {"type": "invalid_request_error", "message": "temperature is not supported"},
                },
            )
        if any(m.get("role") not in ("user", "assistant") for m in body["messages"]):
            raise Reply(
                400,
                {
                    "type": "error",
                    "error": {"type": "invalid_request_error", "message": "messages: Unexpected role"},
                },
            )
        return {
            "id": "msg_013Zva2CMHLNnXjNJJKqJ2EF",
            "type": "message",
            "role": "assistant",
            "model": body["model"],
            "content": [{"type": "text", "text": self.answer}],
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": {"input_tokens": 2095, "output_tokens": 503},
        }
