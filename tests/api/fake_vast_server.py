"""A fake Vast.ai API server for tests. SYNTHETIC: it is not Vast and holds no real data.

It listens on a loopback port and answers the endpoints the adapter uses, in
the shape recorded in docs/integration-evidence.md:

    GET    /api/v0/users/current
    GET    /api/v0/machines?owner=me
    GET    /api/v0/users/me/machine-earnings?owner=me&sday=&eday=&machid=
    DELETE /api/v0/machines/{id}/asks/

Faults are scripted per path: a queue of behaviours consumed one request at a
time (``429``, ``503``, ``timeout``, ``garbage``, ``redirect``, ...). Every
request is recorded so tests can assert on what was and was not sent.
"""

from __future__ import annotations

import json
import threading
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

API_KEY = "SYNTHETIC-test-key-not-a-real-vast-key"


class FakeVast:
    def __init__(self) -> None:
        self.machines: list[dict] = []
        # machine id -> {epoch_day: {"gpu_earn": ..., "sto_earn": ..., "bwu_earn": ..., "bwd_earn": ...}}
        self.earnings: dict[int, dict[int, dict[str, float | str]]] = {}
        self.faults: dict[str, deque] = defaultdict(deque)
        self.requests: list[dict] = []
        self.hang_s = 3.0
        self.per_machine_override: dict[int, dict] = {}
        self.ignore_machine_filter = False
        self._stopped = False
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> FakeVast:
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._stopped:
            return
        self._stopped = True
        self._server.shutdown()
        self._server.server_close()

    def fault(self, path_prefix: str, *behaviours: str | int) -> None:
        self.faults[path_prefix].extend(behaviours)

    def calls(self, method: str | None = None, contains: str = "") -> list[dict]:
        return [
            r for r in self.requests if (method is None or r["method"] == method) and contains in r["path"]
        ]

    def _handler(self):
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):  # keep test output quiet
                pass

            def _send(self, status: int, body: bytes, content_type: str = "application/json", headers=None):
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(body)

            def _json(self, status: int, payload) -> None:
                self._send(status, json.dumps(payload).encode())

            def _handle(self, method: str) -> None:
                parts = urlsplit(self.path)
                query = {k: v[0] for k, v in parse_qs(parts.query).items()}
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                fake.requests.append(
                    {
                        "method": method,
                        "path": parts.path,
                        "query": query,
                        "body": body,
                        "authorization": self.headers.get("Authorization", ""),
                    }
                )
                for prefix, queue in fake.faults.items():
                    if parts.path.startswith(prefix) and queue:
                        behaviour = queue.popleft()
                        if behaviour == "timeout":
                            time.sleep(fake.hang_s)
                            return self._json(200, {})
                        if behaviour == "garbage":
                            return self._send(200, b"<html>not json</html>", "text/html")
                        if behaviour == "wrong_shape":
                            return self._json(200, {"unexpected": True})
                        if behaviour == "redirect":
                            return self._send(302, b"", headers={"Location": "http://127.0.0.1:1/steal"})
                        if behaviour == "success_false":
                            return self._json(200, {"success": False, "error": "nope", "msg": "refused"})
                        if behaviour == 429:
                            return self._json(
                                429, {"detail": "API requests too frequent endpoint threshold=2.0"}
                            )
                        return self._json(int(behaviour), {"success": False, "error": "simulated"})

                if self.headers.get("Authorization") != f"Bearer {API_KEY}":
                    return self._json(403, {"success": False, "error": "auth_error", "msg": "bad key"})

                if method == "GET" and parts.path == "/api/v0/users/current":
                    return self._json(
                        200,
                        {
                            "id": 424242,
                            "email": "synthetic@example.invalid",
                            "api_key": API_KEY,
                            "balance": 0.0,
                            "ssh_key": "ssh-ed25519 AAAA",
                        },
                    )
                if method == "GET" and parts.path == "/api/v0/machines":
                    return self._json(200, {"machines": fake.machines})
                if method == "GET" and parts.path == "/api/v0/users/me/machine-earnings":
                    return self._json(200, fake._earnings(query))
                if (
                    method == "DELETE"
                    and parts.path.startswith("/api/v0/machines/")
                    and parts.path.endswith("/asks/")
                ):
                    machine_id = int(parts.path.split("/")[4])
                    return self._json(200, {"success": True, "machine_id": machine_id, "user_id": 424242})
                return self._json(404, {"success": False, "error": "not_found"})

            def do_GET(self):
                self._handle("GET")

            def do_DELETE(self):
                self._handle("DELETE")

            def do_PUT(self):
                self._handle("PUT")

            def do_POST(self):
                self._handle("POST")

        return Handler

    def _earnings(self, query: dict) -> dict:
        sday, eday = int(float(query["sday"])), int(float(query["eday"]))
        wanted = (
            None
            if self.ignore_machine_filter or query.get("machid") in (None, "null")
            else int(query["machid"])
        )
        per_day: dict[int, dict[str, float]] = {}
        per_machine = []
        for machine_id, days in sorted(self.earnings.items()):
            if wanted is not None and machine_id != wanted:
                continue
            totals = {"gpu_earn": 0.0, "sto_earn": 0.0, "bwu_earn": 0.0, "bwd_earn": 0.0}
            for day, parts in sorted(days.items()):
                if not (sday <= day <= eday):
                    continue
                bucket = per_day.setdefault(
                    day, {"gpu_earn": 0.0, "sto_earn": 0.0, "bwu_earn": 0.0, "bwd_earn": 0.0}
                )
                for name in totals:
                    value = float(parts.get(name, 0))
                    bucket[name] += value
                    totals[name] += value
            entry = {"machine_id": machine_id, **totals, **self.per_machine_override.get(machine_id, {})}
            if any(totals.values()) or machine_id in self.per_machine_override:
                per_machine.append(entry)
        return {
            "summary": {"total_gpu": 0, "total_stor": 0, "total_bwu": 0, "total_bwd": 0},
            "username": "synthetic-host",
            "email": "synthetic@example.invalid",
            "fullname": "Synthetic Fixture",
            "address1": "1 Example Street",
            "city": "Nowhere",
            "taxinfo": "SYNTHETIC-TAX-ID",
            "current": {"balance": 0.0, "service_fee": 0.0, "total": 0.0, "credit": 0.0},
            "per_machine": per_machine,
            "per_day": [{"day": day, **parts} for day, parts in sorted(per_day.items())],
        }
