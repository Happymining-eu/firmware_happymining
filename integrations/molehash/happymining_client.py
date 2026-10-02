"""Client for the HappyMining OS integration API, for use inside Mole Hash.

One file, standard library only, Python 3.8+. Copy it into the Mole Hash
backend, or import it from here. The API it talks to is described in
``docs/integration-api.md``.

    from happymining_client import HappyMiningClient

    hm = HappyMiningClient("https://api.happymining.fr", token)
    print(hm.describe()["client"]["scopes"])
    for machine in hm.machines():
        print(machine["label"], machine["connection"], machine.get("latest_telemetry"))
    hm.request_operation(machine["id"], "refresh_inventory")

The token is an API client token created by a HappyMining OS admin
(Integrations page). It is a secret: keep it in the environment of the Mole
Hash backend, never in the browser and never in the repository.

Quick check from a shell:

    HAPPYMINING_API_URL=https://... HAPPYMINING_API_TOKEN=hmc_... python happymining_client.py describe
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import uuid
from typing import Any, Dict, Iterator, List, Optional
from urllib import error, parse, request

__all__ = ["HappyMiningClient", "HappyMiningError", "to_device_record"]

API_PREFIX = "/api/v1/integration"
_LOOPBACK = ("127.0.0.1", "localhost", "::1")
_TOKEN_RE = re.compile(r"hmc_[0-9a-fA-F]{32}\.[A-Za-z0-9_-]{43}")


def _segment(value: Any) -> str:
    """An id as one path segment. Nothing in it can change which resource is addressed."""
    return parse.quote(str(value), safe="")


class HappyMiningError(Exception):
    """A response the caller has to deal with. ``status`` is 0 when no response arrived."""

    def __init__(self, status: int, code: str, message: str, request_id: str = ""):
        super().__init__(f"{status} {code}: {message}" if status else f"{code}: {message}")
        self.status = status
        self.code = code
        self.message = message
        self.request_id = request_id

    @property
    def blocked_by_rental_protection(self) -> bool:
        """The operation was refused because the machine may be rented. Do not retry it blindly."""
        return self.code == "maintenance_blocked"


class HappyMiningClient:
    """Thin, synchronous client. Safe to share between threads (it keeps no connection)."""

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout: float = 15.0,
        retries: int = 2,
        user_agent: str = "molehash-happymining-client/1",
    ):
        parts = parse.urlsplit(base_url)
        if parts.scheme not in ("https", "http") or not parts.hostname:
            raise ValueError("base_url must look like https://host")
        if parts.username is not None or parts.password is not None:
            raise ValueError("base_url must not contain a user name or a password")
        if parts.scheme == "http" and parts.hostname not in _LOOPBACK:
            # The token would travel in clear text.
            raise ValueError("plain http is only accepted for a loopback address")
        # Read from a file or a secret store, a token often ends with a newline.
        token = (token or "").strip()
        if not _TOKEN_RE.fullmatch(token):
            # The value is deliberately not part of the message.
            raise ValueError("token must be a HappyMining API client token (hmc_...)")
        self._base = f"{parts.scheme}://{parts.netloc}"
        self._token = token
        self._timeout = timeout
        self._retries = max(0, retries)
        self._user_agent = user_agent
        # No proxy from the environment and no redirects: the token goes to the
        # configured host and nowhere else.
        self._opener = request.build_opener(request.ProxyHandler({}), _NoRedirect())

    def __repr__(self) -> str:  # never prints the token
        return f"HappyMiningClient({self._base!r})"

    # --- transport -----------------------------------------------------

    def _call(
        self,
        method: str,
        path: str,
        *,
        query: Optional[Dict[str, Any]] = None,
        body: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        retry: bool = True,
    ) -> Any:
        url = self._base + API_PREFIX + path
        if query:
            clean = {k: v for k, v in query.items() if v is not None}
            if clean:
                url += "?" + parse.urlencode(clean)
        data = json.dumps(body).encode() if body is not None else None
        all_headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "User-Agent": self._user_agent,
        }
        if data is not None:
            all_headers["Content-Type"] = "application/json"
        all_headers.update(headers or {})

        attempts = (self._retries if retry else 0) + 1
        failure = HappyMiningError(0, "unreachable", "no attempt was made")
        for attempt in range(attempts):
            req = request.Request(url, data=data, method=method, headers=all_headers)
            delay = min(8.0, 0.5 * (2**attempt))
            try:
                with self._opener.open(req, timeout=self._timeout) as response:
                    raw = response.read()
                try:
                    return json.loads(raw) if raw else None
                except ValueError:
                    raise HappyMiningError(
                        response.status, "bad_response", "the server did not answer with JSON"
                    ) from None
            except error.HTTPError as exc:
                failure = self._error(exc)
                if failure.status != 429 and failure.status < 500:
                    raise failure from None
                # Worth another try: the server was busy, or told us to slow down.
                wait = exc.headers.get("Retry-After", "") if exc.headers else ""
                if failure.status == 429 and wait.isdigit():
                    delay = float(min(int(wait), 60))
            except (error.URLError, TimeoutError, OSError) as exc:
                # No answer. For a POST this says nothing about whether the
                # request was carried out, which is why operations carry an
                # idempotency key and are retried with the same one.
                failure = HappyMiningError(0, "unreachable", str(getattr(exc, "reason", exc)))
            if attempt + 1 < attempts:
                time.sleep(delay)
        raise failure

    @staticmethod
    def _error(exc: error.HTTPError) -> HappyMiningError:
        try:
            payload = json.loads(exc.read() or b"{}")
            info = payload.get("error", {}) if isinstance(payload, dict) else {}
        except (ValueError, OSError):
            info = {}
        return HappyMiningError(
            exc.code,
            str(info.get("code") or "http_error"),
            str(info.get("message") or exc.reason or "request failed"),
            str(info.get("request_id") or ""),
        )

    def _pages(self, path: str, query: Dict[str, Any], page_size: int) -> Iterator[Dict[str, Any]]:
        offset = 0
        while True:
            page = self._call("GET", path, query={**query, "limit": page_size, "offset": offset})
            items = page.get("items", [])
            for item in items:
                yield item
            offset += len(items)
            if not items or offset >= int(page.get("total", 0)):
                return

    # --- reading -------------------------------------------------------

    def describe(self) -> Dict[str, Any]:
        """Who this token is, what it may do, and whether the server is DEMO (synthetic data) or LIVE."""
        return self._call("GET", "")

    def fleet_summary(self) -> Dict[str, Any]:
        return self._call("GET", "/fleet/summary")

    def machines(self, page_size: int = 100) -> Iterator[Dict[str, Any]]:
        """Every AI server this token may see."""
        return self._pages("/machines", {}, page_size)

    def machine(self, machine_id: str) -> Dict[str, Any]:
        return self._call("GET", f"/machines/{_segment(machine_id)}")

    def telemetry(
        self,
        machine_id: str,
        *,
        since: Optional[str] = None,
        until: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Samples, newest first. ``since`` and ``until`` are RFC 3339 timestamps."""
        page = self._call(
            "GET", f"/machines/{_segment(machine_id)}/telemetry", query={"since": since, "until": until, "limit": limit}
        )
        return page["items"]

    def operation_types(self) -> Dict[str, Any]:
        return self._call("GET", "/operation-types")

    def operations(
        self, *, status: Optional[str] = None, machine_id: Optional[str] = None, page_size: int = 100
    ) -> Iterator[Dict[str, Any]]:
        return self._pages("/operations", {"status": status, "machine_id": machine_id}, page_size)

    def operation(self, operation_id: str) -> Dict[str, Any]:
        return self._call("GET", f"/operations/{_segment(operation_id)}")

    def earnings_daily(
        self,
        *,
        start: Optional[str] = None,
        end: Optional[str] = None,
        machine_id: Optional[str] = None,
        page_size: int = 500,
    ) -> Iterator[Dict[str, Any]]:
        """Earnings per machine and UTC day. Amounts are decimal strings: parse them with ``Decimal``.

        ``reported`` is what the provider says was earned. It is not cash.
        """
        return self._pages("/earnings/daily", {"start": start, "end": end, "machine_id": machine_id}, page_size)

    def earnings_summary(self, *, start: Optional[str] = None, end: Optional[str] = None) -> Dict[str, Any]:
        return self._call("GET", "/earnings/summary", query={"start": start, "end": end})

    # --- acting --------------------------------------------------------

    def request_operation(
        self,
        machine_id: str,
        op_type: str,
        params: Optional[Dict[str, Any]] = None,
        *,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Ask a machine to carry out one typed operation.

        Pass your own ``idempotency_key`` (for example the id of the action in
        Mole Hash) so that a retry after a crash finds the first operation. If
        the machine may be rented, a disruptive operation is refused with
        ``HappyMiningError.blocked_by_rental_protection``; a later attempt
        needs a new key.

        A repeated key returns the operation *as it is now*, which may be
        finished, cancelled or expired. Always look at ``status``; a returned
        operation is not by itself a success.
        """
        key = idempotency_key or f"molehash-{uuid.uuid4().hex}"
        return self._call(
            "POST",
            f"/machines/{_segment(machine_id)}/operations",
            body={"type": op_type, "params": params or {}},
            headers={"Idempotency-Key": key},
        )

    def cancel_operation(self, operation_id: str) -> Dict[str, Any]:
        """Cancel an operation this client requested and the machine has not received yet."""
        return self._call("POST", f"/operations/{_segment(operation_id)}/cancel", body={}, retry=False)


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def to_device_record(machine: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten a machine into the handful of fields a fleet list usually shows.

    A suggestion, not a contract: Mole Hash's own device model decides the
    final shape. ASIC notions such as hashrate and pool have no equivalent for
    an AI server and are left out rather than filled with zeros.
    """
    latest = machine.get("latest_telemetry") or {}
    provider = machine.get("provider") or {}
    hardware = machine.get("hardware") or {}
    return {
        "external_id": machine["id"],
        "source": "happymining-os",
        "kind": machine.get("kind", "gpu_server"),
        "name": machine.get("label") or machine.get("hostname") or machine["id"],
        "hostname": machine.get("hostname"),
        "owner_id": machine.get("owner_id"),
        "online": machine.get("connection") == "online",
        "connection": machine.get("connection"),
        "last_seen_at": machine.get("last_seen_at"),
        "agent_version": machine.get("agent_version"),
        "gpu_count": latest.get("gpu_count") if latest else len(hardware.get("gpus") or []) or None,
        "gpu_utilisation_pct": latest.get("gpu_util_avg"),
        "power_w": latest.get("gpu_power_w"),
        "temperature_c": latest.get("gpu_temp_max"),
        "measured_at": latest.get("collected_at"),
        "marketplace": provider.get("provider"),
        "marketplace_machine_id": provider.get("external_id"),
        "rental_state": provider.get("rental_state"),
        "listed": provider.get("listed"),
        "synthetic": bool(machine.get("synthetic")),
    }


def _main(argv: List[str]) -> int:
    url = os.environ.get("HAPPYMINING_API_URL", "")
    token = os.environ.get("HAPPYMINING_API_TOKEN", "")
    command = argv[1] if len(argv) > 1 else "describe"
    if not url or not token:
        print("set HAPPYMINING_API_URL and HAPPYMINING_API_TOKEN", file=sys.stderr)
        return 2
    client = HappyMiningClient(url, token)
    try:
        if command == "describe":
            out: Any = client.describe()
        elif command == "summary":
            out = client.fleet_summary()
        elif command == "machines":
            out = [to_device_record(m) for m in client.machines()]
        else:
            print("usage: happymining_client.py [describe|summary|machines]", file=sys.stderr)
            return 2
    except HappyMiningError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
