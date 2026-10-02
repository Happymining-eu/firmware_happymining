"""JSON over HTTP with urllib, restricted on purpose.

- Only http and https. No file:, ftp: or data: handler is installed.
- No proxy, whatever the environment says: the host in the URL is the host
  that is contacted.
- No redirect is followed: a 3xx answer is an error. A request therefore
  never reaches a host other than the one in its URL, and neither do its
  headers.
- Responses are read up to a limit.

Errors carry a kind and an HTTP status, never a header, a request body or a
response body: an upstream error text can quote the credentials it was sent.
"""

from __future__ import annotations

import http.client
import json
import ssl
import urllib.error
import urllib.request
from typing import Any

DEFAULT_MAX_RESPONSE_BYTES = 32 * 1024 * 1024


class HttpError(Exception):
    """A request that did not produce a usable 2xx JSON answer.

    kind: "connect" (refused, DNS, TLS), "timeout", "status" (non-2xx),
    "redirect" (3xx, never followed), "too_large", "bad_json", "bad_request"
    (the request could not be built).
    """

    def __init__(self, kind: str, status: int | None = None) -> None:
        self.kind = kind
        self.status = status
        super().__init__(kind if status is None else f"{kind} {status}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def build_opener(ssl_context: ssl.SSLContext | None = None) -> urllib.request.OpenerDirector:
    """An opener with exactly: HTTP, HTTPS, the error handlers, and no redirect."""
    opener = urllib.request.OpenerDirector()
    opener.add_handler(urllib.request.HTTPHandler())
    opener.add_handler(urllib.request.HTTPSHandler(context=ssl_context or ssl.create_default_context()))
    opener.add_handler(_NoRedirect())
    opener.add_handler(urllib.request.HTTPDefaultErrorHandler())
    opener.add_handler(urllib.request.HTTPErrorProcessor())
    return opener


class JsonHttpClient:
    """Sends one JSON request and returns the decoded JSON answer."""

    def __init__(
        self,
        *,
        ssl_context: ssl.SSLContext | None = None,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        self._opener = build_opener(ssl_context)
        self._max = max_response_bytes

    def request(
        self,
        method: str,
        url: str,
        body: Any = None,
        *,
        headers: dict[str, str] | None = None,
        timeout: float = 60.0,
    ) -> Any:
        if not url.startswith(("http://", "https://")):
            raise HttpError("bad_request")
        data = None
        all_headers = {"Accept": "application/json", "User-Agent": "hm-vectorizer"}
        if body is not None:
            try:
                data = json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
            except (TypeError, ValueError):
                raise HttpError("bad_request") from None
            all_headers["Content-Type"] = "application/json"
        if headers:
            all_headers.update(headers)
        for value in all_headers.values():
            # http.client refuses these too; refusing here keeps the value out of any traceback.
            if "\r" in value or "\n" in value:
                raise HttpError("bad_request")
        try:
            # The scheme was checked above: only http and https reach this point.
            req = urllib.request.Request(url, data=data, method=method, headers=all_headers)  # noqa: S310
        except ValueError:
            raise HttpError("bad_request") from None
        try:
            with self._opener.open(req, timeout=timeout) as resp:
                raw = resp.read(self._max + 1)
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
            if 300 <= status < 400:
                raise HttpError("redirect", status) from None
            raise HttpError("status", status) from None
        except TimeoutError:
            raise HttpError("timeout") from None
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                raise HttpError("timeout") from None
            raise HttpError("connect") from None
        except ValueError:
            raise HttpError("bad_request") from None
        except (OSError, http.client.HTTPException):
            raise HttpError("connect") from None
        if len(raw) > self._max:
            raise HttpError("too_large")
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise HttpError("bad_json") from None
