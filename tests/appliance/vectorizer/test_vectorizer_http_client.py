"""The restricted HTTP client every outgoing request goes through."""

from __future__ import annotations

import pytest
from hm_vectorizer.http_client import HttpError, JsonHttpClient
from hm_vectorizer.sync import run_sync
from vz_fakes import FakeOllama, FakeQdrant, FakeServer, Recorded, Reply
from vz_support import Site


class Echo(FakeServer):
    def __init__(self) -> None:
        self.redirect_to: str | None = None
        self.payload: object = {"ok": True}
        super().__init__()

    def handle(self, request: Recorded) -> object:
        if self.redirect_to is not None:
            raise Reply(302, None, {"Location": self.redirect_to})
        return self.payload


@pytest.fixture
def echo():  # type: ignore[no-untyped-def]
    server = Echo()
    yield server
    server.close()


@pytest.fixture
def elsewhere():  # type: ignore[no-untyped-def]
    server = Echo()
    yield server
    server.close()


def test_json_round_trip(echo: Echo) -> None:
    answer = JsonHttpClient().request("POST", f"{echo.url}/path", {"text": "café"}, headers={"X-Extra": "1"})
    assert answer == {"ok": True}
    (request,) = echo.requests
    assert request.body == {"text": "café"}
    assert request.headers["content-type"] == "application/json" and request.headers["x-extra"] == "1"
    assert "é".encode() in request.raw, "UTF-8, not escaped"


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_redirects_are_not_followed(echo: Echo, elsewhere: Echo, status: int) -> None:
    def redirect(request: Recorded) -> object:
        raise Reply(status, None, {"Location": f"{elsewhere.url}/stolen"})

    echo.handle = redirect  # type: ignore[method-assign]
    with pytest.raises(HttpError) as caught:
        JsonHttpClient().request(
            "POST", f"{echo.url}/x", {"a": 1}, headers={"Authorization": "Bearer secret"}
        )
    assert (caught.value.kind, caught.value.status) == ("redirect", status)
    assert elsewhere.requests == []


@pytest.mark.parametrize(
    "url",
    ["file:///etc/passwd", "ftp://127.0.0.1/x", "data:application/json,{}", "/etc/passwd", "gopher://x/"],
)
def test_only_http_and_https(url: str) -> None:
    with pytest.raises(HttpError) as caught:
        JsonHttpClient().request("GET", url)
    assert caught.value.kind == "bad_request"


def test_proxy_settings_of_the_environment_are_ignored(
    site: Site, ollama: FakeOllama, qdrant: FakeQdrant, echo: Echo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The host in the URL is the host contacted, even when the environment names a proxy."""
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(name, echo.url)
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    site.write("a.txt", "Some text to index.")
    result = run_sync(site.load(), site.state_dir)
    assert result.status["state"] == "idle" and result.status["files_indexed"] == 1
    assert ollama.requests and qdrant.requests
    assert echo.requests == [], "nothing went through the proxy"


def test_error_carries_the_status_and_nothing_of_the_answer(echo: Echo) -> None:
    def refuse(request: Recorded) -> object:
        raise Reply(401, {"error": "Incorrect API key provided: sk-live-123"})

    echo.handle = refuse  # type: ignore[method-assign]
    with pytest.raises(HttpError) as caught:
        JsonHttpClient().request("GET", f"{echo.url}/x", headers={"Authorization": "Bearer sk-live-123"})
    assert (caught.value.kind, caught.value.status) == ("status", 401)
    assert "sk-live-123" not in str(caught.value) and "sk-live-123" not in repr(caught.value)
    assert caught.value.__cause__ is None and caught.value.__suppress_context__


def test_response_size_is_limited(echo: Echo) -> None:
    echo.payload = {"data": "x" * 5000}
    with pytest.raises(HttpError) as caught:
        JsonHttpClient(max_response_bytes=1000).request("GET", f"{echo.url}/x")
    assert caught.value.kind == "too_large"
    assert JsonHttpClient(max_response_bytes=10000).request("GET", f"{echo.url}/x") == echo.payload


def test_answer_that_is_not_json(echo: Echo) -> None:
    echo.payload = None  # an empty body
    with pytest.raises(HttpError) as caught:
        JsonHttpClient().request("GET", f"{echo.url}/x")
    assert caught.value.kind == "bad_json"


def test_header_value_with_a_line_break_is_refused_before_anything_is_sent(echo: Echo) -> None:
    with pytest.raises(HttpError) as caught:
        JsonHttpClient().request(
            "GET", f"{echo.url}/x", headers={"Authorization": "Bearer a\r\nX-Injected: 1"}
        )
    assert caught.value.kind == "bad_request"
    assert echo.requests == []


def test_body_that_cannot_be_json_is_refused(echo: Echo) -> None:
    with pytest.raises(HttpError) as caught:
        JsonHttpClient().request("POST", f"{echo.url}/x", {"vector": [float("nan")]})
    assert caught.value.kind == "bad_request"
    assert echo.requests == []


def test_connection_refused_and_timeout(echo: Echo) -> None:
    url = echo.url
    echo.close()
    with pytest.raises(HttpError) as caught:
        JsonHttpClient().request("GET", f"{url}/x", timeout=2)
    assert caught.value.kind == "connect"
