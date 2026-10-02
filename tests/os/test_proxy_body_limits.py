"""The reverse proxies cap request bodies at 1 MB, except the firmware package upload.

The upload (PUT /api/v1/releases/<version>/artifact) is authenticated by the
API before it reads the body, and capped there by HM_RELEASE_MAX_BYTES and by
the size the signed manifest declares. A proxy that capped it at 1 MB would
make publishing a release impossible. These are text checks: Caddy itself is
not installed here, so the files are not validated by Caddy.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

DEPLOY = Path(__file__).resolve().parents[2] / "deploy"
CADDYFILES = [DEPLOY / "Caddyfile", DEPLOY / "Caddyfile.demo"]


def _blocks(text: str, directive: str) -> list[tuple[str, str]]:
    """(matcher, body) of each ``directive [matcher] { ... }`` block."""
    return re.findall(rf"^\s*{directive}(?:\s+(@\S+))?\s*\{{(.*?)^\s*\}}", text, re.M | re.S)


def _matcher(text: str, name: str) -> str:
    match = re.search(rf"^\s*{re.escape(name)}\s*\{{\n(.*?)^\t\}}", text, re.M | re.S)
    assert match, f"matcher {name} is not defined"
    return match.group(1)


@pytest.mark.parametrize("path", CADDYFILES, ids=lambda p: p.name)
def test_only_the_release_upload_escapes_the_1mb_body_limit(path: Path):
    text = path.read_text()
    limits = dict(_blocks(text, "request_body"))
    # Every request_body directive is bound to a matcher, so they never stack.
    assert set(limits) == {"@release_artifact", "@not_release_artifact"}, limits
    assert "max_size 1MB" in limits["@not_release_artifact"]
    assert "max_size 512MB" in limits["@release_artifact"]

    upload = _matcher(text, "@release_artifact")
    others = _matcher(text, "@not_release_artifact")
    assert "method PUT" in upload and "not {" in others and "method PUT" in others
    patterns = {re.search(r"path_regexp (\S+)", block).group(1) for block in (upload, others)}
    assert len(patterns) == 1, "the two matchers must use the same pattern"
    pattern = re.compile(patterns.pop())
    for ok in ("/api/v1/releases/0.2.0/artifact", "/api/v1/releases/12.0.345/artifact"):
        assert pattern.fullmatch(ok), ok
    for other in (
        "/api/v1/releases/0.2.0/artifact/x",
        "/api/v1/releases/0.2.0",
        "/api/v1/releases",
        "/api/v1/device/heartbeat",
        "/api/v1/releases/../device/heartbeat/artifact",
        "/x/api/v1/releases/0.2.0/artifact",
    ):
        assert not pattern.fullmatch(other), other
