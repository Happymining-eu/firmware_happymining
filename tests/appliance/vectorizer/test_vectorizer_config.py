"""vectorizer.json and the token file: what is accepted and what is refused."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from hm_vectorizer import config as vz_config
from hm_vectorizer.config import ConfigError, parse_config, parse_token, take_api_key
from vz_support import API_KEY, REPO, TOKEN, Site

NAS = "/srv/happymining/nas"
FIXTURES = REPO / "appliance" / "testdata" / "documents"

VALID: dict[str, Any] = {
    "sources": ["docs"],
    "extensions": ["pdf", "docx", "md", "txt"],
    "exclude": ["#recycle", "private/hr"],
    "max_file_mib": 64,
    "embedding_model": "bge-m3",
    "ocr": False,
    "answer": {
        "provider": "openai_compatible",
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4.1-mini",
        "secret": "ai.answer.api_key",
    },
    "source_paths": {"docs": f"{NAS}/docs"},
    "ollama_url": "http://ollama:11434",
    "qdrant_url": "http://qdrant:6333",
    "collection": "happymining_docs",
}


def changed(**changes: Any) -> dict[str, Any]:
    document = copy.deepcopy(VALID)
    document.update(changes)
    return document


def with_answer(**answer: Any) -> dict[str, Any]:
    return changed(answer=answer)


def without(key: str) -> dict[str, Any]:
    document = copy.deepcopy(VALID)
    del document[key]
    return document


def test_valid_document_is_loaded_with_its_values() -> None:
    cfg = parse_config(copy.deepcopy(VALID))
    assert [s.source_id for s in cfg.sources] == ["docs"]
    assert cfg.sources[0].path == f"{NAS}/docs"
    assert cfg.sources[0].subpath == ()
    assert cfg.extensions == frozenset({"pdf", "docx", "md", "txt"})
    assert cfg.exclude == (("#recycle",), ("private", "hr"))
    assert cfg.max_file_bytes == 64 * 1024 * 1024
    assert cfg.embedding_model == "bge-m3"
    assert cfg.ocr is False
    assert cfg.answer.provider == "openai_compatible"
    assert cfg.answer.base_url == "https://api.openai.com/v1"
    assert cfg.answer.model == "gpt-4.1-mini"
    assert cfg.ollama_url == "http://ollama:11434"
    assert cfg.qdrant_url == "http://qdrant:6333"
    assert cfg.collection == "happymining_docs"


def test_source_below_the_mount_point_keeps_its_subpath() -> None:
    cfg = parse_config(changed(source_paths={"docs": f"{NAS}/docs/contracts/2026"}))
    assert cfg.sources[0].mount == f"{NAS}/docs"
    assert cfg.sources[0].subpath == ("contracts", "2026")


@pytest.mark.parametrize(
    "answer, expected",
    [
        ({"provider": "none"}, ("none", None, None)),
        ({"provider": "local", "model": "hermes3:8b"}, ("local", "hermes3:8b", None)),
        (
            {"provider": "anthropic", "model": "claude-sonnet-4-5", "secret": "ai.answer.api_key"},
            ("anthropic", "claude-sonnet-4-5", "https://api.anthropic.com"),
        ),
        (
            {
                "provider": "anthropic",
                "model": "m",
                "secret": "ai.answer.api_key",
                "base_url": "https://gateway.example:8443/anthropic/",
            },
            ("anthropic", "m", "https://gateway.example:8443/anthropic"),
        ),
        (
            {
                "provider": "openai_compatible",
                "model": "m",
                "secret": "ai.answer.api_key",
                "base_url": "https://llm.lan:8443/openai_v1.2~x/",
            },
            ("openai_compatible", "m", "https://llm.lan:8443/openai_v1.2~x"),
        ),
        (
            {
                "provider": "openai_compatible",
                "model": "m",
                "secret": "ai.answer.api_key",
                "base_url": "https://10.0.0.7",
            },
            ("openai_compatible", "m", "https://10.0.0.7"),
        ),
    ],
)
def test_answer_providers(answer: dict[str, Any], expected: tuple[str, str | None, str | None]) -> None:
    cfg = parse_config(with_answer(**answer))
    assert (cfg.answer.provider, cfg.answer.model, cfg.answer.base_url) == expected


OPENAI = {"provider": "openai_compatible", "model": "m", "secret": "ai.answer.api_key"}

INVALID: dict[str, Any] = {
    "not an object": ["sources"],
    "unknown top-level key": changed(extra=1),
    **{f"missing {key}": without(key) for key in VALID},
    "sources empty": changed(sources=[], source_paths={}),
    "sources not a list": changed(sources="docs"),
    "sources duplicate": changed(sources=["docs", "docs"]),
    "sources bad id": changed(sources=["Docs"], source_paths={"Docs": f"{NAS}/Docs"}),
    "sources id with newline": changed(sources=["docs\n"], source_paths={"docs\n": f"{NAS}/docs"}),
    "sources nine entries": changed(
        sources=[f"s{i}" for i in range(9)], source_paths={f"s{i}": f"{NAS}/s{i}" for i in range(9)}
    ),
    "extensions empty": changed(extensions=[]),
    "extensions upper case": changed(extensions=["PDF"]),
    "extensions with a dot": changed(extensions=[".pdf"]),
    "extensions too long": changed(extensions=["abcdefghi"]),
    "extensions 41 entries": changed(extensions=[f"e{i}" for i in range(41)]),
    "extensions not strings": changed(extensions=[1]),
    "exclude dotdot": changed(exclude=["../x"]),
    "exclude dot": changed(exclude=["a/./b"]),
    "exclude leading slash": changed(exclude=["/a"]),
    "exclude trailing slash": changed(exclude=["a/"]),
    "exclude empty segment": changed(exclude=["a//b"]),
    "exclude empty string": changed(exclude=[""]),
    "exclude 201 characters": changed(exclude=["a" * 201]),
    "exclude 33 entries": changed(exclude=[f"d{i}" for i in range(33)]),
    "exclude control character": changed(exclude=["a\x07b"]),
    "exclude not a list": changed(exclude="x"),
    "max_file_mib zero": changed(max_file_mib=0),
    "max_file_mib 2049": changed(max_file_mib=2049),
    "max_file_mib string": changed(max_file_mib="64"),
    "max_file_mib float": changed(max_file_mib=64.0),
    "max_file_mib boolean": changed(max_file_mib=True),
    "embedding_model with a space": changed(embedding_model="bge m3"),
    "embedding_model upper case name": changed(embedding_model="BGE-M3"),
    "embedding_model empty": changed(embedding_model=""),
    "embedding_model trailing newline": changed(embedding_model="bge-m3\n"),
    "ocr string": changed(ocr="no"),
    "ocr number": changed(ocr=0),
    "answer not an object": changed(answer="none"),
    "answer unknown key": with_answer(provider="none", temperature=1),
    "answer provider unknown": with_answer(
        **{**OPENAI, "provider": "magic", "base_url": "https://x.example"}
    ),
    "answer provider missing": with_answer(model="m"),
    "answer none with model": with_answer(provider="none", model="x"),
    "answer none with base_url": with_answer(provider="none", base_url="https://x.example"),
    "answer none with secret": with_answer(provider="none", secret="ai.answer.api_key"),
    "answer local without model": with_answer(provider="local"),
    "answer local with base_url": with_answer(provider="local", model="m", base_url="https://x.example"),
    "answer local with secret": with_answer(provider="local", model="m", secret="ai.answer.api_key"),
    "answer model with a space": with_answer(**{**OPENAI, "model": "gpt 4", "base_url": "https://x.example"}),
    "answer model empty": with_answer(**{**OPENAI, "model": "", "base_url": "https://x.example"}),
    "answer model 101 characters": with_answer(
        **{**OPENAI, "model": "m" * 101, "base_url": "https://x.example"}
    ),
    "answer model not a string": with_answer(**{**OPENAI, "model": 4, "base_url": "https://x.example"}),
    "answer openai without base_url": with_answer(**OPENAI),
    "answer openai without secret": with_answer(
        provider="openai_compatible", model="m", base_url="https://x.example"
    ),
    "answer secret wrong name": with_answer(
        **{**OPENAI, "secret": "ai.other", "base_url": "https://x.example"}
    ),
    "answer anthropic without secret": with_answer(provider="anthropic", model="m"),
    "answer url http": with_answer(**OPENAI, base_url="http://api.example.com/v1"),
    "answer url user info": with_answer(**OPENAI, base_url="https://user:pw@api.example.com/v1"),
    "answer url user info without password": with_answer(
        **OPENAI, base_url="https://user@api.example.com/v1"
    ),
    "answer url query": with_answer(**OPENAI, base_url="https://api.example.com/v1?x=1"),
    "answer url fragment": with_answer(**OPENAI, base_url="https://api.example.com/v1#x"),
    "answer url without host": with_answer(**OPENAI, base_url="https:///v1"),
    "answer url port zero": with_answer(**OPENAI, base_url="https://api.example.com:0/v1"),
    "answer url port too large": with_answer(**OPENAI, base_url="https://api.example.com:70000/v1"),
    "answer url with a space": with_answer(**OPENAI, base_url="https://api.example.com/v 1"),
    "answer url with a backslash": with_answer(
        **OPENAI, base_url="https://api.example.com\\@evil.example/v1"
    ),
    "answer url 201 characters": with_answer(**OPENAI, base_url="https://api.example.com/" + "a" * 177),
    # the control plane's rule: host as in 4.3, no leading zero in the port, unreserved path characters
    "answer url IPv6 literal": with_answer(**OPENAI, base_url="https://[::1]:8443/v1"),
    "answer url port with a leading zero": with_answer(**OPENAI, base_url="https://api.example.com:0443/v1"),
    "answer url percent-encoded path": with_answer(**OPENAI, base_url="https://api.example.com/v%2F1"),
    "answer url at sign in the path": with_answer(**OPENAI, base_url="https://api.example.com/@evil.example"),
    "answer url non-ASCII path": with_answer(**OPENAI, base_url="https://api.example.com/vé1"),
    "answer url host starting with a dot": with_answer(**OPENAI, base_url="https://.example.com/v1"),
    "answer url control character": with_answer(**OPENAI, base_url="https://api.example.com/v1\r\nX: y"),
    "answer url not a string": with_answer(**OPENAI, base_url=["https://api.example.com"]),
    "source_paths not an object": changed(source_paths=[f"{NAS}/docs"]),
    "source_paths missing an id": changed(sources=["docs", "more"]),
    "source_paths extra id": changed(source_paths={"docs": f"{NAS}/docs", "more": f"{NAS}/more"}),
    "source_paths outside the NAS root": changed(source_paths={"docs": "/etc"}),
    "source_paths other id's mount": changed(source_paths={"docs": f"{NAS}/other"}),
    "source_paths prefix trick": changed(source_paths={"docs": f"{NAS}/docs-private"}),
    "source_paths dotdot": changed(source_paths={"docs": f"{NAS}/docs/../../etc"}),
    "source_paths trailing slash": changed(source_paths={"docs": f"{NAS}/docs/"}),
    "source_paths relative": changed(source_paths={"docs": "docs"}),
    "source_paths not a string": changed(source_paths={"docs": None}),
    "ollama_url with a path": changed(ollama_url="http://ollama:11434/api"),
    "ollama_url other scheme": changed(ollama_url="file:///etc/passwd"),
    "ollama_url user info": changed(ollama_url="http://u:p@ollama:11434"),
    "ollama_url query": changed(ollama_url="http://ollama:11434?x=1"),
    "ollama_url not a string": changed(ollama_url=11434),
    "qdrant_url empty": changed(qdrant_url=""),
    "qdrant_url port too large": changed(qdrant_url="http://qdrant:99999"),
    "collection with a slash": changed(collection="a/b"),
    "collection empty": changed(collection=""),
    "collection with dots": changed(collection=".."),
    "collection 65 characters": changed(collection="c" * 65),
}


@pytest.mark.parametrize("name", sorted(INVALID))
def test_invalid_document_is_refused(name: str) -> None:
    with pytest.raises(ConfigError):
        parse_config(copy.deepcopy(INVALID[name]))


def test_every_invalid_case_differs_from_the_valid_document_by_what_it_names() -> None:
    """The valid base must be accepted, or the cases above would prove nothing."""
    parse_config(copy.deepcopy(VALID))


def _fixture_vectorizer_file(document: dict[str, Any]) -> dict[str, Any]:
    """What the helper would write for this desired-state document."""
    readable = {n["id"]: n.get("subpath", "") for n in document.get("nas", []) if n.get("access") == "read"}
    out = dict(document["vectorizer"])
    sources = out.get("sources") if isinstance(out.get("sources"), list) else []
    out["source_paths"] = {
        s: f"{NAS}/{s}" + (f"/{readable[s]}" if readable[s] else "") for s in sources if s in readable
    }
    out.update(
        ollama_url="http://ollama:11434", qdrant_url="http://qdrant:6333", collection="happymining_docs"
    )
    return out


def _fixtures(kind: str) -> list[Path]:
    return sorted((FIXTURES / kind).glob("*.json"))


def test_shared_valid_fixtures_are_accepted() -> None:
    seen = 0
    for path in _fixtures("valid"):
        document = json.loads(path.read_text(encoding="utf-8"))["document"]
        if "vectorizer" not in document:
            continue
        parse_config(_fixture_vectorizer_file(document))
        seen += 1
    assert seen >= 4


def test_shared_invalid_vectorizer_fixtures_are_refused() -> None:
    seen = 0
    for path in _fixtures("invalid"):
        if not path.name.startswith("vec-"):
            continue
        document = json.loads(path.read_text(encoding="utf-8"))["document"]
        with pytest.raises(ConfigError):
            parse_config(_fixture_vectorizer_file(document))
        seen += 1
    assert seen >= 20


# -- the file -----------------------------------------------------------------


def test_file_is_loaded_and_nas_root_can_be_moved_for_tests(site: Site) -> None:
    cfg = site.load()
    assert cfg.sources[0].path == str(site.nas_root / "docs")


def test_file_with_a_repeated_key_is_refused(tmp_path: Path) -> None:
    text = json.dumps(VALID)[:-1] + ', "ocr": true}'
    path = tmp_path / "vectorizer.json"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError, match="twice"):
        vz_config.load_config(path)


@pytest.mark.parametrize("content", [b"", b"{not json", b"\xff\xfe\x00", b"[1, 2]", b'"text"'])
def test_file_that_is_not_a_json_object_is_refused(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "vectorizer.json"
    path.write_bytes(content)
    with pytest.raises(ConfigError):
        vz_config.load_config(path)


def test_file_larger_than_64_kib_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "vectorizer.json"
    path.write_text(json.dumps(VALID) + " " * (64 * 1024), encoding="utf-8")
    with pytest.raises(ConfigError, match="larger"):
        vz_config.load_config(path)


def test_missing_file_and_directory_are_refused(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        vz_config.load_config(tmp_path / "absent.json")
    with pytest.raises(ConfigError):
        vz_config.load_config(tmp_path)


def test_error_message_names_the_field_not_the_value(tmp_path: Path) -> None:
    path = tmp_path / "vectorizer.json"
    path.write_text(json.dumps(changed(embedding_model="SECRET VALUE")), encoding="utf-8")
    with pytest.raises(ConfigError) as caught:
        vz_config.load_config(path)
    assert "embedding_model" in str(caught.value)
    assert "SECRET VALUE" not in str(caught.value)


# -- the token ----------------------------------------------------------------


def test_token_is_one_line(site: Site) -> None:
    assert vz_config.load_token(site.config_dir / "token") == TOKEN
    assert parse_token(TOKEN.encode()) == TOKEN
    assert parse_token(TOKEN.encode() + b"\r\n") == TOKEN


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\n",
        b"short",
        b"a" * 15,
        b"a" * 513,
        b"with a space in the token",
        b"first-line-of-token\nsecond-line-of-token\n",
        "tôken-with-an-accent-1234".encode(),
        b"tab\tinside-the-token-123",
        b"nul\x00inside-the-token-123",
    ],
)
def test_token_that_is_not_one_printable_line_is_refused(raw: bytes) -> None:
    with pytest.raises(ConfigError):
        parse_token(raw)


def test_missing_token_file_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        vz_config.load_token(tmp_path / "token")


# -- the cloud key --------------------------------------------------------------


def test_api_key_is_taken_out_of_the_environment() -> None:
    environ = {"HM_ANSWER_API_KEY": f" {API_KEY}\n", "OTHER": "1"}
    key = take_api_key(environ)
    assert key is not None and key.reveal() == API_KEY
    assert environ == {"OTHER": "1"}
    assert API_KEY not in repr(key) and API_KEY not in str(key) and API_KEY not in f"{key}"


@pytest.mark.parametrize("value", ["", "   ", "two words", "line\nbreak", "café-key", "x" * 5000])
def test_api_key_that_cannot_be_a_header_value_is_treated_as_absent(value: str) -> None:
    environ = {"HM_ANSWER_API_KEY": value}
    assert take_api_key(environ) is None
    assert environ == {}


def test_no_api_key() -> None:
    assert take_api_key({}) is None
