"""Loading and strict validation of /config/vectorizer.json and /config/token.

The file is written by the root helper. It holds the `vectorizer` object of
the desired-state document (docs/appliance.md, 4.4) plus four runtime keys.
Everything is validated again here, with the rules of the contract; an
unknown key anywhere is an error; the service refuses to start on an invalid
file. Error messages name the field and the rule, never the value.
"""

from __future__ import annotations

import json
import os
import re
import stat
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any

NAS_ROOT = "/srv/happymining/nas"
MAX_CONFIG_BYTES = 64 * 1024
ANSWER_SECRET_NAME = "ai.answer.api_key"  # noqa: S105 - the name of the secret, not a secret
ANTHROPIC_DEFAULT_BASE_URL = "https://api.anthropic.com"
API_KEY_ENV = "HM_ANSWER_API_KEY"

PROVIDERS = ("none", "local", "openai_compatible", "anthropic")
CLOUD_PROVIDERS = ("openai_compatible", "anthropic")

TOKEN_MIN_CHARS = 16
TOKEN_MAX_CHARS = 512

_ID = re.compile(r"[a-z][a-z0-9-]{0,30}")
_EXTENSION = re.compile(r"[a-z0-9]{1,8}")
_EMBEDDING_MODEL = re.compile(r"[a-z0-9][a-z0-9._/-]{0,80}(:[A-Za-z0-9._-]{1,40})?")
_ANSWER_MODEL = re.compile(r"[A-Za-z0-9._:/-]{1,100}")
# The host rule of docs/appliance.md 4.3 (a name or an IPv4 address; no IPv6 literal).
_HOST = r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?"
# https://host[:port][/path], the path made of unreserved characters only: the
# rule the control plane applies (api/happymining/services/appliance.py), so a
# value it accepted is accepted here and nothing looser is.
_BASE_URL = re.compile(
    rf"https://(?P<host>{_HOST})(?::(?P<port>[0-9]{{1,5}}))?(?P<path>(?:/[A-Za-z0-9._~-]*)*)"
)
_SERVICE_URL = re.compile(rf"https?://(?P<host>{_HOST})(?::(?P<port>[0-9]{{1,5}}))?/?")
_COLLECTION = re.compile(r"[A-Za-z0-9_-]{1,64}")
_TOKEN = re.compile(r"[\x21-\x7e]+")

_TOP_KEYS = frozenset(
    {
        "sources",
        "extensions",
        "exclude",
        "max_file_mib",
        "embedding_model",
        "ocr",
        "answer",
        "source_paths",
        "ollama_url",
        "qdrant_url",
        "collection",
    }
)
_ANSWER_KEYS = frozenset({"provider", "base_url", "model", "secret"})


class ConfigError(ValueError):
    """The configuration file or the token file is not acceptable."""


@dataclass(frozen=True)
class AnswerConfig:
    provider: str
    model: str | None = None
    base_url: str | None = None


@dataclass(frozen=True)
class SourceConfig:
    source_id: str
    mount: str  # <nas root>/<id>: where the NAS entry is mounted
    subpath: tuple[str, ...]  # segments below the mount, () for the root of the share

    @property
    def path(self) -> str:
        return "/".join((self.mount, *self.subpath))


@dataclass(frozen=True)
class Config:
    sources: tuple[SourceConfig, ...]
    extensions: frozenset[str]
    exclude: tuple[tuple[str, ...], ...]  # each pattern as normalised path segments
    max_file_bytes: int
    embedding_model: str
    ocr: bool
    answer: AnswerConfig
    ollama_url: str
    qdrant_url: str
    collection: str

    def source(self, source_id: str) -> SourceConfig | None:
        for src in self.sources:
            if src.source_id == source_id:
                return src
        return None


def normalize_segment(segment: str) -> str:
    """How a path segment is compared with an `exclude` pattern.

    Case-insensitive and insensitive to Unicode composition: SMB shares are
    usually case-insensitive, and an exclusion that misses `Private/HR` because
    it was written `private/hr` would index what the owner meant to keep out.
    """
    return unicodedata.normalize("NFC", segment).casefold()


def _has_control(value: str) -> bool:
    return any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ConfigError("a key appears twice in an object")
        out[key] = value
    return out


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _string(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"{field}: must be a string")
    if _has_control(value):
        raise ConfigError(f"{field}: contains a control character")
    return value


def _string_list(value: Any, field: str, *, low: int, high: int) -> list[str]:
    if not isinstance(value, list):
        raise ConfigError(f"{field}: must be a list")
    if not low <= len(value) <= high:
        raise ConfigError(f"{field}: must have {low} to {high} entries")
    return [_string(item, f"{field}[{i}]") for i, item in enumerate(value)]


def relative_path_segments(value: str, field: str, *, max_chars: int, allow_empty: bool) -> tuple[str, ...]:
    """The contract's rule for `subpath` (4.3), also used for `exclude` (4.4)."""
    if value == "":
        if allow_empty:
            return ()
        raise ConfigError(f"{field}: must not be empty")
    if len(value) > max_chars:
        raise ConfigError(f"{field}: longer than {max_chars} characters")
    segments = tuple(value.split("/"))
    for segment in segments:
        if segment in ("", ".", ".."):
            raise ConfigError(f"{field}: empty, '.' or '..' segment, or a leading or trailing '/'")
    return segments


def _port_ok(port: str | None) -> bool:
    return port is None or (not port.startswith("0") and 1 <= int(port) <= 65535)


def _base_url(value: Any, field: str) -> str:
    text = _string(value, field)
    if len(text) > 200:
        raise ConfigError(f"{field}: longer than 200 characters")
    match = _BASE_URL.fullmatch(text)
    if match is None or not _port_ok(match.group("port")):
        raise ConfigError(f"{field}: must be https://host[:port][/path] without user info, query or fragment")
    return text.rstrip("/")


def _service_url(value: Any, field: str) -> str:
    text = _string(value, field)
    match = _SERVICE_URL.fullmatch(text)
    if len(text) > 300 or match is None or not _port_ok(match.group("port")):
        raise ConfigError(f"{field}: must be http://host[:port] or https://host[:port]")
    return text.rstrip("/")


def _answer(value: Any) -> AnswerConfig:
    if not isinstance(value, dict):
        raise ConfigError("answer: must be an object")
    unknown = set(value) - _ANSWER_KEYS
    if unknown:
        raise ConfigError("answer: unknown key")
    provider = value.get("provider")
    if provider not in PROVIDERS:
        raise ConfigError("answer.provider: must be none, local, openai_compatible or anthropic")

    if provider == "none":
        if "model" in value:
            raise ConfigError("answer.model: must be absent when the provider is none")
        model = None
    else:
        if "model" not in value:
            raise ConfigError("answer.model: required for this provider")
        model = _string(value["model"], "answer.model")
        if _ANSWER_MODEL.fullmatch(model) is None:
            raise ConfigError("answer.model: 1 to 100 characters of A-Z a-z 0-9 . _ : / -")

    base_url: str | None = None
    if provider == "openai_compatible":
        if "base_url" not in value:
            raise ConfigError("answer.base_url: required for openai_compatible")
        base_url = _base_url(value["base_url"], "answer.base_url")
    elif provider == "anthropic":
        base_url = (
            _base_url(value["base_url"], "answer.base_url")
            if "base_url" in value
            else ANTHROPIC_DEFAULT_BASE_URL
        )
    elif "base_url" in value:
        raise ConfigError("answer.base_url: must be absent for this provider")

    if provider in CLOUD_PROVIDERS:
        if value.get("secret") != ANSWER_SECRET_NAME:
            raise ConfigError(f"answer.secret: must be exactly {ANSWER_SECRET_NAME} for a cloud provider")
    elif "secret" in value:
        raise ConfigError("answer.secret: must be absent for this provider")

    return AnswerConfig(provider=provider, model=model, base_url=base_url)


def _source(source_id: str, value: Any, nas_root: str) -> SourceConfig:
    field = f"source_paths.{source_id}"
    text = _string(value, field)
    mount = f"{nas_root}/{source_id}"
    if text == mount:
        return SourceConfig(source_id=source_id, mount=mount, subpath=())
    if not text.startswith(mount + "/"):
        raise ConfigError(f"{field}: must be {nas_root}/<id> or a path below it")
    subpath = relative_path_segments(text[len(mount) + 1 :], field, max_chars=512, allow_empty=False)
    return SourceConfig(source_id=source_id, mount=mount, subpath=subpath)


def parse_config(data: Any, *, nas_root: str = NAS_ROOT) -> Config:
    """Validate the decoded content of vectorizer.json."""
    if not isinstance(data, dict):
        raise ConfigError("the file must hold a JSON object")
    unknown = set(data) - _TOP_KEYS
    if unknown:
        raise ConfigError("unknown key at the top level")
    missing = sorted(_TOP_KEYS - set(data))
    if missing:
        raise ConfigError(f"{missing[0]}: required")

    source_ids = _string_list(data["sources"], "sources", low=1, high=8)
    for i, source_id in enumerate(source_ids):
        if _ID.fullmatch(source_id) is None:
            raise ConfigError(f"sources[{i}]: not a valid id")
    if len(set(source_ids)) != len(source_ids):
        raise ConfigError("sources: an id appears twice")

    extensions = _string_list(data["extensions"], "extensions", low=1, high=40)
    for i, extension in enumerate(extensions):
        if _EXTENSION.fullmatch(extension) is None:
            raise ConfigError(f"extensions[{i}]: 1 to 8 characters of a-z 0-9, without a dot")

    exclude_raw = _string_list(data["exclude"], "exclude", low=0, high=32)
    exclude = tuple(
        tuple(
            normalize_segment(segment)
            for segment in relative_path_segments(pattern, f"exclude[{i}]", max_chars=200, allow_empty=False)
        )
        for i, pattern in enumerate(exclude_raw)
    )

    max_file_mib = data["max_file_mib"]
    if not _is_int(max_file_mib) or not 1 <= max_file_mib <= 2048:
        raise ConfigError("max_file_mib: must be an integer from 1 to 2048")

    embedding_model = _string(data["embedding_model"], "embedding_model")
    if _EMBEDDING_MODEL.fullmatch(embedding_model) is None:
        raise ConfigError("embedding_model: not a valid Ollama model reference")

    if not isinstance(data["ocr"], bool):
        raise ConfigError("ocr: must be a boolean")

    answer = _answer(data["answer"])

    source_paths = data["source_paths"]
    if not isinstance(source_paths, dict):
        raise ConfigError("source_paths: must be an object")
    if set(source_paths) != set(source_ids):
        raise ConfigError("source_paths: must have exactly one entry per id in sources")
    if not nas_root.startswith("/") or nas_root.endswith("/"):
        raise ConfigError("the NAS root must be an absolute path without a trailing '/'")
    sources = tuple(_source(source_id, source_paths[source_id], nas_root) for source_id in source_ids)

    collection = _string(data["collection"], "collection")
    if _COLLECTION.fullmatch(collection) is None:
        raise ConfigError("collection: 1 to 64 characters of A-Z a-z 0-9 _ -")

    return Config(
        sources=sources,
        extensions=frozenset(extensions),
        exclude=exclude,
        max_file_bytes=max_file_mib * 1024 * 1024,
        embedding_model=embedding_model,
        ocr=data["ocr"],
        answer=answer,
        ollama_url=_service_url(data["ollama_url"], "ollama_url"),
        qdrant_url=_service_url(data["qdrant_url"], "qdrant_url"),
        collection=collection,
    )


def _read_small_file(path: Path, limit: int, what: str) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as exc:
        raise ConfigError(f"{what}: cannot be opened ({exc.__class__.__name__})") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ConfigError(f"{what}: not a regular file")
        if info.st_size > limit:
            raise ConfigError(f"{what}: larger than {limit} bytes")
        data = os.read(fd, limit + 1)
    except OSError as exc:
        raise ConfigError(f"{what}: cannot be read ({exc.__class__.__name__})") from None
    finally:
        os.close(fd)
    if len(data) > limit:
        raise ConfigError(f"{what}: larger than {limit} bytes")
    return data


def load_config(path: Path, *, nas_root: str = NAS_ROOT) -> Config:
    """Read and validate vectorizer.json. Raises ConfigError."""
    raw = _read_small_file(path, MAX_CONFIG_BYTES, "vectorizer.json")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except ConfigError as exc:
        raise ConfigError(f"vectorizer.json: {exc}") from None
    except (UnicodeDecodeError, ValueError):
        raise ConfigError("vectorizer.json: not valid UTF-8 JSON") from None
    try:
        return parse_config(data, nas_root=nas_root)
    except ConfigError as exc:
        raise ConfigError(f"vectorizer.json: {exc}") from None


def parse_token(raw: bytes) -> str:
    """The bearer token: one line of 16 to 512 printable ASCII characters, no space."""
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        raise ConfigError("token: must be ASCII") from None
    if text.endswith("\n"):
        text = text[:-1]
    if text.endswith("\r"):
        text = text[:-1]
    if not TOKEN_MIN_CHARS <= len(text) <= TOKEN_MAX_CHARS:
        raise ConfigError(f"token: must be one line of {TOKEN_MIN_CHARS} to {TOKEN_MAX_CHARS} characters")
    if _TOKEN.fullmatch(text) is None:
        raise ConfigError("token: must be one line of printable ASCII without spaces")
    return text


def load_token(path: Path) -> str:
    return parse_token(_read_small_file(path, TOKEN_MAX_CHARS + 2, "token"))


class Secret:
    """A value that does not print itself."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "<secret>"

    __str__ = __repr__


def take_api_key(environ: dict[str, str] | os._Environ[str]) -> Secret | None:
    """Remove the cloud API key from the environment and return it.

    Removing it keeps it away from child processes (the sync run, and the
    document parsers it loads). A key that could not go into an HTTP header as
    it is (empty, non-ASCII, a space or a control character) is treated as
    absent: `/v1/ask` then answers 503 instead of sending something else.
    """
    value = environ.pop(API_KEY_ENV, None)
    if value is None:
        return None
    value = value.strip()
    if not value or len(value) > 4096 or _TOKEN.fullmatch(value) is None:
        return None
    return Secret(value)
