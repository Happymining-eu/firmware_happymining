"""The plugin catalog as the control plane sees it (docs/appliance.md, section 7).

A plugin is a directory ``<catalog>/<id>/`` holding ``plugin.json`` and
``compose.yaml``. The same tree is installed on every machine with the
firmware. The control plane reads only ``plugin.json``: it needs to know which
plugins exist, what settings and secrets each takes and what it requires, so
that it can check a machine's desired-state document and describe the plugins
to the panel. The Compose files are never parsed here, and nothing from the
catalog is ever sent to a machine: the cloud names a plugin, the machine holds
its definition.

Loading is strict. An unknown key, a wrong type or a pattern that could let a
quote or a ``$`` through is an error for the whole catalog, reported as
``CatalogError``: a broken catalog must not be half used. A missing or empty
directory is not an error; the catalog is then empty and no plugin can be
configured.
"""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from re import _constants as _sre  # the parsed form of a pattern, to see which characters it lets through
from re import _parser as _sre_parser
from typing import Any

from ..config import Settings
from ..errors import AppError
from ..sealing import SECRET_NAME_RE

CATALOG_SCHEMA = 1
MAX_PLUGIN_JSON_BYTES = 64 * 1024
MAX_ENTRIES = 64

ID_RE = re.compile(r"[a-z][a-z0-9-]{0,30}")
SETTING_KEY_RE = re.compile(r"[a-z][a-z0-9_]{0,30}")
SECRET_KEY_RE = re.compile(r"[a-z][a-z0-9_]{0,30}")
SETTING_ENV_RE = re.compile(r"HM_SET_[A-Z0-9_]{1,40}")
SECRET_ENV_RE = re.compile(r"[A-Z][A-Z0-9_]{1,60}")
PORT_NAME_RE = re.compile(r"[a-z][a-z0-9-]{0,30}")
# The contract does not enumerate protocols; only the shape is checked.
PROTOCOL_RE = re.compile(r"[a-z][a-z0-9]{0,15}")
IMAGE_REF_RE = re.compile(r"[a-z0-9][a-z0-9._/:-]{0,200}:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
VOLUME_NAME_RE = re.compile(r"[a-z][a-z0-9_-]{0,30}")
SERVICE_NAME_RE = re.compile(r"[a-z][a-z0-9_-]{0,40}")
BUILD_CONTEXT_RE = re.compile(r"[a-z][a-z0-9_-]{0,40}")

PLUGIN_MODES = ("private_ai", "vectorize")  # never "vast": no plugin runs in that mode
SETTING_TYPES = ("bool", "int", "enum", "string", "string_list")
BACKUP_POLICIES = ("always", "models", "never")
# Variables the helper sets itself for every plugin; a secret cannot take their name.
RESERVED_ENV = frozenset({"HM_BIND", "HM_PLUGIN_DATA"})
MAX_STRING_LEN = 200
MAX_LIST_ITEMS = 32
MAX_INT = 2**31 - 1

# What a setting value must never contain: it ends up in an environment file
# read by Docker Compose (docs/appliance.md, section 7).
_CONTROL = frozenset({*range(0x20), 0x7F})
_FORBIDDEN = _CONTROL | {ord(c) for c in "\"'$`\\"}
_FORBIDDEN_IN_LISTS = _FORBIDDEN | {0x20}  # a list travels as one space-separated variable


class CatalogError(AppError):
    """The catalog on this server is not valid. Not the caller's fault."""

    status_code = 500
    code = "catalog_invalid"

    def default_message(self) -> str:
        return "The plugin catalog on the server is not valid."


class _Bad(ValueError):
    """A problem inside one plugin.json; turned into a CatalogError with the file's name."""


# --- small strict readers --------------------------------------------------


def has_control_character(text: str) -> bool:
    return any(ord(ch) in _CONTROL for ch in text)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _obj(value: Any, where: str, required: tuple[str, ...], optional: tuple[str, ...] = ()) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _Bad(f"{where} must be an object")
    unknown = sorted(set(value) - set(required) - set(optional))
    if unknown:
        raise _Bad(f"{where} has an unknown key: {unknown[0][:40]!r}")
    missing = [key for key in required if key not in value]
    if missing:
        raise _Bad(f"{where} needs {missing[0]!r}")
    return value


def _text(value: Any, where: str, *, max_len: int = MAX_STRING_LEN, min_len: int = 0) -> str:
    if not isinstance(value, str) or not (min_len <= len(value) <= max_len) or has_control_character(value):
        raise _Bad(
            f"{where} must be a string of {min_len} to {max_len} characters without control characters"
        )
    return value


def _match(value: Any, pattern: re.Pattern[str], where: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise _Bad(f"{where} must match {pattern.pattern}")
    return value


def _bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise _Bad(f"{where} must be true or false")
    return value


def _list(value: Any, where: str, *, max_items: int) -> list[Any]:
    if not isinstance(value, list) or len(value) > max_items:
        raise _Bad(f"{where} must be a list of at most {max_items} items")
    return value


def _unique(values: list[str], where: str) -> None:
    if len(set(values)) != len(values):
        raise _Bad(f"{where} contains a duplicate")


# --- patterns --------------------------------------------------------------


def _name_of(code: int) -> str:
    return "a space" if code == 0x20 else "a control character" if code in _CONTROL else repr(chr(code))


def pattern_problem(pattern: str, *, for_list: bool) -> str | None:
    """Why ``pattern`` is not acceptable for a setting, or None.

    A pattern is accepted only when every character it can let through is known
    not to be a control character, a quote, ``$``, a backtick or a backslash
    (nor a space, for a list). This is decided on the parsed pattern, so it is
    a proof and not a sample: anything the walk does not understand is refused.
    Patterns must be anchored at both ends, because not every implementation
    that checks the same document matches the whole string by default.
    """
    if not isinstance(pattern, str) or not (2 <= len(pattern) <= 300):
        return "must be a string of 2 to 300 characters"
    if not pattern.startswith("^") or not pattern.endswith("$") or pattern.endswith("\\$"):
        return "must be anchored with ^ and $"
    forbidden = _FORBIDDEN_IN_LISTS if for_list else _FORBIDDEN
    try:
        tree = _sre_parser.parse(pattern, re.ASCII)
    except (re.error, RecursionError, OverflowError):
        return "is not a valid regular expression"
    if tree.state.flags & ~(re.ASCII | re.UNICODE):
        return "must not set flags"

    def walk(items: Any) -> str | None:
        for op, arg in items:
            if op is _sre.LITERAL:
                if arg in forbidden:
                    return f"can match {_name_of(arg)}"
            elif op is _sre.IN:
                for kind, value in arg:
                    if kind is _sre.LITERAL:
                        if value in forbidden:
                            return f"can match {_name_of(value)}"
                    elif kind is _sre.RANGE:
                        low, high = value
                        inside = sorted(code for code in forbidden if low <= code <= high)
                        if inside:
                            return f"has a range that includes {_name_of(inside[0])}"
                    elif kind is _sre.CATEGORY:
                        # With the ASCII flag: digits, and letters, digits and underscore.
                        if value not in (_sre.CATEGORY_DIGIT, _sre.CATEGORY_WORD):
                            return "uses a character class that can match forbidden characters"
                    else:  # a negated class matches almost everything
                        return "uses a negated character class"
            elif op in (_sre.MAX_REPEAT, _sre.MIN_REPEAT):
                problem = walk(arg[2])
                if problem:
                    return problem
            elif op is _sre.SUBPATTERN:
                _group, add_flags, del_flags, inner = arg
                if add_flags or del_flags:
                    return "must not set flags"
                problem = walk(inner)
                if problem:
                    return problem
            elif op is _sre.BRANCH:
                for alternative in arg[1]:
                    problem = walk(alternative)
                    if problem:
                        return problem
            elif op is _sre.AT:
                if arg not in (_sre.AT_BEGINNING, _sre.AT_END):
                    return "uses an assertion that is not allowed"
            else:  # ".", a negated literal, look-around, back-references, ...
                return "uses a construct that can match forbidden characters or is not allowed"
        return None

    return walk(tree)


# --- the entry -------------------------------------------------------------


@dataclass(frozen=True)
class Setting:
    key: str
    type: str
    label: str
    env: str
    default: Any
    min: int | None = None
    max: int | None = None
    values: tuple[str, ...] = ()
    pattern: str | None = None
    max_len: int | None = None
    max_items: int | None = None
    regex: re.Pattern[str] | None = field(default=None, compare=False, repr=False)

    def problem(self, value: Any) -> str | None:
        """Why ``value`` is not acceptable for this setting, or None. Never echoes the value."""
        if self.type == "bool":
            return None if isinstance(value, bool) else "must be true or false"
        if self.type == "int":
            if not _is_int(value):
                return "must be an integer"
            return None if self.min <= value <= self.max else f"must be between {self.min} and {self.max}"
        if self.type == "enum":
            if not isinstance(value, str) or value not in self.values:
                return "must be one of: " + ", ".join(self.values)
            return None
        if self.type == "string":
            return self._text_problem(value, _FORBIDDEN)
        if not isinstance(value, list):
            return "must be a list of strings"
        if len(value) > self.max_items:
            return f"takes at most {self.max_items} items"
        for item in value:
            problem = self._text_problem(item, _FORBIDDEN_IN_LISTS)
            if problem:
                return "items: " + problem
        return None

    def _text_problem(self, value: Any, forbidden: frozenset[int]) -> str | None:
        if not isinstance(value, str):
            return "must be a string"
        limit = self.max_len if self.max_len is not None else MAX_STRING_LEN
        if len(value) > limit:
            return f"must be at most {limit} characters"
        # Checked here as well as through the pattern: two independent nets.
        if any(ord(ch) in forbidden for ch in value):
            return "contains a character that is not allowed"
        if self.regex is None or not self.regex.fullmatch(value):
            return "does not have the expected form"
        return None

    def public(self) -> dict[str, Any]:
        out: dict[str, Any] = {"type": self.type, "label": self.label, "default": self.default}
        if self.type == "int":
            out.update(min=self.min, max=self.max)
        elif self.type == "enum":
            out["values"] = list(self.values)
        elif self.type == "string":
            out.update(pattern=self.pattern, max_len=self.max_len)
        elif self.type == "string_list":
            out.update(pattern=self.pattern, max_items=self.max_items, max_len=MAX_STRING_LEN)
        return out


@dataclass(frozen=True)
class SecretSpec:
    key: str
    env: str
    label: str
    required: bool


@dataclass(frozen=True)
class CatalogEntry:
    id: str
    version: str
    name: str
    summary: str
    homepage: str
    license: str
    gpu: bool
    modes: tuple[str, ...]
    requires: tuple[str, ...]
    ports: tuple[dict[str, Any], ...]
    settings: Mapping[str, Setting]
    secrets: tuple[SecretSpec, ...]
    images: tuple[dict[str, Any], ...]
    volumes: tuple[dict[str, Any], ...]
    build: dict[str, Any] | None
    post_start: tuple[dict[str, Any], ...]

    @property
    def images_verified(self) -> bool:
        """True when every image is pinned to a digest read from its registry."""
        return all(image["verified"] for image in self.images)

    def secret_name(self, key: str) -> str:
        """The name a plugin secret has in a machine's document."""
        return f"plugin.{self.id}.{key}"

    def secret_names(self) -> dict[str, SecretSpec]:
        return {self.secret_name(spec.key): spec for spec in self.secrets}

    def public(self) -> dict[str, Any]:
        """What the panel shows. No environment variable names, images or commands."""
        return {
            "id": self.id,
            "version": self.version,
            "name": self.name,
            "summary": self.summary,
            "homepage": self.homepage,
            "license": self.license,
            "gpu": self.gpu,
            "modes": list(self.modes),
            "requires": list(self.requires),
            "ports": [dict(port) for port in self.ports],
            "settings": {key: setting.public() for key, setting in self.settings.items()},
            "secrets": [
                {
                    "key": spec.key,
                    "name": self.secret_name(spec.key),
                    "label": spec.label,
                    "required": spec.required,
                }
                for spec in self.secrets
            ],
            "images_verified": self.images_verified,
        }


@dataclass(frozen=True)
class Catalog:
    directory: str
    entries: Mapping[str, CatalogEntry]

    def get(self, plugin_id: str) -> CatalogEntry | None:
        return self.entries.get(plugin_id)

    def __contains__(self, plugin_id: object) -> bool:
        return plugin_id in self.entries

    def __iter__(self) -> Iterator[CatalogEntry]:
        return iter(self.entries.values())

    def __len__(self) -> int:
        return len(self.entries)

    def public(self) -> list[dict[str, Any]]:
        return [entry.public() for entry in self]


# --- parsing one plugin.json -----------------------------------------------

_SETTING_KEYS = {
    "bool": ((), ()),
    "int": (("min", "max"), ()),
    "enum": (("values",), ()),
    "string": (("pattern", "max_len"), ()),
    "string_list": (("pattern", "max_items"), ()),
}


def _setting(key: str, raw: Any) -> Setting:
    where = f"settings.{key}"
    if not isinstance(raw, dict) or raw.get("type") not in SETTING_TYPES:
        raise _Bad(f"{where}.type must be one of: " + ", ".join(SETTING_TYPES))
    kind = raw["type"]
    required, optional = _SETTING_KEYS[kind]
    _obj(raw, where, ("type", "label", "env", "default", *required), optional)
    label = _text(raw["label"], f"{where}.label", min_len=1)
    env = _match(raw["env"], SETTING_ENV_RE, f"{where}.env")
    extra: dict[str, Any] = {}
    if kind == "int":
        low, high = raw["min"], raw["max"]
        if not _is_int(low) or not _is_int(high) or not (-MAX_INT <= low <= high <= MAX_INT):
            raise _Bad(f"{where}: min and max must be integers with min <= max")
        extra = {"min": low, "max": high}
    elif kind == "enum":
        values = _list(raw["values"], f"{where}.values", max_items=MAX_LIST_ITEMS)
        for value in values:
            _text(value, f"{where}.values", min_len=1)
            if any(ord(ch) in _FORBIDDEN for ch in value):
                raise _Bad(f"{where}.values contains a character that is not allowed in a setting")
        if not values:
            raise _Bad(f"{where}.values must not be empty")
        _unique(values, f"{where}.values")
        extra = {"values": tuple(values)}
    elif kind in ("string", "string_list"):
        problem = pattern_problem(raw["pattern"], for_list=kind == "string_list")
        if problem:
            raise _Bad(f"{where}.pattern {problem}")
        extra = {"pattern": raw["pattern"], "regex": re.compile(raw["pattern"], re.ASCII)}
        bound = "max_len" if kind == "string" else "max_items"
        ceiling = MAX_STRING_LEN if kind == "string" else MAX_LIST_ITEMS
        if not _is_int(raw[bound]) or not (1 <= raw[bound] <= ceiling):
            raise _Bad(f"{where}.{bound} must be an integer from 1 to {ceiling}")
        extra[bound] = raw[bound]
    setting = Setting(key=key, type=kind, label=label, env=env, default=raw["default"], **extra)
    problem = setting.problem(raw["default"])
    if problem:
        raise _Bad(f"{where}.default {problem}")
    return setting


def _ports(raw: Any) -> tuple[dict[str, Any], ...]:
    out = []
    for index, item in enumerate(_list(raw, "ports", max_items=MAX_LIST_ITEMS)):
        where = f"ports[{index}]"
        _obj(item, where, ("name", "port", "protocol", "ui"))
        if not _is_int(item["port"]) or not (1 <= item["port"] <= 65535):
            raise _Bad(f"{where}.port must be an integer from 1 to 65535")
        out.append(
            {
                "name": _match(item["name"], PORT_NAME_RE, f"{where}.name"),
                "port": item["port"],
                "protocol": _match(item["protocol"], PROTOCOL_RE, f"{where}.protocol"),
                "ui": _bool(item["ui"], f"{where}.ui"),
            }
        )
    _unique([port["name"] for port in out], "ports (names)")
    _unique([str(port["port"]) for port in out], "ports (numbers)")
    return tuple(out)


def _secrets(plugin_id: str, raw: Any) -> tuple[SecretSpec, ...]:
    out = []
    for index, item in enumerate(_list(raw, "secrets", max_items=MAX_LIST_ITEMS)):
        where = f"secrets[{index}]"
        _obj(item, where, ("key", "env", "label", "required"))
        spec = SecretSpec(
            key=_match(item["key"], SECRET_KEY_RE, f"{where}.key"),
            env=_match(item["env"], SECRET_ENV_RE, f"{where}.env"),
            label=_text(item["label"], f"{where}.label", min_len=1),
            required=_bool(item["required"], f"{where}.required"),
        )
        if not SECRET_NAME_RE.fullmatch(f"plugin.{plugin_id}.{spec.key}"):
            raise _Bad(f"{where}.key makes a secret name longer than a secret name may be")
        out.append(spec)
    _unique([spec.key for spec in out], "secrets (keys)")
    return tuple(out)


def _images(raw: Any) -> tuple[dict[str, Any], ...]:
    out = []
    for index, item in enumerate(_list(raw, "images", max_items=MAX_LIST_ITEMS)):
        where = f"images[{index}]"
        _obj(item, where, ("ref", "digest", "verified"))
        digest = item["digest"]
        if digest is not None:
            _match(digest, DIGEST_RE, f"{where}.digest")
        verified = _bool(item["verified"], f"{where}.verified")
        if verified and digest is None:
            raise _Bad(f"{where}: an image without a digest cannot be verified")
        out.append(
            {"ref": _match(item["ref"], IMAGE_REF_RE, f"{where}.ref"), "digest": digest, "verified": verified}
        )
    if not out:
        raise _Bad("images must list every image the Compose file uses")
    return tuple(out)


def _volumes(raw: Any) -> tuple[dict[str, Any], ...]:
    out = []
    for index, item in enumerate(_list(raw, "volumes", max_items=MAX_LIST_ITEMS)):
        where = f"volumes[{index}]"
        _obj(item, where, ("name", "backup"))
        if item["backup"] not in BACKUP_POLICIES:
            raise _Bad(f"{where}.backup must be one of: " + ", ".join(BACKUP_POLICIES))
        out.append({"name": _match(item["name"], VOLUME_NAME_RE, f"{where}.name"), "backup": item["backup"]})
    _unique([volume["name"] for volume in out], "volumes (names)")
    return tuple(out)


def _post_start(raw: Any, settings: Mapping[str, Setting]) -> tuple[dict[str, Any], ...]:
    out = []
    for index, item in enumerate(_list(raw, "post_start", max_items=MAX_LIST_ITEMS)):
        where = f"post_start[{index}]"
        _obj(item, where, ("service", "exec"), ("for_each", "timeout_s"))
        argv = _list(item["exec"], f"{where}.exec", max_items=MAX_LIST_ITEMS)
        if not argv:
            raise _Bad(f"{where}.exec must not be empty")
        for word in argv:
            _text(word, f"{where}.exec", min_len=1)
        step: dict[str, Any] = {
            "service": _match(item["service"], SERVICE_NAME_RE, f"{where}.service"),
            "exec": list(argv),
        }
        each = item.get("for_each")
        if each is not None:
            if not isinstance(each, str) or each not in settings or settings[each].type != "string_list":
                raise _Bad(f"{where}.for_each must name a string_list setting of this plugin")
            step["for_each"] = each
        elif any("{item}" in word for word in argv):
            raise _Bad(f"{where}.exec uses {{item}} without for_each")
        timeout = item.get("timeout_s")
        if timeout is not None:
            if not _is_int(timeout) or not (1 <= timeout <= 86400):
                raise _Bad(f"{where}.timeout_s must be an integer from 1 to 86400")
            step["timeout_s"] = timeout
        out.append(step)
    return tuple(out)


def parse_entry(directory_name: str, raw: Any) -> CatalogEntry:
    """Validate the content of one ``plugin.json``. Raises ``_Bad``."""
    _obj(
        raw,
        "plugin.json",
        ("schema", "id", "version", "name", "summary", "gpu", "modes", "images"),
        ("homepage", "license", "requires", "ports", "settings", "secrets", "volumes", "build", "post_start"),
    )
    if not _is_int(raw["schema"]) or raw["schema"] != CATALOG_SCHEMA:
        raise _Bad(f"schema must be {CATALOG_SCHEMA}")
    plugin_id = _match(raw["id"], ID_RE, "id")
    if plugin_id != directory_name:
        raise _Bad("id must equal the name of its directory")
    modes = _list(raw["modes"], "modes", max_items=len(PLUGIN_MODES))
    if not modes or any(mode not in PLUGIN_MODES for mode in modes):
        raise _Bad("modes must be a non-empty list of: " + ", ".join(PLUGIN_MODES) + " (never vast)")
    _unique(modes, "modes")
    requires = _list(raw.get("requires", []), "requires", max_items=MAX_LIST_ITEMS)
    for other in requires:
        _match(other, ID_RE, "requires")
    _unique(requires, "requires")
    if plugin_id in requires:
        raise _Bad("a plugin cannot require itself")

    raw_settings = raw.get("settings", {})
    if not isinstance(raw_settings, dict) or len(raw_settings) > MAX_LIST_ITEMS:
        raise _Bad(f"settings must be an object with at most {MAX_LIST_ITEMS} entries")
    settings: dict[str, Setting] = {}
    for key, spec in raw_settings.items():
        _match(key, SETTING_KEY_RE, "settings (a key)")
        settings[key] = _setting(key, spec)
    secrets = _secrets(plugin_id, raw.get("secrets", []))
    variables = [setting.env for setting in settings.values()] + [spec.env for spec in secrets]
    _unique(variables, "the environment variable names of settings and secrets")
    for spec in secrets:
        if spec.env in RESERVED_ENV or SETTING_ENV_RE.fullmatch(spec.env):
            raise _Bad(f"secrets: {spec.env} is reserved for the helper or for settings")

    build = raw.get("build")
    if build is not None:
        _obj(build, "build", ("context", "image"))
        build = {
            "context": _match(build["context"], BUILD_CONTEXT_RE, "build.context"),
            "image": _match(build["image"], IMAGE_REF_RE, "build.image"),
        }
    return CatalogEntry(
        id=plugin_id,
        version=_text(raw["version"], "version", min_len=1, max_len=40),
        name=_text(raw["name"], "name", min_len=1, max_len=80),
        summary=_text(raw["summary"], "summary", max_len=300),
        homepage=_text(raw.get("homepage", ""), "homepage"),
        license=_text(raw.get("license", ""), "license", max_len=80),
        gpu=_bool(raw["gpu"], "gpu"),
        modes=tuple(modes),
        requires=tuple(requires),
        ports=_ports(raw.get("ports", [])),
        settings=settings,
        secrets=secrets,
        images=_images(raw["images"]),
        volumes=_volumes(raw.get("volumes", [])),
        build=build,
        post_start=_post_start(raw.get("post_start", []), settings),
    )


# --- loading a directory ---------------------------------------------------


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise _Bad(f"the key {key[:40]!r} appears twice")
        out[key] = value
    return out


def _refuse_constant(name: str) -> Any:
    raise _Bad(f"{name} is not JSON")


def _read_plugin_json(path: Path) -> Any:
    try:
        if path.stat().st_size > MAX_PLUGIN_JSON_BYTES:
            raise _Bad("is larger than 64 KiB")
        text = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise _Bad(f"cannot be read ({type(exc).__name__})") from exc
    try:
        return json.loads(text, object_pairs_hook=_no_duplicate_keys, parse_constant=_refuse_constant)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise _Bad("is not valid JSON") from exc


def load_catalog(directory: Path | str) -> Catalog:
    """Read every ``<directory>/<id>/plugin.json``. A missing directory is an empty catalog."""
    root = Path(directory)
    entries: dict[str, CatalogEntry] = {}
    if not root.is_dir():
        return Catalog(directory=str(root), entries=entries)
    children = sorted(p for p in root.iterdir() if p.is_dir() and not p.name.startswith((".", "_")))
    if len(children) > MAX_ENTRIES:
        raise CatalogError(f"The plugin catalog has more than {MAX_ENTRIES} entries.")
    for child in children:
        manifest = child / "plugin.json"
        try:
            if not manifest.is_file():
                raise _Bad("is missing")
            entries[child.name] = parse_entry(child.name, _read_plugin_json(manifest))
        except _Bad as exc:
            raise CatalogError(f"The plugin catalog is not valid: {child.name}/plugin.json: {exc}") from exc
    for entry in entries.values():
        for other in entry.requires:
            if other not in entries:
                raise CatalogError(
                    f"The plugin catalog is not valid: {entry.id}/plugin.json: requires {other!r}, "
                    "which is not in the catalog"
                )
    return Catalog(directory=str(root), entries=entries)


# --- the catalog of this process -------------------------------------------

# appliance/catalog next to the api directory: <root>/api/happymining/services/catalog.py
SHIPPED_CATALOG_DIR = Path(__file__).resolve().parents[3] / "appliance" / "catalog"

_cache: dict[str, Catalog] = {}
_cache_lock = threading.Lock()


def catalog_dir(settings: Settings) -> Path:
    return Path(settings.catalog_dir) if settings.catalog_dir else SHIPPED_CATALOG_DIR


def get_catalog(settings: Settings) -> Catalog:
    """The catalog this process offers. Read once per directory; ``reload`` reads it again."""
    key = str(catalog_dir(settings))
    with _cache_lock:
        found = _cache.get(key)
        if found is None:
            found = _cache[key] = load_catalog(key)
        return found


def reload(settings: Settings | None = None) -> Catalog | None:
    """Forget what was read. With settings: read that catalog again now and return it."""
    with _cache_lock:
        if settings is None:
            _cache.clear()
            return None
        key = str(catalog_dir(settings))
        _cache.pop(key, None)
        found = _cache[key] = load_catalog(key)
        return found
