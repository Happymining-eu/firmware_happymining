"""The rules of the plugin catalog, checked from the files themselves.

docs/appliance.md, section 7, says what a catalog entry is: a directory
``<id>/`` holding ``plugin.json`` and ``compose.yaml``. The agent
(``agent/internal/appliance``) and the control plane
(``api/happymining/services/catalog.py``) both read ``plugin.json`` and neither
parses ``compose.yaml``: this module is where the Compose rules are enforced,
and it is a third, independent reading of the ``plugin.json`` rules.

Use::

    violations = check_catalog(Path("appliance/catalog"))

Every violation has the plugin it concerns (``""`` for the catalog as a whole),
a stable ``code`` and a ``detail`` for people. An empty list means the catalog
respects every rule checked here. The codes are listed in ``CODES``.

What is deliberately stricter here than in the two loaders:

* every key of ``plugin.json`` except ``build`` is required, so an entry says
  explicitly that it has no secret, no volume, no post_start;
* an image reference names its registry and never uses a moving tag such as
  ``latest``; ``verified`` is true exactly when a digest is given;
* patterns use explicit character classes only (no ``\\d``, ``\\w``: they do not
  mean the same thing in every engine) and a list pattern cannot match a value
  that starts with a dash (an item becomes an argument of a command);
* a secret's variable cannot be one that Docker Compose itself reads
  (``COMPOSE_…``, ``DOCKER_…``) nor start with ``HM_``;
* a setting may reach a ``command``, an ``entrypoint`` or a healthcheck only
  as one element of an argv list that no shell interprets, and a setting that
  begins such an element must be unable to start with a dash (the same reason
  as for lists: a value that starts with a dash would be read as an option).

Nothing here runs Docker. ``compose.yaml`` is read with a safe YAML loader that
also refuses duplicate keys, anchors, aliases and merge keys (``<<``): what
Compose sees must be exactly what is written, with nothing for two YAML
implementations to resolve differently.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from re import _constants as sre_constants  # the parsed form of a pattern
from re import _parser as sre_parser
from typing import Any

import yaml

PLUGIN_FILE = "plugin.json"
COMPOSE_FILE = "compose.yaml"

NETWORK = "hm-appliance"
PLUGIN_LABEL = "eu.happymining.plugin"
NAS_ROOT = "/srv/happymining"
BIND_PROPAGATIONS = frozenset({"rslave", "slave", "rprivate", "private"})
PLUGIN_DATA_ROOT = "/var/lib/happymining-plugins"
BIND_VARIABLE = "HM_BIND"
DATA_VARIABLE = "HM_PLUGIN_DATA"
# Section 11: the vectorizer gets the key of the cloud answer provider in this
# variable. It is not a plugin secret (its name in a document is
# ai.answer.api_key), so it is the one pass-through a Compose file may name
# without declaring it, and only in the plugin "vectorizer".
ANSWER_KEY_VARIABLE = "HM_ANSWER_API_KEY"
ANSWER_KEY_PLUGIN = "vectorizer"

MODES = ("private_ai", "vectorize")
SETTING_TYPES = ("bool", "int", "enum", "string", "string_list")
BACKUP_POLICIES = ("always", "models", "never")
BIND_VALUES = frozenset({"lan", "localhost"})
MOVING_TAGS = frozenset({"latest", "main", "master", "stable", "edge", "nightly", "dev", "beta", "canary"})

MAX_FILE_BYTES = 64 * 1024
MAX_STRING = 200
MAX_LABEL = 128
MAX_LIST_ITEMS = 32
MAX_ENUM_VALUES = 32
MAX_SETTINGS = 32
MAX_SMALL_LIST = 16  # ports, secrets, images, volumes, post_start: the agent's bound
MAX_EXEC_ARGS = 32
MAX_TIMEOUT_S = 24 * 3600
MAX_INT = 2**31 - 1
MAX_PATTERN = 300
MAX_REPEAT = 1000  # RE2 refuses a larger repetition count

ID_RE = re.compile(r"[a-z][a-z0-9-]{0,30}")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,39}")
SETTING_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,30}")
SETTING_ENV_RE = re.compile(r"HM_SET_[A-Z0-9_]{1,40}")
SECRET_KEY_RE = re.compile(r"[a-z][a-z0-9_]{0,30}")
SECRET_ENV_RE = re.compile(r"[A-Z][A-Z0-9_]{1,60}")
SECRET_NAME_RE = re.compile(r"[a-z][a-z0-9_.-]{0,62}")  # section 5: names of sealed secrets
PROTOCOL_RE = re.compile(r"[a-z][a-z0-9]{0,15}")
SIMPLE_NAME_RE = re.compile(r"[a-z][a-z0-9_-]{0,30}")
HOMEPAGE_RE = re.compile(r"https://[A-Za-z0-9.-]+(/[A-Za-z0-9._~/-]*)?")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
# registry host (with a dot, optional port) / path : tag
IMAGE_REF_RE = re.compile(
    r"(?P<registry>[a-z0-9][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)+(:[0-9]{1,5})?)"
    r"/(?P<path>[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*)"
    r":(?P<tag>[A-Za-z0-9_][A-Za-z0-9._-]{0,127})"
)
BUILD_IMAGE_RE = re.compile(
    r"happymining/[a-z0-9][a-z0-9._-]{0,60}:(?P<tag>[A-Za-z0-9_][A-Za-z0-9._-]{0,127})"
)
ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
VOLUME_NAME_RE = re.compile(r"[a-z][a-z0-9_-]{0,30}")
PORT_RE = re.compile(r"\$\{HM_BIND\}:(?P<host>[0-9]{1,5}):(?P<container>[0-9]{1,5})(/tcp)?")

CONTROL = frozenset({*range(0x20), 0x7F})
FORBIDDEN = CONTROL | {ord(c) for c in "\"'$`\\"}
FORBIDDEN_IN_LISTS = FORBIDDEN | {0x20}

# Variables a plugin secret may not use: the helper's own, and names that
# Docker Compose or the container runtime read from the env file or the process.
RESERVED_SECRET_PREFIXES = ("HM_", "COMPOSE_", "DOCKER_", "BUILDKIT_")
RESERVED_SECRET_NAMES = frozenset(
    {"PATH", "HOME", "PWD", "USER", "SHELL", "HOSTNAME", "LD_PRELOAD", "LD_LIBRARY_PATH", "TMPDIR"}
)

TOP_KEYS_REQUIRED = (
    "schema",
    "id",
    "version",
    "name",
    "summary",
    "homepage",
    "license",
    "gpu",
    "modes",
    "requires",
    "ports",
    "settings",
    "secrets",
    "images",
    "volumes",
    "post_start",
)
TOP_KEYS_OPTIONAL = ("build",)

COMPOSE_TOP_KEYS = frozenset({"services", "networks", "volumes"})
# Everything else in a service is refused. The keys that have their own code
# below (privileged, cap_add, network_mode, pid, ...) are refused with it.
SERVICE_KEYS = frozenset(
    {
        "image",
        "restart",
        "labels",
        "networks",
        "ports",
        "volumes",
        "environment",
        "command",
        "entrypoint",
        "deploy",
        "healthcheck",
        "init",
        "cap_drop",
        "security_opt",
        "pull_policy",
        "user",
        "working_dir",
        "stop_grace_period",
        "stop_signal",
        "read_only",
        "tmpfs",
        "depends_on",
        "expose",
    }
)
HOST_NAMESPACE_KEYS = ("pid", "ipc", "uts", "userns_mode", "cgroup", "cgroup_parent")
DEVICE_KEYS = ("devices", "device_cgroup_rules", "gpus", "runtime")
# Capabilities a project documents as strictly required, per plugin. Empty: none is.
ALLOWED_CAP_ADD: dict[str, frozenset[str]] = {}
SECURITY_OPTS = frozenset({"no-new-privileges:true", "no-new-privileges=true"})
PULL_POLICIES = frozenset({"never", "missing", "if_not_present"})
# Where a setting's variable may appear in a service.
SETTING_PLACES = frozenset({"environment", "command", "entrypoint", "healthcheck"})
# The places of SETTING_PLACES whose value becomes the argv of a process.
ARGV_PLACES = ("entrypoint", "command")
# Programs that interpret their arguments as a script: a setting given to one
# of them could add a command, since patterns do not refuse ; | & < > ( ).
SHELLS = frozenset({"sh", "bash", "dash", "ash", "zsh", "ksh", "mksh", "busybox", "env"})
MERGE_KEY = "<<"

CODES: dict[str, str] = {
    # the entry directory
    "bad-id": "a directory of the catalog is not named after a plugin id, or the id differs from it",
    "missing-file": "plugin.json or compose.yaml is missing, is not a regular file or is a symbolic link",
    "extra-file": "the entry holds something else than plugin.json and compose.yaml",
    # plugin.json
    "json-invalid": "plugin.json is not strict JSON (syntax, duplicate key, size, not an object)",
    "unknown-key": "a key the contract does not define",
    "missing-key": "a required key is absent",
    "bad-schema": "schema is not the integer 1",
    "bad-text": "version, name, summary, homepage, license or a label is not acceptable text",
    "bad-type": "a value has the wrong JSON type",
    "bad-modes": "modes is empty, repeats a mode or names an unknown one",
    "vast-mode": "modes contains vast: no plugin runs in that mode",
    "bad-requires": "requires is malformed, repeats an id or names the plugin itself",
    "requires-unknown": "requires names a plugin that is not in the catalog",
    "requires-cycle": "the plugin's requirements lead back to it",
    "requires-mode": "a required plugin does not run in a mode in which this one runs",
    "bad-port": "an entry of ports is malformed or repeats a name or a number",
    "bad-setting": "a setting is malformed or its default is not acceptable",
    "bad-setting-env": "a setting's variable is not HM_SET_…",
    "bad-pattern": (
        "a pattern is not anchored, not portable, or can let a forbidden character "
        "(or, for a list, a space or a leading dash) through"
    ),
    "bad-bind": "the setting named bind is not the enum of lan and localhost in HM_SET_BIND",
    "env-duplicate": "two settings or secrets use the same variable",
    "bad-secret": "an entry of secrets is malformed, or its secret name would exceed 63 characters",
    "secret-env-reserved": "a secret's variable is reserved for the helper, for settings or for Docker",
    "bad-image": "an entry of images is malformed, has no registry, no tag or a moving tag",
    "image-pin": "verified and digest disagree: verified is true exactly when a digest is given",
    "bad-volume": "an entry of volumes is malformed",
    "bad-build": "build is malformed, or its image is not happymining/<name>:<version of the entry>",
    "bad-post-start": "an entry of post_start is malformed",
    # compose.yaml
    "yaml-invalid": (
        "compose.yaml is not acceptable YAML "
        "(syntax, duplicate key, anchor, alias, merge key, tag, nesting, size)"
    ),
    "compose-unknown-key": "a Compose key that no catalog entry may use",
    "no-services": "compose.yaml defines no service",
    "main-service-missing": "no service is named after the plugin",
    "service-name": "a service is named neither <id> nor <id>-…",
    "service-name-duplicate": "two entries define a service with the same name",
    "restart-policy": "a service does not have restart: unless-stopped",
    "label-missing": "a service does not carry eu.happymining.plugin=<id>",
    "network": "a service does not join exactly hm-appliance, or that network is not declared external",
    "privileged": "a service asks for privileged (even privileged: false is refused)",
    "cap-add": "a service adds a capability",
    "host-namespace": "a service uses the host's network, pid, ipc or another host namespace",
    "security-opt": "a service weakens the container's confinement with security_opt",
    "devices": "a service asks for host devices outside the NVIDIA deploy syntax",
    "socket-mount": "a service mounts a socket of the host (the Docker socket)",
    "bind-outside": "a bind mount leaves /srv/happymining and the plugin's data directory",
    "bind-not-readonly": "a bind mount of /srv/happymining is not read-only",
    "volume-syntax": "a volume entry is not a named volume or an allowed bind mount in a known form",
    "volume-undeclared": "a service uses a named volume the Compose file does not declare",
    "volume-options": "a declared volume has options (driver, external, name, …)",
    "volumes-mismatch": "the named volumes of compose.yaml and of plugin.json differ",
    "port-syntax": "a published port is not written ${HM_BIND}:<host>:<container>",
    "port-bind": "a published port is not bound to ${HM_BIND}",
    "ports-mismatch": "the published ports and the ports of plugin.json differ",
    "port-duplicate": "two entries publish the same port",
    "image-undeclared": "a service uses an image that plugin.json does not list",
    "image-not-pinned": "a verified image is not written ref@digest with the digest of plugin.json",
    "image-pinned-unverified": "compose.yaml pins a digest for an image that is not verified",
    "image-unused": "plugin.json lists an image that compose.yaml does not use",
    "build-pull-policy": "the service that uses the locally built image does not say pull_policy: never",
    "pull-policy": "pull_policy is neither never nor missing",
    "unknown-variable": "a ${VARIABLE} that is neither HM_BIND, HM_PLUGIN_DATA, a setting nor a secret",
    "variable-form": "a variable is not written ${NAME} (no default, no $NAME, no stray $)",
    "variable-place": "a variable is used where it may not be (image, key, label, …)",
    "command-form": (
        "a setting reaches a command, entrypoint or healthcheck that is a string, runs a shell, "
        "or is the program itself"
    ),
    "argument-dash": "a setting that begins an argument of a command can start with a dash",
    "secret-in-wrong-place": "a secret is used elsewhere than as the whole value of an environment entry",
    "passthrough-unknown": (
        "an environment entry without a value names something that is not a secret or a setting"
    ),
    "bad-environment": "an environment entry is malformed",
    "gpu-not-declared": "a service reserves a GPU and plugin.json does not say gpu: true",
    "gpu-syntax": "a GPU reservation is not the NVIDIA deploy syntax",
    "post-start-service": "post_start names a service that compose.yaml does not define",
    "depends-on": "depends_on names a service that compose.yaml does not define",
}


@dataclass(frozen=True, order=True)
class Violation:
    """One broken rule. ``plugin`` is ``""`` when the catalog as a whole is concerned."""

    plugin: str
    code: str
    detail: str

    def __str__(self) -> str:
        return f"{self.plugin or '<catalog>'}: {self.code}: {self.detail}"


class _Sink:
    def __init__(self, plugin: str) -> None:
        self.plugin = plugin
        self.items: list[Violation] = []

    def add(self, code: str, detail: str) -> None:
        if code not in CODES:  # a typo here must not hide a violation
            raise KeyError(code)
        self.items.append(Violation(self.plugin, code, detail))


# --- small helpers -----------------------------------------------------------


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _has_control(text: str) -> bool:
    return any(ord(ch) in CONTROL for ch in text)


def _keys(value: Any, where: str, required: Iterable[str], optional: Iterable[str], out: _Sink) -> bool:
    """True when ``value`` is an object; unknown and missing keys are reported."""
    if not isinstance(value, dict):
        out.add("bad-type", f"{where} must be an object")
        return False
    required, optional = tuple(required), tuple(optional)
    for key in sorted(set(value) - set(required) - set(optional)):
        out.add("unknown-key", f"{where} has the unknown key {key[:40]!r}")
    for key in required:
        if key not in value:
            out.add("missing-key", f"{where} needs {key!r}")
    return True


def _text(value: Any, where: str, out: _Sink, *, min_len: int = 1, max_len: int = MAX_STRING) -> bool:
    if not isinstance(value, str) or not (min_len <= len(value) <= max_len) or _has_control(value):
        out.add("bad-text", f"{where} must be {min_len} to {max_len} characters without control characters")
        return False
    return True


# --- patterns ----------------------------------------------------------------


def _class_matches(items: list[tuple[Any, Any]], code: int) -> bool | None:
    """Whether a character class matches ``code``; None when it is negated or uses a category."""
    for kind, value in items:
        if kind is sre_constants.LITERAL:
            if value == code:
                return True
        elif kind is sre_constants.RANGE:
            if value[0] <= code <= value[1]:
                return True
        else:  # NEGATE, CATEGORY
            return None
    return False


def pattern_problem(pattern: Any, *, for_list: bool) -> str | None:
    """Why ``pattern`` may not be the pattern of a setting, or None.

    Accepted only when it is proven, on the parsed expression, that no value it
    matches can contain a control character, a quote, ``$``, a backquote or a
    backslash (nor, for a list, a space, nor start with a dash). Anything the
    walk does not know is refused. The expression must be ``^…$`` as a whole,
    in the syntax Python and Go (RE2) share, with explicit character classes.
    """
    if not isinstance(pattern, str) or not (2 <= len(pattern) <= MAX_PATTERN):
        return f"must be a string of 2 to {MAX_PATTERN} characters"
    if _has_control(pattern):
        return "contains a control character"
    if re.search(r"\(\?(?!:)", pattern):
        return "uses a group syntax other than (?:…): flags, look-around and named groups are not portable"
    forbidden = FORBIDDEN_IN_LISTS if for_list else FORBIDDEN
    try:
        tree = sre_parser.parse(pattern, re.ASCII)
        re.compile(pattern, re.ASCII)
    except (re.error, RecursionError, OverflowError):
        return "is not a valid regular expression"
    if tree.state.flags & ~(re.ASCII | re.UNICODE):
        return "sets flags"
    items = _items(tree)
    if (
        len(items) < 2
        or items[0] != (sre_constants.AT, sre_constants.AT_BEGINNING)
        or items[-1] != (sre_constants.AT, sre_constants.AT_END)
    ):
        return "must be anchored: ^ and $ around the whole expression (^a|b$ is not)"

    def name_of(code: int) -> str:
        return "a space" if code == 0x20 else "a control character" if code in CONTROL else repr(chr(code))

    def walk(seq: Any, top: bool) -> str | None:
        seq = _items(seq)
        for index, (op, arg) in enumerate(seq):
            if op is sre_constants.LITERAL:
                if arg in forbidden:
                    return f"can match {name_of(arg)}"
            elif op is sre_constants.IN:
                for code in sorted(forbidden):
                    matched = _class_matches(arg, code)
                    if matched is None:
                        return (
                            "uses a negated class or a class such as \\d, \\w, \\s: write the characters out"
                        )
                    if matched:
                        return f"has a class that includes {name_of(code)}"
            elif op in (sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT):
                low, high, inner = arg
                if low > MAX_REPEAT or (high is not sre_constants.MAXREPEAT and high > MAX_REPEAT):
                    return f"repeats more than {MAX_REPEAT} times"
                problem = walk(inner, False)
                if problem:
                    return problem
            elif op is sre_constants.SUBPATTERN:
                _group, add_flags, del_flags, inner = arg
                if add_flags or del_flags:
                    return "sets flags"
                problem = walk(inner, False)
                if problem:
                    return problem
            elif op is sre_constants.BRANCH:
                for alternative in arg[1]:
                    problem = walk(alternative, False)
                    if problem:
                        return problem
            elif op is sre_constants.AT:
                at_edge = top and index in (0, len(seq) - 1)
                if arg not in (sre_constants.AT_BEGINNING, sre_constants.AT_END) or not at_edge:
                    return "uses an anchor elsewhere than at both ends"
            else:  # ".", a negated literal, look-around, back-references, atomic groups, ...
                return "uses a construct that is not allowed (., a negated literal, a back-reference, …)"
        return None

    problem = walk(items, True)
    if problem:
        return problem
    if for_list and _can_start_with(items, ord("-")):
        return "can match a value that starts with a dash"
    return None


def _items(seq: Any) -> list[tuple[Any, Any]]:
    """The (operator, argument) pairs of a parsed pattern or of one of its parts."""
    return list(getattr(seq, "data", seq))


def _nullable(seq: Any) -> bool:
    return all(_element_nullable(op, arg) for op, arg in _items(seq))


def _element_nullable(op: Any, arg: Any) -> bool:
    if op is sre_constants.AT:
        return True
    if op in (sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT):
        return arg[0] == 0 or _nullable(arg[2])
    if op is sre_constants.SUBPATTERN:
        return _nullable(arg[3])
    if op is sre_constants.BRANCH:
        return any(_nullable(alternative) for alternative in arg[1])
    return False


def _can_start_with(seq: Any, code: int) -> bool:
    """Whether a string matched by ``seq`` can begin with ``code`` (conservative: True when unsure)."""
    for op, arg in _items(seq):
        if op is sre_constants.LITERAL:
            if arg == code:
                return True
        elif op is sre_constants.IN:
            if _class_matches(arg, code) is not False:
                return True
        elif op in (sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT):
            if _can_start_with(arg[2], code):
                return True
        elif op is sre_constants.SUBPATTERN:
            if _can_start_with(arg[3], code):
                return True
        elif op is sre_constants.BRANCH:
            if any(_can_start_with(alternative, code) for alternative in arg[1]):
                return True
        elif op is not sre_constants.AT:
            return True
        if not _element_nullable(op, arg):
            return False
    return False


def setting_can_start_with_dash(setting: Any) -> bool:
    """Whether a value of this setting, as the helper writes it, can begin with ``-``.

    bool: never (``true``/``false``); int: when ``min`` is negative; enum: when
    a value does; string and string_list: when the pattern can. A setting whose
    definition is itself broken answers False here: it is refused by its own
    rule (bad-setting, bad-pattern) and is not reported a second time.
    """
    if not isinstance(setting, dict):
        return False
    kind = setting.get("type")
    if kind == "int":
        low = setting.get("min")
        return _is_int(low) and low < 0
    if kind == "enum":
        values = setting.get("values")
        return isinstance(values, list) and any(isinstance(v, str) and v.startswith("-") for v in values)
    if kind in ("string", "string_list"):
        pattern = setting.get("pattern")
        if pattern_problem(pattern, for_list=kind == "string_list") is not None:
            return False
        return _can_start_with(_items(sre_parser.parse(pattern, re.ASCII)), ord("-"))
    return False


# --- plugin.json -------------------------------------------------------------


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"the key {key[:40]!r} appears twice")
        out[key] = value
    return out


def _refuse_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _read_small(path: Path, out: _Sink, code: str) -> str | None:
    if path.is_symlink() or not path.is_file():
        out.add("missing-file", f"{path.name} must be a regular file")
        return None
    raw = path.read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        out.add(code, f"{path.name} is larger than {MAX_FILE_BYTES} bytes")
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        out.add(code, f"{path.name} is not UTF-8")
        return None


def read_plugin_json(path: Path, out: _Sink) -> dict[str, Any] | None:
    text = _read_small(path, out, "json-invalid")
    if text is None:
        return None
    try:
        data = json.loads(text, object_pairs_hook=_no_duplicate_keys, parse_constant=_refuse_constant)
    except (ValueError, RecursionError) as exc:
        out.add("json-invalid", f"{path.name}: {exc}")
        return None
    if not isinstance(data, dict):
        out.add("json-invalid", f"{path.name} must be a JSON object")
        return None
    return data


def _check_setting(name: str, raw: Any, out: _Sink) -> None:
    where = f"settings.{name}"
    if not SETTING_NAME_RE.fullmatch(name):
        out.add("bad-setting", f"{where}: not a setting name")
    if not isinstance(raw, dict) or raw.get("type") not in SETTING_TYPES:
        out.add("bad-setting", f"{where}.type must be one of {', '.join(SETTING_TYPES)}")
        return
    kind = raw["type"]
    extra = {
        "bool": (),
        "int": ("min", "max"),
        "enum": ("values",),
        "string": ("pattern", "max_len"),
        "string_list": ("pattern", "max_items"),
    }[kind]
    _keys(raw, where, ("type", "label", "env", "default", *extra), (), out)
    _text(raw.get("label"), f"{where}.label", out, max_len=MAX_LABEL)
    env = raw.get("env")
    if not isinstance(env, str) or not SETTING_ENV_RE.fullmatch(env):
        out.add("bad-setting-env", f"{where}.env must be HM_SET_ and 1 to 40 of A-Z, 0-9, _")
    if "default" not in raw:
        return
    default = raw["default"]

    def bad_default(why: str) -> None:
        out.add("bad-setting", f"{where}.default {why}")

    if kind == "bool":
        if not isinstance(default, bool):
            bad_default("must be true or false")
    elif kind == "int":
        low, high = raw.get("min"), raw.get("max")
        if not _is_int(low) or not _is_int(high) or not (-MAX_INT <= low <= high <= MAX_INT):
            out.add("bad-setting", f"{where}: min and max must be integers with min <= max")
        elif not _is_int(default) or not (low <= default <= high):
            bad_default(f"must be an integer from {low} to {high}")
    elif kind == "enum":
        values = raw.get("values")
        if (
            not isinstance(values, list)
            or not (1 <= len(values) <= MAX_ENUM_VALUES)
            or not all(isinstance(v, str) and 1 <= len(v) <= MAX_STRING for v in values)
            or len(set(values)) != len(values)
        ):
            out.add("bad-setting", f"{where}.values must be 1 to {MAX_ENUM_VALUES} different strings")
        elif any(ord(ch) in FORBIDDEN for v in values for ch in v):
            out.add("bad-setting", f"{where}.values contains a character no setting may contain")
        elif default not in values:
            bad_default("must be one of the values")
    else:
        for_list = kind == "string_list"
        pattern = raw.get("pattern")
        problem = pattern_problem(pattern, for_list=for_list)
        if problem:
            out.add("bad-pattern", f"{where}.pattern {problem}")
        bound_key, ceiling = ("max_items", MAX_LIST_ITEMS) if for_list else ("max_len", MAX_STRING)
        bound = raw.get(bound_key)
        if not _is_int(bound) or not (1 <= bound <= ceiling):
            out.add("bad-setting", f"{where}.{bound_key} must be an integer from 1 to {ceiling}")
            return
        if problem:
            return
        regex = re.compile(pattern, re.ASCII)
        if for_list:
            if not isinstance(default, list) or len(default) > bound:
                bad_default(f"must be a list of at most {bound} strings")
                return
            items, limit, forbidden = default, MAX_STRING, FORBIDDEN_IN_LISTS
        else:
            items, limit, forbidden = [default], bound, FORBIDDEN
        for item in items:
            if not isinstance(item, str) or len(item) > limit or (for_list and not item):
                bad_default("holds something that is not a string of the allowed length")
            elif any(ord(ch) in forbidden for ch in item):
                bad_default("contains a character no setting may contain")
            elif not regex.fullmatch(item):
                bad_default("does not match the pattern")
    if name == "bind" and (
        kind != "enum"
        or env != "HM_SET_BIND"
        or not isinstance(raw.get("values"), list)
        or not set(map(str, raw["values"])) <= BIND_VALUES
    ):
        out.add("bad-bind", f"{where} must be an enum of lan and localhost in HM_SET_BIND")


def _check_images(plugin: dict[str, Any], out: _Sink) -> None:
    images = plugin.get("images")
    if not isinstance(images, list) or not (1 <= len(images) <= MAX_SMALL_LIST):
        out.add("bad-image", f"images must list 1 to {MAX_SMALL_LIST} images")
        return
    seen: set[str] = set()
    for index, image in enumerate(images):
        where = f"images[{index}]"
        if not _keys(image, where, ("ref", "digest", "verified"), (), out):
            continue
        ref, digest, verified = image.get("ref"), image.get("digest"), image.get("verified")
        match = IMAGE_REF_RE.fullmatch(ref) if isinstance(ref, str) and len(ref) <= MAX_STRING else None
        if not match:
            out.add("bad-image", f"{where}.ref must be registry/path:tag, in lower case, without a digest")
        elif match["tag"] in MOVING_TAGS:
            out.add("bad-image", f"{where}.ref uses the moving tag {match['tag']!r}")
        if isinstance(ref, str):
            if ref in seen:
                out.add("bad-image", f"{where}.ref is listed twice")
            seen.add(ref)
        if digest is not None and (not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest)):
            out.add("bad-image", f"{where}.digest must be sha256: and 64 hexadecimal characters, or null")
        if not isinstance(verified, bool):
            out.add("bad-type", f"{where}.verified must be true or false")
        elif verified != (digest is not None):
            out.add("image-pin", f"{where}: verified must be true exactly when a digest is given")


def _check_post_start(plugin: dict[str, Any], out: _Sink) -> None:
    steps = plugin.get("post_start")
    if not isinstance(steps, list) or len(steps) > MAX_SMALL_LIST:
        out.add("bad-post-start", f"post_start must be a list of at most {MAX_SMALL_LIST} entries")
        return
    settings = plugin.get("settings") if isinstance(plugin.get("settings"), dict) else {}
    for index, step in enumerate(steps):
        where = f"post_start[{index}]"
        if not _keys(step, where, ("service", "exec", "timeout_s"), ("for_each",), out):
            continue
        service, argv, timeout = step.get("service"), step.get("exec"), step.get("timeout_s")
        if not isinstance(service, str) or not SIMPLE_NAME_RE.fullmatch(service):
            out.add("bad-post-start", f"{where}.service is not a service name")
        if "timeout_s" in step and (not _is_int(timeout) or not (1 <= timeout <= MAX_TIMEOUT_S)):
            out.add("bad-post-start", f"{where}.timeout_s must be an integer from 1 to {MAX_TIMEOUT_S}")
        uses_item = False
        if (
            not isinstance(argv, list)
            or not (1 <= len(argv) <= MAX_EXEC_ARGS)
            or not all(
                isinstance(a, str) and a and len(a.encode()) <= MAX_STRING and not _has_control(a)
                for a in argv
            )
        ):
            out.add("bad-post-start", f"{where}.exec must be 1 to {MAX_EXEC_ARGS} non-empty strings")
        else:
            uses_item = any("{item}" in a for a in argv)
            if "{item}" in argv[0]:
                out.add("bad-post-start", f"{where}.exec: the command itself cannot be {{item}}")
        if "for_each" in step:
            each = step["for_each"]
            target = settings.get(each) if isinstance(each, str) else None
            if not isinstance(target, dict) or target.get("type") != "string_list":
                out.add("bad-post-start", f"{where}.for_each must name a string_list setting of this plugin")
        elif uses_item:
            out.add("bad-post-start", f"{where}.exec uses {{item}} without for_each")


def check_plugin_json(directory_name: str, plugin: dict[str, Any], out: _Sink) -> None:
    """Every rule that concerns plugin.json alone."""
    _keys(plugin, PLUGIN_FILE, TOP_KEYS_REQUIRED, TOP_KEYS_OPTIONAL, out)

    if "schema" in plugin and (not _is_int(plugin["schema"]) or plugin["schema"] != 1):
        out.add("bad-schema", "schema must be the integer 1")
    plugin_id = plugin.get("id")
    if not isinstance(plugin_id, str) or not ID_RE.fullmatch(plugin_id) or plugin_id != directory_name:
        out.add("bad-id", "id must be a plugin id and equal the name of its directory")
    version = plugin.get("version")
    if "version" in plugin and (not isinstance(version, str) or not VERSION_RE.fullmatch(version)):
        out.add("bad-text", "version must be 1 to 40 characters of A-Z, a-z, 0-9, ., _, -")
    if "name" in plugin:
        _text(plugin["name"], "name", out, max_len=80)
    if "summary" in plugin:
        _text(plugin["summary"], "summary", out, max_len=300)
    if "license" in plugin:
        _text(plugin["license"], "license", out, max_len=80)
    if "homepage" in plugin:
        homepage = plugin["homepage"]
        if not isinstance(homepage, str) or len(homepage) > MAX_STRING or not HOMEPAGE_RE.fullmatch(homepage):
            out.add("bad-text", "homepage must be an https:// address")
    if "gpu" in plugin and not isinstance(plugin["gpu"], bool):
        out.add("bad-type", "gpu must be true or false")

    modes = plugin.get("modes")
    if "modes" in plugin:
        if isinstance(modes, list) and "vast" in modes:
            out.add("vast-mode", "modes contains vast")
        if (
            not isinstance(modes, list)
            or not modes
            or len(set(map(str, modes))) != len(modes)
            or any(mode not in (*MODES, "vast") for mode in modes)
        ):
            out.add("bad-modes", f"modes must be a non-empty list without repetition of: {', '.join(MODES)}")

    requires = plugin.get("requires")
    if "requires" in plugin and (
        not isinstance(requires, list)
        or len(requires) > MAX_LIST_ITEMS
        or not all(isinstance(r, str) and ID_RE.fullmatch(r) for r in requires)
        or len(set(requires)) != len(requires)
        or plugin_id in requires
    ):
        out.add("bad-requires", "requires must be a list of other plugin ids, each once")

    ports = plugin.get("ports")
    if "ports" in plugin:
        if not isinstance(ports, list) or len(ports) > MAX_SMALL_LIST:
            out.add("bad-port", f"ports must be a list of at most {MAX_SMALL_LIST} entries")
        else:
            names: list[Any] = []
            numbers: list[Any] = []
            for index, port in enumerate(ports):
                where = f"ports[{index}]"
                if not _keys(port, where, ("name", "port", "protocol", "ui"), (), out):
                    continue
                if not isinstance(port.get("name"), str) or not ID_RE.fullmatch(port["name"]):
                    out.add("bad-port", f"{where}.name is not a port name")
                if not _is_int(port.get("port")) or not (1 <= port["port"] <= 65535):
                    out.add("bad-port", f"{where}.port must be an integer from 1 to 65535")
                if not isinstance(port.get("protocol"), str) or not PROTOCOL_RE.fullmatch(port["protocol"]):
                    out.add("bad-port", f"{where}.protocol is not a protocol name")
                if not isinstance(port.get("ui"), bool):
                    out.add("bad-type", f"{where}.ui must be true or false")
                names.append(port.get("name"))
                numbers.append(port.get("port"))
            if len(set(map(str, names))) != len(names) or len(set(map(str, numbers))) != len(numbers):
                out.add("bad-port", "ports repeats a name or a number")

    settings = plugin.get("settings")
    envs: list[str] = []
    if "settings" in plugin:
        if not isinstance(settings, dict) or len(settings) > MAX_SETTINGS:
            out.add("bad-setting", f"settings must be an object of at most {MAX_SETTINGS} settings")
        else:
            for name, raw in settings.items():
                _check_setting(name, raw, out)
                if isinstance(raw, dict) and isinstance(raw.get("env"), str):
                    envs.append(raw["env"])

    secrets = plugin.get("secrets")
    if "secrets" in plugin:
        if not isinstance(secrets, list) or len(secrets) > MAX_SMALL_LIST:
            out.add("bad-secret", f"secrets must be a list of at most {MAX_SMALL_LIST} entries")
        else:
            keys: list[Any] = []
            for index, secret in enumerate(secrets):
                where = f"secrets[{index}]"
                if not _keys(secret, where, ("key", "env", "label", "required"), (), out):
                    continue
                key, env = secret.get("key"), secret.get("env")
                if not isinstance(key, str) or not SECRET_KEY_RE.fullmatch(key):
                    out.add("bad-secret", f"{where}.key is not a secret key")
                elif not SECRET_NAME_RE.fullmatch(f"plugin.{plugin_id}.{key}"):
                    out.add("bad-secret", f"{where}.key makes a secret name that is too long")
                if not isinstance(env, str) or not SECRET_ENV_RE.fullmatch(env):
                    out.add("bad-secret", f"{where}.env is not an upper-case variable name")
                else:
                    envs.append(env)
                    if env.startswith(RESERVED_SECRET_PREFIXES) or env in RESERVED_SECRET_NAMES:
                        out.add("secret-env-reserved", f"{where}.env {env} is reserved")
                _text(secret.get("label"), f"{where}.label", out, max_len=MAX_LABEL)
                if not isinstance(secret.get("required"), bool):
                    out.add("bad-type", f"{where}.required must be true or false")
                keys.append(key)
            if len(set(map(str, keys))) != len(keys):
                out.add("bad-secret", "secrets repeats a key")
    for env in sorted({env for env in envs if envs.count(env) > 1}):
        out.add("env-duplicate", f"the variable {env} is used twice")

    if "images" in plugin:
        _check_images(plugin, out)

    volumes = plugin.get("volumes")
    if "volumes" in plugin:
        if not isinstance(volumes, list) or len(volumes) > MAX_SMALL_LIST:
            out.add("bad-volume", f"volumes must be a list of at most {MAX_SMALL_LIST} entries")
        else:
            volume_names: list[Any] = []
            for index, volume in enumerate(volumes):
                where = f"volumes[{index}]"
                if not _keys(volume, where, ("name", "backup"), (), out):
                    continue
                if not isinstance(volume.get("name"), str) or not VOLUME_NAME_RE.fullmatch(volume["name"]):
                    out.add("bad-volume", f"{where}.name is not a volume name")
                if volume.get("backup") not in BACKUP_POLICIES:
                    out.add("bad-volume", f"{where}.backup must be one of {', '.join(BACKUP_POLICIES)}")
                volume_names.append(volume.get("name"))
            if len(set(map(str, volume_names))) != len(volume_names):
                out.add("bad-volume", "volumes repeats a name")

    if "build" in plugin:
        build = plugin["build"]
        if _keys(build, "build", ("context", "image"), (), out):
            context, image = build.get("context"), build.get("image")
            if not isinstance(context, str) or not SIMPLE_NAME_RE.fullmatch(context):
                out.add("bad-build", "build.context must be one directory name")
            match = BUILD_IMAGE_RE.fullmatch(image) if isinstance(image, str) else None
            if not match or match["tag"] != version:
                out.add("bad-build", "build.image must be happymining/<name>:<version of the entry>")

    if "post_start" in plugin:
        _check_post_start(plugin, out)


# --- compose.yaml ------------------------------------------------------------


class _StrictLoader(yaml.SafeLoader):
    """yaml.SafeLoader that also refuses a key written twice in a mapping."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _value in node.value:
            key = self.construct_object(key_node, deep=True)
            try:
                duplicate = key in seen
            except TypeError as exc:
                raise yaml.constructor.ConstructorError(
                    None, None, "a mapping key is not a plain value", key_node.start_mark
                ) from exc
            if duplicate:
                raise yaml.constructor.ConstructorError(
                    None, None, f"the key {str(key)[:40]!r} appears twice", key_node.start_mark
                )
            seen.add(key)
        return super().construct_mapping(node, deep)


def _merge_key_line(node: Any) -> int | None:
    """The line (1-based) of the first ``<<`` key in a composed YAML tree, or None.

    A merge key needs no anchor (``<<: {privileged: true}``), and a quoted
    ``"<<"`` is a merge key for some implementations and not for others: both
    are refused, so that no reader can see a key the checker did not.
    """
    if isinstance(node, yaml.MappingNode):
        for key, value in node.value:
            if isinstance(key, yaml.ScalarNode) and (
                key.tag == "tag:yaml.org,2002:merge" or key.value == MERGE_KEY
            ):
                return key.start_mark.line + 1
            line = _merge_key_line(key) or _merge_key_line(value)
            if line:
                return line
    elif isinstance(node, yaml.SequenceNode):
        for item in node.value:
            line = _merge_key_line(item)
            if line:
                return line
    return None


def read_compose(path: Path, out: _Sink) -> dict[str, Any] | None:
    text = _read_small(path, out, "yaml-invalid")
    if text is None:
        return None
    try:
        for event in yaml.parse(text, Loader=yaml.SafeLoader):
            if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
                out.add("yaml-invalid", f"{path.name} uses an anchor or an alias")
                return None
        line = _merge_key_line(yaml.compose(text, Loader=yaml.SafeLoader))
        if line:
            out.add("yaml-invalid", f"{path.name} uses a merge key (<<) on line {line}")
            return None
        data = yaml.load(text, Loader=_StrictLoader)  # noqa: S506 - _StrictLoader is a SafeLoader
    except yaml.YAMLError as exc:
        out.add("yaml-invalid", f"{path.name}: {str(exc).splitlines()[0][:160]}")
        return None
    except RecursionError:
        out.add("yaml-invalid", f"{path.name} is nested too deeply")
        return None
    if not isinstance(data, dict):
        out.add("yaml-invalid", f"{path.name} must be a mapping")
        return None
    return data


@dataclass(frozen=True)
class _Reference:
    name: str | None  # None when no variable name could be read
    form: str  # "plain", "modifier", "unbraced", "malformed", "stray"


def scan_variables(text: str) -> Iterator[_Reference]:
    """The ``$`` references Docker Compose would interpolate in ``text``. ``$$`` is a literal dollar."""
    index = 0
    while True:
        index = text.find("$", index)
        if index < 0:
            return
        following = text[index + 1 : index + 2]
        if following == "$":
            index += 2
        elif following == "{":
            end = text.find("}", index + 2)
            if end < 0:
                yield _Reference(None, "malformed")
                return
            inner = text[index + 2 : end]
            if ENV_NAME_RE.fullmatch(inner):
                yield _Reference(inner, "plain")
            else:
                match = ENV_NAME_RE.match(inner)
                yield _Reference(match.group() if match else None, "modifier")
            index = end + 1
        else:
            match = ENV_NAME_RE.match(text, index + 1)
            if match:
                yield _Reference(match.group(), "unbraced")
                index = match.end()
            else:
                yield _Reference(None, "stray")
                index += 1


def _walk_strings(node: Any, path: tuple[Any, ...]) -> Iterator[tuple[tuple[Any, ...], str, bool]]:
    """Every string of a YAML tree as (path, text, is_key)."""
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str):
                yield (*path, key), key, True
            yield from _walk_strings(value, (*path, key))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _walk_strings(value, (*path, index))
    elif isinstance(node, str):
        yield path, node, False


def _environment(service: dict[str, Any], where: str, out: _Sink) -> list[tuple[str, str | None]]:
    """The environment of a service as (name, value); the value is None for a pass-through."""
    raw = service.get("environment")
    if raw is None:
        return []
    entries: list[tuple[str, str | None]] = []
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, str):
                out.add("bad-environment", f"{where}.environment holds an entry that is not a string")
                continue
            name, separator, value = item.partition("=")
            entries.append((name, value if separator else None))
    elif isinstance(raw, dict):
        for name, value in raw.items():
            if value is None:
                entries.append((str(name), None))
            elif isinstance(value, str | int | float):  # a bool is an int
                entries.append((str(name), value if isinstance(value, str) else json.dumps(value)))
            else:
                out.add("bad-environment", f"{where}.environment.{name} must be a scalar")
    else:
        out.add("bad-environment", f"{where}.environment must be a list or a mapping")
        return []
    names = [name for name, _ in entries]
    for name in names:
        if not ENV_NAME_RE.fullmatch(name):
            out.add("bad-environment", f"{where}.environment: {name[:40]!r} is not a variable name")
    if len(set(names)) != len(names):
        out.add("bad-environment", f"{where}.environment sets a variable twice")
    return entries


def _bind_source_problem(source: str, plugin_id: str) -> tuple[str, str] | None:
    """(code, detail) when ``source`` may not be bind-mounted, else None. Read-only is checked elsewhere."""
    lowered = source.lower()
    if lowered.endswith(".sock") or "docker.sock" in lowered or "containerd" in lowered:
        return "socket-mount", f"{source!r} is a socket of the host"
    for root in ("${HM_PLUGIN_DATA}", f"{PLUGIN_DATA_ROOT}/{plugin_id}", NAS_ROOT):
        if source == root or source.startswith(root + "/"):
            segments = source[len(root) :].split("/")[1:]
            if any(segment in ("", ".", "..") or "$" in segment for segment in segments):
                return (
                    "bind-outside",
                    f"{source!r} is not a plain path (.., ., //, a trailing / or a variable)",
                )
            return None
    return "bind-outside", f"{source!r} is outside {NAS_ROOT} and the plugin's data directory"


def _check_volumes(
    name: str, service: dict[str, Any], plugin_id: str, declared: set[str], used: set[str], out: _Sink
) -> None:
    where = f"services.{name}.volumes"
    raw = service.get("volumes")
    if raw is None:
        return
    if not isinstance(raw, list):
        out.add("volume-syntax", f"{where} must be a list")
        return
    for index, entry in enumerate(raw):
        at = f"{where}[{index}]"
        read_only = False
        if isinstance(entry, str):
            parts = entry.split(":")
            if len(parts) not in (2, 3) or not parts[0] or not parts[1].startswith("/"):
                out.add("volume-syntax", f"{at} must be <volume or path>:<absolute path>[:ro]")
                continue
            source = parts[0]
            if len(parts) == 3:
                if parts[2] not in ("ro", "rw"):
                    out.add("volume-syntax", f"{at}: the only options are ro and rw")
                    continue
                read_only = parts[2] == "ro"
            is_bind = not VOLUME_NAME_RE.fullmatch(source)
        elif isinstance(entry, dict):
            unknown = sorted(set(entry) - {"type", "source", "target", "read_only", "bind"})
            kind, source, target = entry.get("type"), entry.get("source"), entry.get("target")
            bind_options = entry.get("bind", {})
            # Only the propagation of a bind mount may be chosen, and only a
            # value that lets mounts flow from the host into the container
            # (slave) or not at all (private). A shared mount would let the
            # container's own mounts appear on the host.
            if "bind" in entry and (
                kind != "bind"
                or not isinstance(bind_options, dict)
                or set(bind_options) != {"propagation"}
                or bind_options.get("propagation") not in BIND_PROPAGATIONS
            ):
                out.add(
                    "volume-syntax",
                    f"{at}.bind may only set propagation to one of " + ", ".join(sorted(BIND_PROPAGATIONS)),
                )
                continue
            if (
                unknown
                or kind not in ("volume", "bind")
                or not isinstance(source, str)
                or not source
                or not isinstance(target, str)
                or not target.startswith("/")
                or not isinstance(entry.get("read_only", False), bool)
            ):
                out.add(
                    "volume-syntax",
                    f"{at} must have type volume or bind, source, target, read_only and bind only",
                )
                continue
            read_only = entry.get("read_only", False)
            is_bind = kind == "bind"
            if not is_bind and not VOLUME_NAME_RE.fullmatch(source):
                out.add("volume-syntax", f"{at}.source is not a volume name")
                continue
        else:
            out.add("volume-syntax", f"{at} must be a string or a mapping")
            continue
        if is_bind:
            problem = _bind_source_problem(source, plugin_id)
            if problem:
                out.add(*problem)
            elif (source == NAS_ROOT or source.startswith(NAS_ROOT + "/")) and not read_only:
                out.add("bind-not-readonly", f"{at}: {source!r} must be mounted read-only")
        else:
            used.add(source)
            if source not in declared:
                out.add("volume-undeclared", f"{at}: the volume {source!r} is not declared in compose.yaml")


def _check_commands(name: str, service: dict[str, Any], settings: dict[str, Any], out: _Sink) -> None:
    """Where a setting becomes part of an argv: entrypoint, command, healthcheck test.

    ``settings`` maps each setting's variable to its definition. The rules:
    a string form (Compose splits it into words after substituting the value,
    and a string healthcheck runs in a shell) and an argv that starts with a
    shell or with a setting are refused when a setting appears in them; an
    element that begins with a setting needs a setting that cannot start with
    a dash. A variable that is no setting is refused by the variable rules.
    """
    where = f"services.{name}"

    def uses_setting(value: Any) -> bool:
        return any(
            ref.name in settings
            for _path, text, _key in _walk_strings(value, ())
            for ref in scan_variables(text)
        )

    def program(element: Any) -> str:
        return element.rsplit("/", 1)[-1] if isinstance(element, str) else ""

    def check_elements(at: str, elements: list[Any]) -> None:
        for index, element in enumerate(elements):
            if not isinstance(element, str) or not element.startswith("${"):
                continue
            first = next(iter(scan_variables(element)), None)
            if (
                first is not None
                and first.name in settings
                and setting_can_start_with_dash(settings[first.name])
            ):
                out.add(
                    "argument-dash",
                    f"{at}[{index}] begins with ${{{first.name}}}, whose value can start with a dash",
                )

    argv: list[Any] = []
    for key in ARGV_PLACES:
        value = service.get(key)
        if value is None or not uses_setting(value):
            if isinstance(value, list):
                argv.extend(value)
            elif isinstance(value, str):  # Compose splits it into words; the first is the program
                argv.extend(value.split())
            continue
        if not isinstance(value, list):
            out.add("command-form", f"{where}.{key} holds a setting: write it as a list, one argument each")
            continue
        check_elements(f"{where}.{key}", value)
        argv.extend(value)
    entrypoint, command = service.get("entrypoint"), service.get("command")
    if uses_setting([entrypoint, command]) and argv:
        if uses_setting(argv[0]):
            out.add("command-form", f"{where}: a setting cannot be the program a service runs")
        elif program(argv[0]) in SHELLS:
            out.add("command-form", f"{where} runs {program(argv[0])}: a setting cannot reach a shell")

    healthcheck = service.get("healthcheck")
    test = healthcheck.get("test") if isinstance(healthcheck, dict) else None
    if test is None or not uses_setting(test):
        return
    at = f"{where}.healthcheck.test"
    if not isinstance(test, list) or not test or test[0] != "CMD":
        out.add("command-form", f'{at} holds a setting: write it as ["CMD", program, argument, …], no shell')
        return
    if len(test) < 2 or uses_setting(test[1]):
        out.add("command-form", f"{at}: a setting cannot be the program a healthcheck runs")
    elif program(test[1]) in SHELLS:
        out.add("command-form", f"{at} runs {program(test[1])}: a setting cannot reach a shell")
    check_elements(at, test)


def _check_deploy(name: str, service: dict[str, Any], gpu: bool, out: _Sink) -> None:
    where = f"services.{name}.deploy"
    deploy = service.get("deploy")
    if deploy is None:
        return

    def only(value: Any, at: str, allowed: set[str]) -> bool:
        if not isinstance(value, dict):
            out.add("compose-unknown-key", f"{at} must be a mapping")
            return False
        for key in sorted(set(map(str, value)) - allowed):
            out.add("compose-unknown-key", f"{at}.{key} is not allowed")
        return True

    if not only(deploy, where, {"resources"}):
        return
    resources = deploy.get("resources")
    if resources is None or not only(resources, f"{where}.resources", {"limits", "reservations"}):
        return
    limits = resources.get("limits")
    if limits is not None:
        only(limits, f"{where}.resources.limits", {"cpus", "memory", "pids"})
    reservations = resources.get("reservations")
    if reservations is None or not only(
        reservations, f"{where}.resources.reservations", {"cpus", "memory", "devices"}
    ):
        return
    devices = reservations.get("devices")
    if devices is None:
        return
    if not gpu:
        out.add("gpu-not-declared", f"{where} reserves devices but plugin.json says gpu: false")
    if not isinstance(devices, list) or not devices:
        out.add("gpu-syntax", f"{where}.resources.reservations.devices must be a non-empty list")
        return
    for index, device in enumerate(devices):
        at = f"{where}.resources.reservations.devices[{index}]"
        if not isinstance(device, dict) or set(device) - {"driver", "count", "device_ids", "capabilities"}:
            out.add("gpu-syntax", f"{at} may only have driver, count or device_ids, and capabilities")
            continue
        count, ids = device.get("count"), device.get("device_ids")
        count_ok = count is None or count == "all" or (_is_int(count) and count >= 1)
        ids_ok = ids is None or (isinstance(ids, list) and ids and all(isinstance(i, str) for i in ids))
        if (
            device.get("driver") != "nvidia"
            or device.get("capabilities") != ["gpu"]
            or not count_ok
            or not ids_ok
            or (count is not None and ids is not None)
        ):
            out.add(
                "gpu-syntax", f"{at} must be driver: nvidia, capabilities: [gpu], and count or device_ids"
            )


def check_compose(plugin_id: str, plugin: dict[str, Any], compose: dict[str, Any], out: _Sink) -> None:
    """Every rule that concerns compose.yaml, given the entry's plugin.json."""

    def as_list(value: Any) -> list[Any]:
        return value if isinstance(value, list) else []

    def as_dict(value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    gpu = plugin.get("gpu") is True
    settings_by_env = {
        s["env"]: s
        for s in as_dict(plugin.get("settings")).values()
        if isinstance(s, dict) and isinstance(s.get("env"), str)
    }
    settings_envs = set(settings_by_env)
    secret_envs = {s["env"] for s in as_list(plugin.get("secrets")) if isinstance(s, dict) and "env" in s}
    images = [
        i for i in as_list(plugin.get("images")) if isinstance(i, dict) and isinstance(i.get("ref"), str)
    ]
    build = as_dict(plugin.get("build"))
    build_image = build.get("image") if isinstance(build.get("image"), str) else None

    for key in sorted(set(map(str, compose)) - COMPOSE_TOP_KEYS):
        out.add("compose-unknown-key", f"the top-level key {key[:40]!r} is not allowed")

    # Variables, wherever they are written.
    for path, text, is_key in _walk_strings(compose, ()):
        at = ".".join(map(str, path))
        section = path[2] if len(path) > 2 and path[0] == "services" else None
        for ref in scan_variables(text):
            if ref.form != "plain":
                out.add("variable-form", f"{at}: a variable must be written ${{NAME}} ({ref.form})")
                if ref.name is None:
                    continue
            name = ref.name
            if is_key:
                out.add("variable-place", f"{at}: a key cannot hold a variable")
            elif name == BIND_VARIABLE:
                if section != "ports":
                    out.add("variable-place", f"{at}: ${{{name}}} is for published ports only")
            elif name == DATA_VARIABLE:
                if section != "volumes":
                    out.add("variable-place", f"{at}: ${{{name}}} is for volume sources only")
            elif name in settings_envs:
                if section not in SETTING_PLACES:
                    out.add("variable-place", f"{at}: a setting cannot be used in {section or 'this place'}")
            elif name in secret_envs:
                if section != "environment":
                    out.add(
                        "secret-in-wrong-place", f"{at}: the secret ${{{name}}} is used outside environment"
                    )
            else:
                out.add(
                    "unknown-variable",
                    f"{at}: ${{{name}}} is not HM_BIND, HM_PLUGIN_DATA, a setting or a secret",
                )

    # Networks: hm-appliance, external, and nothing else.
    networks = compose.get("networks")
    network_decl = as_dict(networks).get(NETWORK)
    if (
        not isinstance(networks, dict)
        or set(networks) != {NETWORK}
        or not isinstance(network_decl, dict)
        or network_decl.get("external") is not True
        or set(network_decl) - {"external", "name"}
        or network_decl.get("name", NETWORK) != NETWORK
    ):
        out.add("network", f"networks must declare exactly {NETWORK} with external: true")

    # Named volumes: declared without options, the same as in plugin.json.
    top_volumes = compose.get("volumes")
    declared: set[str] = set()
    if top_volumes is not None and not isinstance(top_volumes, dict):
        out.add("volume-syntax", "volumes must be a mapping")
    for name, options in as_dict(top_volumes).items():
        declared.add(str(name))
        if not isinstance(name, str) or not VOLUME_NAME_RE.fullmatch(name):
            out.add("volume-syntax", f"volumes: {str(name)[:40]!r} is not a volume name")
        if options not in (None, {}):
            out.add("volume-options", f"volumes.{name} must have no option")
    used_volumes: set[str] = set()

    services = compose.get("services")
    if not isinstance(services, dict) or not services:
        out.add("no-services", "services must define at least one service")
        services = {}
    if services and plugin_id not in services:
        out.add("main-service-missing", f"no service is named {plugin_id}")

    allowed_images = {
        (f"{image['ref']}@{image['digest']}" if image.get("verified") is True else image["ref"]): image
        for image in images
    }
    refs = {image["ref"]: image for image in images}
    used_refs: set[str] = set()
    published: list[int] = []

    for name, service in services.items():
        where = f"services.{name}"
        if (
            not isinstance(name, str)
            or not SIMPLE_NAME_RE.fullmatch(name)
            or not (name == plugin_id or name.startswith(plugin_id + "-"))
        ):
            out.add("service-name", f"{where} must be named {plugin_id} or {plugin_id}-…")
        if not isinstance(service, dict):
            out.add("compose-unknown-key", f"{where} must be a mapping")
            continue

        # Keys.
        if "privileged" in service:
            out.add("privileged", f"{where}.privileged is not allowed")
        if "cap_add" in service:
            added = (
                {str(c) for c in as_list(service["cap_add"])}
                if isinstance(service["cap_add"], list)
                else {"?"}
            )
            if not added <= ALLOWED_CAP_ADD.get(plugin_id, frozenset()):
                out.add("cap-add", f"{where}.cap_add adds {', '.join(sorted(added))}")
        if "network_mode" in service:
            code = "host-namespace" if service["network_mode"] == "host" else "network"
            out.add(code, f"{where}.network_mode is not allowed: a service joins {NETWORK}")
        for key in HOST_NAMESPACE_KEYS:
            if key in service:
                out.add("host-namespace", f"{where}.{key} is not allowed")
        for key in DEVICE_KEYS:
            if key in service:
                out.add("devices", f"{where}.{key} is not allowed: a GPU is asked for with deploy")
        specific = {"privileged", "cap_add", "network_mode", *HOST_NAMESPACE_KEYS, *DEVICE_KEYS}
        for key in sorted(set(map(str, service)) - SERVICE_KEYS - specific):
            out.add("compose-unknown-key", f"{where}.{key[:40]} is not allowed")

        if service.get("restart") != "unless-stopped":
            out.add("restart-policy", f"{where}.restart must be unless-stopped")

        labels = service.get("labels")
        if isinstance(labels, list):
            label_ok = f"{PLUGIN_LABEL}={plugin_id}" in labels
        else:
            label_ok = as_dict(labels).get(PLUGIN_LABEL) == plugin_id
        if not label_ok:
            out.add("label-missing", f"{where}.labels must hold {PLUGIN_LABEL}={plugin_id}")

        joined = service.get("networks")
        if not (joined == [NETWORK] or joined == {NETWORK: None}):
            out.add("network", f"{where}.networks must be exactly [{NETWORK}]")

        for option in as_list(service.get("security_opt")) if "security_opt" in service else []:
            if option not in SECURITY_OPTS:
                out.add("security-opt", f"{where}.security_opt: only no-new-privileges:true is allowed")
        if "security_opt" in service and not isinstance(service["security_opt"], list):
            out.add("security-opt", f"{where}.security_opt must be a list")

        policy = service.get("pull_policy")
        if "pull_policy" in service and policy not in PULL_POLICIES:
            out.add("pull-policy", f"{where}.pull_policy must be never or missing")

        # Image.
        image = service.get("image")
        if not isinstance(image, str):
            out.add("image-undeclared", f"{where}.image is missing")
        elif build_image is not None and image == build_image:
            if policy != "never":
                out.add(
                    "build-pull-policy", f"{where} uses the image built on the machine: pull_policy: never"
                )
        elif image in allowed_images:
            used_refs.add(allowed_images[image]["ref"])
        else:
            ref, _, digest = image.partition("@")
            if ref not in refs:
                out.add("image-undeclared", f"{where}.image {image[:120]!r} is not listed in plugin.json")
            else:
                used_refs.add(ref)
                if refs[ref].get("verified") is True:
                    out.add("image-not-pinned", f"{where}.image must be {ref}@<the digest of plugin.json>")
                elif digest:
                    out.add(
                        "image-pinned-unverified", f"{where}.image pins a digest plugin.json does not verify"
                    )
                else:
                    out.add(
                        "image-undeclared", f"{where}.image {image[:120]!r} is not as plugin.json lists it"
                    )

        # Published ports.
        ports = service.get("ports")
        if ports is not None and not isinstance(ports, list):
            out.add("port-syntax", f"{where}.ports must be a list")
        for index, port in enumerate(as_list(ports)):
            at = f"{where}.ports[{index}]"
            if not isinstance(port, str):
                out.add("port-syntax", f'{at} must be the string "${{HM_BIND}}:<host>:<container>"')
            elif not port.startswith("${HM_BIND}:"):
                out.add("port-bind", f"{at} must be bound to ${{HM_BIND}}")
            else:
                match = PORT_RE.fullmatch(port)
                if not match or not all(1 <= int(match[g]) <= 65535 for g in ("host", "container")):
                    out.add("port-syntax", f'{at} must be "${{HM_BIND}}:<host>:<container>"')
                else:
                    published.append(int(match["host"]))

        _check_volumes(name, service, plugin_id, declared, used_volumes, out)

        # Environment: secrets and pass-through.
        for env_name, value in _environment(service, where, out):
            if value is None:
                allowed = env_name in secret_envs or env_name in settings_envs
                if not allowed and not (plugin_id == ANSWER_KEY_PLUGIN and env_name == ANSWER_KEY_VARIABLE):
                    out.add(
                        "passthrough-unknown",
                        f"{where}.environment: {env_name} has no value and is no secret",
                    )
                continue
            for ref in scan_variables(value):
                if ref.name in secret_envs and value != f"${{{ref.name}}}":
                    out.add(
                        "secret-in-wrong-place",
                        f"{where}.environment.{env_name}: a secret must be the whole value",
                    )

        _check_commands(name, service, settings_by_env, out)
        _check_deploy(name, service, gpu, out)

        depends = service.get("depends_on")
        if depends is not None:
            wanted = depends if isinstance(depends, list | dict) else ["?"]
            for other in wanted:
                if other not in services:
                    out.add("depends-on", f"{where}.depends_on names {str(other)[:40]!r}")

    # What plugin.json says against what compose.yaml does.
    declared_ports = sorted(
        p["port"] for p in as_list(plugin.get("ports")) if isinstance(p, dict) and _is_int(p.get("port"))
    )
    if sorted(published) != declared_ports:
        out.add(
            "ports-mismatch",
            f"compose.yaml publishes {sorted(published)}, plugin.json lists {declared_ports}",
        )
    plugin_volumes = {
        v["name"]
        for v in as_list(plugin.get("volumes"))
        if isinstance(v, dict) and isinstance(v.get("name"), str)
    }
    if declared != plugin_volumes or not declared <= used_volumes:
        out.add(
            "volumes-mismatch",
            f"compose.yaml declares {sorted(declared)} and uses {sorted(used_volumes)}, "
            f"plugin.json lists {sorted(plugin_volumes)}",
        )
    if build_image is None:
        for ref in sorted(set(refs) - used_refs):
            out.add("image-unused", f"{ref} is listed in plugin.json and no service uses it")
    for index, step in enumerate(as_list(plugin.get("post_start"))):
        if (
            isinstance(step, dict)
            and isinstance(step.get("service"), str)
            and step["service"] not in services
        ):
            out.add("post-start-service", f"post_start[{index}].service {step['service']!r} is not a service")


# --- entries and catalogs ----------------------------------------------------


@dataclass(frozen=True)
class Entry:
    """One catalog entry as read, with what is wrong in it, by where it was found.

    ``plugin`` or ``compose`` is None when its file could not be read.
    """

    id: str
    directory: Path
    plugin: dict[str, Any] | None
    compose: dict[str, Any] | None
    layout: tuple[Violation, ...]  # the directory itself: its name, missing and extra files
    plugin_json: tuple[Violation, ...]  # plugin.json alone
    compose_yaml: tuple[Violation, ...]  # compose.yaml, given plugin.json

    @property
    def violations(self) -> tuple[Violation, ...]:
        return (*self.layout, *self.plugin_json, *self.compose_yaml)


def check_entry(directory: Path) -> Entry:
    """Read one entry and check every rule that needs nothing but that entry."""
    layout, in_plugin, in_compose = _Sink(directory.name), _Sink(directory.name), _Sink(directory.name)
    if directory.is_symlink() or not ID_RE.fullmatch(directory.name):
        layout.add("bad-id", f"the directory {directory.name[:40]!r} is not named after a plugin id")
    for child in sorted(directory.iterdir()):
        if child.name not in (PLUGIN_FILE, COMPOSE_FILE):
            layout.add("extra-file", f"{child.name[:60]!r} does not belong in a catalog entry")
    plugin = read_plugin_json(directory / PLUGIN_FILE, in_plugin)
    compose = read_compose(directory / COMPOSE_FILE, in_compose)
    for sink in (in_plugin, in_compose):  # a file that is not there is a fault of the directory
        layout.items.extend(v for v in sink.items if v.code == "missing-file")
        sink.items = [v for v in sink.items if v.code != "missing-file"]
    if plugin is not None:
        check_plugin_json(directory.name, plugin, in_plugin)
        if compose is not None:
            check_compose(directory.name, plugin, compose, in_compose)
    return Entry(
        directory.name,
        directory,
        plugin,
        compose,
        tuple(layout.items),
        tuple(in_plugin.items),
        tuple(in_compose.items),
    )


def entry_directories(catalog_dir: Path) -> list[Path]:
    """The directories of a catalog, sorted. Files directly in it (a README) are not entries."""
    return sorted(p for p in catalog_dir.iterdir() if p.is_dir())


def check_catalog(catalog_dir: Path) -> list[Violation]:
    """Every violation of the catalog in ``catalog_dir``: per entry, then across entries."""
    entries = [check_entry(directory) for directory in entry_directories(catalog_dir)]
    violations = [violation for entry in entries for violation in entry.violations]
    plugins = {entry.id: entry.plugin for entry in entries if entry.plugin is not None}

    def modes_of(plugin_id: str) -> set[str]:
        modes = plugins[plugin_id].get("modes")
        return {m for m in modes if isinstance(m, str)} if isinstance(modes, list) else set()

    def requires_of(plugin_id: str) -> list[str]:
        """The other plugins it requires; naming itself is bad-requires, reported per entry."""
        requires = plugins[plugin_id].get("requires")
        if not isinstance(requires, list):
            return []
        return [r for r in requires if isinstance(r, str) and r != plugin_id]

    for plugin_id in plugins:
        for other in requires_of(plugin_id):
            if other not in plugins:
                violations.append(Violation(plugin_id, "requires-unknown", f"requires {other!r}"))
            elif not modes_of(plugin_id) <= modes_of(other):
                missing = ", ".join(sorted(modes_of(plugin_id) - modes_of(other)))
                violations.append(
                    Violation(plugin_id, "requires-mode", f"{other} does not run in: {missing}")
                )

    def leads_back(plugin_id: str) -> bool:
        """Whether following requirements from ``plugin_id`` reaches it again (iterative)."""
        seen: set[str] = set()
        pending = [other for other in requires_of(plugin_id) if other in plugins]
        while pending:
            current = pending.pop()
            if current == plugin_id:
                return True
            if current in seen:
                continue
            seen.add(current)
            pending.extend(other for other in requires_of(current) if other in plugins)
        return False

    for plugin_id in plugins:
        if leads_back(plugin_id):
            violations.append(Violation(plugin_id, "requires-cycle", "its requirements lead back to itself"))

    services: dict[str, str] = {}
    ports: dict[int, str] = {}
    for entry in entries:
        compose_services = entry.compose.get("services") if entry.compose else None
        for name in compose_services if isinstance(compose_services, dict) else ():
            if name in services:
                violations.append(
                    Violation(
                        entry.id, "service-name-duplicate", f"{name} is also a service of {services[name]}"
                    )
                )
            services.setdefault(name, entry.id)
        plugin_ports = entry.plugin.get("ports") if entry.plugin else None
        for port in plugin_ports if isinstance(plugin_ports, list) else ():
            number = port.get("port") if isinstance(port, dict) else None
            if not _is_int(number):
                continue
            if number in ports:
                violations.append(
                    Violation(entry.id, "port-duplicate", f"{number} is also a port of {ports[number]}")
                )
            ports.setdefault(number, entry.id)
    return sorted(violations)
