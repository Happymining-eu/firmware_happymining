"""The plugin catalog respects docs/appliance.md, section 7.

Three parts:

1. The rules of ``catalog_rules.py`` applied to the catalog that ships with the
   firmware (``appliance/catalog``) and to the fixture catalog the other
   implementations are tested against (``appliance/testdata/catalog``).
2. Broken entries, built in a temporary directory: each must be refused, with
   the code of the rule it breaks. A rule without a refused example fails
   ``test_every_rule_has_a_refused_example``.
3. What is specific to the shipped catalog: its plugins, their defaults, the
   layout of the vectorizer, the README, and a second opinion from Docker
   Compose itself when it is installed.

No test starts a container or needs the network or PostgreSQL.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import catalog_rules as rules
import pytest
import yaml

REPO = Path(__file__).resolve().parents[3]
SHIPPED = REPO / "appliance" / "catalog"
FIXTURE = REPO / "appliance" / "testdata" / "catalog"
CATALOGS = {"shipped": SHIPPED, "fixture": FIXTURE}

SHIPPED_PLUGINS = ("hermes", "ollama", "open-webui", "openclaw", "qdrant", "vectorizer")
FIXTURE_PLUGINS = ("assistant", "ollama", "qdrant", "vectorizer")

# The Compose files of the fixture catalog are stubs: an image, the restart
# policy and the label. They join no network, publish no port and declare no
# volume, although their plugin.json lists ports and volumes. They are shared
# fixtures and are not edited here; the deviations are listed so that the test
# fails the day a fixture changes, in either direction.
FIXTURE_DEVIATIONS = {
    (plugin, code) for plugin in FIXTURE_PLUGINS for code in ("network", "ports-mismatch", "volumes-mismatch")
}
KNOWN_DEVIATIONS: dict[str, set[tuple[str, str]]] = {"shipped": set(), "fixture": FIXTURE_DEVIATIONS}

ENTRIES = [
    pytest.param(name, directory, id=f"{name}/{directory.name}")
    for name, catalog in CATALOGS.items()
    for directory in rules.entry_directories(catalog)
]


def _pairs(violations: Any) -> set[tuple[str, str]]:
    return {(v.plugin, v.code) for v in violations}


def _lines(violations: Any) -> str:
    return "\n".join(str(v) for v in violations) or "(none)"


# --- 1. both catalogs ---------------------------------------------------------


def test_the_catalogs_hold_the_expected_plugins() -> None:
    assert tuple(d.name for d in rules.entry_directories(SHIPPED)) == SHIPPED_PLUGINS
    assert tuple(d.name for d in rules.entry_directories(FIXTURE)) == FIXTURE_PLUGINS


@pytest.mark.parametrize(("catalog", "directory"), ENTRIES)
def test_entry_directory_holds_the_two_files_and_nothing_else(catalog: str, directory: Path) -> None:
    entry = rules.check_entry(directory)
    assert not entry.layout, _lines(entry.layout)
    assert entry.plugin is not None and entry.compose is not None, _lines(entry.violations)


@pytest.mark.parametrize(("catalog", "directory"), ENTRIES)
def test_plugin_json_respects_every_rule(catalog: str, directory: Path) -> None:
    entry = rules.check_entry(directory)
    assert not entry.plugin_json, _lines(entry.plugin_json)


@pytest.mark.parametrize(("catalog", "directory"), ENTRIES)
def test_compose_yaml_respects_every_rule(catalog: str, directory: Path) -> None:
    entry = rules.check_entry(directory)
    known = {pair for pair in KNOWN_DEVIATIONS[catalog] if pair[0] == directory.name}
    found = _pairs(entry.compose_yaml)
    assert found - known == set(), _lines(v for v in entry.compose_yaml if (v.plugin, v.code) not in known)
    assert known - found == set(), "a known deviation is gone: remove it from FIXTURE_DEVIATIONS"


@pytest.mark.parametrize("catalog", sorted(CATALOGS))
def test_catalog_as_a_whole(catalog: str) -> None:
    """Per entry and across entries: requirements, service names, ports."""
    violations = rules.check_catalog(CATALOGS[catalog])
    assert _pairs(violations) == KNOWN_DEVIATIONS[catalog], _lines(violations)


def test_the_shipped_catalog_has_no_violation_at_all() -> None:
    assert rules.check_catalog(SHIPPED) == []


@pytest.mark.parametrize(("catalog", "directory"), ENTRIES)
def test_no_plugin_runs_in_vast_mode(catalog: str, directory: Path) -> None:
    plugin = json.loads((directory / rules.PLUGIN_FILE).read_text(encoding="utf-8"))
    assert plugin["modes"] and set(plugin["modes"]) <= {"private_ai", "vectorize"}


# --- 2. broken entries --------------------------------------------------------

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
MODEL = "^[a-z0-9][a-z0-9._/-]{0,80}(:[A-Za-z0-9._-]{1,40})?$"
SERVER = "registry.example/demo/server:2.0.0"
WORKER = "registry.example/demo/worker:2.0.0"


def demo_plugin() -> dict[str, Any]:
    """An entry that uses every feature of the contract and breaks no rule."""
    return {
        "schema": 1,
        "id": "demo",
        "version": "2",
        "name": "Demo",
        "summary": "An entry for the tests.",
        "homepage": "https://example.invalid/demo",
        "license": "MIT",
        "gpu": True,
        "modes": ["private_ai", "vectorize"],
        "requires": [],
        "ports": [{"name": "web", "port": 8088, "protocol": "http", "ui": True}],
        "settings": {
            "bind": {
                "type": "enum",
                "label": "Reachable from",
                "env": "HM_SET_BIND",
                "values": ["lan", "localhost"],
                "default": "localhost",
            },
            "workers": {
                "type": "int",
                "label": "Workers",
                "env": "HM_SET_WORKERS",
                "min": 1,
                "max": 8,
                "default": 2,
            },
            "telemetry": {"type": "bool", "label": "Statistics", "env": "HM_SET_TELEMETRY", "default": False},
            "model": {
                "type": "string",
                "label": "Model",
                "env": "HM_SET_MODEL",
                "max_len": 100,
                "pattern": MODEL,
                "default": "hermes3:8b",
            },
            "models": {
                "type": "string_list",
                "label": "Models",
                "env": "HM_SET_MODELS",
                "max_items": 4,
                "pattern": MODEL,
                "default": ["hermes3:8b"],
            },
            # Not used by the Compose file: free for the tests to break.
            "theme": {
                "type": "enum",
                "label": "Theme",
                "env": "HM_SET_THEME",
                "values": ["light", "dark"],
                "default": "light",
            },
            "note": {
                "type": "string",
                "label": "Note",
                "env": "HM_SET_NOTE",
                "max_len": 40,
                "pattern": "^[a-z ]{0,40}$",
                "default": "",
            },
        },
        "secrets": [
            {"key": "api_key", "env": "DEMO_API_KEY", "label": "API key", "required": False},
            {"key": "spare", "env": "DEMO_SPARE", "label": "Not used by the Compose file", "required": False},
        ],
        "images": [
            {"ref": SERVER, "digest": DIGEST_A, "verified": True},
            {"ref": WORKER, "digest": None, "verified": False},
        ],
        "build": {"context": "demo", "image": "happymining/demo:2"},
        "volumes": [{"name": "data", "backup": "always"}],
        "post_start": [
            {"service": "demo", "exec": ["demo", "pull", "{item}"], "for_each": "models", "timeout_s": 600},
            {"service": "demo-worker", "exec": ["worker", "init"], "timeout_s": 60},
        ],
    }


def demo_compose() -> dict[str, Any]:
    return {
        "services": {
            "demo": {
                "image": f"{SERVER}@{DIGEST_A}",
                "restart": "unless-stopped",
                "labels": {"eu.happymining.plugin": "demo"},
                "environment": [
                    "WORKERS=${HM_SET_WORKERS}",
                    "MODEL=${HM_SET_MODEL}",
                    "TELEMETRY=${HM_SET_TELEMETRY}",
                    "PRICE=5$$",
                    "DEMO_API_KEY",
                ],
                "command": ["serve", "--workers=${HM_SET_WORKERS}", "--models", "${HM_SET_MODELS}"],
                "healthcheck": {"test": ["CMD", "demo", "probe", "${HM_SET_MODEL}"], "interval": "30s"},
                "security_opt": ["no-new-privileges:true"],
                "cap_drop": ["NET_RAW"],
                "volumes": [
                    "data:/data",
                    "${HM_PLUGIN_DATA}/config:/config:ro",
                    "/var/lib/happymining-plugins/demo/cache:/cache",
                    "/srv/happymining/nas:/nas:ro",
                ],
                "ports": ["${HM_BIND}:8088:8080"],
                "networks": ["hm-appliance"],
                "deploy": {
                    "resources": {
                        "limits": {"memory": "8g"},
                        "reservations": {
                            "devices": [{"driver": "nvidia", "count": "all", "capabilities": ["gpu"]}]
                        },
                    }
                },
            },
            "demo-worker": {
                "image": WORKER,
                "restart": "unless-stopped",
                "labels": ["eu.happymining.plugin=demo"],
                "environment": {"API_KEY": "${DEMO_API_KEY}", "MODE": "worker", "THREADS": 2},
                "networks": {"hm-appliance": None},
                "depends_on": ["demo"],
            },
            "demo-index": {
                "image": "happymining/demo:2",
                "pull_policy": "never",
                "restart": "unless-stopped",
                "labels": {"eu.happymining.plugin": "demo"},
                "volumes": [
                    {"type": "bind", "source": "/srv/happymining", "target": "/srv", "read_only": True}
                ],
                "networks": ["hm-appliance"],
            },
        },
        "volumes": {"data": None},
        "networks": {"hm-appliance": {"external": True}},
    }


def other_plugin(plugin_id: str = "other") -> dict[str, Any]:
    return {
        "schema": 1,
        "id": plugin_id,
        "version": "1",
        "name": "Other",
        "summary": "A second entry for the tests.",
        "homepage": "https://example.invalid/other",
        "license": "MIT",
        "gpu": False,
        "modes": ["private_ai", "vectorize"],
        "requires": [],
        "ports": [{"name": "api", "port": 9099, "protocol": "http", "ui": False}],
        "settings": {},
        "secrets": [],
        "images": [{"ref": "registry.example/other/server:1.0.0", "digest": None, "verified": False}],
        "volumes": [],
        "post_start": [],
    }


def other_compose(plugin_id: str = "other") -> dict[str, Any]:
    return {
        "services": {
            plugin_id: {
                "image": "registry.example/other/server:1.0.0",
                "restart": "unless-stopped",
                "labels": {"eu.happymining.plugin": plugin_id},
                "ports": ["${HM_BIND}:9099:9099"],
                "networks": ["hm-appliance"],
            }
        },
        "networks": {"hm-appliance": {"external": True}},
    }


def write_entry(catalog: Path, plugin: Any, compose: Any, name: str | None = None) -> Path:
    """Write an entry; ``plugin`` and ``compose`` are written as they are when they are text."""
    directory = catalog / (name or plugin["id"])
    directory.mkdir(parents=True, exist_ok=True)
    plugin_text = plugin if isinstance(plugin, str) else json.dumps(plugin, indent=2)
    compose_text = compose if isinstance(compose, str) else yaml.safe_dump(compose, sort_keys=False)
    (directory / rules.PLUGIN_FILE).write_text(plugin_text, encoding="utf-8")
    (directory / rules.COMPOSE_FILE).write_text(compose_text, encoding="utf-8")
    return directory


def codes(catalog: Path) -> set[str]:
    return {v.code for v in rules.check_catalog(catalog)}


def test_the_demo_entries_break_no_rule(tmp_path: Path) -> None:
    """Otherwise the refusals below would prove nothing."""
    write_entry(tmp_path, demo_plugin(), demo_compose())
    write_entry(tmp_path, other_plugin(), other_compose())
    assert rules.check_catalog(tmp_path) == []


Mutation = Callable[[dict[str, Any], dict[str, Any]], None]


def _set(path: str, value: Any) -> Mutation:
    """Set a value in plugin.json ("p:…") or compose.yaml ("c:…"); the path is dot-separated."""

    def mutate(plugin: dict[str, Any], compose: dict[str, Any]) -> None:
        target, _, dotted = path.partition(":")
        node: Any = plugin if target == "p" else compose
        keys = [int(k) if k.isdigit() else k for k in dotted.split(".")]
        for key in keys[:-1]:
            node = node[key]
        node[keys[-1]] = value

    return mutate


def _delete(path: str) -> Mutation:
    def mutate(plugin: dict[str, Any], compose: dict[str, Any]) -> None:
        target, _, dotted = path.partition(":")
        node: Any = plugin if target == "p" else compose
        keys = [int(k) if k.isdigit() else k for k in dotted.split(".")]
        for key in keys[:-1]:
            node = node[key]
        del node[keys[-1]]

    return mutate


def _append(path: str, value: Any) -> Mutation:
    def mutate(plugin: dict[str, Any], compose: dict[str, Any]) -> None:
        target, _, dotted = path.partition(":")
        node: Any = plugin if target == "p" else compose
        for key in [int(k) if k.isdigit() else k for k in dotted.split(".")]:
            node = node[key]
        node.append(value)

    return mutate


def _all(*mutations: Mutation) -> Mutation:
    def mutate(plugin: dict[str, Any], compose: dict[str, Any]) -> None:
        for mutation in mutations:
            mutation(plugin, compose)

    return mutate


def _both_images(index: int, service: str, ref: str) -> Mutation:
    """Give the same reference to an image of plugin.json and to the service that uses it."""
    return _all(_set(f"p:images.{index}.ref", ref), _set(f"c:services.{service}.image", ref))


def _rename_main_service(plugin: dict[str, Any], compose: dict[str, Any]) -> None:
    compose["services"]["demo-main"] = compose["services"].pop("demo")
    compose["services"]["demo-worker"]["depends_on"] = ["demo-main"]
    plugin["post_start"][0]["service"] = "demo-main"


def _without_build(plugin: dict[str, Any], compose: dict[str, Any]) -> None:
    del plugin["build"]
    del compose["services"]["demo-index"]
    del compose["services"]["demo-worker"]
    del plugin["post_start"][1]


DEMO = "c:services.demo"

# name, the codes the mutated entry must give (exactly), the mutation.
BROKEN: list[tuple[str, set[str], Mutation]] = [
    # --- plugin.json: shape ---
    ("unknown top-level key", {"unknown-key"}, _set("p:command", "rm -rf /")),
    ("unknown key in a port", {"unknown-key"}, _set("p:ports.0.host", "192.0.2.1")),
    ("unknown key in a setting", {"unknown-key"}, _set("p:settings.theme.secret", True)),
    ("unknown key in a secret", {"unknown-key"}, _set("p:secrets.1.value", "x")),
    ("unknown key in an image", {"unknown-key"}, _set("p:images.0.platform", "linux/amd64")),
    ("unknown key in a volume", {"unknown-key"}, _set("p:volumes.0.path", "/data")),
    ("unknown key in build", {"unknown-key"}, _set("p:build.args", ["X=1"])),
    ("unknown key in post_start", {"unknown-key"}, _set("p:post_start.1.shell", True)),
    ("missing key", {"missing-key"}, _delete("p:license")),
    ("missing timeout_s", {"missing-key"}, _delete("p:post_start.1.timeout_s")),
    ("schema 2", {"bad-schema"}, _set("p:schema", 2)),
    ("schema true", {"bad-schema"}, _set("p:schema", True)),
    ("schema as text", {"bad-schema"}, _set("p:schema", "1")),
    ("id differs from the directory", {"bad-id"}, _set("p:id", "demo2")),
    ("empty name", {"bad-text"}, _set("p:name", "")),
    ("summary with a line break", {"bad-text"}, _set("p:summary", "one\ntwo")),
    ("summary too long", {"bad-text"}, _set("p:summary", "x" * 301)),
    ("homepage over http", {"bad-text"}, _set("p:homepage", "http://example.invalid")),
    ("label too long", {"bad-text"}, _set("p:settings.theme.label", "x" * 129)),
    ("version with a space", {"bad-text", "bad-build"}, _set("p:version", "2 beta")),
    ("gpu as text", {"bad-type", "gpu-not-declared"}, _set("p:gpu", "yes")),
    ("ui as text", {"bad-type"}, _set("p:ports.0.ui", "yes")),
    ("required as text", {"bad-type"}, _set("p:secrets.1.required", "yes")),
    ("verified as text", {"bad-type"}, _set("p:images.1.verified", "no")),
    # --- plugin.json: modes and requirements ---
    ("vast in modes", {"vast-mode"}, _append("p:modes", "vast")),
    ("only vast", {"vast-mode"}, _set("p:modes", ["vast"])),
    ("no mode", {"bad-modes"}, _set("p:modes", [])),
    ("unknown mode", {"bad-modes"}, _append("p:modes", "public")),
    ("mode twice", {"bad-modes"}, _append("p:modes", "private_ai")),
    ("requires itself", {"bad-requires"}, _set("p:requires", ["demo"])),
    ("requires twice", {"bad-requires"}, _set("p:requires", ["other", "other"])),
    (
        "requires something that is not an id",
        {"bad-requires", "requires-unknown"},
        _set("p:requires", ["../x"]),
    ),
    ("requires a plugin that does not exist", {"requires-unknown"}, _set("p:requires", ["nothing"])),
    # --- plugin.json: ports ---
    ("port 70000", {"bad-port", "ports-mismatch"}, _set("p:ports.0.port", 70000)),
    ("port as text", {"bad-port", "ports-mismatch"}, _set("p:ports.0.port", "8088")),
    ("port name in upper case", {"bad-port"}, _set("p:ports.0.name", "Web")),
    ("protocol with a space", {"bad-port"}, _set("p:ports.0.protocol", "http s")),
    (
        "port name twice",
        {"bad-port"},
        _all(
            _append("p:ports", {"name": "web", "port": 8089, "protocol": "http", "ui": False}),
            _append(f"{DEMO[2:] and 'c:services.demo'}.ports", "${HM_BIND}:8089:8089"),
        ),
    ),
    # --- plugin.json: settings ---
    ("setting of an unknown type", {"bad-setting"}, _set("p:settings.theme.type", "path")),
    (
        "setting name in upper case",
        {"bad-setting"},
        _set("p:settings.Theme", {"type": "bool", "label": "x", "env": "HM_SET_T", "default": True}),
    ),
    ("variable without HM_SET_", {"bad-setting-env"}, _set("p:settings.theme.env", "THEME")),
    ("variable in lower case", {"bad-setting-env"}, _set("p:settings.theme.env", "HM_SET_theme")),
    ("two settings, one variable", {"env-duplicate"}, _set("p:settings.theme.env", "HM_SET_NOTE")),
    ("bool default as text", {"bad-setting"}, _set("p:settings.telemetry.default", "false")),
    ("int default as bool", {"bad-setting"}, _set("p:settings.workers.default", True)),
    ("int default out of range", {"bad-setting"}, _set("p:settings.workers.default", 99)),
    ("int min above max", {"bad-setting"}, _set("p:settings.workers.min", 9)),
    ("enum default not in values", {"bad-setting"}, _set("p:settings.theme.default", "blue")),
    ("enum without values", {"bad-setting"}, _set("p:settings.theme.values", [])),
    ("enum value with a dollar", {"bad-setting"}, _set("p:settings.theme.values", ["light", "$HOME"])),
    ("string default against the pattern", {"bad-setting"}, _set("p:settings.model.default", "Hermes 3")),
    ("string default too long", {"bad-setting"}, _set("p:settings.note.default", "a" * 41)),
    ("string max_len above 200", {"bad-setting"}, _set("p:settings.note.max_len", 201)),
    ("list max_items above 32", {"bad-setting"}, _set("p:settings.models.max_items", 33)),
    ("list default too long", {"bad-setting"}, _set("p:settings.models.default", ["a", "b", "c", "d", "e"])),
    ("list default that is not a list", {"bad-setting"}, _set("p:settings.models.default", "hermes3:8b")),
    ("list default with an empty item", {"bad-setting"}, _set("p:settings.models.default", [""])),
    ("pattern without anchors", {"bad-pattern"}, _set("p:settings.model.pattern", "[a-z]+")),
    ("pattern that lets $ through", {"bad-pattern"}, _set("p:settings.model.pattern", "^[a-z$]+$")),
    (
        "list pattern that lets a space through",
        {"bad-pattern"},
        _set("p:settings.models.pattern", "^[a-z ]+$"),
    ),
    ("bind with another value", {"bad-bind"}, _set("p:settings.bind.values", ["lan", "localhost", "public"])),
    ("bind in another variable", {"bad-bind"}, _set("p:settings.bind.env", "HM_SET_LISTEN")),
    (
        "bind that is not an enum",
        {"bad-bind"},
        _set("p:settings.bind", {"type": "bool", "label": "x", "env": "HM_SET_BIND", "default": True}),
    ),
    # --- plugin.json: secrets ---
    ("secret key with a dash", {"bad-secret"}, _set("p:secrets.1.key", "spare-key")),
    ("secret key twice", {"bad-secret"}, _set("p:secrets.1.key", "api_key")),
    ("secret key of 32 characters", {"bad-secret"}, _set("p:secrets.1.key", "k" * 32)),
    ("secret variable in lower case", {"bad-secret"}, _set("p:secrets.1.env", "demo_spare")),
    (
        "secret in a setting's variable",
        {"secret-env-reserved", "env-duplicate"},
        _set("p:secrets.1.env", "HM_SET_NOTE"),
    ),
    ("secret named HM_BIND", {"secret-env-reserved"}, _set("p:secrets.1.env", "HM_BIND")),
    ("secret named HM_PLUGIN_DATA", {"secret-env-reserved"}, _set("p:secrets.1.env", "HM_PLUGIN_DATA")),
    ("secret named HM_ANSWER_API_KEY", {"secret-env-reserved"}, _set("p:secrets.1.env", "HM_ANSWER_API_KEY")),
    ("secret named COMPOSE_FILE", {"secret-env-reserved"}, _set("p:secrets.1.env", "COMPOSE_FILE")),
    ("secret named DOCKER_HOST", {"secret-env-reserved"}, _set("p:secrets.1.env", "DOCKER_HOST")),
    ("secret named PATH", {"secret-env-reserved"}, _set("p:secrets.1.env", "PATH")),
    ("two secrets, one variable", {"env-duplicate"}, _set("p:secrets.1.env", "DEMO_API_KEY")),
    # --- plugin.json: images, volumes, build ---
    (
        "image tagged latest",
        {"bad-image"},
        _both_images(1, "demo-worker", "registry.example/demo/worker:latest"),
    ),
    ("image without a tag", {"bad-image"}, _both_images(1, "demo-worker", "registry.example/demo/worker")),
    ("image without a registry", {"bad-image"}, _both_images(1, "demo-worker", "demo/worker:2.0.0")),
    (
        "image reference with a digest in it",
        {"bad-image"},
        _both_images(1, "demo-worker", f"{WORKER}@{DIGEST_B}"),
    ),
    (
        "image listed twice",
        {"bad-image"},
        _append("p:images", {"ref": WORKER, "digest": None, "verified": False}),
    ),
    (
        "digest that is not a digest",
        {"bad-image"},
        _all(_set("p:images.0.digest", "sha256:xyz"), _set(f"{DEMO}.image", f"{SERVER}@sha256:xyz")),
    ),
    ("no image", {"bad-image", "image-undeclared"}, _set("p:images", [])),
    ("verified without a digest", {"image-pin", "image-not-pinned"}, _set("p:images.0.digest", None)),
    ("digest that is not verified", {"image-pin"}, _set("p:images.1.digest", DIGEST_B)),
    ("unknown backup policy", {"bad-volume"}, _set("p:volumes.0.backup", "weekly")),
    (
        "volume listed twice",
        {"bad-volume"},
        _append("p:volumes", {"name": "data", "backup": "never"}),
    ),
    (
        "built image with another tag than the version",
        {"bad-build"},
        _all(
            _set("p:build.image", "happymining/demo:3"),
            _set("c:services.demo-index.image", "happymining/demo:3"),
        ),
    ),
    (
        "built image named like a registry image",
        {"bad-build"},
        _all(
            _set("p:build.image", "registry.example/demo/index:2"),
            _set("c:services.demo-index.image", "registry.example/demo/index:2"),
        ),
    ),
    ("build context that is a path", {"bad-build"}, _set("p:build.context", "../demo")),
    # --- plugin.json: post_start ---
    ("for_each on nothing", {"bad-post-start"}, _set("p:post_start.0.for_each", "nothing")),
    ("for_each on a string setting", {"bad-post-start"}, _set("p:post_start.0.for_each", "model")),
    ("{item} without for_each", {"bad-post-start"}, _delete("p:post_start.0.for_each")),
    ("empty command", {"bad-post-start"}, _set("p:post_start.1.exec", [])),
    ("command given as one line", {"bad-post-start"}, _set("p:post_start.1.exec", "worker init")),
    ("the command itself is {item}", {"bad-post-start"}, _set("p:post_start.0.exec", ["{item}", "pull"])),
    (
        "argument longer than 200 bytes",
        {"bad-post-start"},
        _set("p:post_start.1.exec", ["worker", "x" * 201]),
    ),
    ("argument with a line break", {"bad-post-start"}, _set("p:post_start.1.exec", ["worker", "a\nb"])),
    ("timeout of zero", {"bad-post-start"}, _set("p:post_start.1.timeout_s", 0)),
    ("timeout of more than a day", {"bad-post-start"}, _set("p:post_start.1.timeout_s", 86401)),
    (
        "command in a service that does not exist",
        {"post-start-service"},
        _set("p:post_start.1.service", "demo-ghost"),
    ),
    # --- compose.yaml: confinement ---
    ("privileged", {"privileged"}, _set(f"{DEMO}.privileged", True)),
    ("privileged: false is still refused", {"privileged"}, _set(f"{DEMO}.privileged", False)),
    ("cap_add", {"cap-add"}, _set(f"{DEMO}.cap_add", ["SYS_ADMIN"])),
    ("host network", {"host-namespace"}, _set(f"{DEMO}.network_mode", "host")),
    ("another network mode", {"network"}, _set(f"{DEMO}.network_mode", "bridge")),
    ("host pid", {"host-namespace"}, _set(f"{DEMO}.pid", "host")),
    ("host ipc", {"host-namespace"}, _set(f"{DEMO}.ipc", "host")),
    ("host uts", {"host-namespace"}, _set(f"{DEMO}.uts", "host")),
    ("host user namespace", {"host-namespace"}, _set(f"{DEMO}.userns_mode", "host")),
    ("seccomp turned off", {"security-opt"}, _set(f"{DEMO}.security_opt", ["seccomp:unconfined"])),
    ("apparmor turned off", {"security-opt"}, _append(f"{DEMO}.security_opt", "apparmor:unconfined")),
    ("host devices", {"devices"}, _set(f"{DEMO}.devices", ["/dev/kfd", "/dev/dri"])),
    ("the nvidia runtime instead of deploy", {"devices"}, _set(f"{DEMO}.runtime", "nvidia")),
    ("gpus instead of deploy", {"devices"}, _set(f"{DEMO}.gpus", "all")),
    # --- compose.yaml: mounts ---
    (
        "Docker socket",
        {"socket-mount"},
        _append(f"{DEMO}.volumes", "/var/run/docker.sock:/var/run/docker.sock"),
    ),
    (
        "Docker socket, read-only",
        {"socket-mount"},
        _append(f"{DEMO}.volumes", "/run/docker.sock:/docker.sock:ro"),
    ),
    (
        "Docker socket, long form",
        {"socket-mount"},
        _append(f"{DEMO}.volumes", {"type": "bind", "source": "/var/run/docker.sock", "target": "/d.sock"}),
    ),
    ("containerd socket directory", {"socket-mount"}, _append(f"{DEMO}.volumes", "/run/containerd:/c:ro")),
    ("/run", {"bind-outside"}, _append(f"{DEMO}.volumes", "/run:/host-run:ro")),
    ("/etc", {"bind-outside"}, _append(f"{DEMO}.volumes", "/etc:/host-etc:ro")),
    ("the whole host", {"bind-outside"}, _append(f"{DEMO}.volumes", "/:/host")),
    (
        "a directory that only starts like the NAS root",
        {"bind-outside"},
        _append(f"{DEMO}.volumes", "/srv/happymining-x:/x:ro"),
    ),
    (
        "out of the data directory with ..",
        {"bind-outside"},
        _append(f"{DEMO}.volumes", "${HM_PLUGIN_DATA}/../other:/x"),
    ),
    (
        "out of the NAS root with ..",
        {"bind-outside"},
        _append(f"{DEMO}.volumes", "/srv/happymining/../../etc:/x:ro"),
    ),
    (
        "another plugin's data directory",
        {"bind-outside"},
        _append(f"{DEMO}.volumes", "/var/lib/happymining-plugins/other:/x"),
    ),
    (
        "the directory of all plugins",
        {"bind-outside"},
        _append(f"{DEMO}.volumes", "/var/lib/happymining-plugins:/x"),
    ),
    ("relative path", {"bind-outside"}, _append(f"{DEMO}.volumes", "./data:/data")),
    ("home directory", {"bind-outside"}, _append(f"{DEMO}.volumes", "~/.ssh:/ssh:ro")),
    (
        "bind mount of a setting",
        {"bind-outside", "variable-place"},
        _append(f"{DEMO}.volumes", "${HM_SET_NOTE}:/x:ro"),
    ),
    ("NAS mounted read-write", {"bind-not-readonly"}, _append(f"{DEMO}.volumes", "/srv/happymining/nas:/rw")),
    ("NAS mounted rw", {"bind-not-readonly"}, _append(f"{DEMO}.volumes", "/srv/happymining/nas:/rw:rw")),
    (
        "NAS, long form, not read-only",
        {"bind-not-readonly"},
        _set("c:services.demo-index.volumes.0.read_only", False),
    ),
    (
        "NAS, long form, shared propagation",
        {"volume-syntax"},
        _set("c:services.demo-index.volumes.0.bind", {"propagation": "rshared"}),
    ),
    (
        "bind options other than propagation",
        {"volume-syntax"},
        _set("c:services.demo-index.volumes.0.bind", {"propagation": "rslave", "create_host_path": True}),
    ),
    (
        "bind options on a named volume",
        {"volume-syntax"},
        _append(
            f"{DEMO}.volumes",
            {"type": "volume", "source": "data", "target": "/d", "bind": {"propagation": "rslave"}},
        ),
    ),
    ("anonymous volume", {"volume-syntax"}, _append(f"{DEMO}.volumes", "/scratch")),
    ("mount option", {"volume-syntax"}, _append(f"{DEMO}.volumes", "data:/again:z")),
    (
        "mount propagation",
        {"volume-syntax"},
        _set("c:services.demo-index.volumes.0.bind", {"propagation": "rshared"}),
    ),
    (
        "volumes that is not a list",
        {"volume-syntax", "volumes-mismatch"},
        _set(f"{DEMO}.volumes", "data:/data"),
    ),
    ("volume that is not declared", {"volume-undeclared"}, _append(f"{DEMO}.volumes", "cache:/var/cache")),
    (
        "volume backed by a host directory",
        {"volume-options"},
        _set(
            "c:volumes.data",
            {"driver": "local", "driver_opts": {"type": "none", "o": "bind", "device": "/etc"}},
        ),
    ),
    ("external volume", {"volume-options"}, _set("c:volumes.data", {"external": True})),
    ("volume with a chosen name", {"volume-options"}, _set("c:volumes.data", {"name": "vast_data"})),
    (
        "volume missing from plugin.json",
        {"volumes-mismatch"},
        _all(_set("c:volumes.cache", None), _append(f"{DEMO}.volumes", "cache:/var/cache")),
    ),
    (
        "volume missing from compose.yaml",
        {"volumes-mismatch"},
        _append("p:volumes", {"name": "cache", "backup": "never"}),
    ),
    (
        "volume declared and not used",
        {"volumes-mismatch"},
        _all(_set("c:volumes.cache", None), _append("p:volumes", {"name": "cache", "backup": "never"})),
    ),
    # --- compose.yaml: ports ---
    (
        "port that plugin.json does not list",
        {"ports-mismatch"},
        _append(f"{DEMO}.ports", "${HM_BIND}:9000:9000"),
    ),
    ("port that is not published", {"ports-mismatch"}, _delete(f"{DEMO}.ports")),
    ("port on every address", {"port-bind", "ports-mismatch"}, _set(f"{DEMO}.ports", ["8088:8080"])),
    ("port on 0.0.0.0", {"port-bind", "ports-mismatch"}, _set(f"{DEMO}.ports", ["0.0.0.0:8088:8080"])),
    (
        "port bound to the setting instead of HM_BIND",
        {"port-bind", "ports-mismatch", "variable-place"},
        _set(f"{DEMO}.ports", ["${HM_SET_BIND}:8088:8080"]),
    ),
    (
        "port in the long form",
        {"port-syntax", "ports-mismatch"},
        _set(f"{DEMO}.ports", [{"target": 8080, "published": 8088}]),
    ),
    ("port as a number", {"port-syntax", "ports-mismatch"}, _set(f"{DEMO}.ports", [8088])),
    ("udp port", {"port-syntax", "ports-mismatch"}, _set(f"{DEMO}.ports", ["${HM_BIND}:8088:8080/udp"])),
    (
        "port range",
        {"port-syntax", "ports-mismatch"},
        _set(f"{DEMO}.ports", ["${HM_BIND}:8088-8090:8080-8082"]),
    ),
    ("port 0", {"port-syntax", "ports-mismatch"}, _set(f"{DEMO}.ports", ["${HM_BIND}:0:8080"])),
    # --- compose.yaml: images ---
    (
        "image that plugin.json does not list",
        {"image-undeclared"},
        _set("c:services.demo-worker.image", "registry.example/evil/miner:1"),
    ),
    ("service without an image", {"image-undeclared"}, _delete("c:services.demo-worker.image")),
    ("verified image used by its tag", {"image-not-pinned"}, _set(f"{DEMO}.image", SERVER)),
    (
        "verified image with another digest",
        {"image-not-pinned"},
        _set(f"{DEMO}.image", f"{SERVER}@{DIGEST_B}"),
    ),
    (
        "unverified image pinned in compose.yaml",
        {"image-pinned-unverified"},
        _set("c:services.demo-worker.image", f"{WORKER}@{DIGEST_B}"),
    ),
    ("listed image that no service uses", {"image-unused"}, _without_build),
    ("built image that could be pulled", {"build-pull-policy"}, _delete("c:services.demo-index.pull_policy")),
    ("pull_policy always", {"pull-policy"}, _set(f"{DEMO}.pull_policy", "always")),
    ("build in compose.yaml", {"compose-unknown-key"}, _set("c:services.demo-index.build", {"context": "/"})),
    # --- compose.yaml: variables ---
    ("unknown variable", {"unknown-variable"}, _append(f"{DEMO}.environment", "HOME_DIR=${HOME}")),
    ("another plugin's setting", {"unknown-variable"}, _append(f"{DEMO}.environment", "X=${HM_SET_OTHER}")),
    ("variable without braces", {"variable-form", "unknown-variable"}, _append(f"{DEMO}.command", "$HOME")),
    ("variable with a default", {"variable-form"}, _append(f"{DEMO}.environment", "X=${HM_SET_MODEL:-x}")),
    (
        "variable with an error message",
        {"variable-form"},
        _append(f"{DEMO}.environment", "X=${HM_SET_MODEL:?no}"),
    ),
    ("stray dollar", {"variable-form"}, _append(f"{DEMO}.environment", "COST=5$")),
    ("unclosed variable", {"variable-form"}, _append(f"{DEMO}.environment", "X=${HM_SET_MODEL")),
    (
        "setting in the image",
        {"variable-place", "image-undeclared"},
        _set("c:services.demo-worker.image", "registry.example/demo/${HM_SET_MODEL}:1"),
    ),
    ("setting in a label", {"variable-place"}, _set(f"{DEMO}.labels.note", "${HM_SET_NOTE}")),
    ("setting in a key", {"variable-place"}, _set(f"{DEMO}.labels.${{HM_SET_NOTE}}", "x")),
    ("HM_BIND outside ports", {"variable-place"}, _append(f"{DEMO}.environment", "LISTEN=${HM_BIND}")),
    ("HM_PLUGIN_DATA outside volumes", {"variable-place"}, _append(f"{DEMO}.command", "${HM_PLUGIN_DATA}")),
    ("secret in the command", {"secret-in-wrong-place"}, _append(f"{DEMO}.command", "${DEMO_API_KEY}")),
    # --- compose.yaml: settings that become arguments ---
    (
        "setting in a command written as one line",
        {"command-form"},
        _set(f"{DEMO}.command", "serve --models ${HM_SET_MODELS}"),
    ),
    (
        "setting in an entrypoint written as one line",
        {"command-form"},
        _set(f"{DEMO}.entrypoint", "demo --model ${HM_SET_MODEL}"),
    ),
    (
        "setting given to a shell",
        {"command-form"},
        _set(f"{DEMO}.command", ["sh", "-c", "serve ${HM_SET_MODEL}"]),
    ),
    (
        "setting given to a shell by its full path",
        {"command-form"},
        _set(f"{DEMO}.command", ["/bin/bash", "-c", "serve ${HM_SET_MODEL}"]),
    ),
    ("command after a shell entrypoint", {"command-form"}, _set(f"{DEMO}.entrypoint", ["/bin/sh", "-c"])),
    (
        "command after a shell entrypoint written as one line",
        {"command-form"},
        _set(f"{DEMO}.entrypoint", "/bin/sh -c"),
    ),
    (
        "setting that chooses the program",
        {"command-form"},
        _set(f"{DEMO}.command", ["${HM_SET_MODEL}", "serve"]),
    ),
    (
        "setting in a healthcheck written as one line",
        {"command-form"},
        _set(f"{DEMO}.healthcheck.test", "demo probe ${HM_SET_MODEL}"),
    ),
    (
        "setting in a CMD-SHELL healthcheck",
        {"command-form"},
        _set(f"{DEMO}.healthcheck.test", ["CMD-SHELL", "demo probe ${HM_SET_MODEL}"]),
    ),
    (
        "setting given to a shell by a healthcheck",
        {"command-form"},
        _set(f"{DEMO}.healthcheck.test", ["CMD", "sh", "-c", "demo probe ${HM_SET_MODEL}"]),
    ),
    (
        "setting that chooses the program of a healthcheck",
        {"command-form"},
        _set(f"{DEMO}.healthcheck.test", ["CMD", "${HM_SET_MODEL}"]),
    ),
    (
        "string setting that can start with a dash, as an argument",
        {"argument-dash"},
        _all(
            _set("p:settings.note.pattern", "^[a-z -]{0,40}$"), _append(f"{DEMO}.command", "${HM_SET_NOTE}")
        ),
    ),
    (
        "negative number as an argument",
        {"argument-dash"},
        _all(_set("p:settings.workers.min", -1), _append(f"{DEMO}.command", "${HM_SET_WORKERS}")),
    ),
    (
        "enum value with a dash as an argument",
        {"argument-dash"},
        _all(
            _set("p:settings.theme.values", ["light", "-dark"]), _append(f"{DEMO}.command", "${HM_SET_THEME}")
        ),
    ),
    (
        "setting that can start with a dash, as a healthcheck argument",
        {"argument-dash"},
        _all(
            _set("p:settings.note.pattern", "^[a-z -]{0,40}$"),
            _append(f"{DEMO}.healthcheck.test", "${HM_SET_NOTE}"),
        ),
    ),
    ("secret in a label", {"secret-in-wrong-place"}, _set(f"{DEMO}.labels.key", "${DEMO_API_KEY}")),
    (
        "secret inside a longer value",
        {"secret-in-wrong-place"},
        _append(f"{DEMO}.environment", "URL=https://u:${DEMO_API_KEY}@h"),
    ),
    (
        "pass-through of something that is no secret",
        {"passthrough-unknown"},
        _append(f"{DEMO}.environment", "DOCKER_HOST"),
    ),
    (
        "pass-through of the answer key outside the vectorizer",
        {"passthrough-unknown"},
        _append(f"{DEMO}.environment", "HM_ANSWER_API_KEY"),
    ),
    (
        "pass-through in a mapping",
        {"passthrough-unknown"},
        _set("c:services.demo-worker.environment.SSH_AUTH_SOCK", None),
    ),
    ("environment entry that is not text", {"bad-environment"}, _append(f"{DEMO}.environment", 5)),
    ("environment variable set twice", {"bad-environment"}, _append(f"{DEMO}.environment", "MODEL=x")),
    (
        "environment value that is a list",
        {"bad-environment"},
        _set("c:services.demo-worker.environment.MODE", ["a"]),
    ),
    ("environment name with a space", {"bad-environment"}, _append(f"{DEMO}.environment", "MY VAR=x")),
    # --- compose.yaml: the service itself ---
    ("no label", {"label-missing"}, _delete(f"{DEMO}.labels")),
    (
        "label of another plugin",
        {"label-missing"},
        _set(f"{DEMO}.labels", {"eu.happymining.plugin": "other"}),
    ),
    ("restart: always", {"restart-policy"}, _set(f"{DEMO}.restart", "always")),
    ("no restart policy", {"restart-policy"}, _delete(f"{DEMO}.restart")),
    ("service outside the network", {"network"}, _delete(f"{DEMO}.networks")),
    ("service on a second network", {"network"}, _set(f"{DEMO}.networks", ["hm-appliance", "default"])),
    (
        "service taking another name on the network",
        {"network"},
        _set(f"{DEMO}.networks", {"hm-appliance": {"aliases": ["ollama"]}}),
    ),
    ("network that is not external", {"network"}, _set("c:networks.hm-appliance", {})),
    ("network that is not declared", {"network"}, _delete("c:networks")),
    ("a second declared network", {"network"}, _set("c:networks.private", {})),
    (
        "network declared under another name",
        {"network"},
        _set("c:networks.hm-appliance", {"external": True, "name": "bridge"}),
    ),
    ("no service named after the plugin", {"main-service-missing"}, _rename_main_service),
    (
        "service with a foreign name",
        {"service-name"},
        lambda p, c: c["services"].update({"ollama": c["services"].pop("demo-index")}),
    ),
    (
        "depends_on a service that does not exist",
        {"depends-on"},
        _set("c:services.demo-worker.depends_on", ["db"]),
    ),
    ("container_name", {"compose-unknown-key"}, _set(f"{DEMO}.container_name", "ollama")),
    ("hostname", {"compose-unknown-key"}, _set(f"{DEMO}.hostname", "ollama")),
    ("env_file", {"compose-unknown-key"}, _set(f"{DEMO}.env_file", "/etc/happymining/helper.conf")),
    (
        "extra_hosts",
        {"compose-unknown-key"},
        _set(f"{DEMO}.extra_hosts", ["host.docker.internal:host-gateway"]),
    ),
    ("volumes_from", {"compose-unknown-key"}, _set(f"{DEMO}.volumes_from", ["container:vast"])),
    ("extends", {"compose-unknown-key"}, _set(f"{DEMO}.extends", {"file": "/etc/x.yaml", "service": "x"})),
    ("sysctls", {"compose-unknown-key"}, _set(f"{DEMO}.sysctls", {"net.ipv4.ip_forward": 1})),
    ("replicas", {"compose-unknown-key"}, _set(f"{DEMO}.deploy.replicas", 2)),
    ("top-level secrets", {"compose-unknown-key"}, _set("c:secrets", {"k": {"file": "/etc/shadow"}})),
    ("top-level configs", {"compose-unknown-key"}, _set("c:configs", {"k": {"file": "/etc/passwd"}})),
    ("top-level include", {"compose-unknown-key"}, _set("c:include", ["/etc/other.yaml"])),
    ("top-level name", {"compose-unknown-key"}, _set("c:name", "vast")),
    ("extension field", {"compose-unknown-key"}, _set("c:x-template", {"privileged": True})),
    # --- compose.yaml: GPU ---
    ("GPU without gpu: true", {"gpu-not-declared"}, _set("p:gpu", False)),
    (
        "GPU of another vendor",
        {"gpu-syntax"},
        _set(f"{DEMO}.deploy.resources.reservations.devices.0.driver", "amd"),
    ),
    (
        "GPU without the driver",
        {"gpu-syntax"},
        _delete(f"{DEMO}.deploy.resources.reservations.devices.0.driver"),
    ),
    (
        "GPU with other capabilities",
        {"gpu-syntax"},
        _set(f"{DEMO}.deploy.resources.reservations.devices.0.capabilities", ["gpu", "utility"]),
    ),
    ("GPU count of zero", {"gpu-syntax"}, _set(f"{DEMO}.deploy.resources.reservations.devices.0.count", 0)),
    (
        "GPU count and ids",
        {"gpu-syntax"},
        _set(f"{DEMO}.deploy.resources.reservations.devices.0.device_ids", ["0"]),
    ),
    (
        "GPU driver options",
        {"gpu-syntax"},
        _set(f"{DEMO}.deploy.resources.reservations.devices.0.options", {"x": "y"}),
    ),
    (
        "no device in the reservation",
        {"gpu-syntax"},
        _set(f"{DEMO}.deploy.resources.reservations.devices", []),
    ),
]


@pytest.mark.parametrize(("expected", "mutation"), [pytest.param(e, m, id=n) for n, e, m in BROKEN])
def test_a_broken_entry_is_refused(tmp_path: Path, expected: set[str], mutation: Mutation) -> None:
    plugin, compose = demo_plugin(), demo_compose()
    mutation(plugin, compose)
    write_entry(tmp_path, plugin, compose, name="demo")
    write_entry(tmp_path, other_plugin(), other_compose())
    violations = rules.check_catalog(tmp_path)
    assert {v.code for v in violations} == expected, _lines(violations)
    assert {v.plugin for v in violations} == {"demo"}, _lines(violations)


def _text_of(compose: dict[str, Any]) -> str:
    return yaml.safe_dump(compose, sort_keys=False)


def _duplicate_json_key() -> str:
    return json.dumps(demo_plugin())[:-1] + ', "gpu": false}'


def _huge_json() -> str:
    plugin = demo_plugin()
    plugin["summary"] = "x" * (rules.MAX_FILE_BYTES + 1)
    return json.dumps(plugin)


# name, expected codes (at least these), plugin.json text or None, compose.yaml text or None
BROKEN_FILES: list[tuple[str, set[str], str | None, str | None]] = [
    ("plugin.json with a key twice", {"json-invalid"}, _duplicate_json_key(), None),
    ("plugin.json with a trailing comma", {"json-invalid"}, json.dumps(demo_plugin())[:-1] + ",}", None),
    (
        "plugin.json with NaN",
        {"json-invalid"},
        json.dumps(demo_plugin()).replace('"schema": 1', '"schema": NaN'),
        None,
    ),
    ("plugin.json that is a list", {"json-invalid"}, "[]", None),
    ("plugin.json that is not UTF-8", {"json-invalid"}, "\udcff", None),
    ("plugin.json larger than 64 KiB", {"json-invalid"}, _huge_json(), None),
    (
        "compose.yaml with a key twice",
        {"yaml-invalid"},
        None,
        _text_of(demo_compose()).replace(
            "    restart: unless-stopped\n", "    restart: unless-stopped\n    restart: 'no'\n", 1
        ),
    ),
    (
        "compose.yaml with an anchor and an alias",
        {"yaml-invalid"},
        None,
        "x-base: &base\n  privileged: true\n"
        + _text_of(demo_compose()).replace("  demo:\n", "  demo:\n    <<: *base\n", 1),
    ),
    ("compose.yaml that does not parse", {"yaml-invalid"}, None, "services:\n\tdemo: {}\n"),
    ("compose.yaml that is a list", {"yaml-invalid"}, None, "- services\n"),
    (
        "compose.yaml with two documents",
        {"yaml-invalid"},
        None,
        _text_of(demo_compose()) + "---\nservices: {}\n",
    ),
    (
        "compose.yaml with a Python object",
        {"yaml-invalid"},
        None,
        _text_of(demo_compose()) + "x-run: !!python/object/apply:os.system ['true']\n",
    ),
    (
        "compose.yaml with Compose's !reset tag",
        {"yaml-invalid"},
        None,
        _text_of(demo_compose()).replace("    restart: unless-stopped\n", "    restart: !reset null\n", 1),
    ),
    (
        "compose.yaml with Compose's !override tag",
        {"yaml-invalid"},
        None,
        _text_of(demo_compose()).replace("  demo:\n", "  demo:\n    stop_signal: !override SIGTERM\n", 1),
    ),
    ("compose.yaml nested too deeply", {"yaml-invalid"}, None, "services: " + "[" * 5000 + "]" * 5000 + "\n"),
    (
        "compose.yaml larger than 64 KiB",
        {"yaml-invalid"},
        None,
        _text_of(demo_compose()) + "# " + "x" * rules.MAX_FILE_BYTES,
    ),
]


@pytest.mark.parametrize(
    ("expected", "plugin_text", "compose_text"), [pytest.param(e, p, c, id=n) for n, e, p, c in BROKEN_FILES]
)
def test_a_file_that_cannot_be_read_strictly_is_refused(
    tmp_path: Path, expected: set[str], plugin_text: str | None, compose_text: str | None
) -> None:
    directory = write_entry(tmp_path, demo_plugin(), demo_compose())
    if plugin_text is not None:
        (directory / rules.PLUGIN_FILE).write_bytes(plugin_text.encode("utf-8", "surrogateescape"))
    if compose_text is not None:
        (directory / rules.COMPOSE_FILE).write_text(compose_text, encoding="utf-8")
    assert codes(tmp_path) == expected


@pytest.mark.parametrize(
    "merge",
    [
        "<<: {privileged: true}",
        '"<<": {privileged: true}',
        "<<: [{privileged: true}]",
        "x: {<<: {privileged: true}}",
    ],
)
def test_a_merge_key_is_refused_so_it_cannot_hide_a_setting(tmp_path: Path, merge: str) -> None:
    """``<<`` needs no anchor, and YAML implementations disagree on what it merges (and on ``"<<"``).

    Refusing it means the checker and Docker Compose read the same keys. Without
    the refusal, PyYAML's safe loader stops on the merge tag with a message about
    constructors; the refusal names the key and its line.
    """
    text = _text_of(demo_compose()).replace("  demo:\n", f"  demo:\n    {merge}\n", 1)
    directory = write_entry(tmp_path, demo_plugin(), demo_compose())
    (directory / rules.COMPOSE_FILE).write_text(text, encoding="utf-8")
    violations = rules.check_catalog(tmp_path)
    assert {v.code for v in violations} == {"yaml-invalid"}, _lines(violations)
    assert "merge key (<<) on line 3" in violations[0].detail, violations[0].detail


def test_no_service_at_all_is_refused(tmp_path: Path) -> None:
    compose = demo_compose()
    compose["services"] = {}
    write_entry(tmp_path, demo_plugin(), compose)
    assert {"no-services", "ports-mismatch", "volumes-mismatch", "post-start-service"} <= codes(tmp_path)


@pytest.mark.parametrize(
    "extra", [".env", "compose.override.yaml", "docker-compose.yml", "Dockerfile", "notes.txt"]
)
def test_an_extra_file_in_an_entry_is_refused(tmp_path: Path, extra: str) -> None:
    directory = write_entry(tmp_path, demo_plugin(), demo_compose())
    (directory / extra).write_text("HM_BIND=0.0.0.0\n", encoding="utf-8")
    assert codes(tmp_path) == {"extra-file"}


@pytest.mark.parametrize("missing", [rules.PLUGIN_FILE, rules.COMPOSE_FILE])
def test_a_missing_file_is_refused(tmp_path: Path, missing: str) -> None:
    directory = write_entry(tmp_path, demo_plugin(), demo_compose())
    (directory / missing).unlink()
    assert codes(tmp_path) == {"missing-file"}


def test_a_symbolic_link_instead_of_a_file_is_refused(tmp_path: Path) -> None:
    directory = write_entry(tmp_path, demo_plugin(), demo_compose())
    target = tmp_path.parent / f"{tmp_path.name}-compose.yaml"
    shutil.move(directory / rules.COMPOSE_FILE, target)
    (directory / rules.COMPOSE_FILE).symlink_to(target)
    assert codes(tmp_path) == {"missing-file"}


@pytest.mark.parametrize("name", ["Demo", "_demo", "demo.d", "9demo", "d" * 32])
def test_a_directory_that_is_not_a_plugin_id_is_refused(tmp_path: Path, name: str) -> None:
    write_entry(tmp_path, demo_plugin(), demo_compose(), name=name)
    assert "bad-id" in codes(tmp_path)


def test_a_file_directly_in_the_catalog_is_not_an_entry(tmp_path: Path) -> None:
    write_entry(tmp_path, demo_plugin(), demo_compose())
    (tmp_path / "README.md").write_text("# Catalog\n", encoding="utf-8")
    assert rules.check_catalog(tmp_path) == []


def test_requirements_that_form_a_cycle_are_refused(tmp_path: Path) -> None:
    demo, other = demo_plugin(), other_plugin()
    demo["requires"], other["requires"] = ["other"], ["demo"]
    write_entry(tmp_path, demo, demo_compose())
    write_entry(tmp_path, other, other_compose())
    violations = rules.check_catalog(tmp_path)
    assert _pairs(violations) == {("demo", "requires-cycle"), ("other", "requires-cycle")}, _lines(violations)


def test_only_the_plugins_on_a_cycle_are_reported(tmp_path: Path) -> None:
    """demo needs other, other and third need each other: demo is not on the cycle."""
    demo, other, third = demo_plugin(), other_plugin(), other_plugin("third")
    demo["requires"], other["requires"], third["requires"] = ["other"], ["third"], ["other"]
    third["ports"][0]["port"] = 9098
    third_compose = other_compose("third")
    third_compose["services"]["third"]["ports"] = ["${HM_BIND}:9098:9099"]
    write_entry(tmp_path, demo, demo_compose())
    write_entry(tmp_path, other, other_compose())
    write_entry(tmp_path, third, third_compose)
    violations = rules.check_catalog(tmp_path)
    assert _pairs(violations) == {("other", "requires-cycle"), ("third", "requires-cycle")}, _lines(
        violations
    )


def test_a_plugin_that_requires_itself_is_not_also_a_cycle(tmp_path: Path) -> None:
    demo = demo_plugin()
    demo["requires"] = ["demo"]
    write_entry(tmp_path, demo, demo_compose())
    assert _pairs(rules.check_catalog(tmp_path)) == {("demo", "bad-requires")}


@pytest.mark.parametrize(("key_length", "refused"), [(25, False), (26, True)])
def test_a_secret_name_is_at_most_63_characters(tmp_path: Path, key_length: int, refused: bool) -> None:
    """``plugin.<id>.<key>`` is a sealed secret's name (section 5: at most 63 characters).

    A key of up to 31 characters is a valid key, and so is an id of up to 31:
    together they can be too long. With an id of 30 characters the name is
    ``7 + 30 + 1 + key`` characters long.
    """
    plugin_id = "p" + "x" * 29
    plugin = other_plugin(plugin_id)
    plugin["secrets"] = [{"key": "k" * key_length, "env": "LONG_KEY", "label": "Key", "required": False}]
    write_entry(tmp_path, plugin, other_compose(plugin_id))
    expected = {(plugin_id, "bad-secret")} if refused else set()
    assert _pairs(rules.check_catalog(tmp_path)) == expected


def test_a_required_plugin_must_run_wherever_the_requiring_one_runs(tmp_path: Path) -> None:
    demo, other = demo_plugin(), other_plugin()
    demo["requires"], other["modes"] = ["other"], ["private_ai"]
    write_entry(tmp_path, demo, demo_compose())
    write_entry(tmp_path, other, other_compose())
    assert _pairs(rules.check_catalog(tmp_path)) == {("demo", "requires-mode")}
    other["modes"] = ["private_ai", "vectorize"]
    write_entry(tmp_path, other, other_compose())
    assert rules.check_catalog(tmp_path) == []


def test_two_entries_cannot_define_the_same_service(tmp_path: Path) -> None:
    """Services are reached by name on hm-appliance: a second ``demo-worker`` would answer for the first."""
    write_entry(tmp_path, demo_plugin(), demo_compose())
    write_entry(tmp_path, other_plugin("demo-worker"), other_compose("demo-worker"))
    assert _pairs(rules.check_catalog(tmp_path)) == {("demo-worker", "service-name-duplicate")}


def test_two_entries_cannot_publish_the_same_port(tmp_path: Path) -> None:
    other, compose = other_plugin(), other_compose()
    other["ports"][0]["port"] = 8088
    compose["services"]["other"]["ports"] = ["${HM_BIND}:8088:9099"]
    write_entry(tmp_path, demo_plugin(), demo_compose())
    write_entry(tmp_path, other, compose)
    assert _pairs(rules.check_catalog(tmp_path)) == {("other", "port-duplicate")}


def test_the_answer_key_may_be_passed_to_the_vectorizer_only(tmp_path: Path) -> None:
    plugin, compose = other_plugin("vectorizer"), other_compose("vectorizer")
    compose["services"]["vectorizer"]["environment"] = ["HM_ANSWER_API_KEY"]
    write_entry(tmp_path, plugin, compose)
    assert rules.check_catalog(tmp_path) == []
    compose["services"]["vectorizer"]["environment"] = ["KEY=${HM_ANSWER_API_KEY}"]
    write_entry(tmp_path, plugin, compose)
    assert codes(tmp_path) == {"unknown-variable"}


def test_every_rule_has_a_refused_example() -> None:
    """A rule that no broken entry of this file triggers is a rule nobody tests."""
    elsewhere = {
        "json-invalid",
        "yaml-invalid",
        "extra-file",
        "missing-file",
        "no-services",
        "requires-cycle",
        "requires-mode",
        "service-name-duplicate",
        "port-duplicate",
    }  # each has its own test above
    exercised = set().union(*(expected for _, expected, _ in BROKEN)) | elsewhere
    assert set(rules.CODES) - exercised == set()
    assert exercised - set(rules.CODES) == set()


# --- patterns -----------------------------------------------------------------

GOOD_PATTERNS = [
    MODEL,
    "^https://[A-Za-z0-9.-]{1,120}(:[0-9]{1,5})?(/[A-Za-z0-9._/-]{0,60})?$",
    "^(?:lan|localhost)$",
    "^([a-z]+)?$",
]
# Safe for a string, not for a list: an item of a list can become an argument of
# a post_start command (an item that starts with a dash would be read as an
# option), and these can start with a dash. The e-mail address pattern of
# open-webui is one: "-x@y" matches it.
STRING_ONLY_PATTERNS = [
    ("^[a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,55}$", "-x@y"),
    ("^[a-z-]{1,40}$", "-x"),
    ("^-?[0-9]{1,5}$", "-1"),
]
BAD_PATTERNS = [
    ("[a-z]+", "anchored"),
    ("^[a-z]+", "anchored"),
    ("[a-z]+$", "anchored"),
    ("^a|b$", "anchored"),
    ("^a$|^b$", "anchored"),
    ("^.+$", "not allowed"),
    ("^[^,]+$", "negated"),
    ("^[a-z$]+$", "'$'"),
    ("^[a-z']+$", '"\'"'),
    ('^[a-z"]+$', "'\"'"),
    ("^[a-z`]+$", "'`'"),
    ("^[a-z\\\\]+$", "'\\\\'"),
    ("^[!-~]+$", "includes"),
    ("^[\\x00-z]+$", "control character"),
    ("^a\\tb$", "control character"),
    ("^\\w+$", "write the characters out"),
    ("^\\S+$", "write the characters out"),
    ("^[\\d]+$", "write the characters out"),
    ("^(?=a)[a-z]+$", "portable"),
    ("(?i)^[a-z]+$", "portable"),
    ("^(?P<x>[a-z]+)$", "portable"),
    ("^([a-z])\\1$", "not allowed"),
    ("^a$b$", "anchor"),
    ("^(^a$)$", "anchor"),
    ("^\\Aa$", "anchor"),
    ("^[a-z]{0,2000}$", "repeats"),
    ("^[a-z+$", "valid regular expression"),
    ("^", "2 to"),
    (5, "2 to"),
]


@pytest.mark.parametrize("pattern", GOOD_PATTERNS)
def test_a_safe_pattern_is_accepted(pattern: str) -> None:
    assert rules.pattern_problem(pattern, for_list=False) is None
    assert rules.pattern_problem(pattern, for_list=True) is None


@pytest.mark.parametrize(("pattern", "dashed"), STRING_ONLY_PATTERNS)
def test_a_pattern_that_can_start_with_a_dash_is_for_strings_only(pattern: str, dashed: str) -> None:
    assert re.fullmatch(pattern, dashed), "the example must be a value the pattern lets through"
    assert rules.pattern_problem(pattern, for_list=False) is None
    assert rules.pattern_problem(pattern, for_list=True) == "can match a value that starts with a dash"


@pytest.mark.parametrize(("pattern", "why"), BAD_PATTERNS)
def test_a_pattern_that_could_let_a_dangerous_value_through_is_refused(pattern: Any, why: str) -> None:
    for for_list in (False, True):
        problem = rules.pattern_problem(pattern, for_list=for_list)
        assert problem is not None and why in problem, problem


@pytest.mark.parametrize(
    ("setting", "dash"),
    [
        ({"type": "bool"}, False),
        ({"type": "int", "min": 0, "max": 9}, False),
        ({"type": "int", "min": -1, "max": 9}, True),
        ({"type": "enum", "values": ["a", "b-"]}, False),
        ({"type": "enum", "values": ["a", "-b"]}, True),
        ({"type": "string", "pattern": MODEL}, False),
        ({"type": "string", "pattern": "^[a-z -]{0,40}$"}, True),
        ({"type": "string", "pattern": "^(x|-)[a-z]*$"}, True),
        ({"type": "string", "pattern": "^[a-z]*-$"}, True),  # "-" alone matches
        ({"type": "string_list", "pattern": MODEL}, False),
        # A broken definition is reported by its own rule, not a second time here.
        ({"type": "string", "pattern": "^.*$"}, False),
        ({"type": "string_list", "pattern": "^[a-z-]+$"}, False),
        ({"type": "int", "min": "-1"}, False),
    ],
)
def test_whether_a_setting_can_start_with_a_dash(setting: dict[str, Any], dash: bool) -> None:
    assert rules.setting_can_start_with_dash(setting) is dash


def test_a_list_pattern_is_held_to_more_than_a_string_pattern() -> None:
    """A list travels as one space-separated variable and its items become arguments of commands."""
    assert rules.pattern_problem("^[a-z ]+$", for_list=False) is None
    assert "a space" in (rules.pattern_problem("^[a-z ]+$", for_list=True) or "")
    for pattern in ("^[a-z-]+$", "^-?[a-z]+$", "^(-|[a-z])[a-z]*$", "^[a-z]*-[a-z]*$", "^(?:[a-z]*)-$"):
        assert rules.pattern_problem(pattern, for_list=False) is None, pattern
        assert "dash" in (rules.pattern_problem(pattern, for_list=True) or ""), pattern
    assert rules.pattern_problem("^[a-z][a-z-]*$", for_list=True) is None


def test_the_proof_about_patterns_holds_on_samples() -> None:
    """A second net under the proof.

    No accepted pattern of either catalog matches a value with a forbidden character.
    """
    seen = 0
    for catalog in CATALOGS.values():
        for directory in rules.entry_directories(catalog):
            plugin = json.loads((directory / rules.PLUGIN_FILE).read_text(encoding="utf-8"))
            for setting in plugin["settings"].values():
                if setting["type"] not in ("string", "string_list"):
                    continue
                regex = re.compile(setting["pattern"], re.ASCII)
                forbidden = rules.FORBIDDEN_IN_LISTS if setting["type"] == "string_list" else rules.FORBIDDEN
                default = setting["default"]
                samples = [
                    *(default if isinstance(default, list) else [default]),
                    "a",
                    "a1",
                    "ollama/x:1",
                    "a@b.c",
                ]
                for sample in samples:
                    for code in forbidden:
                        for position in range(len(sample) + 1):
                            value = sample[:position] + chr(code) + sample[position:]
                            assert not regex.fullmatch(value), (directory.name, setting["env"], value)
                            seen += 1
    assert seen > 1000


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("plain", []),
        ("${HM_BIND}:1:2", [("HM_BIND", "plain")]),
        ("a$$b", []),
        ("$$${HM_SET_X}", [("HM_SET_X", "plain")]),
        ("${A}${B}", [("A", "plain"), ("B", "plain")]),
        ("${A:-x}", [("A", "modifier")]),
        ("${A-x}", [("A", "modifier")]),
        ("${A:?x}", [("A", "modifier")]),
        ("${A:+x}", [("A", "modifier")]),
        ("${}", [(None, "modifier")]),
        ("$A/b", [("A", "unbraced")]),
        ("${A", [(None, "malformed")]),
        ("5$", [(None, "stray")]),
        ("$ {A}", [(None, "stray")]),
    ],
)
def test_variables_are_found_as_docker_compose_would_interpolate_them(
    text: str, expected: list[tuple[str | None, str]]
) -> None:
    assert [(ref.name, ref.form) for ref in rules.scan_variables(text)] == expected


# --- 3. the shipped catalog ---------------------------------------------------


def shipped(plugin_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    entry = rules.check_entry(SHIPPED / plugin_id)
    assert entry.plugin is not None and entry.compose is not None
    return entry.plugin, entry.compose


def _environment(service: dict[str, Any]) -> dict[str, str | None]:
    return dict(item.partition("=")[::2] if "=" in item else (item, None) for item in service["environment"])


# Plugins whose published port answers without any authentication of its own,
# because the project offers none (Ollama) or none that the appliance can turn
# on today (Qdrant: the vectorizer sends no API key).
WITHOUT_AUTHENTICATION = {"ollama", "qdrant"}


@pytest.mark.parametrize("plugin_id", SHIPPED_PLUGINS)
def test_a_published_port_follows_the_bind_setting(plugin_id: str) -> None:
    plugin, _ = shipped(plugin_id)
    assert plugin["ports"], "every shipped plugin serves something"
    bind = plugin["settings"]["bind"]
    assert bind["env"] == "HM_SET_BIND" and set(bind["values"]) == {"lan", "localhost"}


@pytest.mark.parametrize("plugin_id", SHIPPED_PLUGINS)
def test_what_has_no_authentication_stays_on_the_machine_by_default(plugin_id: str) -> None:
    plugin, _ = shipped(plugin_id)
    default = plugin["settings"]["bind"]["default"]
    if plugin_id in WITHOUT_AUTHENTICATION:
        assert default == "localhost"
        assert "no authentication" in plugin["summary"] and "this machine" in plugin["summary"]
    else:
        assert default == "lan"
        assert any(word in plugin["summary"] for word in ("token", "password", "account"))


def test_pages_with_a_login_keep_it() -> None:
    plugin, compose = shipped("open-webui")
    environment = _environment(compose["services"]["open-webui"])
    assert "WEBUI_AUTH" not in environment  # upstream default: true
    assert environment["WEBUI_ADMIN_PASSWORD"] is None  # passed from the secret
    assert {s["key"]: s["required"] for s in plugin["secrets"]}["admin_password"] is True

    plugin, compose = shipped("openclaw")
    service = compose["services"]["openclaw"]
    assert _environment(service)["OPENCLAW_GATEWAY_TOKEN"] is None
    assert {s["key"]: s["required"] for s in plugin["secrets"]}["gateway_token"] is True
    assert "--auth" not in service["command"]  # token authentication is the default; "none" would turn it off

    plugin, compose = shipped("hermes")
    environment = _environment(compose["services"]["hermes"])
    assert environment["HERMES_DASHBOARD_BASIC_AUTH_USERNAME"] == "${HM_SET_DASHBOARD_USER}"
    assert environment["HERMES_DASHBOARD_BASIC_AUTH_PASSWORD"] is None
    assert "HERMES_DASHBOARD_INSECURE" not in environment and "API_SERVER_ENABLED" not in environment
    assert {s["key"]: s["required"] for s in plugin["secrets"]}["dashboard_password"] is True


def test_the_plugins_that_use_models_point_at_the_local_ollama() -> None:
    for plugin_id in ("open-webui", "openclaw", "hermes", "vectorizer"):
        assert "ollama" in shipped(plugin_id)[0]["requires"], plugin_id
    assert (
        _environment(shipped("open-webui")[1]["services"]["open-webui"])["OLLAMA_BASE_URL"]
        == "http://ollama:11434"
    )
    openclaw = json.dumps(shipped("openclaw")[0]["post_start"])
    assert "http://ollama:11434" in openclaw and "/v1" not in openclaw  # OpenClaw wants Ollama's native API
    hermes = [step["exec"] for step in shipped("hermes")[0]["post_start"]]
    assert ["/opt/hermes/bin/hermes", "config", "set", "model.base_url", "http://ollama:11434/v1"] in hermes
    # The service every one of them names exists, under that name, in the catalog.
    assert "ollama" in shipped("ollama")[1]["services"]
    assert shipped("ollama")[0]["ports"][0]["port"] == 11434


def test_a_cloud_key_is_always_a_secret_and_never_required() -> None:
    for plugin_id in ("openclaw", "hermes"):
        cloud = [s for s in shipped(plugin_id)[0]["secrets"] if s["env"].endswith("_API_KEY")]
        assert cloud, plugin_id
        assert not any(s["required"] for s in cloud), plugin_id
    # Open WebUI reads its connections from the environment at the first start
    # only (then from its database): a key set in the panel later would do
    # nothing, so cloud connections are added in Open WebUI itself.
    plugin, compose = shipped("open-webui")
    assert not [s for s in plugin["secrets"] if s["env"].startswith("OPENAI_")]
    assert not [s for s in plugin["settings"].values() if s["env"].startswith("HM_SET_OPENAI")]
    assert _environment(compose["services"]["open-webui"])["ENABLE_OPENAI_API"] == "false"


def test_what_the_plugins_send_out_by_themselves_is_turned_off() -> None:
    """Requests the projects make on their own (statistics, update checks), not what a user asks for."""
    environment = _environment(shipped("qdrant")[1]["services"]["qdrant"])
    assert environment["QDRANT__TELEMETRY_DISABLED"] == "true"
    plugin, compose = shipped("ollama")
    assert plugin["settings"]["local_only"]["default"] is True
    assert _environment(compose["services"]["ollama"])["OLLAMA_NO_CLOUD"] == "${HM_SET_LOCAL_ONLY}"
    environment = _environment(shipped("open-webui")[1]["services"]["open-webui"])
    assert environment["ENABLE_VERSION_UPDATE_CHECK"] == "false"
    assert environment["RAG_EMBEDDING_MODEL_AUTO_UPDATE"] == "false"
    plugin, compose = shipped("openclaw")
    assert _environment(compose["services"]["openclaw"])["OPENCLAW_NO_AUTO_UPDATE"] == "1"
    arguments = [argument for step in plugin["post_start"] for argument in step["exec"]]
    assert any('{"path":"update.checkOnStart","value":false}' in argument for argument in arguments)


def test_gpu_plugins_ask_for_the_gpus_the_documented_way() -> None:
    for plugin_id in SHIPPED_PLUGINS:
        plugin, compose = shipped(plugin_id)
        devices = [
            device
            for service in compose["services"].values()
            for device in service.get("deploy", {})
            .get("resources", {})
            .get("reservations", {})
            .get("devices", [])
        ]
        if plugin["gpu"]:
            assert devices == [{"driver": "nvidia", "count": "all", "capabilities": ["gpu"]}], plugin_id
        else:
            assert devices == [], plugin_id
    assert [p for p in SHIPPED_PLUGINS if shipped(p)[0]["gpu"]] == ["ollama"]


def test_ollama_keeps_the_models_the_owner_listed() -> None:
    plugin, compose = shipped("ollama")
    assert plugin["settings"]["models"]["type"] == "string_list"
    assert plugin["post_start"] == [
        {"service": "ollama", "exec": ["ollama", "pull", "{item}"], "for_each": "models", "timeout_s": 3600}
    ]
    assert compose["services"]["ollama"]["volumes"] == ["models:/root/.ollama"]
    assert plugin["volumes"] == [{"name": "models", "backup": "models"}]
    assert set(plugin["modes"]) == {"private_ai", "vectorize"}  # it serves the embeddings of the vectorizer


def test_qdrant_runs_for_the_vectorizer_and_is_backed_up() -> None:
    plugin, compose = shipped("qdrant")
    assert set(plugin["modes"]) == {"private_ai", "vectorize"}
    assert {"name": "storage", "backup": "always"} in plugin["volumes"]
    assert "storage:/qdrant/storage" in compose["services"]["qdrant"]["volumes"]
    assert compose["services"]["qdrant"]["ports"] == ["${HM_BIND}:6333:6333"]  # gRPC (6334) is not published


def test_the_vectorizer_has_the_layout_of_the_contract() -> None:
    plugin, compose = shipped("vectorizer")
    assert plugin["requires"] == ["qdrant", "ollama"]
    assert set(plugin["modes"]) == {"private_ai", "vectorize"}
    assert plugin["build"] == {
        "context": "vectorizer",
        "image": f"happymining/vectorizer:{plugin['version']}",
    }
    assert plugin["secrets"] == []  # its cloud key is ai.answer.api_key, not a plugin secret
    service = compose["services"]["vectorizer"]
    assert service["image"] == plugin["build"]["image"] and service["pull_policy"] == "never"
    assert service["ports"] == ["${HM_BIND}:8765:8765"]
    assert service["volumes"] == [
        "${HM_PLUGIN_DATA}/config:/config:ro",
        "state:/state",
        {
            "type": "bind",
            "source": "/srv/happymining/nas",
            "target": "/srv/happymining/nas",
            "read_only": True,
            # Shares mounted after the container started must be visible in it.
            "bind": {"propagation": "rslave"},
        },
    ]
    assert service["environment"] == ["HM_ANSWER_API_KEY"]
    assert plugin["volumes"] == [{"name": "state", "backup": "always"}]


def test_the_vectorizer_is_built_from_a_directory_that_ships_with_the_package() -> None:
    plugin, _ = shipped("vectorizer")
    context = REPO / "appliance" / plugin["build"]["context"]
    assert context.is_dir(), f"{context} is where the helper builds {plugin['build']['image']} from"
    dockerfile = context / "Dockerfile"
    if not dockerfile.is_file():
        pytest.skip("appliance/vectorizer/Dockerfile is not written yet: its base image cannot be compared")
    bases = re.findall(r"(?im)^FROM\s+(?:--platform=\S+\s+)?(\S+)", dockerfile.read_text(encoding="utf-8"))
    listed = {(f"{i['ref']}@{i['digest']}" if i["verified"] else i["ref"]) for i in plugin["images"]}
    stages = set(re.findall(r"(?im)^FROM\s+.*\s+AS\s+(\S+)", dockerfile.read_text(encoding="utf-8")))
    external = {base for base in bases if base not in stages and base != "scratch"}
    assert external == listed, (
        "plugin.json must list the base images of the Dockerfile, as the Dockerfile writes them"
    )


def test_the_readme_records_what_was_verified() -> None:
    readme = (SHIPPED / "README.md").read_text(encoding="utf-8")
    assert "2026-10-02" in readme
    for plugin_id in SHIPPED_PLUGINS:
        plugin, _ = shipped(plugin_id)
        assert f"`{plugin_id}`" in readme, plugin_id
        for image in plugin["images"]:
            assert image["ref"] in readme, image["ref"]
            if image["verified"]:
                assert image["digest"] in readme, image["ref"]
        for port in plugin["ports"]:
            assert str(port["port"]) in readme, plugin_id
    for code in rules.CODES:
        assert f"`{code}`" in readme, f"the README does not explain {code}"


def test_the_control_plane_reads_both_catalogs() -> None:
    """The control plane's own loader (another reading of section 7) accepts what this module accepts."""
    try:
        from happymining.services import catalog as control_plane
    except Exception as exc:  # the API is being written by someone else
        pytest.skip(f"the control plane's catalog module cannot be imported: {type(exc).__name__}")
    assert sorted(entry.id for entry in control_plane.load_catalog(SHIPPED)) == list(SHIPPED_PLUGINS)
    assert sorted(entry.id for entry in control_plane.load_catalog(FIXTURE)) == list(FIXTURE_PLUGINS)


# --- Docker Compose's own reading ---------------------------------------------


def _docker_compose() -> list[str] | None:
    docker = shutil.which("docker")
    if docker is None:
        return None
    try:
        probe = subprocess.run([docker, "compose", "version"], capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return [docker, "compose"] if probe.returncode == 0 else None


def _env_value(setting: dict[str, Any]) -> str:
    """A setting's default as the helper writes it: true/false, decimal digits, items joined by spaces."""
    default = setting["default"]
    if isinstance(default, bool):
        return "true" if default else "false"
    if isinstance(default, list):
        return " ".join(default)
    return str(default)


@pytest.mark.parametrize(("catalog", "directory"), ENTRIES)
def test_docker_compose_reads_the_file_as_the_rules_do(catalog: str, directory: Path, tmp_path: Path) -> None:
    """``docker compose config`` with dummy values: the file is valid, and Docker sees what the checker saw.

    Nothing is pulled or started. Skipped when Docker Compose is not installed.
    """
    compose_command = _docker_compose()
    if compose_command is None:
        pytest.skip("docker compose is not installed: the Compose files are not validated by Docker here")
    plugin = json.loads((directory / rules.PLUGIN_FILE).read_text(encoding="utf-8"))
    plugin_id = plugin["id"]
    data_dir = f"/var/lib/happymining-plugins/{plugin_id}"
    values = {"HM_BIND": "127.0.0.1", "HM_PLUGIN_DATA": data_dir}
    values.update({s["env"]: _env_value(s) for s in plugin["settings"].values()})
    values.update({s["env"]: "dummy-secret" for s in plugin["secrets"]})
    env_file = tmp_path / "plugin.env"
    env_file.write_text("".join(f"{name}='{value}'\n" for name, value in values.items()), encoding="utf-8")
    result = subprocess.run(
        [
            *compose_command,
            *("-p", f"hm-{plugin_id}", "--env-file", str(env_file)),
            *("-f", str(directory / rules.COMPOSE_FILE), "config", "--format", "json"),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        cwd=tmp_path,
        env={"PATH": os.environ.get("PATH", ""), "HOME": str(tmp_path)},
    )
    assert result.returncode == 0, result.stderr[-2000:]
    model = json.loads(result.stdout)
    declared = {port["port"] for port in plugin["ports"]}
    for name, service in model["services"].items():
        for key in ("privileged", "cap_add", "network_mode", "pid", "ipc", "devices", "build", "env_file"):
            assert key not in service, f"{name}.{key}"
        assert service["restart"] == "unless-stopped", name
        assert service["labels"]["eu.happymining.plugin"] == plugin_id, name
        for port in service.get("ports", []):
            assert port["host_ip"] == "127.0.0.1", f"{name}: a port is not bound to HM_BIND"
            assert int(port["published"]) in declared, f"{name}: {port['published']} is not in plugin.json"
        for volume in service.get("volumes", []):
            if volume["type"] == "bind":
                assert volume["source"] == data_dir or volume["source"].startswith(
                    (data_dir + "/", "/srv/happymining")
                ), f"{name}: {volume['source']}"
                if volume["source"].startswith("/srv/happymining"):
                    assert volume.get("read_only") is True, f"{name}: {volume['source']} is writable"
        for value in (service.get("environment") or {}).values():
            assert value is None or "${" not in value, f"{name}: a variable was not replaced"
        if catalog == "shipped":
            assert list(service["networks"]) == ["hm-appliance"], name
    if catalog == "shipped":
        published = {int(p["published"]) for s in model["services"].values() for p in s.get("ports", [])}
        assert published == declared
        # Compose adds keys of its own to what it prints (e.g. "ipam": {}); any
        # such key must be empty, so that only "name" and "external" say anything.
        assert list(model["networks"]) == ["hm-appliance"], model["networks"]
        network = model["networks"]["hm-appliance"]
        assert network["name"] == "hm-appliance" and network["external"] is True, network
        added = {key: value for key, value in network.items() if key not in ("name", "external")}
        assert all(value in (None, {}, [], "") for value in added.values()), network
        assert {v["name"] for v in model.get("volumes", {}).values()} == {
            f"hm-{plugin_id}_{volume['name']}" for volume in plugin["volumes"]
        }
        secrets_seen = {
            name
            for service in model["services"].values()
            for name, value in (service.get("environment") or {}).items()
            if value == "dummy-secret"
        }
        assert secrets_seen == {s["env"] for s in plugin["secrets"]}, "a secret does not reach its container"
