"""The image definition and the package's dependencies, checked without Docker.

Nothing here builds the image (there is no Docker where these tests run): the
Dockerfile is parsed and its properties asserted, and the package's imports
are read with `ast`.
"""

from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

import pytest
from vz_support import VECTORIZER_DIR

DOCKERFILE = VECTORIZER_DIR / "Dockerfile"
LOCK = VECTORIZER_DIR / "requirements.lock"
PACKAGE = VECTORIZER_DIR / "hm_vectorizer"
DOCLING_VERSION = "2.132.0"


def instructions(path: Path = DOCKERFILE) -> list[tuple[str, str]]:
    """(INSTRUCTION, arguments) in order, continuation lines joined, comments dropped."""
    out: list[tuple[str, str]] = []
    pending = ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not pending and (not line or line.startswith("#")):
            continue
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        pending += line
        keyword, _, rest = pending.partition(" ")
        out.append((keyword.upper(), " ".join(rest.split())))
        pending = ""
    assert not pending, "the Dockerfile ends with a continuation"
    return out


def stages() -> list[list[tuple[str, str]]]:
    result: list[list[tuple[str, str]]] = []
    for keyword, args in instructions():
        if keyword == "FROM":
            result.append([])
        result[-1].append((keyword, args))
    return result


def env_of(stage: list[tuple[str, str]]) -> dict[str, str]:
    env: dict[str, str] = {}
    for keyword, args in stage:
        if keyword == "ENV":
            for pair in args.split():
                key, _, value = pair.partition("=")
                env[key] = value
    return env


def exec_form(args: str) -> list[str]:
    value = json.loads(args)
    assert isinstance(value, list) and all(isinstance(v, str) for v in value)
    return value


# -- base image ----------------------------------------------------------------------


def test_every_stage_starts_from_the_same_pinned_base_image() -> None:
    froms = [args for keyword, args in instructions() if keyword == "FROM"]
    assert len(froms) == 2, "a build stage and a final stage"
    refs = [args.split()[0] for args in froms]
    assert len(set(refs)) == 1
    ref = refs[0]
    match = re.fullmatch(r"docker\.io/library/python:(3\.\d+)-slim-bookworm@sha256:([0-9a-f]{64})", ref)
    if match is None:
        assert "# digest: unverified" in DOCKERFILE.read_text(encoding="utf-8"), ref
    assert froms[0].endswith(" AS build")


# -- the final stage -------------------------------------------------------------------


@pytest.fixture(scope="module")
def final() -> list[tuple[str, str]]:
    return stages()[-1]


def test_runs_as_an_unprivileged_numeric_user(final: list[tuple[str, str]]) -> None:
    users = [i for i, (keyword, _) in enumerate(final) if keyword == "USER"]
    assert len(users) == 1
    user = final[users[0]][1]
    uid, _, gid = user.partition(":")
    assert uid.isdigit() and gid.isdigit() and int(uid) >= 1000 and int(gid) >= 1000
    entry = next(i for i, (keyword, _) in enumerate(final) if keyword == "ENTRYPOINT")
    assert users[0] < entry
    # the state directory is the one thing that user owns
    runs = " ".join(args for keyword, args in final[: users[0]] if keyword == "RUN")
    assert f"install -d -o {uid} -g {gid} -m 0750 /state" in runs


def test_no_installer_or_compiler_is_left_in_the_final_stage(final: list[tuple[str, str]]) -> None:
    runs = " ".join(args for keyword, args in final if keyword == "RUN")
    for tool in ("apt-get", "apt ", "gcc", "build-essential", "make ", "pip install"):
        assert tool not in runs, tool
    assert "python -m pip uninstall -y pip" in runs
    build = " ".join(args for keyword, args in stages()[0] if keyword == "RUN")
    assert "/opt/venv/bin/pip uninstall -y pip" in build, "the virtualenv copied over has no pip either"


def test_code_and_models_belong_to_root_and_writes_go_to_state_and_tmp(final: list[tuple[str, str]]) -> None:
    for keyword, args in final:
        if keyword == "COPY":
            assert "--chown" not in args, args
    env = env_of(final)
    tmp = "/" + "tmp"  # the container's /tmp, a path in the image, not one used here
    for key in ("HOME", "TMPDIR", "XDG_CACHE_HOME", "HF_HOME"):
        assert env[key] == tmp or env[key].startswith(tmp + "/"), key
    assert env["PYTHONDONTWRITEBYTECODE"] == "1"
    assert env["PYTHONSAFEPATH"] == "1", "the working directory is not on the import path"
    assert env["PYTHONPATH"] == "/opt/hm"
    assert ("COPY", "hm_vectorizer /opt/hm/hm_vectorizer") in final


def test_parsing_is_offline_and_checked_at_build_time(final: list[tuple[str, str]]) -> None:
    env = env_of(final)
    assert env["HF_HUB_OFFLINE"] == "1"
    models = env["DOCLING_ARTIFACTS_PATH"]
    build_runs = " ".join(args for keyword, args in stages()[0] if keyword == "RUN")
    assert f"docling-tools models download layout tableformer rapidocr -o {models}" in build_runs
    assert ("COPY", f"--from=build {models} {models}") in final
    user_at = next(i for i, (keyword, _) in enumerate(final) if keyword == "USER")
    selfcheck = [i for i, (keyword, args) in enumerate(final) if keyword == "RUN" and "selfcheck" in args]
    assert len(selfcheck) == 1 and selfcheck[0] > user_at, "run as the service's user"
    assert exec_form(final[selfcheck[0]][1]) == ["/opt/venv/bin/python", "-m", "hm_vectorizer", "selfcheck"]


def test_port_healthcheck_and_entry_point(final: list[tuple[str, str]]) -> None:
    assert ("EXPOSE", "8765") in final
    (health,) = [args for keyword, args in final if keyword == "HEALTHCHECK"]
    options, _, command = health.partition(" CMD ")
    assert "--interval=" in options and "--timeout=" in options
    assert exec_form(command) == ["/opt/venv/bin/python", "-m", "hm_vectorizer", "healthcheck"]
    (entry,) = [args for keyword, args in final if keyword == "ENTRYPOINT"]
    (cmd,) = [args for keyword, args in final if keyword == "CMD"]
    assert exec_form(entry) + exec_form(cmd) == ["/opt/venv/bin/python", "-m", "hm_vectorizer", "serve"]


# -- what is installed --------------------------------------------------------------------


def test_docling_is_pinned_and_everything_from_pypi_is_hashed() -> None:
    text = LOCK.read_text(encoding="utf-8")
    requirements = re.findall(r"^([A-Za-z0-9_.-]+)==(\S+) \\$", text, flags=re.M)
    names = {name.lower(): version for name, version in requirements}
    assert names["docling"] == DOCLING_VERSION and names["docling-slim"] == DOCLING_VERSION
    for forbidden in ("torch", "torchvision", "triton"):
        assert forbidden not in names, forbidden
    assert not [n for n in names if n.startswith(("nvidia-", "cuda-"))], "no CUDA package"
    blocks = re.split(r"\n(?=[A-Za-z0-9_.-]+==)", text)  # the header, then one block per package
    assert len(blocks) - 1 == len(requirements) >= 90
    for block in blocks[1:]:
        assert "--hash=sha256:" in block, block.splitlines()[0]
    build = " ".join(args for keyword, args in stages()[0] if keyword == "RUN")
    assert "pip install --no-deps --require-hashes -r /tmp/requirements.lock" in build
    torch = re.search(r"--index-url (\S+) torch==(\S+) torchvision==(\S+)", build)
    assert torch is not None and torch.group(1) == "https://download.pytorch.org/whl/cpu"
    assert "pip check" in build


def test_build_context_excludes_bytecode() -> None:
    ignored = (VECTORIZER_DIR / ".dockerignore").read_text(encoding="utf-8").split()
    assert "**/__pycache__" in ignored and "**/*.pyc" in ignored


# -- the core runs on the standard library ---------------------------------------------------------


def _imports(tree: ast.AST) -> list[tuple[str, int]]:
    """(top-level module name, level) of every import in the tree."""
    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend((alias.name.split(".")[0], 0) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            found.append(((node.module or "").split(".")[0], node.level))
    return found


def _module_level_imports(tree: ast.Module) -> list[tuple[str, int]]:
    found: list[tuple[str, int]] = []
    for node in tree.body:
        if isinstance(node, ast.Import | ast.ImportFrom | ast.If | ast.Try):
            found.extend(_imports(node))
    return found


@pytest.mark.parametrize("path", sorted(PACKAGE.glob("*.py")), ids=lambda p: p.name)
def test_package_imports_only_the_standard_library(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for name, level in _module_level_imports(tree):
        assert level > 0 or name in sys.stdlib_module_names or name == "__future__", (path.name, name)
    lazy = {name for name, level in _imports(tree) if level == 0 and name not in sys.stdlib_module_names}
    lazy.discard("__future__")
    if path.name == "parsers.py":
        assert lazy == {"docling", "docling_core"}, "Docling is the one optional import, inside functions"
    else:
        assert lazy == set(), (path.name, lazy)
