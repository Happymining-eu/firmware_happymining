"""deploy/hostinger/bootstrap.py: fetch one commit and its pinned dependencies into a volume."""

from __future__ import annotations

import importlib.util
import io
import sys
import tarfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SHA = "c" * 40
OLD = "a" * 40


def load():
    spec = importlib.util.spec_from_file_location("hm_bootstrap", REPO / "deploy" / "hostinger" / "bootstrap.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tarball(files: dict[str, bytes], *, extra=None) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, content in files.items():
            info = tarfile.TarInfo(f"firmware_happymining-{SHA}/{name}")
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
        for info in extra or []:
            archive.addfile(info)
    return buffer.getvalue()


APP = {
    "api/happymining/main.py": b"app = 1\n",
    "api/happymining/services/ledger.py": b"x = 1\n",
    "api/requirements.lock.txt": b"fastapi==0.142.2 --hash=sha256:00\n",
    "dashboard/templates/base.html": b"<html></html>\n",
    "migrations/versions/0001_initial_schema.py": b"\n",
    "alembic.ini": b"[alembic]\n",
    # Not part of what runs on the server:
    "agent/cmd/main.go": b"package main\n",
    "tests/api/test_x.py": b"\n",
    "deploy/.env.example": b"HM_SECRET_KEY=change-me\n",
    "api/pyproject.toml": b"\n",
}


@pytest.fixture
def fake_pip(tmp_path):
    """A stand-in for pip that records its arguments and creates the target directory."""
    script = tmp_path / "fake_pip.py"
    log = tmp_path / "pip.log"
    script.write_text(
        "import sys, pathlib\n"
        f"pathlib.Path({str(log)!r}).write_text('\\n'.join(sys.argv[1:]))\n"
        "target = sys.argv[sys.argv.index('--target') + 1]\n"
        "pathlib.Path(target).mkdir(parents=True)\n"
        "(pathlib.Path(target) / 'installed.txt').write_text('ok')\n"
    )
    return [sys.executable, str(script)], log


def test_prepares_only_what_the_server_runs(tmp_path, fake_pip):
    bootstrap = load()
    pip, log = fake_pip
    root = tmp_path / "hm"
    final = bootstrap.prepare("Happymining-eu/firmware_happymining", SHA, root, fetcher=lambda url: tarball(APP), pip=pip)

    assert final == root / SHA and (final / ".ready").read_text() == SHA + "\n"
    present = sorted(str(p.relative_to(final)) for p in final.rglob("*") if p.is_file())
    assert present == [
        ".ready",
        "alembic.ini",
        "api/happymining/main.py",
        "api/happymining/services/ledger.py",
        "api/requirements.lock.txt",
        "dashboard/templates/base.html",
        "migrations/versions/0001_initial_schema.py",
        "site/installed.txt",
    ]
    args = log.read_text().split("\n")
    # Nothing is resolved and nothing is compiled: exact hashes, wheels only.
    assert "--require-hashes" in args and "--only-binary=:all:" in args and "install" in args
    assert args[args.index("-r") + 1] == str(root / f"{SHA}.partial" / "api" / "requirements.lock.txt")
    assert not (root / f"{SHA}.partial").exists()


def test_the_url_names_exactly_the_commit(tmp_path, fake_pip):
    bootstrap = load()
    seen = []

    def fetcher(url):
        seen.append(url)
        return tarball(APP)

    bootstrap.prepare("Happymining-eu/firmware_happymining", SHA, tmp_path / "hm", fetcher=fetcher, pip=fake_pip[0])
    assert seen == [f"https://codeload.github.com/Happymining-eu/firmware_happymining/tar.gz/{SHA}"]


def test_a_prepared_version_is_never_touched_again(tmp_path, fake_pip):
    bootstrap = load()
    root = tmp_path / "hm"
    bootstrap.prepare("o/r", SHA, root, fetcher=lambda url: tarball(APP), pip=fake_pip[0])
    marker = root / SHA / "api" / "happymining" / "main.py"
    marker.write_text("kept\n")

    def must_not_fetch(url):
        raise AssertionError("fetched again")

    bootstrap.prepare("o/r", SHA, root, fetcher=must_not_fetch, pip=["false"])
    assert marker.read_text() == "kept\n"


def test_older_versions_go_only_after_the_new_one_is_complete(tmp_path, fake_pip):
    bootstrap = load()
    root = tmp_path / "hm"
    (root / OLD).mkdir(parents=True)
    (root / OLD / ".ready").write_text(OLD)
    (root / "keep-me").mkdir()

    # A failed preparation leaves the running version alone.
    with pytest.raises(SystemExit):
        bootstrap.prepare("o/r", SHA, root, fetcher=lambda url: tarball({"README.md": b""}), pip=fake_pip[0])
    assert (root / OLD / ".ready").is_file() and not (root / SHA).exists()

    bootstrap.prepare("o/r", SHA, root, fetcher=lambda url: tarball(APP), pip=fake_pip[0])
    assert sorted(p.name for p in root.iterdir()) == [SHA, "keep-me"]


def test_failed_dependency_install_leaves_nothing_marked_ready(tmp_path):
    bootstrap = load()
    root = tmp_path / "hm"
    with pytest.raises(Exception):  # noqa: B017, PT011 - CalledProcessError from the failing installer
        bootstrap.prepare("o/r", SHA, root, fetcher=lambda url: tarball(APP), pip=[sys.executable, "-c", "raise SystemExit(1)"])
    assert not (root / SHA).exists()


def test_links_and_paths_that_leave_the_directory_are_ignored(tmp_path, fake_pip):
    bootstrap = load()
    link = tarfile.TarInfo(f"firmware_happymining-{SHA}/api/happymining/evil_link.py")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/passwd"
    hard = tarfile.TarInfo(f"firmware_happymining-{SHA}/dashboard/hard.html")
    hard.type = tarfile.LNKTYPE
    hard.linkname = f"firmware_happymining-{SHA}/alembic.ini"
    climbing = tarfile.TarInfo(f"firmware_happymining-{SHA}/api/happymining/../../../escaped.py")
    climbing.size = 0
    root = tmp_path / "hm"
    final = bootstrap.prepare(
        "o/r", SHA, root, fetcher=lambda url: tarball(APP, extra=[link, hard, climbing]), pip=fake_pip[0]
    )
    names = {p.name for p in final.rglob("*")}
    assert not {"evil_link.py", "hard.html", "escaped.py"} & names
    assert not (tmp_path / "escaped.py").exists() and not (root / "escaped.py").exists()


@pytest.mark.parametrize(
    ("repo", "sha"),
    [
        ("o/r", "main"),
        ("o/r", "c" * 39),
        ("o/r", "C" * 40),
        ("o/r/../x", "c" * 40),
        ("https://evil.example/o/r", "c" * 40),
        ("o", "c" * 40),
    ],
)
def test_only_a_full_commit_sha_of_an_owner_repo_is_accepted(tmp_path, repo, sha):
    bootstrap = load()

    def must_not_fetch(url):
        raise AssertionError("fetched")

    with pytest.raises(SystemExit):
        bootstrap.prepare(repo, sha, tmp_path / "hm", fetcher=must_not_fetch, pip=["false"])


def test_lock_file_in_the_repository_matches_the_lockfile():
    """api/requirements.lock.txt is generated from api/uv.lock; `make lint` regenerates and compares."""
    lock = (REPO / "api" / "requirements.lock.txt").read_text()
    assert "--hash=sha256:" in lock and "uv export --frozen" in lock
    pinned = [line for line in lock.splitlines() if line and not line.startswith((" ", "#"))]
    assert pinned and all("==" in line for line in pinned)


def test_compose_file_fits_the_hostinger_api_limit():
    """The Hostinger API takes the compose file as text of at most 8192 characters."""
    text = (REPO / "deploy" / "hostinger" / "docker-compose.yml").read_text()
    assert len(text) <= 8192, f"{len(text)} characters"
    # What that file relies on: no build step, and the bootstrap service.
    assert "build:" not in text and "bootstrap:" in text and "service_completed_successfully" in text
