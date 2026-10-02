"""Fixtures for the HappyMining OS installer tests.

Everything works on temporary directories and fake paths. No test partitions,
formats or mounts anything. Helpers live in hm_os_testlib.py.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from hm_os_testlib import (
    GpgKey,
    build_stub_deb,
    load_versions,
    make_ed25519_pubkey_line,
    make_fake_root,
    make_key,
    write_sums,
)


@pytest.fixture(scope="session")
def versions() -> dict[str, str]:
    return load_versions()


@pytest.fixture(scope="session")
def gpg_base():
    """Short-named temp dir: gpg-agent sockets need a short home path."""
    if shutil.which("gpg") is None or shutil.which("gpgv") is None:
        pytest.skip("gpg/gpgv not available")
    # Deliberately /tmp and not $TMPDIR: gpg-agent's socket lives inside the
    # GnuPG home and UNIX socket paths are limited to about 107 bytes.
    base = Path(tempfile.mkdtemp(prefix="hmk", dir="/tmp"))
    yield base
    for home in base.iterdir():
        if home.is_dir():
            subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "all"], capture_output=True)
    shutil.rmtree(base, ignore_errors=True)


@pytest.fixture(scope="session")
def release_key(gpg_base) -> GpgKey:
    """The throwaway key that plays the HappyMining release signer."""
    return make_key(gpg_base, "release")


@pytest.fixture(scope="session")
def other_key(gpg_base) -> GpgKey:
    """A second throwaway key that the tests do NOT trust."""
    return make_key(gpg_base, "other")


@pytest.fixture()
def release_dir(tmp_path, release_key) -> Path:
    """A signed release directory with a stub agent package."""
    directory = tmp_path / "release"
    directory.mkdir()
    build_stub_deb(directory)
    write_sums(directory, release_key)
    return directory


@pytest.fixture()
def stub_deb(release_dir) -> Path:
    return release_dir / "happymining-agent_0.1.0_amd64.deb"


@pytest.fixture()
def fake_root(tmp_path) -> Path:
    return make_fake_root(tmp_path)


@pytest.fixture()
def pubkey_file(tmp_path) -> Path:
    path = tmp_path / "operator_key.pub"
    path.write_text(make_ed25519_pubkey_line() + "\n")
    return path
