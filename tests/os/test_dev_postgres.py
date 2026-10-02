"""scripts/dev-postgres.sh must never delete the data of a server that is still running.

It used to treat "pg_isready does not answer" as "nothing runs here" and
delete the data directory. pg_isready also fails for reasons that say nothing
about the server (it cannot look up the current user, for one), so a live
server lost its files under it.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "dev-postgres.sh"


def _stub(bindir: Path, name: str, body: str) -> None:
    path = bindir / name
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(0o755)


@pytest.fixture
def fake_pg(tmp_path: Path):
    """PostgreSQL client and server tools that do nothing but log their arguments."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "calls.log"
    for tool in ("pg_ctl", "initdb", "createdb"):
        _stub(bindir, tool, f'echo "{tool} $*" >> "{log}"; exit 0')
    _stub(bindir, "docker", "exit 1")  # no Docker daemon
    state = tmp_path / "state"
    (state / "data").mkdir(parents=True)
    (state / "data" / "PG_VERSION").write_text("16\n")
    return bindir, state, log


def _run(bindir: Path, state: Path) -> subprocess.CompletedProcess:
    env = {
        **os.environ,
        "PATH": f"{bindir}:{os.environ.get('PATH', '/usr/bin:/bin')}",
        "HM_DEV_PG_DIR": str(state),
        "HM_DEV_PG_PORT": "54999",
    }
    return subprocess.run(
        ["bash", str(SCRIPT), "start"], env=env, capture_output=True, text=True, timeout=60
    )


def test_a_live_server_that_does_not_answer_keeps_its_data(fake_pg):
    bindir, state, log = fake_pg
    _stub(bindir, "pg_isready", "exit 3")  # "no attempt"
    # The postmaster is alive: this very test process stands in for it.
    (state / "data" / "postmaster.pid").write_text(f"{os.getpid()}\n{state / 'data'}\n")

    result = _run(bindir, state)

    assert result.returncode != 0
    assert "still runs" in result.stderr
    assert (state / "data" / "PG_VERSION").read_text() == "16\n", "the data directory was deleted"
    assert not log.exists() or "initdb" not in log.read_text()


def test_a_server_that_answers_is_reused(fake_pg):
    bindir, state, log = fake_pg
    _stub(bindir, "pg_isready", 'case "$*" in *"-U happymining"*) exit 0;; *) exit 3;; esac')
    (state / "data" / "postmaster.pid").write_text(f"{os.getpid()}\n")

    result = _run(bindir, state)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().endswith("@127.0.0.1:54999/happymining")
    assert (state / "data" / "PG_VERSION").exists()
    assert not log.exists() or "initdb" not in log.read_text()
