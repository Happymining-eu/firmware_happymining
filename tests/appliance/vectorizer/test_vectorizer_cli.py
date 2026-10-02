"""The command line and the real processes: serve, sync, status, healthcheck,
and two sync requests of which one runs."""

from __future__ import annotations

import http.client
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from hm_vectorizer import server as server_mod
from hm_vectorizer import status as status_mod
from hm_vectorizer.config import take_api_key
from hm_vectorizer.server import SyncLauncher
from vz_fakes import FakeOllama, FakeQdrant
from vz_support import API_KEY, TOKEN, VECTORIZER_DIR, Site

COLLECTION = "happymining_docs"


def cli_env(**extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k != "HM_ANSWER_API_KEY"}
    env["PYTHONPATH"] = str(VECTORIZER_DIR)
    env.update(extra)
    return env


def cli(
    site: Site, command: str, *args: str, timeout: float = 60, **env: str
) -> subprocess.CompletedProcess[str]:
    argv = [sys.executable, "-m", "hm_vectorizer", command]
    if command != "healthcheck":
        argv += ["--state-dir", str(site.state_dir)]
    if command in ("serve", "sync"):
        argv += ["--config-dir", str(site.config_dir), "--nas-root", str(site.nas_root)]
    return subprocess.run(
        [*argv, *args], env=cli_env(**env), capture_output=True, text=True, timeout=timeout, check=False
    )


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def get(port: int, path: str, *, token: str | None = TOKEN, method: str = "GET") -> tuple[int, Any]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
    try:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        if method == "POST":
            headers["Content-Length"] = "0"
        connection.request(method, path, headers=headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read().decode("utf-8"))
    finally:
        connection.close()


def wait_for(predicate: Any, *, timeout: float = 30, what: str = "condition") -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for {what}")


@pytest.fixture
def three_files(site: Site) -> Site:
    site.write("handbook.md", "# Handbook\n\nThe pump reference is HM-PUMP-7731.")
    site.write("contracts/lease.txt", "The lease of the warehouse ends in March.")
    site.write("contracts/2026/invoice.txt", "Invoice 42 is payable within thirty days.")
    return site


@pytest.fixture
def served(three_files: Site) -> Iterator[tuple[Site, int, subprocess.Popen[str]]]:
    """`python -m hm_vectorizer serve` as a real process."""
    port = free_port()
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "hm_vectorizer",
            "serve",
            "--config-dir",
            str(three_files.config_dir),
            "--state-dir",
            str(three_files.state_dir),
            "--nas-root",
            str(three_files.nas_root),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        env=cli_env(HM_ANSWER_API_KEY=API_KEY),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        wait_for(lambda: _answers(port) or process.poll() is not None, what="the server to listen")
        assert process.poll() is None, process.stderr.read() if process.stderr else ""
        yield three_files, port, process
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()


def _answers(port: int) -> bool:
    try:
        return get(port, "/healthz", token=None)[0] == 200
    except OSError:
        return False


# -- sync and status commands -------------------------------------------------------


def test_sync_command_indexes_and_status_command_prints_the_status(
    three_files: Site, qdrant: FakeQdrant
) -> None:
    before = cli(three_files, "status")
    assert before.returncode == 0 and json.loads(before.stdout)["state"] == "idle"
    assert json.loads(before.stdout)["last_run_at"] == ""

    done = cli(three_files, "sync")
    assert done.returncode == 0, done.stderr
    assert len(qdrant.payloads(COLLECTION)) == 3
    assert "sync finished: state=idle indexed=3" in done.stderr
    for forbidden in ("handbook", "lease", "invoice", "HM-PUMP", str(three_files.nas_root)):
        assert forbidden not in done.stderr and forbidden not in done.stdout

    after = cli(three_files, "status")
    status = json.loads(after.stdout)
    assert (status["state"], status["files_indexed"], status["chunks"]) == ("idle", 3, 3)
    assert status == json.loads((three_files.state_dir / "status.json").read_text())


def test_sync_command_exit_codes(three_files: Site, ollama: FakeOllama) -> None:
    fd = status_mod.try_lock(three_files.state_dir)
    assert fd is not None
    try:
        busy = cli(three_files, "sync")
        assert busy.returncode == 3 and "already running" in busy.stderr
    finally:
        status_mod.unlock(fd)

    three_files.save(embedding_model="not-pulled")
    failed = cli(three_files, "sync")
    assert failed.returncode == 1
    assert json.loads(cli(three_files, "status").stdout)["detail"] == "error: embedder_model_missing"


def test_sync_command_when_the_status_file_cannot_be_written(three_files: Site, qdrant: FakeQdrant) -> None:
    # A directory where status.json should be: refused even to root.
    (three_files.state_dir / "status.json").mkdir()
    (three_files.state_dir / "status.json" / "x").write_text("x")
    result = cli(three_files, "sync")
    assert result.returncode == 2
    assert "state directory not writable (IsADirectoryError)" in result.stderr
    assert "Traceback" not in result.stderr
    assert qdrant.requests == [], "nothing was indexed"


def test_commands_refuse_an_invalid_configuration(three_files: Site) -> None:
    three_files.document["max_file_mib"] = 0
    (three_files.config_dir / "vectorizer.json").write_text(json.dumps(three_files.document))
    for command in ("sync", "serve"):
        result = cli(three_files, command, timeout=30)
        assert result.returncode == 2
        assert "configuration refused: vectorizer.json: max_file_mib" in result.stderr
    assert not (three_files.state_dir / "status.json").exists(), "nothing ran"


def test_serve_refuses_a_missing_or_weak_token(three_files: Site) -> None:
    (three_files.config_dir / "token").write_text("weak\n")
    result = cli(three_files, "serve", "--host", "127.0.0.1", "--port", str(free_port()), timeout=30)
    assert result.returncode == 2 and "token refused" in result.stderr
    assert "weak" not in result.stderr
    (three_files.config_dir / "token").unlink()
    result = cli(three_files, "serve", "--host", "127.0.0.1", "--port", str(free_port()), timeout=30)
    assert result.returncode == 2 and "token refused" in result.stderr


def test_serve_refuses_a_missing_state_directory(three_files: Site, tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "hm_vectorizer",
            "serve",
            "--config-dir",
            str(three_files.config_dir),
            "--state-dir",
            str(tmp_path / "absent"),
            "--nas-root",
            str(three_files.nas_root),
            "--port",
            str(free_port()),
        ],
        env=cli_env(),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 2 and "state directory" in result.stderr


def test_healthcheck_fails_when_nothing_listens(three_files: Site) -> None:
    assert cli(three_files, "healthcheck", "--port", str(free_port()), timeout=30).returncode == 1


# -- the real server process -----------------------------------------------------------


def test_served_process_answers_and_two_sync_requests_run_one(
    served: tuple[Site, int, subprocess.Popen[str]], ollama: FakeOllama, qdrant: FakeQdrant
) -> None:
    site, port, process = served
    assert cli(site, "healthcheck", "--port", str(port), timeout=30).returncode == 0
    assert get(port, "/v1/status", token=None)[0] == 401
    assert get(port, "/v1/status")[1]["state"] == "idle"

    ollama.gate = threading.Event()  # hold the run at its first embedding request
    try:
        assert get(port, "/v1/sync", method="POST") == (202, {"started": True})
        assert ollama.gate_entered.wait(timeout=30), "the run reached the embedding service"
        assert get(port, "/v1/sync", method="POST") == (409, {"error": "sync_running"})
        assert get(port, "/v1/sync", method="POST") == (409, {"error": "sync_running"})
        assert get(port, "/v1/status")[1]["state"] == "running"
        assert json.loads((site.state_dir / "status.json").read_text())["state"] == "running"
        by_hand = cli(site, "sync")
        assert by_hand.returncode == 3, "a sync started by hand is refused as well"
    finally:
        ollama.gate.set()
    wait_for(lambda: get(port, "/v1/status")[1]["state"] != "running", what="the run to finish")

    status = get(port, "/v1/status")[1]
    assert (status["state"], status["files_indexed"], status["chunks"]) == ("idle", 3, 3)
    assert len(ollama.embedded_texts()) == 3, "one run embedded the three files once"
    assert len(qdrant.payloads(COLLECTION)) == 3

    ollama.gate = None
    assert get(port, "/v1/sync", method="POST") == (202, {"started": True}), "a new run can start afterwards"
    wait_for(lambda: get(port, "/v1/status")[1]["state"] != "running", what="the second run to finish")
    assert len(ollama.embedded_texts()) == 3, "nothing changed: nothing embedded again"

    process.send_signal(signal.SIGTERM)
    assert process.wait(timeout=20) == 0
    stderr = process.stderr.read() if process.stderr else ""
    assert "serving on port" in stderr and "stopped" in stderr
    assert API_KEY not in stderr and TOKEN not in stderr
    for forbidden in ("handbook", "lease", "invoice", "HM-PUMP"):
        assert forbidden not in stderr


def test_sync_killed_by_force_is_reported_as_interrupted(
    served: tuple[Site, int, subprocess.Popen[str]], ollama: FakeOllama
) -> None:
    site, port, _ = served
    ollama.gate = threading.Event()
    try:
        assert get(port, "/v1/sync", method="POST")[0] == 202
        assert ollama.gate_entered.wait(timeout=30)
        children = subprocess.run(
            ["pgrep", "-f", f"hm_vectorizer sync --config-dir {site.config_dir}"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.split()
        assert len(children) == 1, "exactly one sync process"
        os.kill(int(children[0]), signal.SIGKILL)
        wait_for(
            lambda: json.loads((site.state_dir / "status.json").read_text())["state"] == "error",
            what="the status file to be repaired",
        )
    finally:
        ollama.gate.set()
    status = get(port, "/v1/status")[1]
    assert (status["state"], status["detail"]) == ("error", "interrupted")
    ollama.gate = None
    assert get(port, "/v1/sync", method="POST")[0] == 202, "the lock died with the process"
    wait_for(lambda: get(port, "/v1/status")[1]["state"] == "idle", what="the next run to finish")
    assert get(port, "/v1/status")[1]["files_indexed"] == 3


# -- what the sync process inherits ----------------------------------------------------------


def test_sync_process_gets_no_api_key_and_no_shell(site: Site, monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class FakeChild:
        def poll(self) -> int | None:
            return 0

        def wait(self, timeout: float | None = None) -> int:
            return 0

    def fake_popen(argv: list[str], **kwargs: Any) -> FakeChild:
        captured["argv"] = argv
        captured.update(kwargs)
        captured["lock_held"] = status_mod.run_in_progress(site.state_dir)
        return FakeChild()

    monkeypatch.setenv("HM_ANSWER_API_KEY", API_KEY)
    key = take_api_key(os.environ)  # what `serve` does first
    assert key is not None and key.reveal() == API_KEY
    monkeypatch.setattr(server_mod.subprocess, "Popen", fake_popen)
    launcher = SyncLauncher(config_dir=site.config_dir, state_dir=site.state_dir, nas_root=str(site.nas_root))
    assert launcher.start() is True

    assert "HM_ANSWER_API_KEY" not in captured["env"]
    assert API_KEY not in json.dumps(captured["env"]) and API_KEY not in json.dumps(captured["argv"])
    assert captured.get("shell") in (None, False)
    argv = captured["argv"]
    assert argv[:4] == [sys.executable, "-m", "hm_vectorizer", "sync"]
    lock_fd = int(argv[argv.index("--lock-fd") + 1])
    assert captured["pass_fds"] == (lock_fd,)
    assert captured["lock_held"], "the lock is taken before the process is started"
    assert str(VECTORIZER_DIR) in captured["env"]["PYTHONPATH"].split(os.pathsep)
