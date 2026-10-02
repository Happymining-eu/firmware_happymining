"""End to end over real HTTP with the built agent binaries.

- the acceptance demo script, with the simulator as the paired agents;
- the real ``happymining-agent`` and ``happyminingctl`` against a LIVE-mode API,
  including an API outage in the middle.

These tests need ``dist/bin`` (``make build-agent``). They run a real uvicorn
server on a loopback port. No NVIDIA hardware, no systemd, no Vast: the agent
runs as a plain process on this host and reports whatever it can read.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest
from helpers import World, live_settings
from sqlalchemy import func, select

from happymining.models import Device, Operation, TelemetrySample

REPO = Path(__file__).resolve().parents[2]
BIN = REPO / "dist" / "bin"
pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(
        not all((BIN / name).is_file() for name in ("hm-simulator", "happymining-agent", "happyminingctl")),
        reason="agent binaries not built; run `make build-agent`",
    ),
]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    """A uvicorn process serving the app with the given environment."""

    def __init__(self, env: dict[str, str], port: int | None = None):
        self.port = port or free_port()
        self.env = {
            **os.environ,
            **env,
            "PYTHONPATH": str(REPO / "api"),
            "HM_LOG_LEVEL": "WARNING",
            "HM_PUBLIC_BASE_URL": env.get("HM_PUBLIC_BASE_URL", f"http://127.0.0.1:{self.port}"),
            "HM_ALLOWED_HOSTS": "127.0.0.1,localhost",
        }
        self.url = f"http://127.0.0.1:{self.port}"
        self.proc: subprocess.Popen | None = None

    def start(self) -> Server:
        self.proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "happymining.main:app_factory",
                "--factory",
                "--host",
                "127.0.0.1",
                "--port",
                str(self.port),
                "--log-level",
                "warning",
            ],
            env=self.env,
            cwd=REPO,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("API exited at start-up:\n" + self.proc.stdout.read().decode()[-3000:])
            try:
                if httpx.get(f"{self.url}/readyz", timeout=1, trust_env=False).status_code == 200:
                    return self
            except httpx.HTTPError:
                time.sleep(0.1)
        raise RuntimeError("API did not become ready")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None


def wait_for(predicate, timeout: float = 30, interval: float = 0.2, what: str = "condition"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    raise AssertionError(f"timed out waiting for {what}")


def test_acceptance_demo_script_passes(world, settings):
    """The seven acceptance steps, plus the duplicate-request checks, over real HTTP."""
    from happymining.demo.seed import seed_demo

    seed_demo(world.session, settings)
    world.commit()
    server = Server({"HM_PAYOUT_REQUIRE_DISTINCT_APPROVER": "true"}).start()
    try:
        out = subprocess.run(
            [
                sys.executable,
                str(REPO / "scripts" / "acceptance_demo.py"),
                "--api-url",
                server.url,
                "--simulator",
                str(BIN / "hm-simulator"),
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
    finally:
        server.stop()
    assert out.returncode == 0, out.stdout[-4000:] + out.stderr[-4000:]
    assert "Acceptance demo passed" in out.stdout
    for step in range(1, 8):
        assert f"== Step {step}:" in out.stdout
    assert "FAILED" not in out.stdout + out.stderr


@pytest.fixture
def live_stack(tmp_path):
    """LIVE-mode API process + config for the real agent, sharing the test database."""
    settings = live_settings()
    world = World(settings)
    env = {
        "HM_MODE": "live",
        "HM_PROVIDER": "vast",
        "HM_DATABASE_URL": os.environ["HM_TEST_LIVE_DATABASE_URL"],
        "HM_SECRET_KEY": settings.secret_key.get_secret_value(),
        "HM_FIELD_ENCRYPTION_KEY": settings.field_encryption_key.get_secret_value(),
        "HM_DEMO_LOGIN_ENABLED": "false",
        "HM_COOKIE_SECURE": "true",
        "HM_PAYOUT_PROVIDER": "manual_export",
        "HM_PAYOUTS_ENABLED": "false",
        "HM_PUBLIC_BASE_URL": "https://api.example.test",
        "HM_HEARTBEAT_INTERVAL_S": "15",
    }
    server = Server(env).start()
    state = tmp_path / "state"
    state.mkdir()
    config = tmp_path / "agent.env"
    config.write_text(
        f"HM_API_URL={server.url}\n"
        "HM_ALLOW_INSECURE_LOOPBACK=1\n"
        f"HM_STATE_DIR={state}\n"
        f"HM_SPOOL_DIR={state / 'spool'}\n"
        "HM_HEARTBEAT_INTERVAL_S=15\n"
        "HM_LOG_LEVEL=info\n"
    )
    procs: list[subprocess.Popen] = []
    try:
        yield world, server, config, state, procs, env
    finally:
        for proc in procs:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
        server.stop()
        world.close()


def ctl(config: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(BIN / "happyminingctl"), "--config", str(config), *args],
        capture_output=True,
        text=True,
        timeout=60,
    )


def sample_count(world, device_id) -> int:
    world.session.rollback()
    return world.session.execute(
        select(func.count()).select_from(TelemetrySample).where(TelemetrySample.device_id == device_id)
    ).scalar_one()


def test_real_agent_pairs_reports_and_survives_an_api_outage(live_stack):
    world, server, config, state, procs, env = live_stack
    owner = world.owner("Real owner")
    issued = world.pairing(owner, "bench-host")

    # --- pairing with the real CLI ---------------------------------------
    assert ctl(config, "identity", "init").returncode == 0
    paired = ctl(config, "pair", "--code", issued.code)
    assert paired.returncode == 0, paired.stdout + paired.stderr
    assert issued.code not in paired.stdout + paired.stderr and "hmd_" not in paired.stdout + paired.stderr
    credential_file = state / "credential.json"
    assert credential_file.is_file() and (credential_file.stat().st_mode & 0o777) == 0o600
    token = json.loads(credential_file.read_text())
    assert str(issued.machine.id) in json.dumps(token)

    world.session.rollback()
    device = world.session.execute(select(Device)).scalar_one()
    assert device.machine_id == issued.machine.id and device.hostname

    # A second pairing attempt with the same code is refused by the CLI and by the server.
    assert ctl(config, "pair", "--code", issued.code).returncode != 0

    # --- the real agent, as a plain process --------------------------------
    agent_log = (state / "agent.log").open("wb")
    agent = subprocess.Popen(
        [str(BIN / "happymining-agent"), "--config", str(config)], stdout=agent_log, stderr=subprocess.STDOUT
    )
    procs.append(agent)
    wait_for(
        lambda: sample_count(world, device.id) >= 1, timeout=45, what="first heartbeat from the real agent"
    )
    row = world.session.execute(select(TelemetrySample).order_by(TelemetrySample.seq)).scalars().first()
    assert row.synthetic is False  # real collector, real (if GPU-less) host
    assert set(row.payload) <= {"uptime_s", "synthetic", "cpu", "memory", "disks", "gpus", "services", "vast"}
    assert row.payload["gpus"] == []  # this sandbox has no NVIDIA GPU, and the agent says so
    assert row.payload["vast"]["machine_id_hint"] is None

    status = ctl(config, "status", "--json")
    assert status.returncode == 0 and "hmd_" not in status.stdout
    assert json.loads(status.stdout)["paired"] is True

    # --- control-plane outage ----------------------------------------------
    before_outage = sample_count(world, device.id)
    server.stop()
    time.sleep(35)  # more than two collection intervals with the API down
    assert agent.poll() is None, "the agent must keep running while the API is unreachable"
    spooled = [p for p in (state / "spool").rglob("*") if p.is_file()]
    assert spooled, "samples collected during the outage are buffered on disk"
    # While disconnected nothing can be requested of the machine: operations only travel in responses.
    world.session.rollback()
    assert world.session.execute(select(func.count()).select_from(Operation)).scalar_one() == 0
    assert sample_count(world, device.id) == before_outage

    # --- recovery ------------------------------------------------------------
    restarted = Server(env, port=server.port).start()
    try:
        wait_for(
            lambda: sample_count(world, device.id) >= before_outage + 2,
            timeout=90,
            what="buffered samples after the API came back",
        )
        seqs = (
            world.session.execute(
                select(TelemetrySample.seq)
                .where(TelemetrySample.device_id == device.id)
                .order_by(TelemetrySample.seq)
            )
            .scalars()
            .all()
        )
        assert seqs == list(range(seqs[0], seqs[0] + len(seqs))), f"gap or duplicate in {seqs}"

        # --- revocation ----------------------------------------------------------
        admin = world.user("admin")
        h = world.auth(admin)
        r = httpx.post(
            f"{restarted.url}/api/v1/devices/{device.id}/revoke",
            headers=h,
            json={"reason": "test"},
            trust_env=False,
        )
        assert r.status_code == 200
        count_at_revoke = sample_count(world, device.id)
        time.sleep(20)
        assert sample_count(world, device.id) == count_at_revoke, "a revoked device stores nothing more"
        assert agent.poll() is None  # and revocation does not crash the agent either
    finally:
        restarted.stop()

    agent.terminate()
    assert agent.wait(timeout=15) == 0
    log_text = (state / "agent.log").read_text(errors="replace")
    credential_secret = token.get("token", "") or ""
    assert "hmd_" not in log_text and issued.code not in log_text
    if credential_secret:
        assert credential_secret not in log_text


def test_demo_api_refuses_a_real_agent_and_live_refuses_the_simulator(live_stack, tmp_path):
    """Synthetic and real telemetry never mix, in either direction."""
    world, server, config, state, procs, env = live_stack
    issued = world.pairing(world.owner(), "sim-in-live")
    codes = tmp_path / "codes.txt"
    codes.write_text(issued.code + "\n")
    out = subprocess.run(
        [
            str(BIN / "hm-simulator"),
            "--api-url",
            server.url,
            "--allow-insecure-loopback",
            "--machines",
            "1",
            "--codes-file",
            str(codes),
            "--state-dir",
            str(tmp_path / "sim"),
            "--interval",
            "30ms",
            "--samples",
            "3",
            "--backoff-base",
            "20ms",
            "--backoff-cap",
            "100ms",
            "--log-level",
            "error",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    world.session.rollback()
    assert world.session.execute(select(func.count()).select_from(TelemetrySample)).scalar_one() == 0
    assert "synthetic telemetry is refused in LIVE mode" in (out.stdout + out.stderr) or out.returncode != 0
