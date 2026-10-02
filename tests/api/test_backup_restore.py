"""The backup and restore procedure, run for real against PostgreSQL."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from test_payouts import funded, prepare

from happymining.config import get_settings
from happymining.services import payouts

REPO = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.skipif(
    not all(shutil.which(tool) for tool in ("pg_dump", "pg_restore", "psql")),
    reason="PostgreSQL client tools (pg_dump, pg_restore, psql) are not installed",
)


def run(script: str, *args: str, env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(REPO / "scripts" / script), *args], capture_output=True, text=True, env=env, timeout=180
    )


def test_backup_then_restore_into_scratch_database_and_verify(world, tmp_path):
    from helpers import SYSTEM

    # Some real state: earnings, a receipt, an approved payout, audit rows.
    owner, account, admin = funded(world)
    batch, _ = prepare(world, admin)
    payouts.approve_batch(world.session, world.settings, SYSTEM, batch.id, approver_id=admin.id)
    world.commit()

    url = make_url(get_settings().database_url)
    env = {
        **os.environ,
        "PGPASSWORD": url.password or "",
        "HM_PYTHON": os.environ.get("HM_PYTHON", "") or str(REPO / "api" / ".venv" / "bin" / "python"),
    }
    common = ["--host", url.host, "--port", str(url.port), "--user", url.username]

    backup = run("backup.sh", *common, "--database", url.database, "--out-dir", str(tmp_path), env=env)
    assert backup.returncode == 0, backup.stderr
    dump = Path(backup.stdout.strip().splitlines()[-1])
    assert dump.is_file() and dump.stat().st_size > 1000
    assert (dump.stat().st_mode & 0o077) == 0  # not readable by group or others
    assert Path(str(dump) + ".sha256").is_file()

    restore = run(
        "restore-verify.sh",
        "--dump",
        str(dump),
        *common,
        "--scratch-db",
        "hm_restore_check",
        "--keep",
        env=env,
    )
    try:
        assert restore.returncode == 0, restore.stdout + restore.stderr
        assert "checksum ok" in restore.stdout and "restore verified" in restore.stdout
        assert '"ok": true' in restore.stdout  # ledger and audit chain recomputed from the restored data
        assert "schema revision: 0001" in restore.stdout

        # The restored copy still enforces the ledger rules: triggers came with it.
        scratch = create_engine(url.set(database="hm_restore_check"))
        with scratch.connect() as conn:
            assert conn.execute(text("SELECT count(*) FROM journal_entries")).scalar_one() >= 3
            with pytest.raises(Exception, match="append-only"):
                conn.execute(text("DELETE FROM journal_lines"))
        scratch.dispose()
    finally:
        admin_engine = create_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT")
        with admin_engine.connect() as conn:
            conn.execute(text("DROP DATABASE IF EXISTS hm_restore_check WITH (FORCE)"))
        admin_engine.dispose()


def test_restore_refuses_a_tampered_dump_and_the_production_name(world, tmp_path):
    url = make_url(get_settings().database_url)
    env = {**os.environ, "PGPASSWORD": url.password or ""}
    common = ["--host", url.host, "--port", str(url.port), "--user", url.username]
    backup = run("backup.sh", *common, "--database", url.database, "--out-dir", str(tmp_path), env=env)
    dump = Path(backup.stdout.strip().splitlines()[-1])
    with dump.open("ab") as fh:
        fh.write(b"tampered")
    tampered = run(
        "restore-verify.sh", "--dump", str(dump), *common, "--scratch-db", "hm_restore_bad", env=env
    )
    assert tampered.returncode != 0 and "restore verified" not in tampered.stdout

    refused = run("restore-verify.sh", "--dump", str(dump), *common, "--scratch-db", "happymining", env=env)
    assert refused.returncode == 2 and "refusing" in refused.stderr
