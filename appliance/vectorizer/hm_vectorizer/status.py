"""status.json and the run lock, both under /state.

status.json holds exactly the eight fields of docs/appliance.md 6.1
(`vectorizer`): state, last_run_at, last_ok_at, files_indexed, files_failed,
files_skipped, chunks, detail. It never holds a file name or a piece of a
document; `detail` is made of reason codes and counts. It is replaced
atomically (written beside, then renamed).

The lock is an advisory `flock` on /state/sync.lock. It is held by whichever
process runs a sync and is released by the kernel when that process ends,
however it ends.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

STATUS_NAME = "status.json"
LOCK_NAME = "sync.lock"
DETAIL_MAX_CHARS = 500
STATES = ("idle", "running", "error")

_INT_FIELDS = ("files_indexed", "files_failed", "files_skipped", "chunks")
_STR_FIELDS = ("last_run_at", "last_ok_at", "detail")


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def empty_status() -> dict[str, Any]:
    """What is reported before the first run. Timestamps are "" until there is one."""
    return {
        "state": "idle",
        "last_run_at": "",
        "last_ok_at": "",
        "files_indexed": 0,
        "files_failed": 0,
        "files_skipped": 0,
        "chunks": 0,
        "detail": "",
    }


def _clean(data: Any) -> dict[str, Any]:
    """Keep only well-formed fields: the file is read back as untrusted input."""
    status = empty_status()
    if not isinstance(data, dict):
        return status
    if data.get("state") in STATES:
        status["state"] = data["state"]
    for key in _INT_FIELDS:
        value = data.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            status[key] = value
    for key in _STR_FIELDS:
        value = data.get(key)
        if isinstance(value, str):
            status[key] = value[:DETAIL_MAX_CHARS] if key == "detail" else value[:32]
    return status


def load_status_file(state_dir: Path) -> dict[str, Any]:
    try:
        raw = (state_dir / STATUS_NAME).read_bytes()
    except OSError:
        return empty_status()
    try:
        return _clean(json.loads(raw.decode("utf-8")))
    except (UnicodeDecodeError, ValueError):
        return empty_status()


def write_status(state_dir: Path, status: dict[str, Any]) -> None:
    payload = _clean(status)
    data = (json.dumps(payload, ensure_ascii=True, sort_keys=False) + "\n").encode("ascii")
    fd, tmp_name = tempfile.mkstemp(prefix=".status-", suffix=".tmp", dir=state_dir)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, state_dir / STATUS_NAME)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


def try_lock(state_dir: Path) -> int | None:
    """Take the run lock. Returns the descriptor that holds it, or None if busy."""
    fd = os.open(state_dir / LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd


def unlock(fd: int) -> None:
    with contextlib.suppress(OSError):
        fcntl.flock(fd, fcntl.LOCK_UN)
    with contextlib.suppress(OSError):
        os.close(fd)


def run_in_progress(state_dir: Path) -> bool:
    """True when some process holds the run lock.

    The probe asks for a shared lock, which a running sync refuses and which
    two probes do not refuse each other.
    """
    try:
        fd = os.open(state_dir / LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except OSError:
        return True
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


def read_status(state_dir: Path) -> dict[str, Any]:
    """The status as it should be reported now.

    `running` is decided by the lock, not by the file: a run that was killed
    leaves `running` in the file, and that is reported as an error.
    """
    status = load_status_file(state_dir)
    if run_in_progress(state_dir):
        status["state"] = "running"
    elif status["state"] == "running":
        status["state"] = "error"
        status["detail"] = "interrupted"
    return status


def repair_status(state_dir: Path) -> None:
    """Rewrite a status file left at `running` by a run that no longer exists."""
    on_disk = load_status_file(state_dir)
    if on_disk["state"] == "running" and not run_in_progress(state_dir):
        on_disk["state"] = "error"
        on_disk["detail"] = "interrupted"
        write_status(state_dir, on_disk)
