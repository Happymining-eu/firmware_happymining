"""What has been indexed, in a SQLite file under /state. Survives restarts.

One row per file that was indexed or that failed:

- `size`, `mtime_ns`: what the file looked like when the row was last decided;
- `sha256`: hash of the content whose passages are in the vector store, or
  NULL when the store holds nothing for this file;
- `chunks`: how many passages the store holds for this file;
- `status`: `ok` or `failed`; `error_code` says why it failed.

`index_id` identifies this database. Every point written to the vector store
carries it, so points written under another (lost) database can be removed.
"""

from __future__ import annotations

import contextlib
import logging
import os
import sqlite3
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

SCHEMA_VERSION = 1
DB_NAME = "state.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS files (
    source_id TEXT NOT NULL,
    rel_path TEXT NOT NULL,
    size INTEGER NOT NULL,
    mtime_ns INTEGER NOT NULL,
    sha256 TEXT,
    chunks INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL CHECK (status IN ('ok', 'failed')),
    error_code TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    PRIMARY KEY (source_id, rel_path)
);
"""


class StateError(Exception):
    """The state database cannot be used."""


@dataclass(frozen=True)
class FileRecord:
    source_id: str
    rel_path: str
    size: int
    mtime_ns: int
    sha256: str | None
    chunks: int
    status: str
    error_code: str
    updated_at: str


class State:
    def __init__(self, state_dir: Path) -> None:
        self.path = state_dir / DB_NAME
        self._db = self._open()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
        db.executescript(_SCHEMA)
        return db

    def _open(self) -> sqlite3.Connection:
        try:
            db = self._connect()
            version = self._read_meta(db, "schema_version")
        except sqlite3.OperationalError as exc:
            # Locked, read-only, disk full: not a reason to discard anything.
            raise StateError("state database cannot be opened") from exc
        except sqlite3.DatabaseError:
            # A damaged file. Its content is derived data: set it aside and start again;
            # the new index_id makes the next run remove what the old one had stored.
            log.warning("state database unreadable: starting a new one")
            self._set_aside()
            try:
                db = self._connect()
            except sqlite3.DatabaseError as exc:
                raise StateError("state database cannot be created") from exc
            version = None
        if version is None:
            db.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            db.execute("INSERT OR IGNORE INTO meta (key, value) VALUES ('index_id', ?)", (str(uuid.uuid4()),))
        elif version != str(SCHEMA_VERSION):
            db.close()
            raise StateError("state database was written by another version")
        return db

    def _set_aside(self) -> None:
        for suffix in ("", "-wal", "-shm"):
            source = Path(str(self.path) + suffix)
            with contextlib.suppress(OSError):
                os.replace(source, Path(str(self.path) + ".corrupt" + suffix))

    @staticmethod
    def _read_meta(db: sqlite3.Connection, key: str) -> str | None:
        row = db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return None if row is None else row[0]

    def close(self) -> None:
        self._db.close()

    # -- meta ---------------------------------------------------------------

    @property
    def index_id(self) -> str:
        value = self.meta_get("index_id")
        if value is None:
            raise StateError("state database has no index id")
        return value

    def meta_get(self, key: str) -> str | None:
        return self._read_meta(self._db, key)

    def meta_set(self, key: str, value: str) -> None:
        self._db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))

    # -- files --------------------------------------------------------------

    @staticmethod
    def _record(row: tuple) -> FileRecord:
        return FileRecord(*row)

    def get_file(self, source_id: str, rel_path: str) -> FileRecord | None:
        row = self._db.execute(
            "SELECT source_id, rel_path, size, mtime_ns, sha256, chunks, status, error_code, updated_at "
            "FROM files WHERE source_id = ? AND rel_path = ?",
            (source_id, rel_path),
        ).fetchone()
        return None if row is None else self._record(row)

    def put_file(self, record: FileRecord) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO files "
            "(source_id, rel_path, size, mtime_ns, sha256, chunks, status, error_code, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record.source_id,
                record.rel_path,
                record.size,
                record.mtime_ns,
                record.sha256,
                record.chunks,
                record.status,
                record.error_code,
                record.updated_at,
            ),
        )

    def delete_file(self, source_id: str, rel_path: str) -> None:
        self._db.execute("DELETE FROM files WHERE source_id = ? AND rel_path = ?", (source_id, rel_path))

    def iter_files(self) -> Iterator[FileRecord]:
        cursor = self._db.execute(
            "SELECT source_id, rel_path, size, mtime_ns, sha256, chunks, status, error_code, updated_at "
            "FROM files ORDER BY source_id, rel_path"
        )
        for row in cursor:
            yield self._record(row)

    def clear_files(self) -> None:
        self._db.execute("DELETE FROM files")

    def file_count(self) -> int:
        return self._db.execute("SELECT COUNT(*) FROM files").fetchone()[0]

    def counters(self) -> dict[str, int]:
        indexed, failed, chunks = self._db.execute(
            "SELECT COALESCE(SUM(status = 'ok'), 0), COALESCE(SUM(status = 'failed'), 0), "
            "COALESCE(SUM(chunks), 0) FROM files"
        ).fetchone()
        return {"files_indexed": int(indexed), "files_failed": int(failed), "chunks": int(chunks)}

    def failed_by_code(self) -> dict[str, int]:
        return _failed_by_code(self._db)


def _failed_by_code(db: sqlite3.Connection) -> dict[str, int]:
    rows = db.execute(
        "SELECT error_code, COUNT(*) FROM files WHERE status = 'failed' "
        "GROUP BY error_code ORDER BY error_code"
    ).fetchall()
    return {code: int(count) for code, count in rows}


def read_summary(state_dir: Path) -> tuple[dict[str, int], str | None]:
    """(failed files by reason, the stored skip counts) without writing anything.

    Used by the server while a run may be writing: the database is opened
    read-only and nothing is created or repaired. Returns empty values when
    there is no usable database.
    """
    path = state_dir / DB_NAME
    if not path.exists():
        return {}, None
    try:
        db = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2.0)
    except sqlite3.Error:
        return {}, None
    try:
        skipped = db.execute("SELECT value FROM meta WHERE key = 'skipped_by_reason'").fetchone()
        return _failed_by_code(db), None if skipped is None else skipped[0]
    except sqlite3.Error:
        return {}, None
    finally:
        db.close()
