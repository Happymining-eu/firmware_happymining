"""One indexing run.

Only one run at a time (the lock of `status`). The run is incremental:

- a file whose size and modification time are those recorded is not opened;
- otherwise it is copied to a private spool file while its SHA-256 is
  computed; if the hash is the one already indexed, nothing is embedded;
- otherwise it is parsed, cut into passages, embedded and stored, and the
  passages of its previous version are replaced;
- a file that fails is recorded as failed with a reason code and tried again
  at the next run; it does not stop the run;
- files that are no longer listed have their passages removed, unless the
  walk could not see where they were (source unavailable, directory
  unreadable): not seeing is not the same as gone.

A failure of the embedding service or of the vector store stops the run with
state `error`; what was recorded stays, and the next run resumes from there.

Nothing here logs a file name or document text at INFO or above.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import os
import shutil
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Protocol

from . import status as status_mod
from .chunker import Chunk
from .config import Config
from .embedder import EmbedderError, OllamaEmbedder
from .parsers import DefaultParser, ParseError, Parser
from .state import FileRecord, State, StateError
from .store import QdrantStore, StoreError
from .walker import FileEntry, NotRegularFile, SourceWalk, open_regular_file, open_source_root, walk_source

log = logging.getLogger(__name__)

SPOOL_DIR = "spool"
STATUS_EVERY_FILES = 20
STATUS_EVERY_SECONDS = 15.0
# After this many files in a row that the embedding service refused or
# garbled, the service is considered broken and the run stops.
MAX_CONSECUTIVE_EMBED_FAILURES = 3
_COPY_BLOCK = 1024 * 1024

# Reasons after which the passages of the previous version of a file are
# removed: the new content was read, and it cannot be indexed.
_CONTENT_FAILURES = frozenset({"parse_error", "parse_timeout", "no_text", "not_text", "too_many_chunks"})
# A file modified this recently may change again within the same timestamp:
# its modification time is not recorded, so the next run hashes it again.
_RECENT_NS = 5 * 1_000_000_000
_UNSTABLE_MTIME = -1


class SyncBusy(Exception):
    """Another run holds the lock."""


class RunAborted(Exception):
    """The run cannot continue. `code` goes into the status detail."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class Embedder(Protocol):
    def dimension(self) -> int: ...

    def embed(self, texts: list[str]) -> list[Any]: ...


@dataclass
class RunResult:
    status: dict[str, Any]
    processed: int = 0  # files parsed and embedded during this run
    unchanged: int = 0
    removed: int = 0


class _FileFailed(Exception):
    def __init__(self, code: str, *, sha256: str | None = None) -> None:
        self.code = code
        self.sha256 = sha256
        super().__init__(code)


def run_sync(
    cfg: Config,
    state_dir: Path,
    *,
    parser: Parser | None = None,
    embedder: Embedder | None = None,
    store: QdrantStore | None = None,
    lock_fd: int | None = None,
    should_stop: Callable[[], bool] = lambda: False,
) -> RunResult:
    """Run one sync. Raises SyncBusy when a run is already in progress.

    `lock_fd` is a descriptor that already holds the run lock (handed over by
    the server that started this process); without it the lock is taken here.
    """
    owned_lock = lock_fd is None
    if lock_fd is None:
        lock_fd = status_mod.try_lock(state_dir)
        if lock_fd is None:
            raise SyncBusy
    try:
        return _Run(cfg, state_dir, parser, embedder, store, should_stop).execute()
    finally:
        if owned_lock:
            status_mod.unlock(lock_fd)


class _Run:
    def __init__(
        self,
        cfg: Config,
        state_dir: Path,
        parser: Parser | None,
        embedder: Embedder | None,
        store: QdrantStore | None,
        should_stop: Callable[[], bool],
    ) -> None:
        self.cfg = cfg
        self.state_dir = state_dir
        self.parser = parser or DefaultParser(ocr=cfg.ocr, max_file_bytes=cfg.max_file_bytes)
        self.embedder = embedder or OllamaEmbedder(cfg.ollama_url, cfg.embedding_model)
        self.store = store or QdrantStore(cfg.qdrant_url, cfg.collection)
        self.should_stop = should_stop
        self.spool = state_dir / SPOOL_DIR
        self.started_at = status_mod.utc_now()
        self.previous = status_mod.load_status_file(state_dir)
        self.skipped = 0
        self.result = RunResult(status={})
        self._last_status_write = 0.0
        self._since_status_write = 0
        self._embed_failures_in_a_row = 0

    # -- status ---------------------------------------------------------------

    def _status(self, state: str, detail: str, counters: dict[str, int]) -> dict[str, Any]:
        return {
            "state": state,
            "last_run_at": self.started_at,
            "last_ok_at": self.previous["last_ok_at"],
            "files_indexed": counters["files_indexed"],
            "files_failed": counters["files_failed"],
            "files_skipped": self.skipped,
            "chunks": counters["chunks"],
            "detail": detail[: status_mod.DETAIL_MAX_CHARS],
        }

    def _progress(self, db: State, *, force: bool = False) -> None:
        self._since_status_write += 1
        now = time.monotonic()
        if (
            not force
            and self._since_status_write < STATUS_EVERY_FILES
            and now - self._last_status_write < STATUS_EVERY_SECONDS
        ):
            return
        status_mod.write_status(self.state_dir, self._status("running", "", db.counters()))
        self._last_status_write = now
        self._since_status_write = 0

    # -- the run --------------------------------------------------------------

    def execute(self) -> RunResult:
        log.info("sync started")
        previous_counters = {k: self.previous[k] for k in ("files_indexed", "files_failed", "chunks")}
        self.skipped = self.previous["files_skipped"]
        status_mod.write_status(self.state_dir, self._status("running", "", previous_counters))
        db: State | None = None
        try:
            db = State(self.state_dir)
            self._prepare_spool()
            detail = self._index(db)
            final = self._status("error" if detail.startswith("error:") else "idle", detail, db.counters())
            if final["state"] == "idle":
                final["last_ok_at"] = status_mod.utc_now()
        except RunAborted as exc:
            counters = db.counters() if db is not None else previous_counters
            final = self._status("error", f"error: {exc.code}", counters)
        except StateError:
            final = self._status("error", "error: state_unusable", previous_counters)
        except Exception as exc:
            # Whatever it is, the status must not stay at "running".
            log.error("sync failed: %s", exc.__class__.__name__)
            log.debug("sync failure", exc_info=True)
            counters = previous_counters
            if db is not None:
                with contextlib.suppress(Exception):
                    counters = db.counters()
            final = self._status("error", "error: internal", counters)
        finally:
            shutil.rmtree(self.spool, ignore_errors=True)
            if db is not None:
                with contextlib.suppress(Exception):
                    db.close()
        status_mod.write_status(self.state_dir, final)
        log.info(
            "sync finished: state=%s indexed=%d failed=%d skipped=%d chunks=%d processed=%d removed=%d",
            final["state"],
            final["files_indexed"],
            final["files_failed"],
            final["files_skipped"],
            final["chunks"],
            self.result.processed,
            self.result.removed,
        )
        self.result.status = final
        return self.result

    def _prepare_spool(self) -> None:
        shutil.rmtree(self.spool, ignore_errors=True)
        self.spool.mkdir(mode=0o700, parents=True, exist_ok=True)

    def _index(self, db: State) -> str:
        """Do the work; return the status detail ("error: ..." for a failed run)."""
        self._prepare_store(db)

        walks: dict[str, SourceWalk] = {}
        skipped: Counter[str] = Counter()
        for source in self.cfg.sources:
            walk = walk_source(self.cfg, source)
            walks[source.source_id] = walk
            skipped.update(walk.skipped)
            log.info(
                "source %s: available=%s candidates=%d skipped=%d unreadable_directories=%d",
                source.source_id,
                walk.available,
                len(walk.files),
                sum(walk.skipped.values()),
                len(walk.unknown_prefixes),
            )
        self.skipped = sum(skipped.values())
        db.meta_set("skipped_by_reason", _encode_counts(skipped))

        seen: set[tuple[str, str]] = set()
        for source in self.cfg.sources:
            walk = walks[source.source_id]
            if not walk.available:
                continue
            try:
                root_fd = open_source_root(source)
            except OSError:
                # It was there a moment ago. Its files are neither indexed nor removed.
                walk.available = False
                continue
            try:
                for entry in walk.files:
                    if self.should_stop():
                        raise RunAborted("interrupted")
                    seen.add((entry.source_id, entry.rel_path))
                    self._one_file(db, root_fd, entry)
                    self._progress(db)
            finally:
                os.close(root_fd)

        self._remove_missing(db, walks, seen)

        unavailable = sorted(s for s, walk in walks.items() if not walk.available)
        if unavailable:
            return f"error: source_unavailable ({len(unavailable)} of {len(walks)} sources)"
        parts = []
        failed = db.failed_by_code()
        if failed:
            parts.append("failed: " + " ".join(f"{code}={count}" for code, count in failed.items()))
        if skipped:
            parts.append("skipped: " + " ".join(f"{code}={count}" for code, count in sorted(skipped.items())))
        unreadable = sum(len(walk.unknown_prefixes) for walk in walks.values())
        if unreadable:
            parts.append(f"unreadable_directories={unreadable}")
        return "; ".join(parts)

    def _prepare_store(self, db: State) -> None:
        try:
            size = self.embedder.dimension()
        except EmbedderError as exc:
            raise RunAborted(exc.code) from None
        try:
            outcome = self.store.ensure(size)
            if (
                outcome == "existing"
                and db.file_count() > 0
                and db.meta_get("embedding_model") != self.cfg.embedding_model
            ):
                # Same vector size, another model: the stored vectors cannot be
                # compared with new ones.
                self.store.drop()
                self.store.create(size)
                outcome = "recreated"
            if outcome != "existing" and db.file_count() > 0:
                log.info("collection %s: the index is rebuilt from the start", outcome)
                db.clear_files()
            db.meta_set("embedding_model", self.cfg.embedding_model)
            if outcome == "existing":
                self.store.delete_foreign(db.index_id)
        except StoreError as exc:
            raise RunAborted(exc.code) from None

    # -- one file -------------------------------------------------------------

    def _one_file(self, db: State, root_fd: int, entry: FileEntry) -> None:
        record = db.get_file(entry.source_id, entry.rel_path)
        if (
            record is not None
            and record.status == "ok"
            and record.size == entry.size
            and record.mtime_ns == entry.mtime_ns
        ):
            self.result.unchanged += 1
            return
        try:
            outcome = self._process(db, root_fd, entry, record)
        except _FileFailed as failure:
            self._record_failure(db, entry, record, failure)
            return
        self._embed_failures_in_a_row = 0
        db.put_file(outcome)

    def _process(self, db: State, root_fd: int, entry: FileEntry, record: FileRecord | None) -> FileRecord:
        reason = self.parser.unsupported_reason(entry.ext)
        if reason is not None:
            raise _FileFailed(reason)

        spooled = self.spool / f"doc.{entry.ext}"
        try:
            sha256 = self._spool_file(root_fd, entry, spooled)
            if record is not None and record.sha256 == sha256:
                # Touched, renamed back, or a failed read last time: the indexed content is this one.
                self.result.unchanged += 1
                return replace(
                    record,
                    size=entry.size,
                    mtime_ns=_recorded_mtime(entry),
                    status="ok",
                    error_code="",
                    updated_at=status_mod.utc_now(),
                )
            try:
                chunks = self.parser.parse(spooled, entry.ext)
            except ParseError as exc:
                raise _FileFailed(exc.code, sha256=sha256) from None
            except Exception as exc:
                # A parser must not be able to stop the run.
                log.debug("parser raised %s", exc.__class__.__name__, exc_info=True)
                raise _FileFailed("parse_error", sha256=sha256) from None
            if not chunks:
                raise _FileFailed("no_text", sha256=sha256)
        finally:
            with contextlib.suppress(OSError):
                spooled.unlink()

        vectors = self._embed(chunks)
        try:
            self.store.upsert_file(
                index_id=db.index_id,
                source_id=entry.source_id,
                rel_path=entry.rel_path,
                sha256=sha256,
                chunks=chunks,
                vectors=vectors,
            )
        except StoreError as exc:
            raise RunAborted(exc.code) from None
        self.result.processed += 1
        return FileRecord(
            source_id=entry.source_id,
            rel_path=entry.rel_path,
            size=entry.size,
            mtime_ns=_recorded_mtime(entry),
            sha256=sha256,
            chunks=len(chunks),
            status="ok",
            error_code="",
            updated_at=status_mod.utc_now(),
        )

    def _spool_file(self, root_fd: int, entry: FileEntry, target: Path) -> str:
        """Copy the file to the spool and return its SHA-256.

        What is hashed is what is parsed: one read of the file, through a
        descriptor opened without following any link.
        """
        digest = hashlib.sha256()
        copied = 0
        try:
            fd = open_regular_file(root_fd, entry.rel_path)
        except NotRegularFile:
            raise _FileFailed("not_regular_file") from None
        except OSError:
            raise _FileFailed("read_error") from None
        with contextlib.ExitStack() as stack:
            source = stack.enter_context(os.fdopen(fd, "rb"))
            try:
                out = stack.enter_context(open(target, "wb"))
            except OSError:
                raise RunAborted("state_unwritable") from None
            while True:
                try:
                    block = source.read(_COPY_BLOCK)
                except OSError:
                    raise _FileFailed("read_error") from None
                if not block:
                    break
                copied += len(block)
                if copied > self.cfg.max_file_bytes:
                    raise _FileFailed("changed_during_read")
                digest.update(block)
                try:
                    out.write(block)
                except OSError:
                    raise RunAborted("state_unwritable") from None
            try:
                out.flush()
            except OSError:
                raise RunAborted("state_unwritable") from None
        if copied == 0:
            raise _FileFailed("changed_during_read")
        return digest.hexdigest()

    def _embed(self, chunks: list[Chunk]) -> list[Any]:
        try:
            vectors = self.embedder.embed([chunk.embed_text for chunk in chunks])
        except EmbedderError as exc:
            if exc.unavailable:
                raise RunAborted(exc.code) from None
            self._embed_failures_in_a_row += 1
            if self._embed_failures_in_a_row >= MAX_CONSECUTIVE_EMBED_FAILURES:
                raise RunAborted(exc.code) from None
            raise _FileFailed("embed_error") from None
        if len(vectors) != len(chunks):
            raise RunAborted("embedder_bad_response")
        return vectors

    def _record_failure(
        self, db: State, entry: FileEntry, record: FileRecord | None, failure: _FileFailed
    ) -> None:
        log.debug("file failed: %s", failure.code)
        keep_passages = record is not None and record.chunks > 0 and failure.code not in _CONTENT_FAILURES
        if record is not None and record.chunks > 0 and not keep_passages:
            try:
                self.store.delete_file(entry.source_id, entry.rel_path)
            except StoreError as exc:
                raise RunAborted(exc.code) from None
        db.put_file(
            FileRecord(
                source_id=entry.source_id,
                rel_path=entry.rel_path,
                size=entry.size,
                mtime_ns=_recorded_mtime(entry),
                sha256=record.sha256 if keep_passages and record is not None else None,
                chunks=record.chunks if keep_passages and record is not None else 0,
                status="failed",
                error_code=failure.code,
                updated_at=status_mod.utc_now(),
            )
        )

    # -- files that are gone --------------------------------------------------

    def _remove_missing(self, db: State, walks: dict[str, SourceWalk], seen: set[tuple[str, str]]) -> None:
        for record in list(db.iter_files()):
            key = (record.source_id, record.rel_path)
            if key in seen:
                continue
            walk = walks.get(record.source_id)
            if walk is not None and walk.is_unknown(record.rel_path):
                continue
            if self.should_stop():
                raise RunAborted("interrupted")
            if record.chunks > 0:
                try:
                    self.store.delete_file(record.source_id, record.rel_path)
                except StoreError as exc:
                    raise RunAborted(exc.code) from None
            db.delete_file(record.source_id, record.rel_path)
            self.result.removed += 1


def _encode_counts(counts: Counter[str]) -> str:
    return " ".join(f"{key}={value}" for key, value in sorted(counts.items()))


def decode_counts(text: str | None) -> dict[str, int]:
    out: dict[str, int] = {}
    for part in (text or "").split():
        key, _, value = part.partition("=")
        if key and value.isdigit():
            out[key] = int(value)
    return out


def _recorded_mtime(entry: FileEntry) -> int:
    if entry.mtime_ns > time.time_ns() - _RECENT_NS:
        return _UNSTABLE_MTIME
    return entry.mtime_ns
