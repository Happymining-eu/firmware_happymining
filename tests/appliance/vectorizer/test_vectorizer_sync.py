"""The indexing run: incremental, resumable, and careful about what it removes."""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Any

import pytest
from hm_vectorizer import status as status_mod
from hm_vectorizer import walker
from hm_vectorizer.chunker import Chunk
from hm_vectorizer.parsers import DefaultParser
from hm_vectorizer.state import State
from hm_vectorizer.store import file_id, point_id
from hm_vectorizer.sync import SyncBusy, run_sync
from vz_fakes import FakeOllama, FakeQdrant
from vz_support import Site

COLLECTION = "happymining_docs"
STATUS_KEYS = [
    "state",
    "last_run_at",
    "last_ok_at",
    "files_indexed",
    "files_failed",
    "files_skipped",
    "chunks",
    "detail",
]


def sync(site: Site, **kwargs: Any):  # type: ignore[no-untyped-def]
    return run_sync(site.load(), site.state_dir, **kwargs)


def status_file(site: Site) -> dict[str, Any]:
    return json.loads((site.state_dir / "status.json").read_text(encoding="utf-8"))


def records(site: Site) -> dict[str, Any]:
    db = State(site.state_dir)
    try:
        return {f"{r.source_id}/{r.rel_path}": r for r in db.iter_files()}
    finally:
        db.close()


def touch(path: Path, *, age_s: float) -> None:
    stamp = time.time() - age_s
    os.utime(path, (stamp, stamp))


@pytest.fixture
def three_files(site: Site) -> Site:
    site.write(
        "handbook.md",
        "# Handbook\n\nThe pump reference is HM-PUMP-7731.\n\n## Valves\n\nClose valve V1 first.",
    )
    site.write("contracts/lease.txt", "The lease of the warehouse ends in March.")
    site.write("contracts/2026/invoice.txt", "Invoice 42 is payable within thirty days.")
    return site


# -- a first run -----------------------------------------------------------------


def test_first_run_indexes_every_file(three_files: Site, qdrant: FakeQdrant) -> None:
    result = sync(three_files)
    assert result.processed == 3
    assert qdrant.texts(COLLECTION) == [
        "Close valve V1 first.",
        "Invoice 42 is payable within thirty days.",
        "The lease of the warehouse ends in March.",
        "The pump reference is HM-PUMP-7731.",
    ]
    by_text = {p["text"]: p for p in qdrant.payloads(COLLECTION)}
    valve = by_text["Close valve V1 first."]
    assert valve["source"] == "docs" and valve["path"] == "handbook.md"
    assert valve["headings"] == ["Handbook", "Valves"] and valve["page"] is None
    assert valve["chunk_index"] == 1
    assert valve["file_id"] == file_id("docs", "handbook.md")
    assert len(valve["sha256"]) == 64
    assert by_text["Invoice 42 is payable within thirty days."]["path"] == "contracts/2026/invoice.txt"


def test_status_file_has_exactly_the_contract_fields(three_files: Site) -> None:
    sync(three_files)
    status = status_file(three_files)
    assert list(status) == STATUS_KEYS
    assert status["state"] == "idle"
    assert (status["files_indexed"], status["files_failed"], status["files_skipped"], status["chunks"]) == (
        3,
        0,
        0,
        4,
    )
    assert status["detail"] == ""
    for key in ("last_run_at", "last_ok_at"):
        assert len(status[key]) == 20 and status[key].endswith("Z") and status[key][10] == "T"
    assert all(isinstance(status[k], int) and not isinstance(status[k], bool) for k in STATUS_KEYS[3:7])
    assert oct((three_files.state_dir / "status.json").stat().st_mode & 0o777) == "0o644"
    assert not list(three_files.state_dir.glob(".status-*")), "no temporary file is left"


def test_status_before_any_run(site: Site) -> None:
    assert status_mod.read_status(site.state_dir) == {
        "state": "idle",
        "last_run_at": "",
        "last_ok_at": "",
        "files_indexed": 0,
        "files_failed": 0,
        "files_skipped": 0,
        "chunks": 0,
        "detail": "",
    }


def test_no_file_name_and_no_document_text_in_status_or_info_logs(
    site: Site, caplog: pytest.LogCaptureFixture
) -> None:
    site.write("zebra-quarterly/okapi-minutes.md", "# Giraffe heading\n\nThe wombat clause applies.")
    site.write("zebra-quarterly/broken-narwhal.md", bytes(range(256)) * 8)
    site.write("zebra-quarterly/too-big-platypus.txt", b"a" * (1024 * 1024 + 1))
    with caplog.at_level(logging.INFO):
        result = sync(site)
    assert result.status["files_indexed"] == 1 and result.status["files_failed"] == 1
    assert result.status["files_skipped"] == 1
    assert result.status["detail"] == "failed: not_text=1; skipped: too_large=1"
    on_disk = (site.state_dir / "status.json").read_text(encoding="utf-8")
    logged = "\n".join(r.getMessage() for r in caplog.records if r.levelno >= logging.INFO)
    assert "sync finished" in logged
    for forbidden in ("zebra", "okapi", "narwhal", "platypus", "Giraffe", "wombat", str(site.nas_root)):
        assert forbidden not in on_disk
        assert forbidden not in logged


# -- request shapes ----------------------------------------------------------------


def test_ollama_embed_requests_have_the_documented_shape(three_files: Site, ollama: FakeOllama) -> None:
    sync(three_files)
    calls = ollama.calls("POST", "/api/embed")
    assert len(calls) == 4  # the dimension probe, then one request per file
    assert all(set(c.body) == {"model", "input"} for c in calls)
    assert all(c.body["model"] == "bge-m3" and isinstance(c.body["input"], list) for c in calls)
    assert all(c.headers["content-type"] == "application/json" for c in calls)
    # headings are embedded with the passage they introduce
    assert "Handbook\nValves\nClose valve V1 first." in ollama.embedded_texts()
    assert len(ollama.requests) == len(calls), "nothing else is asked of Ollama"


def test_long_files_are_embedded_in_batches(site: Site, ollama: FakeOllama, qdrant: FakeQdrant) -> None:
    site.write("long.txt", "\n\n".join(f"Paragraph {i}. " + "filler " * 200 for i in range(40)))
    result = sync(site)
    chunks = result.status["chunks"]
    assert chunks == len(qdrant.payloads(COLLECTION)) >= 33
    sizes = [len(c.body["input"]) for c in ollama.calls("POST", "/api/embed")[1:]]
    assert max(sizes) == 16 and sum(sizes) == chunks


def test_qdrant_requests_have_the_documented_shape(three_files: Site, qdrant: FakeQdrant) -> None:
    sync(three_files)
    base = f"/collections/{COLLECTION}"
    assert [(r.method, r.path) for r in qdrant.requests[:5]] == [
        ("GET", f"{base}/exists"),
        ("PUT", base),
        ("PUT", f"{base}/index"),
        ("PUT", f"{base}/index"),
        ("PUT", f"{base}/points"),
    ]
    (create,) = qdrant.calls("PUT", base)
    assert create.body == {"vectors": {"size": 32, "distance": "Cosine"}}
    indexes = qdrant.calls("PUT", f"{base}/index")
    assert [r.body for r in indexes] == [
        {"field_name": "file_id", "field_schema": "keyword"},
        {"field_name": "index_id", "field_schema": "keyword"},
    ]
    upserts = qdrant.calls("PUT", f"{base}/points")
    assert len(upserts) == 3
    for request in upserts + indexes + qdrant.calls("POST", f"{base}/points/delete"):
        assert request.query == {"wait": ["true"]}
    first = upserts[0].body
    assert set(first) == {"points"}
    for point in first["points"]:
        assert set(point) == {"id", "vector", "payload"}
        assert str(uuid.UUID(point["id"])) == point["id"]
        assert len(point["vector"]) == 32 and all(isinstance(v, float) for v in point["vector"])
        assert set(point["payload"]) == {
            "index_id",
            "file_id",
            "source",
            "path",
            "chunk_index",
            "text",
            "headings",
            "page",
            "sha256",
        }
    deletes = qdrant.calls("POST", f"{base}/points/delete")
    assert deletes[0].body == {
        "filter": {
            "must": [
                {"key": "file_id", "match": {"value": first["points"][0]["payload"]["file_id"]}},
                {"key": "chunk_index", "range": {"gte": len(first["points"])}},
            ]
        }
    }


def test_point_ids_are_uuid5_of_source_path_and_passage_number(three_files: Site, qdrant: FakeQdrant) -> None:
    sync(three_files)
    points = qdrant.collections[COLLECTION].points
    expected = {
        point_id("docs", "handbook.md", 0),
        point_id("docs", "handbook.md", 1),
        point_id("docs", "contracts/lease.txt", 0),
        point_id("docs", "contracts/2026/invoice.txt", 0),
    }
    assert set(points) == expected
    assert all(uuid.UUID(pid).version == 5 for pid in points)
    assert point_id("docs", "a", 1) != point_id("docs", "a", 2) != point_id("other", "a", 1)
    assert point_id("a", "b\n1", 2) != point_id("a\nb", "1", 2)


# -- incremental ---------------------------------------------------------------------


def test_unchanged_files_are_not_embedded_again(
    three_files: Site, ollama: FakeOllama, qdrant: FakeQdrant
) -> None:
    sync(three_files)
    before = dict(qdrant.collections[COLLECTION].points)
    ollama.clear()
    qdrant.clear()
    result = sync(three_files)
    assert (result.processed, result.unchanged, result.removed) == (0, 3, 0)
    assert ollama.embedded_texts() == []
    assert qdrant.calls("PUT", f"/collections/{COLLECTION}/points") == []
    assert qdrant.collections[COLLECTION].points == before
    assert result.status["files_indexed"] == 3 and result.status["chunks"] == 4


def test_unchanged_files_are_not_even_opened(three_files: Site, monkeypatch: pytest.MonkeyPatch) -> None:
    sync(three_files)
    opened: list[str] = []
    real = walker.open_regular_file

    def spy(root_fd: int, rel_path: str) -> int:
        opened.append(rel_path)
        return real(root_fd, rel_path)

    monkeypatch.setattr("hm_vectorizer.sync.open_regular_file", spy)
    sync(three_files)
    assert opened == []


def test_touched_file_with_the_same_content_is_hashed_but_not_embedded(
    three_files: Site, ollama: FakeOllama
) -> None:
    sync(three_files)
    ollama.clear()
    touch(three_files.source_dir() / "handbook.md", age_s=600)
    result = sync(three_files)
    assert (result.processed, result.unchanged) == (0, 3)
    assert ollama.embedded_texts() == []
    # the new modification time is recorded: the next run does not hash it again
    record = records(three_files)["docs/handbook.md"]
    assert record.mtime_ns == (three_files.source_dir() / "handbook.md").stat().st_mtime_ns


def test_changed_file_is_replaced(three_files: Site, ollama: FakeOllama, qdrant: FakeQdrant) -> None:
    sync(three_files)
    ollama.clear()
    three_files.write("handbook.md", "# Handbook\n\nThe pump reference is now HM-PUMP-9000.", age_s=600)
    result = sync(three_files)
    assert (result.processed, result.unchanged) == (1, 2)
    assert ollama.embedded_texts() == ["Handbook\nThe pump reference is now HM-PUMP-9000."]
    assert qdrant.texts(COLLECTION) == [
        "Invoice 42 is payable within thirty days.",
        "The lease of the warehouse ends in March.",
        "The pump reference is now HM-PUMP-9000.",
    ], "the passages of the old version are gone, including the second one"
    assert result.status["chunks"] == 3


def test_file_modified_a_moment_ago_is_hashed_again_next_time(site: Site, ollama: FakeOllama) -> None:
    """Its timestamp may not change if it is written again at once."""
    path = site.write("live.txt", "first version", age_s=0)
    sync(site)
    stamp = path.stat()
    path.write_text("other version")  # same length, and put back the same timestamp
    os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    ollama.clear()
    result = sync(site)
    assert result.processed == 1 and ollama.embedded_texts() == ["other version"]


def test_deleted_file_has_its_passages_removed(
    three_files: Site, ollama: FakeOllama, qdrant: FakeQdrant
) -> None:
    sync(three_files)
    ollama.clear()
    (three_files.source_dir() / "handbook.md").unlink()
    result = sync(three_files)
    assert (result.processed, result.removed) == (0, 1)
    assert qdrant.paths(COLLECTION) == {"contracts/lease.txt", "contracts/2026/invoice.txt"}
    assert "docs/handbook.md" not in records(three_files)
    assert (result.status["files_indexed"], result.status["chunks"]) == (2, 2)
    assert ollama.embedded_texts() == []


def test_file_that_is_no_longer_wanted_is_removed(three_files: Site, qdrant: FakeQdrant) -> None:
    sync(three_files)
    three_files.save(exclude=["contracts/2026"], extensions=["txt"])
    result = sync(three_files)
    assert result.removed == 2
    assert qdrant.paths(COLLECTION) == {"contracts/lease.txt"}


def test_source_removed_from_the_configuration_is_removed_from_the_index(
    three_files: Site, qdrant: FakeQdrant
) -> None:
    (three_files.nas_root / "more").mkdir()
    three_files.write("extra.txt", "Extra source text.", source_id="more")
    three_files.save(
        sources=["docs", "more"],
        source_paths={"docs": f"{three_files.nas_root}/docs", "more": f"{three_files.nas_root}/more"},
    )
    sync(three_files)
    assert {p["source"] for p in qdrant.payloads(COLLECTION)} == {"docs", "more"}
    three_files.save(sources=["docs"], source_paths={"docs": f"{three_files.nas_root}/docs"})
    result = sync(three_files)
    assert result.removed == 1
    assert {p["source"] for p in qdrant.payloads(COLLECTION)} == {"docs"}


def test_same_relative_path_in_two_sources_does_not_collide(site: Site, qdrant: FakeQdrant) -> None:
    (site.nas_root / "more").mkdir()
    site.write("same.txt", "Text of the first source.")
    site.write("same.txt", "Text of the second source.", source_id="more")
    site.save(
        sources=["docs", "more"],
        source_paths={"docs": f"{site.nas_root}/docs", "more": f"{site.nas_root}/more"},
    )
    sync(site)
    assert qdrant.texts(COLLECTION) == ["Text of the first source.", "Text of the second source."]


# -- failures -------------------------------------------------------------------------


def test_failing_file_is_counted_and_does_not_stop_the_run(three_files: Site, qdrant: FakeQdrant) -> None:
    three_files.write("a-broken.md", bytes(range(256)) * 8)
    three_files.write("report.pdf", b"%PDF-1.4 not really")
    parser = _NoDocling(three_files)
    result = sync(three_files, parser=parser)
    assert result.processed == 3
    assert (result.status["state"], result.status["files_indexed"], result.status["files_failed"]) == (
        "idle",
        3,
        2,
    )
    assert result.status["detail"] == "failed: not_text=1 parser_unavailable=1"
    assert result.status["last_ok_at"] != ""
    assert qdrant.paths(COLLECTION) == {"handbook.md", "contracts/lease.txt", "contracts/2026/invoice.txt"}
    failed = records(three_files)["docs/a-broken.md"]
    assert (failed.status, failed.error_code, failed.chunks, failed.sha256) == ("failed", "not_text", 0, None)


class _NoDocling:
    """The default parser on a machine without Docling, counting what it is asked."""

    def __init__(self, site: Site) -> None:
        self._inner = DefaultParser(ocr=False, max_file_bytes=site.load().max_file_bytes)
        self.parsed: list[str] = []

    def unsupported_reason(self, ext: str) -> str | None:
        if ext in ("txt", "md"):
            return None
        return "parser_unavailable"

    def parse(self, path: Path, ext: str) -> list[Chunk]:
        self.parsed.append(path.name)
        return self._inner.parse(path, ext)


def test_failed_file_is_tried_again_at_the_next_run(three_files: Site, qdrant: FakeQdrant) -> None:
    three_files.write("a-broken.md", bytes(range(256)) * 8)
    parser = _NoDocling(three_files)
    sync(three_files, parser=parser)
    assert parser.parsed.count("doc.md") == 2  # handbook.md and a-broken.md
    parser.parsed.clear()

    result = sync(three_files, parser=parser)
    assert parser.parsed == ["doc.md"], "only the failed file is parsed again, with unchanged content"
    assert (result.status["files_indexed"], result.status["files_failed"]) == (3, 1)

    three_files.write("a-broken.md", "Repaired: the text is readable now.", age_s=600)
    result = sync(three_files, parser=parser)
    assert (result.status["files_indexed"], result.status["files_failed"]) == (4, 0)
    assert result.status["detail"] == ""
    assert "Repaired: the text is readable now." in qdrant.texts(COLLECTION)


def test_parser_never_sees_the_name_or_the_path_on_the_nas(three_files: Site) -> None:
    seen: list[Path] = []

    class Spy:
        def unsupported_reason(self, ext: str) -> str | None:
            return None

        def parse(self, path: Path, ext: str) -> list[Chunk]:
            seen.append(path)
            assert path.read_bytes()
            return [Chunk(text="x")]

    sync(three_files, parser=Spy())
    assert {p.name for p in seen} == {"doc.md", "doc.txt"}
    assert all(p.parent == three_files.state_dir / "spool" for p in seen)
    assert not (three_files.state_dir / "spool").exists(), "the spool is removed after the run"


def test_parser_that_raises_anything_fails_the_file_only(three_files: Site) -> None:
    class Exploding:
        def unsupported_reason(self, ext: str) -> str | None:
            return None

        def parse(self, path: Path, ext: str) -> list[Chunk]:
            if path.suffix == ".md":
                raise RuntimeError("segfault-ish")
            return [Chunk(text="fine")]

    result = sync(three_files, parser=Exploding())
    assert (result.status["state"], result.status["files_indexed"], result.status["files_failed"]) == (
        "idle",
        2,
        1,
    )
    assert result.status["detail"] == "failed: parse_error=1"


def test_file_that_becomes_unparseable_loses_its_old_passages(three_files: Site, qdrant: FakeQdrant) -> None:
    sync(three_files)
    three_files.write("handbook.md", bytes(range(256)) * 8, age_s=600)
    result = sync(three_files)
    assert "handbook.md" not in qdrant.paths(COLLECTION)
    assert (result.status["files_indexed"], result.status["files_failed"], result.status["chunks"]) == (
        2,
        1,
        2,
    )


def test_file_that_cannot_be_read_keeps_its_passages(
    three_files: Site, qdrant: FakeQdrant, ollama: FakeOllama, monkeypatch: pytest.MonkeyPatch
) -> None:
    sync(three_files)
    touch(three_files.source_dir() / "handbook.md", age_s=600)
    real = walker.open_regular_file

    def flaky(root_fd: int, rel_path: str) -> int:
        if rel_path == "handbook.md":
            raise OSError(5, "Input/output error")
        return real(root_fd, rel_path)

    monkeypatch.setattr("hm_vectorizer.sync.open_regular_file", flaky)
    result = sync(three_files)
    assert result.status["detail"] == "failed: read_error=1"
    assert "handbook.md" in qdrant.paths(COLLECTION), "an unreadable file is not a deleted file"
    assert result.status["chunks"] == 4

    monkeypatch.setattr("hm_vectorizer.sync.open_regular_file", real)
    ollama.clear()
    result = sync(three_files)
    assert (result.status["files_failed"], result.status["files_indexed"]) == (0, 3)
    assert ollama.embedded_texts() == [], "same content as indexed: nothing to embed"


def test_link_swapped_in_after_the_listing_is_not_read(
    three_files: Site, qdrant: FakeQdrant, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP SECRET outside the share")
    target = three_files.source_dir() / "contracts" / "lease.txt"
    real_walk = walker.walk_source

    def walk_then_swap(cfg: Any, source: Any) -> Any:
        result = real_walk(cfg, source)
        target.unlink()
        os.symlink(secret, target)
        return result

    monkeypatch.setattr("hm_vectorizer.sync.walk_source", walk_then_swap)
    result = sync(three_files)
    assert result.status["detail"] == "failed: not_regular_file=1"
    assert all("TOP SECRET" not in text for text in qdrant.texts(COLLECTION))


# -- stopping and resuming ---------------------------------------------------------------


def test_embedding_service_failure_stops_the_run_and_the_next_one_resumes(
    three_files: Site, ollama: FakeOllama, qdrant: FakeQdrant, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("hm_vectorizer.embedder.RETRY_DELAYS_S", (0.0, 0.0))
    ollama.fail_embed_after = 2
    result = sync(three_files)
    assert result.status["state"] == "error"
    assert result.status["detail"] == "error: embedder_unavailable"
    assert result.status["last_ok_at"] == ""
    assert (result.status["files_indexed"], result.status["chunks"]) == (2, 2)
    assert len(ollama.calls("POST", "/api/embed")) == 1 + 2 + 3, "the failing request was tried three times"
    assert set(records(three_files)) == {"docs/contracts/2026/invoice.txt", "docs/contracts/lease.txt"}

    ollama.fail_embed_after = None
    ollama.clear()
    result = sync(three_files)
    assert result.status["state"] == "idle" and result.status["files_indexed"] == 3
    assert (result.processed, result.unchanged) == (1, 2)
    assert ollama.embedded_texts() == [
        "Handbook\nThe pump reference is HM-PUMP-7731.",
        "Handbook\nValves\nClose valve V1 first.",
    ], "only the file that was not done is embedded"
    assert len(qdrant.payloads(COLLECTION)) == 4


def test_missing_embedding_model_is_reported_before_anything_is_touched(
    three_files: Site, qdrant: FakeQdrant
) -> None:
    three_files.save(embedding_model="not-pulled")
    result = sync(three_files)
    assert (result.status["state"], result.status["detail"]) == ("error", "error: embedder_model_missing")
    assert qdrant.requests == []


def test_ollama_down(three_files: Site, ollama: FakeOllama, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("hm_vectorizer.embedder.RETRY_DELAYS_S", (0.0,))
    ollama.close()
    result = sync(three_files)
    assert (result.status["state"], result.status["detail"]) == ("error", "error: embedder_unavailable")


def test_vector_store_failure_stops_the_run_and_the_next_one_resumes(
    three_files: Site, qdrant: FakeQdrant
) -> None:
    qdrant.fail_upserts = True
    result = sync(three_files)
    assert (result.status["state"], result.status["detail"]) == ("error", "error: store_error")
    assert result.status["files_indexed"] == 0
    qdrant.fail_upserts = False
    result = sync(three_files)
    assert (result.status["state"], result.status["files_indexed"]) == ("idle", 3)


def test_run_killed_midway_is_reported_and_resumed(three_files: Site, ollama: FakeOllama) -> None:
    """A process that dies leaves `running` in the file and no lock."""
    calls = {"n": 0}

    def stop_after_one() -> bool:
        calls["n"] += 1
        return calls["n"] > 1

    result = sync(three_files, should_stop=stop_after_one)
    assert (result.status["state"], result.status["detail"]) == ("error", "error: interrupted")
    assert result.status["files_indexed"] == 1

    # what a kill -9 leaves behind
    killed = dict(result.status, state="running", detail="")
    status_mod.write_status(three_files.state_dir, killed)
    assert status_mod.read_status(three_files.state_dir)["state"] == "error"
    assert status_mod.read_status(three_files.state_dir)["detail"] == "interrupted"
    status_mod.repair_status(three_files.state_dir)
    assert status_file(three_files)["state"] == "error"

    ollama.clear()
    result = sync(three_files)
    assert result.status["state"] == "idle" and (result.processed, result.unchanged) == (2, 1)


def test_one_run_at_a_time(three_files: Site) -> None:
    fd = status_mod.try_lock(three_files.state_dir)
    assert fd is not None
    try:
        assert status_mod.run_in_progress(three_files.state_dir)
        assert status_mod.read_status(three_files.state_dir)["state"] == "running"
        with pytest.raises(SyncBusy):
            sync(three_files)
        assert status_mod.try_lock(three_files.state_dir) is None
    finally:
        status_mod.unlock(fd)
    assert not status_mod.run_in_progress(three_files.state_dir)
    assert sync(three_files).status["state"] == "idle"


def test_status_says_running_during_the_run(three_files: Site) -> None:
    seen: list[str] = []

    class Peek:
        def unsupported_reason(self, ext: str) -> str | None:
            return None

        def parse(self, path: Path, ext: str) -> list[Chunk]:
            seen.append(status_file(three_files)["state"])
            seen.append(status_mod.read_status(three_files.state_dir)["state"])
            return [Chunk(text="x")]

    sync(three_files, parser=Peek())
    assert seen and set(seen) == {"running"}
    assert status_file(three_files)["state"] == "idle"


# -- not seeing is not the same as gone -------------------------------------------------------


def test_unmounted_source_empties_nothing(three_files: Site, qdrant: FakeQdrant) -> None:
    first = sync(three_files)
    before = dict(qdrant.collections[COLLECTION].points)
    docs = three_files.source_dir()
    docs.rename(three_files.nas_root / "docs.away")
    docs.mkdir()  # what an unmounted NAS looks like: the empty mount point
    result = sync(three_files)
    assert result.status["state"] == "error"
    assert result.status["detail"] == "error: source_unavailable (1 of 1 sources)"
    assert result.removed == 0 and qdrant.collections[COLLECTION].points == before
    assert (result.status["files_indexed"], result.status["chunks"]) == (3, 4)
    assert result.status["last_ok_at"] == first.status["last_ok_at"]

    docs.rmdir()
    (three_files.nas_root / "docs.away").rename(docs)
    result = sync(three_files)
    assert result.status["state"] == "idle" and (result.processed, result.unchanged) == (0, 3)


def test_one_source_down_does_not_stop_the_other(site: Site, qdrant: FakeQdrant) -> None:
    site.write("a.txt", "Text of the first source.")
    site.save(
        sources=["docs", "more"],
        source_paths={"docs": f"{site.nas_root}/docs", "more": f"{site.nas_root}/more"},
    )
    result = sync(site)
    assert result.status["detail"] == "error: source_unavailable (1 of 2 sources)"
    assert qdrant.texts(COLLECTION) == ["Text of the first source."]


def test_unreadable_directory_keeps_what_was_indexed_below_it(
    three_files: Site, qdrant: FakeQdrant, monkeypatch: pytest.MonkeyPatch
) -> None:
    sync(three_files)
    contracts = os.stat(three_files.source_dir() / "contracts").st_ino
    real = walker._list_dir

    def failing(fd: int) -> list[os.DirEntry[str]]:
        if os.fstat(fd).st_ino == contracts:
            raise OSError(116, "Stale file handle")
        return real(fd)

    monkeypatch.setattr(walker, "_list_dir", failing)
    (three_files.source_dir() / "handbook.md").unlink()
    result = sync(three_files)
    assert result.removed == 1, "the file that is really gone is removed"
    assert qdrant.paths(COLLECTION) == {"contracts/lease.txt", "contracts/2026/invoice.txt"}
    assert result.status["state"] == "idle" and result.status["detail"] == "unreadable_directories=1"


# -- the store and the state disagree --------------------------------------------------------------


def test_lost_state_database_removes_the_points_it_no_longer_knows(
    three_files: Site, qdrant: FakeQdrant
) -> None:
    sync(three_files)
    for name in ("state.db", "state.db-wal", "state.db-shm"):
        (three_files.state_dir / name).unlink(missing_ok=True)
    (three_files.source_dir() / "handbook.md").unlink()  # deleted while the state was lost
    result = sync(three_files)
    assert result.processed == 2
    assert qdrant.paths(COLLECTION) == {"contracts/lease.txt", "contracts/2026/invoice.txt"}
    foreign = [
        r
        for r in qdrant.calls("POST", f"/collections/{COLLECTION}/points/delete")
        if "must_not" in r.body["filter"]
    ]
    assert foreign[-1].body == {
        "filter": {
            "must_not": [{"key": "index_id", "match": {"value": qdrant.payloads(COLLECTION)[0]["index_id"]}}]
        }
    }


def test_damaged_state_database_is_set_aside(three_files: Site, qdrant: FakeQdrant) -> None:
    sync(three_files)
    for name in ("state.db-wal", "state.db-shm"):
        (three_files.state_dir / name).unlink(missing_ok=True)
    (three_files.state_dir / "state.db").write_bytes(b"this is not a database" * 100)
    result = sync(three_files)
    assert result.status["state"] == "idle" and result.processed == 3
    assert (three_files.state_dir / "state.db.corrupt").exists()
    assert len(qdrant.payloads(COLLECTION)) == 4


def test_lost_collection_is_rebuilt(three_files: Site, qdrant: FakeQdrant) -> None:
    sync(three_files)
    qdrant.collections.clear()
    result = sync(three_files)
    assert result.processed == 3 and len(qdrant.payloads(COLLECTION)) == 4


def test_another_embedding_model_rebuilds_the_index(
    three_files: Site, ollama: FakeOllama, qdrant: FakeQdrant
) -> None:
    sync(three_files)
    ollama.models.add("other-embed")
    three_files.save(embedding_model="other-embed")
    ollama.clear()
    result = sync(three_files)
    assert result.processed == 3, "same vector size, other model: everything is embedded again"
    assert {c.body["model"] for c in ollama.calls("POST", "/api/embed")} == {"other-embed"}
    assert len(qdrant.calls("DELETE", f"/collections/{COLLECTION}")) == 1
    assert len(qdrant.payloads(COLLECTION)) == 4


def test_another_vector_size_recreates_the_collection(
    three_files: Site, ollama: FakeOllama, qdrant: FakeQdrant
) -> None:
    sync(three_files)
    ollama.dim = 48
    result = sync(three_files)
    assert result.processed == 3
    assert qdrant.collections[COLLECTION].size == 48
    assert all(len(p["vector"]) == 48 for p in qdrant.collections[COLLECTION].points.values())


def test_link_is_never_indexed(site: Site, qdrant: FakeQdrant, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "passwords.txt").write_text("root password is hunter2")
    site.write("ok.txt", "Public text.")
    os.symlink(outside / "passwords.txt", site.source_dir() / "link.txt")
    os.symlink(outside, site.source_dir() / "linkdir")
    result = sync(site)
    assert qdrant.texts(COLLECTION) == ["Public text."]
    assert result.status["files_skipped"] == 2 and result.status["detail"] == "skipped: symlink=2"
