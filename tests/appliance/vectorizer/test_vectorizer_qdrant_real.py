"""The vector store against a real Qdrant.

Skipped unless HM_TEST_QDRANT_URL points at a Qdrant that may be used for
tests, for example a release binary started on a private port:

    HM_TEST_QDRANT_URL=http://127.0.0.1:16333 \
        api/.venv/bin/python -m pytest tests/appliance/vectorizer/test_vectorizer_qdrant_real.py -q

Each test uses its own collection and deletes it. The embedding service is
still the fake one: what is checked here is that a real Qdrant accepts the
requests of `store.py` and answers in the shape it expects.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from hm_vectorizer.http_client import JsonHttpClient
from hm_vectorizer.store import QdrantStore, point_id
from hm_vectorizer.sync import run_sync
from vz_fakes import FakeOllama, fake_embedding
from vz_support import Site

QDRANT_URL = os.environ.get("HM_TEST_QDRANT_URL", "").rstrip("/")
pytestmark = pytest.mark.skipif(
    not QDRANT_URL, reason="HM_TEST_QDRANT_URL is not set: no real Qdrant to test against"
)


@pytest.fixture
def real(site: Site) -> Iterator[tuple[Site, QdrantStore, str]]:
    collection = f"hm_test_{uuid.uuid4().hex[:12]}"
    site.save(qdrant_url=QDRANT_URL, collection=collection)
    store = QdrantStore(QDRANT_URL, collection)
    try:
        yield site, store, collection
    finally:
        if store.exists():
            store.drop()


def scroll(collection: str) -> list[dict[str, Any]]:
    """Every point of the collection, read with Qdrant's scroll endpoint."""
    answer = JsonHttpClient().request(
        "POST",
        f"{QDRANT_URL}/collections/{collection}/points/scroll",
        {"limit": 1000, "with_payload": True, "with_vector": False},
    )
    return answer["result"]["points"]


def search(site: Site, store: QdrantStore, text: str, limit: int = 3) -> list[Any]:
    from array import array

    return store.search(array("f", fake_embedding(text)), limit)


def test_real_qdrant_accepts_a_whole_life_cycle(
    real: tuple[Site, QdrantStore, str], ollama: FakeOllama
) -> None:
    site, store, collection = real
    site.write(
        "handbook.md",
        "# Handbook\n\nThe pump reference is HM-PUMP-7731.\n\n## Valves\n\nClose valve V1 first.",
    )
    site.write("contracts/lease.txt", "The lease of the warehouse ends in March.")
    site.write(
        "long.txt", "\n\n".join(f"Paragraph {i} about maintenance. " + "filler " * 150 for i in range(12))
    )

    assert store.exists() is False
    first = run_sync(site.load(), site.state_dir)
    assert first.status["state"] == "idle", first.status
    assert store.exists() is True
    assert store.vector_params() == (32, "Cosine")
    points = scroll(collection)
    assert len(points) == first.status["chunks"] >= 5
    assert {p["id"] for p in points} >= {
        point_id("docs", "handbook.md", 0),
        point_id("docs", "handbook.md", 1),
    }

    hits = search(site, store, "pump reference HM-PUMP-7731")
    assert hits[0].path == "handbook.md" and hits[0].text == "The pump reference is HM-PUMP-7731."
    assert hits[0].headings == ("Handbook",) and hits[0].page is None and hits[0].source == "docs"
    assert hits[0].score > hits[-1].score > -1.0

    # unchanged: nothing written
    again = run_sync(site.load(), site.state_dir)
    assert (again.processed, again.unchanged) == (0, 3)

    # a file gets shorter: the passages beyond its new end are removed (delete by filter with a range)
    long_before = [p for p in points if p["payload"]["path"] == "long.txt"]
    assert len(long_before) >= 3
    site.write("long.txt", "Now one short paragraph.", age_s=600)
    changed = run_sync(site.load(), site.state_dir)
    assert changed.processed == 1
    long_after = [p for p in scroll(collection) if p["payload"]["path"] == "long.txt"]
    assert [p["payload"]["text"] for p in long_after] == ["Now one short paragraph."]

    # a file disappears: its passages are removed (delete by filter)
    (site.source_dir() / "handbook.md").unlink()
    removed = run_sync(site.load(), site.state_dir)
    assert removed.removed == 1
    assert {p["payload"]["path"] for p in scroll(collection)} == {"contracts/lease.txt", "long.txt"}

    # the state database is lost: points written under the old one are removed (must_not filter)
    for name in ("state.db", "state.db-wal", "state.db-shm"):
        (site.state_dir / name).unlink(missing_ok=True)
    (site.source_dir() / "contracts" / "lease.txt").unlink()
    rebuilt = run_sync(site.load(), site.state_dir)
    assert rebuilt.status["state"] == "idle" and rebuilt.processed == 1
    assert {p["payload"]["path"] for p in scroll(collection)} == {"long.txt"}

    # another vector size: the collection is dropped and created again
    ollama.dim = 48
    resized = run_sync(site.load(), site.state_dir)
    assert resized.status["state"] == "idle" and resized.processed == 1
    assert store.vector_params() == (48, "Cosine")
    assert len(scroll(collection)) == 1


def test_real_qdrant_refuses_what_the_fake_refuses(real: tuple[Site, QdrantStore, str]) -> None:
    """The fake server's strictness is not invented: the real one refuses these too."""
    _, store, collection = real
    store.create(4)
    client = JsonHttpClient()
    base = f"{QDRANT_URL}/collections/{collection}"
    bad_requests = [
        ("PUT", "/points?wait=true", {"points": [{"id": "not-a-uuid", "vector": [0.1, 0.2, 0.3, 0.4]}]}),
        ("PUT", "/points?wait=true", {"points": [{"id": 1, "vector": [0.1, 0.2]}]}),
        ("POST", "/points/delete?wait=true", {"filter": {"unknown": []}}),
    ]
    from hm_vectorizer.http_client import HttpError

    for method, path, body in bad_requests:
        with pytest.raises(HttpError) as caught:
            client.request(method, base + path, body)
        assert caught.value.kind == "status" and caught.value.status in (400, 422), (path, body)
