"""The vector store: the Qdrant plugin, over its REST API.

Endpoints used, as described by Qdrant's OpenAPI specification
(qdrant/qdrant, docs/redoc/master/openapi.json):

- `GET  /collections/{name}/exists`           -> `result.exists`
- `GET  /collections/{name}`                  -> `result.config.params.vectors`
- `PUT  /collections/{name}`                  `{"vectors": {"size": N, "distance": "Cosine"}}`
- `DELETE /collections/{name}`
- `PUT  /collections/{name}/index?wait=true`  `{"field_name": ..., "field_schema": "keyword"}`
- `PUT  /collections/{name}/points?wait=true` `{"points": [{"id", "vector", "payload"}]}`
- `POST /collections/{name}/points/delete?wait=true` `{"filter": {...}}`
- `POST /collections/{name}/points/query`     `{"query": [..], "limit": N, "with_payload": true}`
  -> `result.points[]` with `id`, `score`, `payload`

Point ids are UUID5 values of (source id, relative path, passage number): the
same passage always gets the same id, so indexing a file again overwrites its
points instead of adding to them.
"""

from __future__ import annotations

import json
import uuid
from array import array
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from .chunker import Chunk
from .http_client import HttpError, JsonHttpClient

DISTANCE = "Cosine"
UPSERT_BATCH = 64
REQUEST_TIMEOUT_S = 120.0

# Namespace of the ids below. Changing it orphans every stored point.
_NAMESPACE = uuid.UUID("6f1d2c9e-5b0a-4a57-9d2e-3f6f0c1b7a44")


def file_id(source_id: str, rel_path: str) -> str:
    return str(uuid.uuid5(_NAMESPACE, json.dumps([source_id, rel_path], ensure_ascii=True)))


def point_id(source_id: str, rel_path: str, index: int) -> str:
    return str(uuid.uuid5(_NAMESPACE, json.dumps([source_id, rel_path, index], ensure_ascii=True)))


class StoreError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class Passage:
    score: float
    source: str
    path: str
    text: str
    page: int | None
    headings: tuple[str, ...]


class QdrantStore:
    def __init__(
        self,
        base_url: str,
        collection: str,
        *,
        client: JsonHttpClient | None = None,
        timeout: float = REQUEST_TIMEOUT_S,
    ) -> None:
        self._base = f"{base_url}/collections/{collection}"
        self._client = client or JsonHttpClient()
        self._timeout = timeout

    def _call(self, method: str, path: str, body: Any = None) -> Any:
        try:
            answer = self._client.request(method, self._base + path, body, timeout=self._timeout)
        except HttpError as exc:
            if exc.kind in ("connect", "timeout"):
                raise StoreError("store_unavailable") from None
            raise StoreError("store_error") from None
        if not isinstance(answer, dict) or "result" not in answer:
            raise StoreError("store_bad_response")
        return answer["result"]

    def _update(self, method: str, path: str, body: Any) -> None:
        result = self._call(method, path, body)
        if not isinstance(result, dict) or result.get("status") != "completed":
            raise StoreError("store_not_completed")

    # -- collection -----------------------------------------------------------

    def exists(self) -> bool:
        result = self._call("GET", "/exists")
        if not isinstance(result, dict) or not isinstance(result.get("exists"), bool):
            raise StoreError("store_bad_response")
        return result["exists"]

    def vector_params(self) -> tuple[int, str] | None:
        """(size, distance) of the collection's single unnamed vector, or None
        when the collection is laid out differently."""
        result = self._call("GET", "")
        try:
            vectors = result["config"]["params"]["vectors"]
            size, distance = vectors["size"], vectors["distance"]
        except (KeyError, TypeError):
            return None
        if not isinstance(size, int) or isinstance(size, bool) or not isinstance(distance, str):
            return None
        return size, distance

    def create(self, size: int) -> None:
        if self._call("PUT", "", {"vectors": {"size": size, "distance": DISTANCE}}) is not True:
            raise StoreError("store_bad_response")
        for field_name in ("file_id", "index_id"):
            self._update("PUT", "/index?wait=true", {"field_name": field_name, "field_schema": "keyword"})

    def drop(self) -> None:
        self._call("DELETE", "")

    def ensure(self, size: int) -> str:
        """Make the collection exist with this vector size and cosine distance.

        Returns "existing", "created" (it was missing) or "recreated" (it had
        another layout: its points were made by another model and are dropped).
        """
        if not self.exists():
            self.create(size)
            return "created"
        if self.vector_params() == (size, DISTANCE):
            return "existing"
        self.drop()
        self.create(size)
        return "recreated"

    # -- points ---------------------------------------------------------------

    def upsert_file(
        self,
        *,
        index_id: str,
        source_id: str,
        rel_path: str,
        sha256: str,
        chunks: Sequence[Chunk],
        vectors: Sequence[array[float]],
    ) -> None:
        """Write the passages of one file, then remove what an earlier, longer
        version of the file left behind."""
        if len(chunks) != len(vectors):
            raise StoreError("store_bad_request")
        fid = file_id(source_id, rel_path)
        for start in range(0, len(chunks), UPSERT_BATCH):
            points = []
            for index in range(start, min(start + UPSERT_BATCH, len(chunks))):
                chunk = chunks[index]
                points.append(
                    {
                        "id": point_id(source_id, rel_path, index),
                        "vector": vectors[index].tolist(),
                        "payload": {
                            "index_id": index_id,
                            "file_id": fid,
                            "source": source_id,
                            "path": rel_path,
                            "chunk_index": index,
                            "text": chunk.text,
                            "headings": list(chunk.headings),
                            "page": chunk.page,
                            "sha256": sha256,
                        },
                    }
                )
            self._update("PUT", "/points?wait=true", {"points": points})
        self.delete_file(source_id, rel_path, from_index=len(chunks))

    def delete_file(self, source_id: str, rel_path: str, *, from_index: int = 0) -> None:
        """Remove the points of one file whose passage number is >= from_index."""
        must: list[dict[str, Any]] = [{"key": "file_id", "match": {"value": file_id(source_id, rel_path)}}]
        if from_index > 0:
            must.append({"key": "chunk_index", "range": {"gte": from_index}})
        self._update("POST", "/points/delete?wait=true", {"filter": {"must": must}})

    def delete_foreign(self, index_id: str) -> None:
        """Remove every point that was not written under this state database."""
        self._update(
            "POST",
            "/points/delete?wait=true",
            {"filter": {"must_not": [{"key": "index_id", "match": {"value": index_id}}]}},
        )

    def search(self, vector: array[float], limit: int) -> list[Passage]:
        result = self._call(
            "POST", "/points/query", {"query": vector.tolist(), "limit": limit, "with_payload": True}
        )
        points = result.get("points") if isinstance(result, dict) else None
        if not isinstance(points, list):
            raise StoreError("store_bad_response")
        passages: list[Passage] = []
        for point in points:
            payload = point.get("payload") if isinstance(point, dict) else None
            score = point.get("score") if isinstance(point, dict) else None
            if not isinstance(payload, dict) or not isinstance(score, int | float):
                continue
            source, path, text = payload.get("source"), payload.get("path"), payload.get("text")
            if not isinstance(source, str) or not isinstance(path, str) or not isinstance(text, str):
                continue
            page = payload.get("page")
            headings = payload.get("headings")
            passages.append(
                Passage(
                    score=float(score),
                    source=source,
                    path=path,
                    text=text,
                    page=page if isinstance(page, int) and not isinstance(page, bool) else None,
                    headings=tuple(h for h in headings if isinstance(h, str))
                    if isinstance(headings, list)
                    else (),
                )
            )
        return passages
