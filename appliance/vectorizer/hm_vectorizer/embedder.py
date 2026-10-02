"""Embeddings from the Ollama plugin.

`POST <ollama_url>/api/embed` with `{"model": ..., "input": [texts]}`; the
answer has `embeddings`, one vector per input, in order (Ollama API
documentation, docs/api.md "Generate Embeddings"). `truncate` is left at its
default (true): an input longer than the model's context is cut by Ollama
instead of failing the file.
"""

from __future__ import annotations

import logging
import math
import time
from array import array
from collections.abc import Callable, Sequence

from .http_client import HttpError, JsonHttpClient

log = logging.getLogger(__name__)

BATCH_SIZE = 16
REQUEST_TIMEOUT_S = 300.0  # the first request loads the model
RETRY_DELAYS_S = (1.0, 4.0)


class EmbedderError(Exception):
    """`code` is a short reason. `unavailable` means the service itself is at
    fault (down, model missing): the caller should stop instead of failing
    one file after another."""

    def __init__(self, code: str, *, unavailable: bool) -> None:
        self.code = code
        self.unavailable = unavailable
        super().__init__(code)


class OllamaEmbedder:
    def __init__(
        self,
        base_url: str,
        model: str,
        *,
        client: JsonHttpClient | None = None,
        batch_size: int = BATCH_SIZE,
        timeout: float = REQUEST_TIMEOUT_S,
        retry_delays: Sequence[float] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._url = f"{base_url}/api/embed"
        self._model = model
        self._client = client or JsonHttpClient()
        self._batch_size = batch_size
        self._timeout = timeout
        self._retry_delays = tuple(RETRY_DELAYS_S if retry_delays is None else retry_delays)
        self._sleep = sleep
        self._dimension: int | None = None

    def dimension(self) -> int:
        """Size of the model's vectors, found by embedding a short text."""
        if self._dimension is None:
            self.embed(["dimension probe"])
        assert self._dimension is not None
        return self._dimension

    def embed(self, texts: Sequence[str]) -> list[array[float]]:
        vectors: list[array[float]] = []
        for start in range(0, len(texts), self._batch_size):
            vectors.extend(self._embed_batch(list(texts[start : start + self._batch_size])))
        return vectors

    def _embed_batch(self, batch: list[str]) -> list[array[float]]:
        attempt = 0
        while True:
            try:
                answer = self._client.request(
                    "POST", self._url, {"model": self._model, "input": batch}, timeout=self._timeout
                )
                break
            except HttpError as exc:
                if exc.kind == "status" and exc.status == 404:
                    raise EmbedderError("embedder_model_missing", unavailable=True) from None
                if exc.kind == "status" and exc.status is not None and 400 <= exc.status < 500:
                    raise EmbedderError("embedder_rejected", unavailable=False) from None
                if exc.kind in ("bad_request", "bad_json", "too_large", "redirect"):
                    raise EmbedderError("embedder_bad_response", unavailable=False) from None
                if attempt >= len(self._retry_delays):
                    raise EmbedderError("embedder_unavailable", unavailable=True) from None
                log.warning("embedding request failed (%s), retrying", exc)
                self._sleep(self._retry_delays[attempt])
                attempt += 1
        return self._vectors(answer, len(batch))

    def _vectors(self, answer: object, expected: int) -> list[array[float]]:
        embeddings = answer.get("embeddings") if isinstance(answer, dict) else None
        if not isinstance(embeddings, list) or len(embeddings) != expected:
            raise EmbedderError("embedder_bad_response", unavailable=False)
        vectors: list[array[float]] = []
        for embedding in embeddings:
            if not isinstance(embedding, list) or not embedding:
                raise EmbedderError("embedder_bad_response", unavailable=False)
            try:
                vector = array("f", embedding)
            except (TypeError, OverflowError):
                raise EmbedderError("embedder_bad_response", unavailable=False) from None
            if not all(math.isfinite(value) for value in vector):
                raise EmbedderError("embedder_bad_response", unavailable=False)
            if self._dimension is None:
                self._dimension = len(vector)
            elif len(vector) != self._dimension:
                raise EmbedderError("embedder_bad_response", unavailable=False)
            vectors.append(vector)
        return vectors
