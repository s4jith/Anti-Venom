from __future__ import annotations

import importlib.util
import threading
import time
from typing import Any

import numpy as np

from antivenom.core.chunk import Chunk
from antivenom.core.result import LayerResult
from antivenom.layers.base import AbstractDetectionLayer


def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Cosine similarity between a 1-D vector and each row of a 2-D matrix; returns max."""
    if b.ndim == 1:
        b = b[np.newaxis, :]
    dots = b @ a  # (n_centroids,)
    return float(np.max(dots))


class SemanticLayer(AbstractDetectionLayer):
    """Layer 4 (MEDIUM): cosine similarity against malicious-intent centroid corpus.

    Requires: pip install antivenom[semantic]
    Model: all-MiniLM-L6-v2 (22MB, downloaded once on first use)
    """

    name = "semantic"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config = config or {}
        self._threshold: float = self._config.get("threshold", 0.72)
        self._model_name: str = self._config.get("model_name", "all-MiniLM-L6-v2")
        self._embedder: Any = None
        self._centroids: np.ndarray | None = None
        self._labels: list[str] | None = None
        self._ready_lock = threading.Lock()

    def _ensure_ready(self) -> None:
        if self._embedder is not None:
            return
        with self._ready_lock:
            if self._embedder is not None:
                return
            if importlib.util.find_spec("sentence_transformers") is None:
                raise ImportError(
                    "sentence-transformers is required for SemanticLayer. "
                    "Install with: pip install antivenom[semantic]"
                )
            from antivenom.models.embeddings import EmbeddingModel
            from antivenom.models.malicious_corpus import get_centroids
            embedder = EmbeddingModel(self._model_name)
            self._centroids, self._labels = get_centroids(embedder)
            self._embedder = embedder

    async def scan(self, chunk: Chunk) -> LayerResult:
        start = time.perf_counter()
        try:
            self._ensure_ready()
        except ImportError as e:
            # Gracefully degrade if sentence-transformers not installed
            return LayerResult(
                layer_name=self.name,
                triggered=False,
                confidence=0.0,
                evidence=[f"semantic layer unavailable: {e}"],
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        # Truncate to avoid very long embed times
        text = chunk.text[:2000]
        vec = self._embedder.embed(text)

        assert self._centroids is not None
        assert self._labels is not None

        # Per-centroid similarities
        sims = self._centroids @ vec  # (n_centroids,)
        max_idx = int(np.argmax(sims))
        max_sim = float(sims[max_idx])
        matched_family = self._labels[max_idx]

        triggered = max_sim >= self._threshold
        confidence = min(max_sim, 0.95) if triggered else max_sim * 0.3

        evidence: list[str] = []
        if triggered:
            evidence.append(
                f"cosine={max_sim:.3f} (threshold={self._threshold}) "
                f"family={matched_family}"
            )

        return LayerResult(
            layer_name=self.name,
            triggered=triggered,
            confidence=confidence,
            evidence=evidence,
            duration_ms=(time.perf_counter() - start) * 1000,
        )
