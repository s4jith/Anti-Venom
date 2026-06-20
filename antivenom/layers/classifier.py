from __future__ import annotations

import asyncio
import os
import threading
import time
from typing import Any

from antivenom.core.chunk import Chunk
from antivenom.core.result import LayerResult
from antivenom.layers.base import AbstractDetectionLayer
from antivenom.models.distilbert import DistilBertClassifier


class ClassifierLayer(AbstractDetectionLayer):
    """SLOW layer: fine-tuned DistilBERT injection classifier.

    Only active when BOTH transformers/torch are installed AND a fine-tuned
    checkpoint is configured (via the ANTIVENOM_CLASSIFIER_MODEL env var or a
    ``model`` path in layer config). The base ``distilbert-base-uncased`` has a
    randomly-initialized classification head and cannot detect injections, so
    the layer degrades to a non-triggered result rather than loading it.
    """

    name = "classifier"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config = config or {}
        self._threshold: float = self._config.get("threshold", 0.5)
        self._model_path: str | None = self._config.get("model")
        self._classifier: DistilBertClassifier | None = None
        self._load_lock = threading.Lock()

    def _resolve_checkpoint(self) -> str | None:
        # Explicit config path wins, then the env var. No fallback to the base
        # model — an untrained head must never be used for detection.
        return self._model_path or os.environ.get("ANTIVENOM_CLASSIFIER_MODEL")

    def _get_classifier(self, checkpoint: str) -> DistilBertClassifier:
        if self._classifier is None:
            with self._load_lock:
                if self._classifier is None:
                    self._classifier = DistilBertClassifier(model_name_or_path=checkpoint)
        return self._classifier

    def _skip(self, reason: str, start: float) -> LayerResult:
        return LayerResult(
            layer_name=self.name,
            triggered=False,
            confidence=0.0,
            evidence=[reason] if reason else [],
            duration_ms=(time.perf_counter() - start) * 1000,
        )

    async def scan(self, chunk: Chunk) -> LayerResult:
        start = time.perf_counter()

        if not DistilBertClassifier.is_available():
            return self._skip("classifier unavailable: install antivenom[classifier]", start)

        checkpoint = self._resolve_checkpoint()
        if not checkpoint:
            return self._skip(
                "classifier inactive: no fine-tuned model configured "
                "(set ANTIVENOM_CLASSIFIER_MODEL)",
                start,
            )

        clf = self._get_classifier(checkpoint)
        loop = asyncio.get_event_loop()
        is_injection, confidence = await loop.run_in_executor(None, clf.predict, chunk.text)

        # Cap at 0.95 to leave headroom for the LLM judge layer.
        capped = min(confidence, 0.95)
        triggered = is_injection and confidence >= self._threshold
        evidence: list[str] = []
        if triggered:
            evidence.append(f"DistilBERT: {confidence:.2%} injection probability")

        return LayerResult(
            layer_name=self.name,
            triggered=triggered,
            confidence=capped if triggered else confidence,
            evidence=evidence,
            duration_ms=(time.perf_counter() - start) * 1000,
        )
