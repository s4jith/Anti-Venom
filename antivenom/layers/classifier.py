from __future__ import annotations
import asyncio
import time
from typing import Any
from antivenom.core.chunk import Chunk
from antivenom.core.result import LayerResult
from antivenom.layers.base import AbstractDetectionLayer
from antivenom.models.distilbert import DistilBertClassifier


class ClassifierLayer(AbstractDetectionLayer):
    name = "classifier"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config = config or {}
        self._threshold: float = self._config.get("threshold", 0.5)
        self._classifier: DistilBertClassifier | None = None

    def _get_classifier(self) -> DistilBertClassifier:
        if self._classifier is None:
            self._classifier = DistilBertClassifier()
        return self._classifier

    async def scan(self, chunk: Chunk) -> LayerResult:
        start = time.perf_counter()

        if not DistilBertClassifier.is_available():
            return LayerResult(
                layer_name=self.name,
                triggered=False,
                confidence=0.0,
                evidence=[],
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        clf = self._get_classifier()
        loop = asyncio.get_event_loop()
        is_injection, confidence = await loop.run_in_executor(None, clf.predict, chunk.text)

        # Cap at 0.95 to leave headroom for LLM judge layer
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
