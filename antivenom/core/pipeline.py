from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

from antivenom.core.chunk import Chunk
from antivenom.core.config import ScannerConfig
from antivenom.core.result import LayerResult

if TYPE_CHECKING:
    from antivenom.layers.base import AbstractDetectionLayer


def _layer_name(layer: AbstractDetectionLayer) -> str:
    try:
        return str(layer.name)
    except Exception:
        return layer.__class__.__name__


class DetectionPipeline:
    """Runs FAST → MEDIUM → SLOW stages with short-circuit on high confidence.

    Fault isolation: every layer call is wrapped so that an exception in one
    layer degrades to a non-triggered result instead of failing the scan.
    """

    def __init__(
        self,
        fast_layers: list[AbstractDetectionLayer],
        medium_layers: list[AbstractDetectionLayer] | None = None,
        slow_layers: list[AbstractDetectionLayer] | None = None,
        config: ScannerConfig | None = None,
    ) -> None:
        self.fast_layers = fast_layers
        self.medium_layers = medium_layers or []
        self.slow_layers = slow_layers or []
        self.config = config or ScannerConfig()

    async def _run_layer(self, layer: AbstractDetectionLayer, chunk: Chunk) -> LayerResult:
        start = time.perf_counter()
        try:
            result = await layer.scan(chunk)
            # Defend against a layer returning something malformed.
            if not isinstance(result, LayerResult):
                raise TypeError(
                    f"layer {_layer_name(layer)} returned {type(result).__name__}, "
                    "expected LayerResult"
                )
            # Clamp confidence into [0, 1] so a buggy layer can't poison aggregation.
            if result.confidence < 0.0 or result.confidence > 1.0:
                result.confidence = max(0.0, min(1.0, result.confidence))
            return result
        except Exception as exc:  # noqa: BLE001 — fault isolation is the whole point
            return LayerResult(
                layer_name=_layer_name(layer),
                triggered=False,
                confidence=0.0,
                evidence=[f"layer error (isolated): {type(exc).__name__}: {exc}"],
                duration_ms=(time.perf_counter() - start) * 1000,
            )

    async def _gather(self, layers: list[AbstractDetectionLayer], chunk: Chunk) -> list[LayerResult]:
        if not layers:
            return []
        return list(await asyncio.gather(*[self._run_layer(layer, chunk) for layer in layers]))

    async def run(self, chunk: Chunk) -> tuple[bool, float, list[LayerResult]]:
        """Returns (is_poisoned, max_confidence, all_layer_results). Never raises."""
        all_results: list[LayerResult] = []
        threshold = self.config.short_circuit_threshold

        # FAST — all in parallel
        fast_results = await self._gather(self.fast_layers, chunk)
        all_results.extend(fast_results)
        max_conf = max((r.confidence for r in fast_results if r.triggered), default=0.0)
        if max_conf >= threshold:
            return True, max_conf, all_results

        # MEDIUM — parallel
        if self.medium_layers:
            medium_results = await self._gather(self.medium_layers, chunk)
            all_results.extend(medium_results)
            med_conf = max((r.confidence for r in medium_results if r.triggered), default=0.0)
            max_conf = max(max_conf, med_conf)
            if max_conf >= threshold:
                return True, max_conf, all_results

        # SLOW — sequential
        for layer in self.slow_layers:
            result = await self._run_layer(layer, chunk)
            all_results.append(result)
            if result.triggered:
                max_conf = max(max_conf, result.confidence)
            if max_conf >= threshold:
                break

        is_poisoned = max_conf >= self.config.confidence_threshold
        return is_poisoned, max_conf, all_results
