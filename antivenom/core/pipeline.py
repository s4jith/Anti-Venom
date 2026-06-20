from __future__ import annotations
import asyncio
import time
from typing import TYPE_CHECKING

from antivenom.core.chunk import Chunk
from antivenom.core.result import LayerResult, ScanResult, Severity
from antivenom.core.config import ScannerConfig

if TYPE_CHECKING:
    from antivenom.layers.base import AbstractDetectionLayer


class DetectionPipeline:
    """Runs FAST → MEDIUM → SLOW stages with short-circuit on high confidence."""

    def __init__(
        self,
        fast_layers: list["AbstractDetectionLayer"],
        medium_layers: list["AbstractDetectionLayer"] | None = None,
        slow_layers: list["AbstractDetectionLayer"] | None = None,
        config: ScannerConfig | None = None,
    ) -> None:
        self.fast_layers = fast_layers
        self.medium_layers = medium_layers or []
        self.slow_layers = slow_layers or []
        self.config = config or ScannerConfig()

    async def run(self, chunk: Chunk) -> tuple[bool, float, list[LayerResult]]:
        """Returns (is_poisoned, max_confidence, all_layer_results)."""
        all_results: list[LayerResult] = []
        threshold = self.config.short_circuit_threshold

        # FAST — all in parallel
        fast_results = await asyncio.gather(
            *[layer.scan(chunk) for layer in self.fast_layers],
            return_exceptions=False,
        )
        all_results.extend(fast_results)
        max_conf = max((r.confidence for r in fast_results if r.triggered), default=0.0)
        if max_conf >= threshold:
            return True, max_conf, all_results

        # MEDIUM — parallel
        if self.medium_layers:
            medium_results = await asyncio.gather(
                *[layer.scan(chunk) for layer in self.medium_layers],
                return_exceptions=False,
            )
            all_results.extend(medium_results)
            med_conf = max((r.confidence for r in medium_results if r.triggered), default=0.0)
            max_conf = max(max_conf, med_conf)
            if max_conf >= threshold:
                return True, max_conf, all_results

        # SLOW — sequential
        for layer in self.slow_layers:
            result = await layer.scan(chunk)
            all_results.append(result)
            if result.triggered:
                max_conf = max(max_conf, result.confidence)
            if max_conf >= threshold:
                break

        is_poisoned = max_conf >= self.config.confidence_threshold
        return is_poisoned, max_conf, all_results
