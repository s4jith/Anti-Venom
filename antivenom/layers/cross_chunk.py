from __future__ import annotations
import re
import time
from typing import Any
from antivenom.core.chunk import Chunk
from antivenom.core.result import LayerResult
from antivenom.layers.base import AbstractDetectionLayer

# Attack phrases that might be split across chunk boundaries.
# We scan the concatenated boundary region (end of chunk N + start of chunk N+1).
_BOUNDARY_PATTERNS: list[tuple[str, float]] = [
    (r"ignore\s+.{0,30}(previous|prior|above)\s+.{0,30}(instructions?|context|prompts?)", 0.92),
    (r"you\s+are\s+now\s+.{0,20}(DAN|uncensored|unrestricted|free)", 0.93),
    (r"(forget|disregard)\s+.{0,30}(everything|all|prior)", 0.88),
    (r"new\s+.{0,15}(directive|instruction|rule|command)\s*:", 0.82),
    (r"(override|bypass)\s+.{0,20}(your\s+)?(guidelines?|restrictions?|training)", 0.90),
    (r"(system|instruction)\s*prompt\s*[:=]", 0.85),
    (r"before\s+.{0,20}answering.{0,30}(send|forward|transmit|post)", 0.93),
    (r"(output|reveal|expose|echo)\s+.{0,20}(api\s+key|secret|token|password)", 0.95),
]

_COMPILED_BOUNDARY = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), w)
    for p, w in _BOUNDARY_PATTERNS
]

# How many characters from each side of the boundary to scan
_BOUNDARY_WINDOW = 150


class CrossChunkLayer(AbstractDetectionLayer):
    """Layer 5 (MEDIUM): detects injection payloads split across chunk boundaries.

    This layer requires a batch of chunks from the same document to be meaningful.
    When scanning a single chunk it operates on an internal overlap window only.
    In batch mode (called from scanner.ascan_batch with context), it scans
    the concatenated tail+head of adjacent chunks.
    """

    name = "cross_chunk"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config = config or {}
        self._window: int = self._config.get("boundary_window", _BOUNDARY_WINDOW)

    async def scan(self, chunk: Chunk) -> LayerResult:
        """Single-chunk scan: look for patterns in the first and last windows of the chunk."""
        start = time.perf_counter()
        # For single chunk: scan head and tail independently (catches intra-chunk splits)
        head = chunk.text[: self._window]
        tail = chunk.text[-self._window :]
        boundary_text = tail + " " + head  # simulate boundary with itself
        return self._scan_boundary(boundary_text, start)

    async def scan_pair(self, chunk_a: Chunk, chunk_b: Chunk) -> LayerResult:
        """Scan the boundary between two adjacent chunks."""
        start = time.perf_counter()
        tail_a = chunk_a.text[-self._window :]
        head_b = chunk_b.text[: self._window]
        boundary_text = tail_a + " " + head_b
        return self._scan_boundary(boundary_text, start)

    def _scan_boundary(self, boundary_text: str, start: float) -> LayerResult:
        matched: list[tuple[str, float]] = []
        for pattern, weight in _COMPILED_BOUNDARY:
            m = pattern.search(boundary_text)
            if m:
                matched.append((m.group(0)[:100], weight))

        triggered = len(matched) > 0
        confidence = max((w for _, w in matched), default=0.0) if triggered else 0.0
        evidence = [f'boundary: "{phrase}" ({w:.2f})' for phrase, w in matched[:3]]

        return LayerResult(
            layer_name=self.name,
            triggered=triggered,
            confidence=confidence,
            evidence=evidence,
            duration_ms=(time.perf_counter() - start) * 1000,
        )
