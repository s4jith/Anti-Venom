from __future__ import annotations

import re
import time
from typing import Any

from antivenom.core.chunk import Chunk
from antivenom.core.result import LayerResult
from antivenom.layers.base import AbstractDetectionLayer

# Known adversarial phrases — ordered by severity weight (highest first)
_PHRASES: list[tuple[str, float]] = [
    # Direct injection
    (r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|directions?)", 0.97),
    (r"disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|directions?)", 0.97),
    (r"forget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|directions?)", 0.95),
    (r"override\s+(your\s+)?(instructions?|programming|training|directives?)", 0.95),
    # Role override
    (r"you\s+are\s+now\s+(DAN|jailbreak|an?\s+AI\s+with\s+no\s+restrictions?)", 0.98),
    (r"pretend\s+you\s+(have\s+no\s+restrictions?|are\s+not\s+an?\s+AI|can\s+do\s+anything)", 0.96),
    (r"act\s+as\s+(if\s+you\s+(have\s+no|without)\s+(restrictions?|limitations?|rules?))", 0.95),
    (r"you\s+are\s+no\s+longer\s+bound\s+by", 0.95),
    (r"DAN\s+mode", 0.98),
    (r"jailbreak\s+mode", 0.97),
    # System prompt extraction
    (r"(repeat|output|print|reveal|display|show|echo)\s+(your\s+)?(system\s+prompt|initial\s+instructions?|original\s+prompt|base\s+prompt)", 0.96),
    (r"what\s+(are\s+)?your\s+(system\s+)?instructions?", 0.75),
    (r"(tell|show)\s+me\s+(your\s+)?(system\s+prompt|hidden\s+instructions?)", 0.90),
    # Instruction boundary markers
    (r"</?(system|instruction|prompt)>", 0.85),
    (r"\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>", 0.90),
    (r"###\s*(Instruction|System|Human|Assistant)\s*:", 0.75),
    # Generic override attempts
    (r"from\s+now\s+on\s+(you\s+)?(will|must|should|shall)\s+(ignore|disregard|forget)", 0.93),
    (r"new\s+(prime\s+)?directive\s*:", 0.80),
    (r"(your\s+new\s+|override\s+)(instructions?|rules?|guidelines?)\s*(are|is)\s*:", 0.88),
    (r"stop\s+being\s+(an?\s+)?(AI|assistant|language\s+model)", 0.85),
    # Fictional framing jailbreaks
    (r"(in\s+this\s+fiction|hypothetically\s+speaking|for\s+a\s+story)\s*[,:]?\s*(ignore|bypass|override)", 0.88),
    (r"imagine\s+(you\s+are|there\s+(are|is)\s+no)\s+(restrictions?|limitations?|rules?|guidelines?)", 0.87),
]

_COMPILED: list[tuple[re.Pattern[str], float]] = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), weight)
    for p, weight in _PHRASES
]

# Cap regex scan length to bound worst-case time on pathological/huge inputs.
# RAG chunks are typically a few hundred to a few thousand characters.
_MAX_SCAN_CHARS = 100_000


class PatternLayer(AbstractDetectionLayer):
    """Layer 1 (FAST): regex/phrase matching against known injection patterns."""

    name = "pattern"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config = config or {}

    async def scan(self, chunk: Chunk) -> LayerResult:
        start = time.perf_counter()
        text = chunk.text[:_MAX_SCAN_CHARS]
        matched: list[tuple[str, float]] = []

        for pattern, weight in _COMPILED:
            m = pattern.search(text)
            if m:
                matched.append((m.group(0)[:100], weight))

        triggered = len(matched) > 0
        confidence = max((w for _, w in matched), default=0.0) if triggered else 0.0
        evidence = [f'"{phrase}" (confidence={w:.2f})' for phrase, w in matched[:5]]

        return LayerResult(
            layer_name=self.name,
            triggered=triggered,
            confidence=confidence,
            evidence=evidence,
            duration_ms=(time.perf_counter() - start) * 1000,
        )
