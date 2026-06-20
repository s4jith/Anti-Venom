from __future__ import annotations
import re
import time
from typing import Any
from antivenom.core.chunk import Chunk
from antivenom.core.result import LayerResult
from antivenom.layers.base import AbstractDetectionLayer

_EXFIL_PATTERNS: list[tuple[str, float]] = [
    # Secret echo / system prompt leakage
    (r"(echo|output|print|repeat|reveal|send|return|show)\s+(back\s+)?(your\s+)?(system\s+prompt|api\s+key|secret|password|token|credentials?|auth)", 0.97),
    (r"(before|prior to)\s+(answering|responding|replying)\s*[,.]?\s*(send|transmit|forward|post)", 0.95),
    # External URL exfiltration
    (r"(send|post|transmit|fetch|curl|requests?\.(get|post)|http[s]?://\S+)\s*(to|at|via)\s*(http[s]?://|www\.)", 0.96),
    (r"make\s+a\s+(http|web|api)\s+(request|call)\s+to", 0.93),
    (r"(navigate|go)\s+to\s+https?://", 0.90),
    # Credential/data exfiltration
    (r"(include|attach|append)\s+(your|the)\s+(api\s+key|secret|token|password|credentials?)\s+in", 0.97),
    (r"output\s+your\s+(configuration|environment|env\s+var)", 0.92),
    (r"\$\{?[A-Z_]{3,}\}?\s*(=|is|contains)", 0.80),  # env var references
    # Code injection attempts
    (r"(exec|eval|subprocess|os\.system|__import__)\s*\(", 0.95),
    (r"import\s+os\s*;\s*os\.(system|popen|execv)", 0.97),
    # Data extraction markers
    (r"(extract|retrieve|dump)\s+(all\s+)?(data|context|memory|history|conversation|users?|passwords?|credentials?|tokens?|secrets?)", 0.88),
    (r"(list|show|display)\s+(all\s+)?(users?|passwords?|api\s+keys?|secrets?|tokens?)", 0.90),
]

_COMPILED_EXFIL: list[tuple[re.Pattern[str], float]] = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), w)
    for p, w in _EXFIL_PATTERNS
]


class CanaryLayer(AbstractDetectionLayer):
    """Layer 3 (FAST): detects exfiltration attempts and secret-echo instructions."""

    name = "canary"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config = config or {}

    async def scan(self, chunk: Chunk) -> LayerResult:
        start = time.perf_counter()
        text = chunk.text
        matched: list[tuple[str, float]] = []

        for pattern, weight in _COMPILED_EXFIL:
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
