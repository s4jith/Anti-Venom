from __future__ import annotations

import re
import time
from typing import Any

from antivenom.core.chunk import Chunk
from antivenom.core.finding import Finding, Technique
from antivenom.core.result import LayerResult
from antivenom.layers.base import AbstractDetectionLayer

_EX = Technique.EXFILTRATION
_CT = Technique.CREDENTIAL_THEFT
_CI = Technique.CODE_INJECTION
_DE = Technique.DATA_EXTRACTION

_EXFIL_PATTERNS: list[tuple[str, float, Technique]] = [
    # Secret echo / system prompt leakage
    (r"(echo|output|print|repeat|reveal|send|return|show)\s+(back\s+)?(your\s+)?(system\s+prompt|api\s+key|secret|password|token|credentials?|auth)", 0.97, _EX),
    (r"(before|prior to)\s+(answering|responding|replying)\s*[,.]?\s*(send|transmit|forward|post)", 0.95, _EX),
    # External URL exfiltration
    (r"(send|post|transmit|fetch|curl|requests?\.(get|post)|http[s]?://\S+)\s*(to|at|via)\s*(http[s]?://|www\.)", 0.96, _EX),
    (r"make\s+a\s+(http|web|api)\s+(request|call)\s+to", 0.93, _EX),
    (r"(navigate|go)\s+to\s+https?://", 0.90, _EX),
    # Credential/data exfiltration
    (r"(include|attach|append)\s+(your|the)\s+(api\s+key|secret|token|password|credentials?)\s+in", 0.97, _CT),
    (r"output\s+your\s+(configuration|environment|env\s+var)", 0.92, _CT),
    (r"\$\{?[A-Z_]{3,}\}?\s*(=|is|contains)", 0.80, _CT),  # env var references
    # Code injection attempts
    (r"(exec|eval|subprocess|os\.system|__import__)\s*\(", 0.95, _CI),
    (r"import\s+os\s*;\s*os\.(system|popen|execv)", 0.97, _CI),
    # Data extraction markers
    (r"(extract|retrieve|dump)\s+(all\s+)?(data|context|memory|history|conversation|users?|passwords?|credentials?|tokens?|secrets?)", 0.88, _DE),
    (r"(list|show|display)\s+(all\s+)?(users?|passwords?|api\s+keys?|secrets?|tokens?)", 0.90, _DE),
]

_COMPILED_EXFIL: list[tuple[re.Pattern[str], float, Technique]] = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), w, tech)
    for p, w, tech in _EXFIL_PATTERNS
]

# Cap regex scan length to bound worst-case time on pathological/huge inputs.
_MAX_SCAN_CHARS = 100_000


class CanaryLayer(AbstractDetectionLayer):
    """Layer 3 (FAST): detects exfiltration attempts and secret-echo instructions."""

    name = "canary"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config = config or {}

    async def scan(self, chunk: Chunk) -> LayerResult:
        start = time.perf_counter()
        text = chunk.text[:_MAX_SCAN_CHARS]
        findings: list[Finding] = []

        for pattern, weight, technique in _COMPILED_EXFIL:
            m = pattern.search(text)
            if m:
                span = m.group(0)[:100]
                findings.append(Finding(
                    technique=technique,
                    reason=f"matched exfiltration pattern: {span!r}",
                    confidence=weight,
                    layer=self.name,
                    matched_span=span,
                    span_start=m.start(),
                    span_end=m.end(),
                ))

        triggered = len(findings) > 0
        confidence = max((f.confidence for f in findings), default=0.0)

        return LayerResult(
            layer_name=self.name,
            triggered=triggered,
            confidence=confidence,
            findings=findings[:5],
            duration_ms=(time.perf_counter() - start) * 1000,
        )
