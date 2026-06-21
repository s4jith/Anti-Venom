from __future__ import annotations

import re
import time
from typing import Any

from antivenom.core.chunk import Chunk
from antivenom.core.finding import Finding, Technique
from antivenom.core.result import LayerResult
from antivenom.layers.base import AbstractDetectionLayer

_IO = Technique.INSTRUCTION_OVERRIDE
_RO = Technique.ROLE_OVERRIDE
_SPE = Technique.SYSTEM_PROMPT_EXTRACTION
_IB = Technique.INSTRUCTION_BOUNDARY
_JB = Technique.JAILBREAK

# Known adversarial phrases — (regex, severity weight, technique)
_PHRASES: list[tuple[str, float, Technique]] = [
    # Direct injection
    (r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|directions?)", 0.97, _IO),
    (r"disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|directions?)", 0.97, _IO),
    (r"forget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|directions?)", 0.95, _IO),
    (r"override\s+(your\s+)?(instructions?|programming|training|directives?)", 0.95, _IO),
    # Role override
    (r"you\s+are\s+now\s+(DAN|jailbreak|an?\s+AI\s+with\s+no\s+restrictions?)", 0.98, _RO),
    (r"pretend\s+you\s+(have\s+no\s+restrictions?|are\s+not\s+an?\s+AI|can\s+do\s+anything)", 0.96, _RO),
    (r"act\s+as\s+(if\s+you\s+(have\s+no|without)\s+(restrictions?|limitations?|rules?))", 0.95, _RO),
    (r"you\s+are\s+no\s+longer\s+bound\s+by", 0.95, _RO),
    (r"DAN\s+mode", 0.98, _RO),
    (r"jailbreak\s+mode", 0.97, _RO),
    # System prompt extraction
    (r"(repeat|output|print|reveal|display|show|echo)\s+(your\s+)?(system\s+prompt|initial\s+instructions?|original\s+prompt|base\s+prompt)", 0.96, _SPE),
    (r"what\s+(are\s+)?your\s+(system\s+)?instructions?", 0.75, _SPE),
    (r"(tell|show)\s+me\s+(your\s+)?(system\s+prompt|hidden\s+instructions?)", 0.90, _SPE),
    # Instruction boundary markers
    (r"</?(system|instruction|prompt)>", 0.85, _IB),
    (r"\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>", 0.90, _IB),
    (r"###\s*(Instruction|System|Human|Assistant)\s*:", 0.75, _IB),
    # Generic override attempts
    (r"from\s+now\s+on\s+(you\s+)?(will|must|should|shall)\s+(ignore|disregard|forget)", 0.93, _IO),
    (r"new\s+(prime\s+)?directive\s*:", 0.80, _IO),
    (r"(your\s+new\s+|override\s+)(instructions?|rules?|guidelines?)\s*(are|is)\s*:", 0.88, _IO),
    (r"stop\s+being\s+(an?\s+)?(AI|assistant|language\s+model)", 0.85, _RO),
    # Fictional framing jailbreaks
    (r"(in\s+this\s+fiction|hypothetically\s+speaking|for\s+a\s+story)\s*[,:]?\s*(ignore|bypass|override)", 0.88, _JB),
    (r"imagine\s+(you\s+are|there\s+(are|is)\s+no)\s+(restrictions?|limitations?|rules?|guidelines?)", 0.87, _JB),
]

_COMPILED: list[tuple[re.Pattern[str], float, Technique]] = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), weight, tech)
    for p, weight, tech in _PHRASES
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
        findings: list[Finding] = []

        for pattern, weight, technique in _COMPILED:
            m = pattern.search(text)
            if m:
                span = m.group(0)[:100]
                findings.append(Finding(
                    technique=technique,
                    reason=f"matched injection pattern: {span!r}",
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
