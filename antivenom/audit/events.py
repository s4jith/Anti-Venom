from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class AuditEvent:
    event_id: str
    timestamp: str
    chunk_id: str
    source_id: str
    verdict: str          # "clean" | "suspicious" | "malicious"
    confidence: float
    layers_triggered: list[str]
    evidence_summary: list[str]
    metadata: dict = field(default_factory=dict)

    @classmethod
    def now(cls, **kwargs) -> AuditEvent:
        return cls(
            timestamp=datetime.now(timezone.utc).isoformat(),
            **kwargs,
        )
