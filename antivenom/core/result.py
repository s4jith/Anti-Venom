from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


@dataclass
class LayerResult:
    layer_name: str
    triggered: bool
    confidence: float
    evidence: list[str] = field(default_factory=list)
    duration_ms: float = 0.0


@dataclass
class ScanResult:
    chunk_id: str
    is_poisoned: bool
    confidence: float
    severity: Severity
    layer_results: list[LayerResult] = field(default_factory=list)
    scan_duration_ms: float = 0.0
    from_cache: bool = False

    @classmethod
    def clean(cls, chunk_id: str, layer_results: list[LayerResult] | None = None, duration_ms: float = 0.0) -> ScanResult:
        return cls(
            chunk_id=chunk_id,
            is_poisoned=False,
            confidence=0.0,
            severity=Severity.CLEAN,
            layer_results=layer_results or [],
            scan_duration_ms=duration_ms,
        )

    @classmethod
    def poisoned(cls, chunk_id: str, confidence: float, layer_results: list[LayerResult], duration_ms: float = 0.0) -> ScanResult:
        severity = Severity.MALICIOUS if confidence >= 0.75 else Severity.SUSPICIOUS
        return cls(
            chunk_id=chunk_id,
            is_poisoned=True,
            confidence=confidence,
            severity=severity,
            layer_results=layer_results,
            scan_duration_ms=duration_ms,
        )
