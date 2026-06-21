from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from antivenom.core.finding import Finding, Technique

if TYPE_CHECKING:
    from antivenom.core.report import RiskReport


class Severity(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class LayerResult:
    """Result emitted by a single detection layer.

    `findings` is the source of truth. `evidence` is kept as a derived, read-only
    property (rendering legacy strings) so every pre-v0.4 reader keeps working.
    Construction accepts BOTH the new `findings=[Finding]` and the legacy
    `evidence=[str]` (wrapped as UNKNOWN-technique findings).
    """

    __slots__ = ("layer_name", "triggered", "confidence", "findings", "duration_ms")

    def __init__(
        self,
        layer_name: str,
        triggered: bool,
        confidence: float,
        evidence: list[str] | None = None,
        findings: list[Finding] | None = None,
        duration_ms: float = 0.0,
    ) -> None:
        self.layer_name = layer_name
        self.triggered = triggered
        self.confidence = confidence
        self.duration_ms = duration_ms
        if findings is None and evidence is not None:
            findings = [
                Finding(
                    technique=Technique.UNKNOWN,
                    reason=e,
                    confidence=confidence,
                    layer=layer_name,
                )
                for e in evidence
            ]
        self.findings: list[Finding] = findings or []

    @property
    def evidence(self) -> list[str]:
        return [f.to_evidence_string() for f in self.findings]

    def __repr__(self) -> str:
        return (
            f"LayerResult(layer_name={self.layer_name!r}, triggered={self.triggered}, "
            f"confidence={self.confidence}, findings={len(self.findings)})"
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, LayerResult):
            return NotImplemented
        return (
            self.layer_name == other.layer_name
            and self.triggered == other.triggered
            and self.confidence == other.confidence
            and self.findings == other.findings
        )


@dataclass
class ScanResult:
    chunk_id: str
    is_poisoned: bool
    confidence: float
    severity: Severity
    layer_results: list[LayerResult] = field(default_factory=list)
    scan_duration_ms: float = 0.0
    from_cache: bool = False
    report: RiskReport | None = field(default=None, compare=False)

    @property
    def findings(self) -> list[Finding]:
        return [f for lr in self.layer_results for f in lr.findings]

    def explain(self) -> str:
        """Human-readable rationale. Uses the attached RiskReport if present,
        otherwise a static fallback. The LLM-backed rationale comes from
        AntiVenomScanner.explain(), never from here."""
        if self.report is not None:
            return self.report.explain()
        verdict = self.severity.value.upper()
        if not self.is_poisoned:
            return f"{verdict} (confidence {self.confidence:.2f}); no adversarial content detected."
        techniques = sorted({f.technique.value for f in self.findings})
        return (
            f"{verdict} (confidence {self.confidence:.2f}). "
            f"Techniques: {', '.join(techniques) or 'unknown'}."
        )

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
