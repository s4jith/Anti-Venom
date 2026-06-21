from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Technique(str, Enum):
    """The specific adversarial technique a finding represents.

    Layers emit findings tagged with a technique so the engine can produce a
    categorized, explainable report instead of an opaque confidence score.
    """

    INSTRUCTION_OVERRIDE = "instruction_override"
    ROLE_OVERRIDE = "role_override"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    INSTRUCTION_BOUNDARY = "instruction_boundary"
    JAILBREAK = "jailbreak"
    EXFILTRATION = "exfiltration"
    CREDENTIAL_THEFT = "credential_theft"
    CODE_INJECTION = "code_injection"
    DATA_EXTRACTION = "data_extraction"
    ENCODING_EVASION = "encoding_evasion"
    SEMANTIC_ANOMALY = "semantic_anomaly"
    STRUCTURAL_ANOMALY = "structural_anomaly"
    CROSS_CHUNK = "cross_chunk"
    UNKNOWN = "unknown"


# Coarse category grouping used for the per-category breakdown in RiskReport.
TECHNIQUE_CATEGORY: dict[Technique, str] = {
    Technique.INSTRUCTION_OVERRIDE: "injection",
    Technique.ROLE_OVERRIDE: "injection",
    Technique.SYSTEM_PROMPT_EXTRACTION: "extraction",
    Technique.INSTRUCTION_BOUNDARY: "injection",
    Technique.JAILBREAK: "injection",
    Technique.EXFILTRATION: "exfiltration",
    Technique.CREDENTIAL_THEFT: "exfiltration",
    Technique.CODE_INJECTION: "exfiltration",
    Technique.DATA_EXTRACTION: "extraction",
    Technique.ENCODING_EVASION: "evasion",
    Technique.SEMANTIC_ANOMALY: "anomaly",
    Technique.STRUCTURAL_ANOMALY: "anomaly",
    Technique.CROSS_CHUNK: "injection",
    Technique.UNKNOWN: "anomaly",
}

# Short remediation hints keyed by coarse category.
CATEGORY_REMEDIATION: dict[str, str] = {
    "injection": "Quarantine the document; do not embed it. The text attempts to "
                 "override the assistant's instructions.",
    "extraction": "Quarantine the document; it attempts to extract the system "
                  "prompt or hidden configuration.",
    "exfiltration": "Quarantine the document; it attempts to exfiltrate data or "
                    "execute commands. Review for leaked secrets.",
    "evasion": "Treat as hostile: the content was obfuscated (encoding/homoglyph/"
               "zero-width) to evade detection.",
    "anomaly": "Review manually; the content shows adversarial structure but no "
               "single deterministic match.",
}


@dataclass(frozen=True)
class Finding:
    """A single categorized detection produced by a layer."""

    technique: Technique
    reason: str
    confidence: float
    layer: str = ""
    matched_span: str = ""
    span_start: int | None = None
    span_end: int | None = None
    # Which form of the text this matched: "raw", "normalized", "decoded:base64", ...
    form: str = "raw"

    @property
    def category(self) -> str:
        return TECHNIQUE_CATEGORY.get(self.technique, "anomaly")

    def to_evidence_string(self) -> str:
        """Legacy-compatible rendering used by the derived LayerResult.evidence."""
        span = self.matched_span or self.reason
        suffix = "" if self.form == "raw" else f" [{self.form}]"
        return f'"{span}" (confidence={self.confidence:.2f}){suffix}'

    def to_dict(self) -> dict:
        return {
            "technique": self.technique.value,
            "reason": self.reason,
            "confidence": self.confidence,
            "layer": self.layer,
            "matched_span": self.matched_span,
            "span_start": self.span_start,
            "span_end": self.span_end,
            "form": self.form,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Finding:
        return cls(
            technique=Technique(d.get("technique", "unknown")),
            reason=d.get("reason", ""),
            confidence=float(d.get("confidence", 0.0)),
            layer=d.get("layer", ""),
            matched_span=d.get("matched_span", ""),
            span_start=d.get("span_start"),
            span_end=d.get("span_end"),
            form=d.get("form", "raw"),
        )
