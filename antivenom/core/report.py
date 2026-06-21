from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from antivenom.core.finding import CATEGORY_REMEDIATION, Finding, Technique
from antivenom.core.result import Severity

if TYPE_CHECKING:
    from antivenom.core.result import ScanResult


@dataclass
class CategoryBreakdown:
    category: str
    techniques: list[Technique]
    max_confidence: float
    count: int

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "techniques": [t.value for t in self.techniques],
            "max_confidence": self.max_confidence,
            "count": self.count,
        }


@dataclass
class RiskReport:
    """An actionable, categorized view over a ScanResult.

    Wraps (does not replace) ScanResult. Built via from_scan(); attached to
    ScanResult.report. The deterministic explain() uses no LLM.
    """

    risk_level: Severity
    confidence: float
    is_poisoned: bool
    top_reason: str
    categories: list[CategoryBreakdown]
    findings: list[Finding]
    classifier_confidence: float | None = None
    normalized_forms: list[str] = field(default_factory=list)
    remediation: str = ""
    layers_triggered: list[str] = field(default_factory=list)
    llm_rationale: str | None = None

    @classmethod
    def from_scan(cls, result: ScanResult) -> RiskReport:
        findings = result.findings

        # Per-category breakdown.
        by_cat: dict[str, list[Finding]] = {}
        for f in findings:
            if not f.matched_span and f.confidence == 0.0:
                continue
            by_cat.setdefault(f.category, []).append(f)
        categories = [
            CategoryBreakdown(
                category=cat,
                techniques=sorted({f.technique for f in fs}, key=lambda t: t.value),
                max_confidence=max((f.confidence for f in fs), default=0.0),
                count=len(fs),
            )
            for cat, fs in by_cat.items()
        ]
        # Most severe category first, so categories[0] drives the remediation hint.
        categories.sort(key=lambda c: c.max_confidence, reverse=True)

        # Top reason = highest-confidence meaningful finding.
        meaningful = [f for f in findings if f.reason and f.confidence > 0]
        top = max(meaningful, key=lambda f: f.confidence, default=None)
        top_reason = top.reason if top else ("No adversarial content detected."
                                             if not result.is_poisoned else "Adversarial content detected.")

        classifier_conf = next(
            (lr.confidence for lr in result.layer_results if lr.layer_name == "classifier" and lr.triggered),
            None,
        )
        normalized_forms = sorted({f.form for f in findings if f.form != "raw"})
        top_category = categories[0].category if categories else "anomaly"
        remediation = CATEGORY_REMEDIATION.get(top_category, "") if result.is_poisoned else ""
        layers = sorted({lr.layer_name for lr in result.layer_results if lr.triggered})

        return cls(
            risk_level=result.severity,
            confidence=result.confidence,
            is_poisoned=result.is_poisoned,
            top_reason=top_reason,
            categories=categories,
            findings=findings,
            classifier_confidence=classifier_conf,
            normalized_forms=normalized_forms,
            remediation=remediation,
            layers_triggered=layers,
        )

    def to_dict(self) -> dict:
        return {
            "risk_level": self.risk_level.value,
            "confidence": self.confidence,
            "is_poisoned": self.is_poisoned,
            "top_reason": self.top_reason,
            "categories": [c.to_dict() for c in self.categories],
            "findings": [f.to_dict() for f in self.findings],
            "classifier_confidence": self.classifier_confidence,
            "normalized_forms": self.normalized_forms,
            "remediation": self.remediation,
            "layers_triggered": self.layers_triggered,
            "llm_rationale": self.llm_rationale,
        }

    def explain(self) -> str:
        lines = [f"Risk Level: {self.risk_level.value.upper()}  (confidence {self.confidence:.2f})"]
        if self.categories:
            lines.append("")
            lines.append("Matched categories:")
            for c in self.categories:
                techs = ", ".join(t.value for t in c.techniques)
                lines.append(f"  - {c.category}: {techs}  (max {c.max_confidence:.2f})")
        if self.classifier_confidence is not None:
            lines.append("")
            lines.append(f"Classifier confidence: {self.classifier_confidence:.1%}")
        if self.normalized_forms:
            lines.append("")
            lines.append(f"Evasion detected via: {', '.join(self.normalized_forms)}")
        lines.append("")
        lines.append(f"Reason: {self.top_reason}")
        if self.llm_rationale:
            lines.append("")
            lines.append(f"LLM rationale: {self.llm_rationale}")
        if self.remediation:
            lines.append("")
            lines.append(f"Remediation: {self.remediation}")
        return "\n".join(lines)
