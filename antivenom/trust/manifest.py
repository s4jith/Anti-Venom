from __future__ import annotations

from dataclasses import dataclass, field

from antivenom.trust.label import TrustTier


@dataclass(frozen=True)
class ItemProvenance:
    """What happened to one retrieved item as it passed through the TrustGate."""

    source_id: str
    tier: TrustTier
    trust_score: float
    action: str  # FlowAction value: allow | downrank | neutralize | drop
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "source_id": self.source_id,
            "tier": self.tier.value,
            "trust_score": self.trust_score,
            "action": self.action,
            "reason": self.reason,
        }


@dataclass
class ProvenanceManifest:
    """Audit record of a single retrieval: every item, its trust, and the action
    taken — plus the aggregate signals an application needs to decide how much to
    trust the answer it is about to generate."""

    items: list[ItemProvenance] = field(default_factory=list)
    authoritative_trust: float = 0.0
    contains_untrusted: bool = False

    @classmethod
    def from_items(cls, items: list[ItemProvenance]) -> ProvenanceManifest:
        authoritative = [i for i in items if i.action == "allow"]
        auth_trust = min((i.trust_score for i in authoritative), default=0.0)
        contains_untrusted = any(
            i.action in ("neutralize", "downrank")
            or i.tier in (TrustTier.UNTRUSTED, TrustTier.QUARANTINED)
            for i in items
        )
        return cls(
            items=list(items),
            authoritative_trust=auth_trust,
            contains_untrusted=contains_untrusted,
        )

    def to_dict(self) -> dict:
        return {
            "authoritative_trust": self.authoritative_trust,
            "contains_untrusted": self.contains_untrusted,
            "items": [i.to_dict() for i in self.items],
        }

    def explain(self) -> str:
        lines = [f"Provenance manifest: {len(self.items)} item(s)"]
        for i in self.items:
            lines.append(
                f"  - {i.source_id or '<unknown>':<32} "
                f"{i.tier.value:<11} trust {i.trust_score:.2f}  -> {i.action}"
                + (f"  ({i.reason})" if i.reason else "")
            )
        lines.append(f"Authoritative trust floor: {self.authoritative_trust:.2f}")
        lines.append(f"Contains untrusted content: {'yes' if self.contains_untrusted else 'no'}")
        return "\n".join(lines)
