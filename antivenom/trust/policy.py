from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from antivenom.trust.label import TrustLabel, TrustTier
from antivenom.trust.manifest import ItemProvenance, ProvenanceManifest
from antivenom.trust.sealer import TrustSealer
from antivenom.trust.spotlight import spotlight

# A retrieved item to gate: (source_id, text, metadata). The 2-tuple form
# (text, metadata) is also accepted, with source_id read from the label.
GatedItem = tuple


class FlowAction(str, Enum):
    ALLOW = "allow"  # passes through, may be authoritative
    DOWNRANK = "downrank"  # kept but never authoritative (sorted last)
    NEUTRALIZE = "neutralize"  # kept but spotlighted into inert data
    DROP = "drop"  # removed from the context entirely


@dataclass
class FlowPolicy:
    """Declarative information-flow policy enforced at retrieval time.

    Defaults fail closed: unsigned or tampered chunks are dropped, quarantined
    chunks are dropped, and untrusted chunks are neutralized (spotlighted) rather
    than silently trusted.
    """

    min_authoritative_trust: float = 0.7
    on_untrusted: FlowAction = FlowAction.NEUTRALIZE
    on_quarantined: FlowAction = FlowAction.DROP
    require_signature: bool = True
    on_unsigned: FlowAction = FlowAction.DROP


@dataclass
class KeptItem:
    source_id: str
    text: str  # possibly spotlighted
    metadata: dict
    trust_score: float
    tier: TrustTier
    is_authoritative: bool
    action: FlowAction


@dataclass
class GateResult:
    kept: list[KeptItem]
    dropped: list[ItemProvenance]
    manifest: ProvenanceManifest

    @property
    def texts(self) -> list[str]:
        """Context-ready texts in trust order (authoritative first)."""
        return [k.text for k in self.kept]

    @property
    def authoritative_texts(self) -> list[str]:
        return [k.text for k in self.kept if k.is_authoritative]


def _unpack(item: GatedItem) -> tuple[str, str, dict]:
    if len(item) == 3:
        source_id, text, metadata = item
        return str(source_id), str(text), dict(metadata or {})
    if len(item) == 2:
        text, metadata = item
        meta = dict(metadata or {})
        label = TrustLabel.from_metadata(meta)
        return (label.source_id if label else ""), str(text), meta
    raise ValueError("GatedItem must be (source_id, text, metadata) or (text, metadata)")


class TrustGate:
    """Enforces a FlowPolicy over retrieved chunks.

    For each item it verifies the signed label, decides an action from the trust
    tier, and either drops it, neutralizes it (spotlight), down-ranks it, or lets
    it through as authoritative. Returns the surviving context plus a
    ProvenanceManifest describing every decision.
    """

    def __init__(self, sealer: TrustSealer | None, policy: FlowPolicy | None = None) -> None:
        self.sealer = sealer
        self.policy = policy or FlowPolicy()

    def _decide(self, label: TrustLabel | None) -> tuple[FlowAction, TrustTier, float, str]:
        verified = bool(label and self.sealer and self.sealer.verify(label))
        if label is None:
            return self.policy.on_unsigned, TrustTier.UNTRUSTED, 0.0, "unsigned"
        if self.policy.require_signature and not verified:
            reason = "tampered/invalid-signature" if label.signature else "unsigned"
            return self.policy.on_unsigned, TrustTier.QUARANTINED, 0.0, reason
        if label.tier == TrustTier.QUARANTINED:
            return self.policy.on_quarantined, label.tier, label.trust_score, "quarantined source/scan"
        if label.tier == TrustTier.UNTRUSTED or label.trust_score < self.policy.min_authoritative_trust:
            return self.policy.on_untrusted, label.tier, label.trust_score, "below authoritative trust"
        return FlowAction.ALLOW, label.tier, label.trust_score, "trusted source"

    def gate(self, items: list[GatedItem]) -> GateResult:
        kept: list[KeptItem] = []
        dropped: list[ItemProvenance] = []
        provs: list[ItemProvenance] = []

        for item in items:
            source_id, text, metadata = _unpack(item)
            label = TrustLabel.from_metadata(metadata)
            action, tier, score, reason = self._decide(label)
            provs.append(ItemProvenance(source_id, tier, score, action.value, reason))

            if action == FlowAction.DROP:
                dropped.append(provs[-1])
                continue

            out_text = text
            authoritative = action == FlowAction.ALLOW and score >= self.policy.min_authoritative_trust
            if action == FlowAction.NEUTRALIZE:
                out_text = spotlight(text, source_id=source_id, trust_score=score)
                authoritative = False
            elif action == FlowAction.DOWNRANK:
                authoritative = False
            kept.append(KeptItem(source_id, out_text, metadata, score, tier, authoritative, action))

        # Down-ranking: authoritative content first, then by trust score, stably.
        kept.sort(key=lambda k: (not k.is_authoritative, -k.trust_score))
        return GateResult(kept=kept, dropped=dropped, manifest=ProvenanceManifest.from_items(provs))
