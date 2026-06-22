from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

# Key under which a sealed label is stored inside chunk.metadata.
METADATA_KEY = "antivenom_trust"


class TrustTier(str, Enum):
    """Coarse trust classification carried by every sealed chunk.

    Ordering (least to most trusted): QUARANTINED < UNTRUSTED < TRUSTED < VERIFIED.
    """

    QUARANTINED = "quarantined"
    UNTRUSTED = "untrusted"
    TRUSTED = "trusted"
    VERIFIED = "verified"


# Rank used to *cap* a derived tier by a source's ceiling tier (a clean scan must
# never promote web content above what its source reputation allows).
_TIER_ORDER = [TrustTier.QUARANTINED, TrustTier.UNTRUSTED, TrustTier.TRUSTED, TrustTier.VERIFIED]
_TIER_RANK = {t: i for i, t in enumerate(_TIER_ORDER)}


def tier_for_score(score: float) -> TrustTier:
    """Map a final trust score to a tier (before capping by source ceiling)."""
    if score >= 0.85:
        return TrustTier.VERIFIED
    if score >= 0.6:
        return TrustTier.TRUSTED
    return TrustTier.UNTRUSTED


def cap_tier(derived: TrustTier, ceiling: TrustTier) -> TrustTier:
    """Return the lower-trust of two tiers (source reputation is a ceiling)."""
    return derived if _TIER_RANK[derived] <= _TIER_RANK[ceiling] else ceiling


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class TrustLabel:
    """Signed provenance label bound to a chunk and carried through the vector store.

    `canonical_payload()` is the exact byte-string the signature covers — every
    field except `signature` itself. The label is tamper-evident: changing any
    signed field after sealing invalidates the HMAC.
    """

    trust_score: float
    tier: TrustTier
    source_id: str = ""
    source_type: str = ""
    scan_verdict: str = "unknown"  # clean | suspicious | malicious | unknown
    scan_confidence: float = 0.0
    sealed_at: str = field(default_factory=_now_iso)
    signature: str = ""
    key_id: str = ""

    def canonical_payload(self) -> str:
        """Deterministic JSON of all signed fields (everything but the signature)."""
        return json.dumps(
            {
                "trust_score": round(self.trust_score, 6),
                "tier": self.tier.value,
                "source_id": self.source_id,
                "source_type": self.source_type,
                "scan_verdict": self.scan_verdict,
                "scan_confidence": round(self.scan_confidence, 6),
                "sealed_at": self.sealed_at,
                "key_id": self.key_id,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    def to_metadata(self) -> dict:
        """Flat dict stored under chunk.metadata[METADATA_KEY]."""
        return {
            "trust_score": self.trust_score,
            "tier": self.tier.value,
            "source_id": self.source_id,
            "source_type": self.source_type,
            "scan_verdict": self.scan_verdict,
            "scan_confidence": self.scan_confidence,
            "sealed_at": self.sealed_at,
            "signature": self.signature,
            "key_id": self.key_id,
        }

    @classmethod
    def from_metadata(cls, meta: dict | None) -> TrustLabel | None:
        """Rebuild a label from either a full chunk metadata dict (looks up
        METADATA_KEY) or a flat label dict. Returns None if no label is present."""
        if not meta:
            return None
        data = meta.get(METADATA_KEY) if METADATA_KEY in meta else meta
        if not isinstance(data, dict) or "tier" not in data:
            return None
        try:
            tier = TrustTier(data.get("tier", "untrusted"))
        except ValueError:
            tier = TrustTier.UNTRUSTED
        return cls(
            trust_score=float(data.get("trust_score", 0.0)),
            tier=tier,
            source_id=str(data.get("source_id", "")),
            source_type=str(data.get("source_type", "")),
            scan_verdict=str(data.get("scan_verdict", "unknown")),
            scan_confidence=float(data.get("scan_confidence", 0.0)),
            sealed_at=str(data.get("sealed_at", "")),
            signature=str(data.get("signature", "")),
            key_id=str(data.get("key_id", "")),
        )
