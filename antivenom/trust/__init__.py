"""antivenom.trust — the Trust Plane for RAG.

A vector database destroys provenance: once a chunk is embedded, "where did this
come from / who vouches for it / did it try to inject" is lost, and at retrieval a
hostile web scrape is indistinguishable from a verified manual. This package binds
a **signed trust label** to every chunk at ingestion and enforces an
**information-flow policy** at retrieval — so even an injection the detector missed
is contained, because its *source* was untrusted.

Two calls:
    sealed = seal_chunk(chunk, source_type="web", registry=reg, sealer=sealer,
                        scan_result=scanner.scan_text(chunk.text))
    result = TrustGate(sealer, FlowPolicy()).gate(retrieved_items)
"""
from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from antivenom.core.chunk import Chunk
from antivenom.trust.label import (
    METADATA_KEY,
    TrustLabel,
    TrustTier,
    cap_tier,
    tier_for_score,
)
from antivenom.trust.manifest import ItemProvenance, ProvenanceManifest
from antivenom.trust.policy import (
    FlowAction,
    FlowPolicy,
    GatedItem,
    GateResult,
    KeptItem,
    TrustGate,
)
from antivenom.trust.registry import SourceRegistry, SourceRule
from antivenom.trust.sealer import TrustSealer
from antivenom.trust.spotlight import spotlight

if TYPE_CHECKING:
    from antivenom.core.result import ScanResult

# A flagged scan downgrades trust: malicious zeroes it (quarantine), suspicious
# heavily discounts it, clean leaves the source's reputation intact.
_SCAN_FACTOR = {"clean": 1.0, "suspicious": 0.4, "malicious": 0.0}


def _verdict(scan_result: ScanResult | None) -> tuple[str, float, float]:
    """Return (verdict, scan_confidence, trust_factor)."""
    if scan_result is None:
        return "unknown", 0.0, 1.0
    verdict = scan_result.severity.value
    return verdict, scan_result.confidence, _SCAN_FACTOR.get(verdict, 1.0)


def seal_chunk(
    chunk: Chunk,
    *,
    sealer: TrustSealer,
    source_type: str = "",
    registry: SourceRegistry | None = None,
    scan_result: ScanResult | None = None,
) -> Chunk:
    """Compute a trust label for `chunk`, sign it, and return a copy of the chunk
    with the sealed label stored under metadata[METADATA_KEY].

    Trust = source reputation × scan factor. A malicious scan quarantines the
    chunk regardless of how reputable its source is; source reputation also caps
    how high a clean scan can lift the tier (a clean web page never becomes
    VERIFIED).
    """
    registry = registry or SourceRegistry()
    base_score, base_tier = registry.base_trust(chunk.source_id, source_type)
    verdict, confidence, factor = _verdict(scan_result)
    final_score = round(base_score * factor, 6)

    if verdict == "malicious":
        tier = TrustTier.QUARANTINED
    else:
        tier = cap_tier(tier_for_score(final_score), base_tier)

    label = sealer.seal(
        TrustLabel(
            trust_score=final_score,
            tier=tier,
            source_id=chunk.source_id,
            source_type=source_type,
            scan_verdict=verdict,
            scan_confidence=confidence,
        )
    )
    new_meta = dict(chunk.metadata)
    new_meta[METADATA_KEY] = label.to_metadata()
    return replace(chunk, metadata=new_meta)


__all__ = [
    "METADATA_KEY",
    "TrustLabel",
    "TrustTier",
    "tier_for_score",
    "cap_tier",
    "TrustSealer",
    "SourceRegistry",
    "SourceRule",
    "spotlight",
    "FlowAction",
    "FlowPolicy",
    "TrustGate",
    "GatedItem",
    "GateResult",
    "KeptItem",
    "ItemProvenance",
    "ProvenanceManifest",
    "seal_chunk",
]
