from antivenom.trust.label import (
    METADATA_KEY,
    TrustLabel,
    TrustTier,
    cap_tier,
    tier_for_score,
)


def _label(**kw):
    base = dict(trust_score=0.9, tier=TrustTier.TRUSTED, source_id="internal/a.md",
                source_type="internal", scan_verdict="clean", scan_confidence=0.0,
                sealed_at="2026-06-22T00:00:00+00:00")
    base.update(kw)
    return TrustLabel(**base)


def test_to_from_metadata_round_trip():
    label = _label(signature="deadbeef", key_id="abc123")
    meta = {METADATA_KEY: label.to_metadata()}
    restored = TrustLabel.from_metadata(meta)
    assert restored == label


def test_from_metadata_accepts_flat_dict():
    label = _label(signature="sig", key_id="kid")
    restored = TrustLabel.from_metadata(label.to_metadata())
    assert restored == label


def test_from_metadata_none_when_absent():
    assert TrustLabel.from_metadata(None) is None
    assert TrustLabel.from_metadata({}) is None
    assert TrustLabel.from_metadata({"unrelated": 1}) is None


def test_canonical_payload_excludes_signature():
    a = _label(signature="sigA")
    b = _label(signature="sigB")
    # Changing only the signature must not change the signed payload.
    assert a.canonical_payload() == b.canonical_payload()


def test_canonical_payload_changes_with_signed_field():
    a = _label(trust_score=0.9)
    b = _label(trust_score=0.1)
    assert a.canonical_payload() != b.canonical_payload()


def test_canonical_payload_is_stable():
    label = _label()
    assert label.canonical_payload() == label.canonical_payload()


def test_tier_for_score_boundaries():
    assert tier_for_score(0.95) == TrustTier.VERIFIED
    assert tier_for_score(0.85) == TrustTier.VERIFIED
    assert tier_for_score(0.7) == TrustTier.TRUSTED
    assert tier_for_score(0.6) == TrustTier.TRUSTED
    assert tier_for_score(0.59) == TrustTier.UNTRUSTED
    assert tier_for_score(0.0) == TrustTier.UNTRUSTED


def test_cap_tier_takes_lower_trust():
    # A clean score implying VERIFIED is capped by an UNTRUSTED source ceiling.
    assert cap_tier(TrustTier.VERIFIED, TrustTier.UNTRUSTED) == TrustTier.UNTRUSTED
    assert cap_tier(TrustTier.TRUSTED, TrustTier.VERIFIED) == TrustTier.TRUSTED
    assert cap_tier(TrustTier.VERIFIED, TrustTier.VERIFIED) == TrustTier.VERIFIED


def test_tier_ordering_quarantined_is_lowest():
    assert cap_tier(TrustTier.VERIFIED, TrustTier.QUARANTINED) == TrustTier.QUARANTINED
