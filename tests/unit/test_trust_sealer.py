import dataclasses

import pytest

from antivenom.trust.label import TrustLabel, TrustTier
from antivenom.trust.sealer import TrustSealer


def _label():
    return TrustLabel(trust_score=0.9, tier=TrustTier.TRUSTED, source_id="internal/a.md",
                      source_type="internal", scan_verdict="clean",
                      sealed_at="2026-06-22T00:00:00+00:00")


def test_seal_then_verify_succeeds():
    sealer = TrustSealer(key="k1")
    sealed = sealer.seal(_label())
    assert sealed.signature
    assert sealed.key_id == sealer.key_id
    assert sealer.verify(sealed) is True


def test_tamper_any_signed_field_fails_verification():
    sealer = TrustSealer(key="k1")
    sealed = sealer.seal(_label())
    for field, value in [
        ("trust_score", 0.99),
        ("tier", TrustTier.VERIFIED),
        ("source_id", "evil/source"),
        ("source_type", "internal-but-not"),
        ("scan_verdict", "clean!"),
        ("sealed_at", "2099-01-01T00:00:00+00:00"),
    ]:
        tampered = dataclasses.replace(sealed, **{field: value})
        assert sealer.verify(tampered) is False, f"tamper on {field} should fail"


def test_wrong_key_fails_verification():
    a = TrustSealer(key="k1")
    b = TrustSealer(key="k2")
    sealed = a.seal(_label())
    assert b.verify(sealed) is False


def test_unsigned_label_fails_verification():
    sealer = TrustSealer(key="k1")
    assert sealer.verify(_label()) is False  # no signature/key_id


def test_key_id_is_deterministic_and_short():
    assert TrustSealer(key="k1").key_id == TrustSealer(key="k1").key_id
    assert TrustSealer(key="k1").key_id != TrustSealer(key="k2").key_id
    assert len(TrustSealer(key="k1").key_id) == 8


def test_env_var_key(monkeypatch):
    monkeypatch.setenv("ANTIVENOM_TRUST_KEY", "from-env")
    sealer = TrustSealer()
    assert sealer.verify(sealer.seal(_label())) is True


def test_missing_key_raises(monkeypatch):
    monkeypatch.delenv("ANTIVENOM_TRUST_KEY", raising=False)
    with pytest.raises(ValueError):
        TrustSealer()
