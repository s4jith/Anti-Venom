from antivenom.trust.label import TrustTier
from antivenom.trust.registry import SourceRegistry, SourceRule


def test_default_source_types():
    reg = SourceRegistry()
    assert reg.base_trust(source_type="internal") == (0.90, TrustTier.TRUSTED)
    assert reg.base_trust(source_type="verified") == (0.95, TrustTier.VERIFIED)
    assert reg.base_trust(source_type="web") == (0.20, TrustTier.UNTRUSTED)


def test_default_url_glob():
    reg = SourceRegistry()
    score, tier = reg.base_trust(source_id="https://evil.example/page")
    assert score == 0.20
    assert tier == TrustTier.UNTRUSTED


def test_unknown_source_falls_back_to_default():
    reg = SourceRegistry()
    assert reg.base_trust(source_id="weird://x", source_type="mystery") == (0.30, TrustTier.UNTRUSTED)


def test_source_id_glob_beats_source_type():
    # An explicit per-source rule should win over the generic source_type rule.
    reg = SourceRegistry(rules=[SourceRule("https://trusted.internal/*", 0.92, TrustTier.TRUSTED)])
    score, tier = reg.base_trust(source_id="https://trusted.internal/doc", source_type="web")
    assert score == 0.92
    assert tier == TrustTier.TRUSTED


def test_custom_rule_overrides_default_type():
    reg = SourceRegistry(rules=[SourceRule("web", 0.05, TrustTier.UNTRUSTED)])
    assert reg.base_trust(source_type="web") == (0.05, TrustTier.UNTRUSTED)


def test_no_defaults_mode():
    reg = SourceRegistry(use_defaults=False)
    assert reg.base_trust(source_type="internal") == (0.30, TrustTier.UNTRUSTED)


def test_from_yaml(tmp_path):
    p = tmp_path / "sources.yaml"
    p.write_text(
        "- match: partner_feed\n  base_trust: 0.6\n  tier: trusted\n"
        "- match: 'ftp://*'\n  base_trust: 0.1\n  tier: untrusted\n",
        encoding="utf-8",
    )
    reg = SourceRegistry.from_yaml(p, use_defaults=False)
    assert reg.base_trust(source_type="partner_feed") == (0.6, TrustTier.TRUSTED)
    assert reg.base_trust(source_id="ftp://host/file")[0] == 0.1
