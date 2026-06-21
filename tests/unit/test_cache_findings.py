from antivenom.cache.hash_cache import _deserialize_result, _serialize_result
from antivenom.core.finding import Finding, Technique
from antivenom.core.result import LayerResult, ScanResult


def _poisoned_result():
    lr = LayerResult("pattern", True, 0.97, findings=[
        Finding(Technique.INSTRUCTION_OVERRIDE, "ignore previous", 0.97,
                layer="pattern", matched_span="ignore previous instructions"),
    ])
    return ScanResult.poisoned("abc123", 0.97, [lr])


def test_findings_survive_serialize_roundtrip():
    data = _serialize_result(_poisoned_result())
    assert "findings" in data["layer_results"][0]
    restored = _deserialize_result(data)
    f = restored.findings
    assert len(f) == 1
    assert f[0].technique == Technique.INSTRUCTION_OVERRIDE
    assert f[0].matched_span == "ignore previous instructions"


def test_report_rebuilt_on_deserialize():
    data = _serialize_result(_poisoned_result())
    restored = _deserialize_result(data)
    assert restored.report is not None
    assert restored.report.is_poisoned is True
    assert restored.from_cache is True


def test_legacy_cache_dict_without_findings_key():
    # A pre-v0.4 cache entry has only `evidence`, no `findings`.
    legacy = {
        "chunk_id": "abc",
        "is_poisoned": True,
        "confidence": 0.9,
        "severity": "malicious",
        "scan_duration_ms": 1.0,
        "layer_results": [
            {
                "layer_name": "pattern",
                "triggered": True,
                "confidence": 0.9,
                "evidence": ['"ignore previous" (confidence=0.90)'],
                "duration_ms": 0.5,
            }
        ],
    }
    restored = _deserialize_result(legacy)  # must not crash
    assert restored.is_poisoned is True
    assert len(restored.findings) == 1
    assert restored.findings[0].technique == Technique.UNKNOWN
    assert restored.findings[0].reason == '"ignore previous" (confidence=0.90)'
