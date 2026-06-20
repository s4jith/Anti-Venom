from antivenom.core.result import ScanResult, LayerResult, Severity


def test_scan_result_clean():
    r = ScanResult.clean(chunk_id="abc")
    assert not r.is_poisoned
    assert r.severity == Severity.CLEAN
    assert r.confidence == 0.0


def test_scan_result_poisoned_malicious():
    r = ScanResult.poisoned("abc", confidence=0.90, layer_results=[])
    assert r.is_poisoned
    assert r.severity == Severity.MALICIOUS


def test_scan_result_poisoned_suspicious():
    r = ScanResult.poisoned("abc", confidence=0.65, layer_results=[])
    assert r.is_poisoned
    assert r.severity == Severity.SUSPICIOUS


def test_layer_result_defaults():
    lr = LayerResult(layer_name="pattern", triggered=True, confidence=0.95)
    assert lr.evidence == []
    assert lr.duration_ms == 0.0
