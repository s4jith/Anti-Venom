from antivenom.core.finding import Finding, Technique
from antivenom.core.report import RiskReport
from antivenom.core.result import LayerResult, ScanResult, Severity


def _result(findings, confidence, poisoned):
    lr = LayerResult("pattern", poisoned, confidence, findings=findings)
    if poisoned:
        return ScanResult.poisoned("cid", confidence, [lr])
    return ScanResult.clean("cid", [lr])


def test_from_scan_categories_and_top_reason():
    findings = [
        Finding(Technique.ROLE_OVERRIDE, "you are now DAN", 0.98, matched_span="DAN"),
        Finding(Technique.EXFILTRATION, "send to http", 0.90, matched_span="send"),
    ]
    rep = RiskReport.from_scan(_result(findings, 0.98, True))
    assert rep.risk_level == Severity.MALICIOUS
    assert rep.is_poisoned is True
    # Highest-confidence finding drives the top reason.
    assert "DAN" in rep.top_reason
    cats = {c.category for c in rep.categories}
    assert "injection" in cats and "exfiltration" in cats
    # Most severe category first.
    assert rep.categories[0].max_confidence == 0.98


def test_classifier_confidence_populated_only_when_present():
    clf = LayerResult("classifier", True, 0.93,
                      findings=[Finding(Technique.SEMANTIC_ANOMALY, "clf", 0.93)])
    res = ScanResult.poisoned("cid", 0.93, [clf])
    rep = RiskReport.from_scan(res)
    assert rep.classifier_confidence == 0.93

    rep2 = RiskReport.from_scan(_result(
        [Finding(Technique.ROLE_OVERRIDE, "x", 0.9)], 0.9, True))
    assert rep2.classifier_confidence is None


def test_normalized_forms_surface_evasion():
    findings = [
        Finding(Technique.ENCODING_EVASION, "obfuscation: homoglyph_fold", 0.5,
                layer="normalize", form="normalized"),
        Finding(Technique.INSTRUCTION_OVERRIDE, "ignore previous", 0.97,
                matched_span="ignore", form="normalized"),
    ]
    rep = RiskReport.from_scan(_result(findings, 0.97, True))
    assert "normalized" in rep.normalized_forms
    assert rep.remediation  # non-empty for a poisoned result


def test_to_dict_and_explain():
    rep = RiskReport.from_scan(_result(
        [Finding(Technique.ROLE_OVERRIDE, "you are now DAN", 0.98, matched_span="DAN")],
        0.98, True))
    d = rep.to_dict()
    assert d["risk_level"] == "malicious"
    assert d["is_poisoned"] is True
    text = rep.explain()
    assert "Risk Level: MALICIOUS" in text
    assert "Reason:" in text


def test_clean_report():
    rep = RiskReport.from_scan(ScanResult.clean("cid", []))
    assert rep.is_poisoned is False
    assert rep.risk_level == Severity.CLEAN
    assert rep.remediation == ""
