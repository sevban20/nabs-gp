"""Faz 3: CPE üretimi ve NVD yanıt ayrıştırma (offline)."""
from app.services.cve_sync import build_cpe_string, cvss_to_severity, parse_nvd_response


def test_cpe_string_for_known_vendors():
    assert build_cpe_string("cisco_ios", "15.2(4)M7") == \
        "cpe:2.3:o:cisco:ios:15.2(4)m7:*:*:*:*:*:*:*"
    assert build_cpe_string("fortinet", "7.0.5").startswith("cpe:2.3:o:fortinet:fortios:7.0.5")


def test_cpe_none_for_unknown_or_missing():
    assert build_cpe_string("unknown", "1.0") is None
    assert build_cpe_string("cisco_ios", None) is None


def test_cvss_severity_mapping():
    assert cvss_to_severity(9.8) == "CRITICAL"
    assert cvss_to_severity(7.5) == "HIGH"
    assert cvss_to_severity(5.0) == "MEDIUM"
    assert cvss_to_severity(2.0) == "LOW"
    assert cvss_to_severity(None) == "INFO"


def test_parse_nvd_response_shape():
    sample = {"vulnerabilities": [{"cve": {
        "id": "CVE-2023-20198",
        "descriptions": [{"lang": "en", "value": "Web UI privilege escalation."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0}}]},
    }}]}
    findings = parse_nvd_response(sample)
    assert findings[0]["rule_id"] == "CVE-2023-20198"
    assert findings[0]["severity"] == "CRITICAL"
    assert "privilege escalation" in findings[0]["description"]


def test_parse_empty_response():
    assert parse_nvd_response({}) == []
