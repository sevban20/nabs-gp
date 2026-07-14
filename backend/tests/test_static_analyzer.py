"""Spec Section 4.3: static rule engine."""
from app.services.static_analyzer import StaticAnalyzer

SAMPLE = """\
hostname EDGE-RTR-01
no service password-encryption
ip http server
snmp-server community public RO
line vty 0 4
 transport input telnet ssh
line vty 5 15
 transport input ssh
"""


def test_detects_telnet_only_on_offending_vty():
    findings = StaticAnalyzer.audit_cisco_ios(SAMPLE)
    telnet = [f for f in findings if f["rule_id"] == "SEC-PROT-001"]
    assert len(telnet) == 1
    assert "line vty 0 4" in telnet[0]["description"]


def test_detects_insecure_snmp():
    findings = StaticAnalyzer.audit_cisco_ios(SAMPLE)
    assert any(f["rule_id"] == "SEC-SNMP-002" for f in findings)


def test_detects_http_server_and_password_encryption():
    ids = {f["rule_id"] for f in StaticAnalyzer.audit_cisco_ios(SAMPLE)}
    assert "SEC-PROT-003" in ids
    assert "SEC-PASS-004" in ids


def test_clean_config_no_findings():
    clean = "hostname OK\nline vty 0 4\n transport input ssh\n"
    assert StaticAnalyzer.audit_cisco_ios(clean) == []


def test_findings_have_required_shape():
    for f in StaticAnalyzer.audit_cisco_ios(SAMPLE):
        assert set(f) == {"rule_id", "title", "description", "severity", "remediation"}
