"""Faz 3: YAML politika motoru testleri (gerçek policy dosyasıyla)."""
from pathlib import Path

from app.services.policy_engine import evaluate_policies, load_policies

POLICY_DIR = Path(__file__).parent.parent / "policies"

HARDENED = """\
hostname GOOD-RTR
aaa new-model
ip ssh version 2
logging host 10.0.0.5
line vty 0 4
 transport input ssh
"""

WEAK = """\
hostname BAD-RTR
ip http server
line vty 0 4
 transport input telnet
"""


def test_policies_load():
    rules = load_policies(POLICY_DIR)
    assert len(rules) >= 5
    assert all({"rule_id", "title", "match"} <= set(r) for r in rules)


def test_hardened_config_passes():
    rules = load_policies(POLICY_DIR)
    findings = evaluate_policies(HARDENED, rules, vendor="cisco_ios")
    assert findings == []


def test_weak_config_fails_expected_rules():
    rules = load_policies(POLICY_DIR)
    ids = {f["rule_id"] for f in evaluate_policies(WEAK, rules, vendor="cisco_ios")}
    assert {"POL-SSH-001", "POL-HTTP-002", "POL-VTY-003", "POL-AAA-004"} <= ids


def test_vendor_filter_skips_other_vendors():
    rules = load_policies(POLICY_DIR)
    assert evaluate_policies(WEAK, rules, vendor="fortinet") == []


def test_finding_shape_matches_advisory_schema():
    rules = load_policies(POLICY_DIR)
    for f in evaluate_policies(WEAK, rules, vendor="cisco_ios"):
        assert {"rule_id", "title", "description", "severity", "remediation"} <= set(f)
