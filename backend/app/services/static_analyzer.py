"""Static Security Policy Engine (Spec Section 4.3).

Uses CiscoConfParse when available (ciscoconfparse2 on Python 3.11+),
with a lightweight internal hierarchical parser as fallback so the
engine works in constrained environments. New rules must follow the
(rule_id, title, description, severity, remediation) shape so they
merge cleanly into security_advisories.
"""
from typing import Dict, List

try:  # pragma: no cover - environment dependent
    from ciscoconfparse2 import CiscoConfParse  # type: ignore
    _HAS_CCP = True
except ImportError:
    try:  # pragma: no cover
        from ciscoconfparse import CiscoConfParse  # type: ignore
        _HAS_CCP = True
    except ImportError:
        _HAS_CCP = False


def _parse_blocks(config_text: str) -> list[tuple[str, list[str]]]:
    """Minimal IOS-style hierarchy parser: (parent_line, [child_lines])."""
    blocks: list[tuple[str, list[str]]] = []
    current: tuple[str, list[str]] | None = None
    for line in config_text.splitlines():
        if not line.strip() or line.strip().startswith("!"):
            current = None
            continue
        if line.startswith((" ", "\t")):
            if current is not None:
                current[1].append(line.strip())
        else:
            current = (line.strip(), [])
            blocks.append(current)
    return blocks


class StaticAnalyzer:
    @staticmethod
    def audit_cisco_ios(config_text: str) -> List[Dict]:
        findings: List[Dict] = []

        # Audit 1: Unencrypted line management (Telnet)
        for parent, children in _parse_blocks(config_text):
            if parent.startswith("line vty"):
                for child in children:
                    if "transport input" in child and "telnet" in child:
                        findings.append({
                            "rule_id": "SEC-PROT-001",
                            "title": "Unencrypted Telnet Management Protocol Active",
                            "description": f"Telnet found under '{parent}': '{child}'.",
                            "severity": "HIGH",
                            "remediation": f"Under '{parent}', apply: 'transport input ssh'",
                        })

        # Audit 2: Insecure SNMP community strings
        for parent, _ in _parse_blocks(config_text):
            if parent.startswith("snmp-server community"):
                if not any(v in parent for v in ["v3", "version 3"]):
                    findings.append({
                        "rule_id": "SEC-SNMP-002",
                        "title": "Insecure SNMP Community Strings Detected",
                        "description": f"'{parent}' relies on SNMPv1/v2c.",
                        "severity": "MEDIUM",
                        "remediation": "Configure SNMPv3 groups/users with AES and SHA.",
                    })

        # Audit 3: HTTP management server enabled
        for parent, _ in _parse_blocks(config_text):
            if parent == "ip http server":
                findings.append({
                    "rule_id": "SEC-PROT-003",
                    "title": "Plaintext HTTP Management Server Enabled",
                    "description": "'ip http server' exposes unencrypted management.",
                    "severity": "MEDIUM",
                    "remediation": "Apply 'no ip http server'; use 'ip http secure-server' if web management is required.",
                })

        # Audit 4: Password encryption service disabled
        for parent, _ in _parse_blocks(config_text):
            if parent == "no service password-encryption":
                findings.append({
                    "rule_id": "SEC-PASS-004",
                    "title": "Password Encryption Service Disabled",
                    "description": "Plaintext passwords will be stored in the configuration.",
                    "severity": "MEDIUM",
                    "remediation": "Apply 'service password-encryption'.",
                })

        return findings
