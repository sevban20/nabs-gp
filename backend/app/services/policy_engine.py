"""Faz 3 Sprint 19-20: YAML tabanlı yapısal politika motoru.

Kural şeması (policies/*.yaml):
    rules:
      - rule_id: POL-SSH-001
        title: SSH version 2 zorunlu
        severity: HIGH
        vendor: cisco_ios           # opsiyonel filtre
        match:
          type: must_exist | must_not_exist | child_must_exist
          pattern: "^ip ssh version 2"
          parent: "^line vty"       # yalnizca child_must_exist için
          child: "transport input ssh"
        description: ...
        remediation: ...

Bulgular StaticAnalyzer ile aynı şekle sahiptir ve security_advisories'e
aynı yoldan yazılır (Spec 4.3 ile uyumlu).
"""
import re
from pathlib import Path
from typing import Dict, List

import yaml

from app.services.static_analyzer import _parse_blocks


def load_policies(policy_dir: str | Path) -> list[dict]:
    rules: list[dict] = []
    for path in sorted(Path(policy_dir).glob("*.yaml")):
        data = yaml.safe_load(path.read_text()) or {}
        for rule in data.get("rules", []):
            rule.setdefault("_source_file", path.name)
            rules.append(rule)
    return rules


def _finding(rule: dict, detail: str) -> Dict:
    return {
        "rule_id": rule["rule_id"],
        "title": rule["title"],
        "description": rule.get("description", "") + (f" [{detail}]" if detail else ""),
        "severity": rule.get("severity", "MEDIUM"),
        "remediation": rule.get("remediation"),
    }


def evaluate_policies(config_text: str, rules: list[dict],
                      vendor: str | None = None) -> List[Dict]:
    findings: List[Dict] = []
    lines = config_text.splitlines()
    blocks = _parse_blocks(config_text)

    for rule in rules:
        if vendor and rule.get("vendor") and rule["vendor"] != vendor:
            continue
        match = rule.get("match", {})
        mtype = match.get("type")
        pattern = match.get("pattern", "")

        if mtype == "must_exist":
            if not any(re.search(pattern, line) for line in lines):
                findings.append(_finding(rule, f"beklenen desen yok: {pattern}"))

        elif mtype == "must_not_exist":
            for line in lines:
                if re.search(pattern, line):
                    findings.append(_finding(rule, f"yasaklı satır: '{line.strip()}'"))

        elif mtype == "child_must_exist":
            parent_pat, child_pat = match.get("parent", ""), match.get("child", "")
            for parent, children in blocks:
                if re.search(parent_pat, parent):
                    if not any(re.search(child_pat, c) for c in children):
                        findings.append(_finding(rule, f"'{parent}' altında eksik: {child_pat}"))
    return findings
