"""Spec Section 4.4: LLM output parsing resilience."""
from app.ai.analyzer import AIConfigAnalyzer


def test_parses_clean_json_list():
    raw = '[{"rule_id":"AI-01","title":"t","description":"d","severity":"HIGH","remediation":"r"}]'
    out = AIConfigAnalyzer.parse_llm_output(raw)
    assert out[0]["rule_id"] == "AI-01"


def test_extracts_json_from_prose():
    raw = 'Here are the findings:\n[{"rule_id":"AI-02","title":"t","description":"d","severity":"LOW","remediation":"r"}]\nDone.'
    out = AIConfigAnalyzer.parse_llm_output(raw)
    assert out[0]["rule_id"] == "AI-02"


def test_garbage_returns_parse_error_finding():
    out = AIConfigAnalyzer.parse_llm_output("not json at all")
    assert out[0]["rule_id"] == "AI-PARSE-ERR"
    assert out[0]["severity"] == "INFO"
