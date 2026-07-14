"""Spec Section 6: risk score formula."""
from app.services.risk_engine import compute_risk_score


def test_no_advisories_full_score():
    assert compute_risk_score([]) == 100


def test_weights_applied():
    advisories = [
        {"severity": "CRITICAL"},  # 40
        {"severity": "HIGH"},      # 20
        {"severity": "MEDIUM"},    # 8
        {"severity": "LOW"},       # 3
        {"severity": "INFO"},      # 0
    ]
    assert compute_risk_score(advisories) == 100 - 71


def test_floor_at_zero():
    assert compute_risk_score([{"severity": "CRITICAL"}] * 5) == 0


def test_silenced_advisories_excluded():
    advisories = [
        {"severity": "CRITICAL", "is_silenced": True},
        {"severity": "HIGH", "is_silenced": False},
    ]
    assert compute_risk_score(advisories) == 80


def test_unknown_severity_ignored():
    assert compute_risk_score([{"severity": "WEIRD"}]) == 100
