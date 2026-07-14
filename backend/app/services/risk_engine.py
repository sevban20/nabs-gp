"""Risk Scoring Engine (Spec Section 6).

Composite score recomputed whenever a security_advisories row is
inserted, resolved, or silenced. Weights stay app-level (not a DB
trigger) so tuning them never requires a migration.
"""
SEVERITY_WEIGHTS = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 3, "INFO": 0}


def compute_risk_score(open_advisories: list[dict]) -> int:
    """100 = fully hardened, 0 = maximally exposed. Only advisories that
    are unresolved AND not silenced count against the score."""
    penalty = sum(
        SEVERITY_WEIGHTS.get(a["severity"], 0)
        for a in open_advisories if not a.get("is_silenced")
    )
    return max(0, 100 - penalty)
