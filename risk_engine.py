"""
risk_engine.py — Weighted risk scoring and Fix-First Intelligence for SecureSight AI.
Scoring is configuration-based and does not constitute a certified security rating.
"""

from __future__ import annotations
from typing import Any

# ---------------------------------------------------------------------------
# Severity weights
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS: dict[str, int] = {
    "Critical":      10,
    "High":          7,
    "Medium":        4,
    "Low":           1,
    "Informational": 0,
}

# Confidence multipliers
CONFIDENCE_MULTIPLIERS: dict[str, float] = {
    "High":   1.0,
    "Medium": 0.8,
    "Low":    0.5,
}

# Maximum possible score denominator baseline (6 headers + https + cors = ~8 common checks)
# We use a dynamic approach: score = 100 - penalty, capped at [0, 100]
PENALTY_CAP = 100.0

# Per-finding penalty contribution
FINDING_PENALTY_BASE: dict[str, float] = {
    "Critical":      25.0,
    "High":          15.0,
    "Medium":        8.0,
    "Low":           3.0,
    "Informational": 0.0,
}


def calculate_posture_score(findings: list[dict]) -> float:
    """
    Calculate a 0–100 security posture score.
    Score starts at 100 and deductions are applied for each open finding
    weighted by severity and confidence.
    Returns a float rounded to one decimal place.
    """
    if not findings:
        return 100.0

    total_penalty = 0.0
    for f in findings:
        if f.get("status", "open") != "open":
            continue
        sev = f.get("severity", "Informational")
        conf = f.get("confidence", "Medium")
        base = FINDING_PENALTY_BASE.get(sev, 0.0)
        mult = CONFIDENCE_MULTIPLIERS.get(conf, 0.8)
        total_penalty += base * mult

    score = max(0.0, 100.0 - total_penalty)
    return round(score, 1)


def get_posture_label(score: float) -> tuple[str, str]:
    """Return (label, color_key) for a posture score."""
    if score >= 80:
        return "Good", "mint"
    if score >= 60:
        return "Fair", "lavender"
    if score >= 40:
        return "Poor", "coral"
    return "Critical", "coral"


def count_by_severity(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0,
    }
    for f in findings:
        sev = f.get("severity", "Informational")
        if sev in counts:
            counts[sev] += 1
    return counts


# ---------------------------------------------------------------------------
# Remediation effort estimates
# ---------------------------------------------------------------------------

EFFORT_MAP: dict[str, str] = {
    "HTTPS Configuration":          "High — requires server/infrastructure changes",
    "HSTS Header":                  "Low — add a single HTTP response header",
    "Content Security Policy":      "Medium — requires policy tuning per application",
    "X-Content-Type-Options Header": "Low — add a single HTTP response header",
    "Clickjacking Protection":      "Low — add a single HTTP response header",
    "Referrer Policy":              "Low — add a single HTTP response header",
    "Permissions Policy":           "Low — add a single HTTP response header",
    "CORS Configuration":           "Medium — requires server-side CORS logic review",
    "Response Status":              "Varies",
    "Response Time":                "Medium — requires performance investigation",
}


def get_effort(check_name: str) -> str:
    return EFFORT_MAP.get(check_name, "Varies — review implementation")


# ---------------------------------------------------------------------------
# Fix-First Intelligence
# ---------------------------------------------------------------------------

_FIX_PRIORITY_SCORE: dict[str, int] = {
    "Critical": 100,
    "High":     75,
    "Medium":   40,
    "Low":      10,
    "Informational": 0,
}

_CONFIDENCE_BOOST: dict[str, int] = {
    "High": 10,
    "Medium": 0,
    "Low": -10,
}


def _priority_score(finding: dict) -> int:
    sev = finding.get("severity", "Informational")
    conf = finding.get("confidence", "Medium")
    return _FIX_PRIORITY_SCORE.get(sev, 0) + _CONFIDENCE_BOOST.get(conf, 0)


def get_fix_first_recommendations(findings: list[dict], top_n: int = 5) -> list[dict]:
    """
    Return up to top_n prioritized remediation recommendations
    from open findings, sorted by priority score (severity + confidence).
    """
    open_findings = [f for f in findings if f.get("status", "open") == "open"
                     and f.get("severity", "Informational") != "Informational"]

    sorted_findings = sorted(open_findings, key=_priority_score, reverse=True)

    recommendations = []
    for i, f in enumerate(sorted_findings[:top_n]):
        score = _priority_score(f)
        if score >= 75:
            priority_label = "Fix Immediately"
        elif score >= 40:
            priority_label = "Fix Next"
        else:
            priority_label = "Review"

        expected_benefit = _expected_benefit(f.get("severity", "Low"))
        recommendations.append({
            "rank": i + 1,
            "priority_label": priority_label,
            "finding_id": f.get("id", ""),
            "title": f.get("title", ""),
            "check_name": f.get("check_name", ""),
            "why_it_matters": f.get("explanation", ""),
            "suggested_fix": f.get("recommendation", ""),
            "expected_benefit": expected_benefit,
            "estimated_effort": get_effort(f.get("check_name", "")),
            "evidence": f.get("evidence", ""),
            "severity": f.get("severity", ""),
            "confidence": f.get("confidence", ""),
        })

    return recommendations


def _expected_benefit(severity: str) -> str:
    benefits = {
        "Critical": "Eliminates a critical security gap that could enable serious attacks.",
        "High": "Significantly reduces attack surface and improves security posture.",
        "Medium": "Improves defence-in-depth and reduces risk of common attack vectors.",
        "Low": "Applies a security best practice that reduces minor risk exposure.",
    }
    return benefits.get(severity, "Improves overall security configuration.")


def compare_scan_findings(
    findings_a: list[dict],
    findings_b: list[dict],
) -> dict:
    """
    Compare two sets of findings (A = older, B = newer).
    Returns categorised comparison result.
    Does NOT auto-resolve findings — absence in B is noted separately.
    """
    # Use check_name + title as a stable identifier for comparison
    def key(f: dict) -> str:
        return f"{f.get('check_name', '')}|{f.get('title', '')}"

    keys_a = {key(f): f for f in findings_a}
    keys_b = {key(f): f for f in findings_b}

    set_a = set(keys_a.keys())
    set_b = set(keys_b.keys())

    new_in_b = [keys_b[k] for k in set_b - set_a]
    still_present = [keys_b[k] for k in set_a & set_b]
    not_in_b = [keys_a[k] for k in set_a - set_b]
    resolved_in_b = [keys_b[k] for k in set_b if keys_b[k].get("status") == "resolved"]

    return {
        "new_findings": new_in_b,
        "persistent_findings": still_present,
        "not_detected_in_b": not_in_b,  # Not auto-resolved
        "resolved_findings": resolved_in_b,
    }
