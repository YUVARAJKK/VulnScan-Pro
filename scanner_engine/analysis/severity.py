"""Canonical risk & health scoring model for VulnScan Pro.

This module is the SINGLE SOURCE OF TRUTH for security health scoring.
The Node.js API (`backend/src/utils/riskScoring.js`) and the frontend report
view mirror this exact model so that the same finding set always yields the
same score, grade and rating on every surface (dashboard, report UI, PDF/XML/
JSON exports).

Model (v2 — explainable, per-finding risk bands)
=================================================
Each finding contributes fixed risk points by severity:

    CRITICAL   70      (can be exploited remotely to compromise data/system)
    HIGH       50      (serious weakness, likely exploitable)
    MEDIUM     30      (real risk under favourable conditions)
    LOW        10      (minor hardening issue)
    INFO        0      (no measurable risk)

risk_score  = min(100, sum of contribution points)
health_score = 100 - risk_score        (never below 0, never above 100)
grade        = derived from health_score:

    A+  health >= 95
    A   health >= 85
    B   health >= 75
    C   health >= 60
    D   health >= 40
    F   health <  40

Rationale: a single critical issue brings the health score down to 30 (grade F,
rating CRITICAL) because a remotely exploitable flaw outweighs everything else;
low/info findings barely move the score. Deductions are additive and capped,
so no score can fall below 0 or above 100.
"""

from __future__ import annotations

# Severity -> risk-point contribution (see module docstring)
SEVERITY_WEIGHT = {
    'critical': 70,
    'high': 50,
    'medium': 30,
    'low': 10,
    'info': 0,
}


def risk_to_grade(health_score: int) -> str:
    """Map a health score (0-100) to a letter grade."""
    if health_score >= 95:
        return 'A+'
    if health_score >= 85:
        return 'A'
    if health_score >= 75:
        return 'B'
    if health_score >= 60:
        return 'C'
    if health_score >= 40:
        return 'D'
    return 'F'


def risk_to_rating(risk_score: int) -> str:
    """Map a risk score (0-100) to a human threat-level rating."""
    if risk_score >= 70:
        return 'CRITICAL'
    if risk_score >= 50:
        return 'HIGH'
    if risk_score >= 30:
        return 'MODERATE'
    if risk_score >= 10:
        return 'LOW'
    return 'SECURE'


def calculate_risk_score(findings: list) -> dict:
    """
    Calculate overall risk score, health score and grade from findings.

    Returns {risk_score, health_score, grade, rating, severity_counts,
             total_findings, non_info_findings, breakdown}.
    """
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}

    for f in findings:
        sev = getattr(f, 'severity', 'info')
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Additive, capped contribution model
    contributions = {
        sev: SEVERITY_WEIGHT.get(sev, 0) * count
        for sev, count in severity_counts.items()
    }
    total_points = sum(contributions.values())
    risk_score = min(100, total_points)
    health_score = max(0, 100 - risk_score)
    grade = risk_to_grade(health_score)
    rating = risk_to_rating(risk_score)

    total_findings = sum(severity_counts.values())
    non_info = total_findings - severity_counts['info']

    breakdown = {
        'model': 'severity-band v2 (critical=70, high=50, medium=30, low=10, info=0; capped at 100)',
        'risk_contribution': contributions,
        'total_risk_points': total_points,
        'deductions': [
            {
                'severity': sev,
                'count': count,
                'points_each': SEVERITY_WEIGHT.get(sev, 0),
                'total_deduction': contributions[sev],
            }
            for sev, count in severity_counts.items()
            if count > 0 and SEVERITY_WEIGHT.get(sev, 0) > 0
        ],
    }

    return {
        'risk_score': risk_score,
        'health_score': health_score,
        'grade': grade,
        'rating': rating,
        'severity_counts': severity_counts,
        'total_findings': total_findings,
        'non_info_findings': non_info,
        'breakdown': breakdown,
    }
