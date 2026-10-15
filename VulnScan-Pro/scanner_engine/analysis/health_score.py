"""Health score engine — converts a risk score into health score + grade.

Pure-function facade over the canonical model in ``analysis.severity``.
Kept as a separate module because several callers (and tests) only need the
risk -> (health, grade) conversion.
"""

from __future__ import annotations

from analysis.severity import risk_to_grade


def compute_health_score(risk_score: int) -> tuple[int, str]:
    """
    Convert risk score (0-100) to health score (0-100) and grade.
    Returns (health_score, grade).
    """
    risk_score = max(0, min(100, int(risk_score)))
    health_score = 100 - risk_score
    return health_score, risk_to_grade(health_score)
