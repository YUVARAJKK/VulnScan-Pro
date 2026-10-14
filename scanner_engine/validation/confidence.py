"""Confidence scoring engine for vulnerability findings."""

from __future__ import annotations


def calculate_confidence(
    evidence_count: int = 0,
    is_reflected: bool = False,
    has_error_pattern: bool = False,
    baseline_differs: bool = False,
    false_positive_rate: float = 0.0,
) -> str:
    """
    Calculate confidence level for a vulnerability finding.

    Returns: 'high', 'medium', or 'low'
    """
    score = 0

    # Evidence-based scoring
    if evidence_count >= 3:
        score += 3
    elif evidence_count >= 1:
        score += 1

    # Reflection/confirmation signals
    if is_reflected:
        score += 2
    if has_error_pattern:
        score += 2
    if baseline_differs:
        score += 1

    # False positive penalty
    score -= false_positive_rate * 3

    if score >= 4:
        return 'high'
    elif score >= 2:
        return 'medium'
    else:
        return 'low'


def confidence_to_cvss_modifier(confidence: str) -> float:
    """Map confidence to a CVSS score modifier."""
    return {'high': 0.0, 'medium': -0.5, 'low': -1.0}.get(confidence, -1.0)
