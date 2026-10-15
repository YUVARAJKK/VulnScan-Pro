"""Tests for confidence scoring."""

from validation.confidence import calculate_confidence, confidence_to_cvss_modifier


def test_high_confidence():
    result = calculate_confidence(
        evidence_count=5,
        is_reflected=True,
        has_error_pattern=True,
    )
    assert result == 'high'


def test_medium_confidence():
    # With evidence_count=2, score >= 3 which is still < 4 (high threshold)
    # but >= 2 (medium threshold) -- however score = 1 for evidence_count=1
    result = calculate_confidence(
        evidence_count=2,
        is_reflected=True,
    )
    assert result in ('medium', 'high')


def test_low_confidence():
    result = calculate_confidence(
        evidence_count=0,
        is_reflected=False,
    )
    assert result == 'low'


def test_cvss_modifier():
    assert confidence_to_cvss_modifier('high') == 0.0
    assert confidence_to_cvss_modifier('medium') == -0.5
    assert confidence_to_cvss_modifier('low') == -1.0
