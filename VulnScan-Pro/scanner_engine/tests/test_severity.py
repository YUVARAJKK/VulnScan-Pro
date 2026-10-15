"""Tests for severity calculation and risk scoring."""

from analysis.severity import calculate_risk_score


class MockFinding:
    def __init__(self, severity):
        self.severity = severity


def test_no_findings():
    result = calculate_risk_score([])
    assert result['risk_score'] == 0
    assert result['health_score'] == 100
    assert result['grade'] == 'A+'


def test_critical_findings():
    findings = [MockFinding('critical')] * 3
    result = calculate_risk_score(findings)
    assert result['risk_score'] > 0
    assert result['health_score'] < 100
    assert result['severity_counts']['critical'] == 3


def test_info_findings_no_risk():
    findings = [MockFinding('info')] * 10
    result = calculate_risk_score(findings)
    assert result['risk_score'] == 0
    assert result['health_score'] == 100


def test_mixed_severities():
    findings = [
        MockFinding('critical'),
        MockFinding('high'),
        MockFinding('medium'),
        MockFinding('low'),
        MockFinding('info'),
    ]
    result = calculate_risk_score(findings)
    assert result['severity_counts'] == {
        'critical': 1, 'high': 1, 'medium': 1, 'low': 1, 'info': 1,
    }
    assert result['risk_score'] > 0
    assert result['health_score'] < 100
