"""Tests for finding deduplication."""

from uuid import uuid4
from models.finding import Finding
from validation.deduplication import deduplicate_findings, fingerprint_finding


def test_fingerprint_deterministic():
    f1 = Finding(scan_id=uuid4(), title='Missing HSTS', severity='medium', detected_by='security_headers')
    f2 = Finding(scan_id=uuid4(), title='Missing HSTS', severity='medium', detected_by='security_headers')
    assert fingerprint_finding(f1) == fingerprint_finding(f2)


def test_different_fingerprints():
    f1 = Finding(scan_id=uuid4(), title='Missing HSTS', severity='medium', detected_by='security_headers')
    f2 = Finding(scan_id=uuid4(), title='Missing CSP', severity='medium', detected_by='security_headers')
    assert fingerprint_finding(f1) != fingerprint_finding(f2)


def test_deduplication_keeps_highest_severity():
    scan_id = uuid4()
    findings = [
        Finding(scan_id=scan_id, title='Missing HSTS', severity='low', affected_component='example.com', detected_by='security_headers'),
        Finding(scan_id=scan_id, title='Missing HSTS', severity='high', affected_component='example.com', detected_by='security_headers'),
        Finding(scan_id=scan_id, title='Missing HSTS', severity='medium', affected_component='example.com', detected_by='security_headers'),
    ]
    result = deduplicate_findings(findings)
    assert len(result) == 1
    assert result[0].severity == 'high'


def test_deduplication_no_duplicates():
    scan_id = uuid4()
    findings = [
        Finding(scan_id=scan_id, title='Missing HSTS', severity='medium', detected_by='security_headers'),
        Finding(scan_id=scan_id, title='Missing CSP', severity='medium', detected_by='security_headers'),
    ]
    result = deduplicate_findings(findings)
    assert len(result) == 2
