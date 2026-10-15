"""Tests for evidence collection."""

from validation.evidence import collect_evidence


def test_collect_evidence_basic():
    evidence = collect_evidence(url='https://example.com', payload='test')
    assert evidence['url'] == 'https://example.com'
    assert evidence['payload'] == 'test'


def test_collect_evidence_truncation():
    long_url = 'https://example.com/' + 'a' * 3000
    evidence = collect_evidence(url=long_url)
    assert len(evidence['url']) <= 2048


def test_collect_evidence_status_code():
    evidence = collect_evidence(status_code=404)
    assert evidence['status_code'] == 404


def test_collect_evidence_headers():
    headers = {'Content-Type': 'text/html', 'X-Custom': 'value'}
    evidence = collect_evidence(headers=headers)
    assert 'content-type' in evidence.get('headers', {})
    assert 'x-custom' not in evidence.get('headers', {})
