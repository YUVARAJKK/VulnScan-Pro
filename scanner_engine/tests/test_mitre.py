"""Tests for MITRE ATT&CK mapping."""

from uuid import uuid4
from models.finding import Finding
from mitre.mapper import map_finding_to_mitre


def test_hsts_mapping():
    f = Finding(scan_id=uuid4(), title='Missing HSTS', severity='medium')
    result = map_finding_to_mitre(f)
    technique_ids = [t['id'] for t in result['techniques']]
    # HSTS maps to T1040 (Network Sniffing) and T1190 (Exploit Public-Facing App)
    assert 'T1040' in technique_ids or 'T1190' in technique_ids


def test_xss_mapping():
    f = Finding(scan_id=uuid4(), title='Reflected XSS in search parameter', severity='high')
    result = map_finding_to_mitre(f)
    technique_ids = [t['id'] for t in result['techniques']]
    assert 'T1059.007' in technique_ids


def test_sqli_mapping():
    f = Finding(scan_id=uuid4(), title='SQL Injection in id parameter', severity='critical')
    result = map_finding_to_mitre(f)
    technique_ids = [t['id'] for t in result['techniques']]
    assert 'T1190' in technique_ids


def test_port_mapping():
    f = Finding(scan_id=uuid4(), title='Port 3306 open: MySQL', severity='high')
    result = map_finding_to_mitre(f)
    technique_ids = [t['id'] for t in result['techniques']]
    assert 'T1046' in technique_ids or 'T1133' in technique_ids


def test_existing_mitre_info():
    f = Finding(scan_id=uuid4(), title='Test', severity='low', mitre_technique='T1190', mitre_tactic='Initial Access')
    result = map_finding_to_mitre(f)
    assert result['primary']['id'] == 'T1190'


def test_no_mapping():
    f = Finding(scan_id=uuid4(), title='Something unknown', severity='info')
    result = map_finding_to_mitre(f)
    assert 'primary' in result
