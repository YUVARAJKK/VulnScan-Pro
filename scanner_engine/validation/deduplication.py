"""Fingerprint-based deduplication for vulnerability findings."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner_engine.models.finding import Finding


def fingerprint_finding(finding: 'Finding') -> str:
    """Generate a fingerprint for a finding to detect duplicates.

    Excludes severity (keeps the highest-severity version of a duplicate) but
    includes endpoint/parameter so the same finding on DIFFERENT pages is not
    collapsed into a single record.
    """
    key_parts = [
        finding.title.lower().strip(),
        finding.affected_component or '',
        finding.detected_by,
        finding.endpoint or '',
        finding.parameter or '',
    ]
    raw = '|'.join(key_parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def deduplicate_findings(findings: list['Finding']) -> list['Finding']:
    """
    Deduplicate findings by fingerprint, keeping the highest-severity version.
    """
    severity_weight = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}
    seen: dict[str, tuple[int, 'Finding']] = {}

    for f in findings:
        fp = fingerprint_finding(f)
        weight = severity_weight.get(f.severity, 0)

        if fp in seen:
            existing_weight, _ = seen[fp]
            if weight > existing_weight:
                seen[fp] = (weight, f)
        else:
            seen[fp] = (weight, f)

    return [f for _, f in seen.values()]
