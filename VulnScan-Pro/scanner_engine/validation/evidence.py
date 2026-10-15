"""Evidence collector and validator."""

from __future__ import annotations

from typing import Any


def collect_evidence(
    url: str = '',
    payload: str = '',
    response_snippet: str = '',
    status_code: int | None = None,
    headers: dict | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """
    Collect structured evidence for a finding.
    Truncates large values to prevent storage bloat.
    """
    evidence: dict[str, Any] = {}

    if url:
        evidence['url'] = url[:2048]
    if payload:
        evidence['payload'] = payload[:500]
    if response_snippet:
        evidence['response_snippet'] = response_snippet[:2000]
    if status_code is not None:
        evidence['status_code'] = status_code
    if headers:
        # Only include security-relevant headers (lowercase keys for consistency)
        relevant_keys = {
            'content-type', 'location', 'set-cookie',
            'x-frame-options', 'content-security-policy',
            'strict-transport-security', 'server',
        }
        relevant = {k.lower(): v for k, v in headers.items()
                    if k.lower() in relevant_keys}
        if relevant:
            evidence['headers'] = relevant

    for k, v in extra.items():
        if isinstance(v, str):
            evidence[k] = v[:500]
        elif isinstance(v, (int, float, bool)):
            evidence[k] = v

    return evidence
