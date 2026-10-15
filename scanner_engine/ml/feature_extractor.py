"""Feature extractor — converts a Finding dict into a fixed-length feature
vector suitable for the Random Forest classifier.

Uses *only* the centrally-defined feature schema so training and inference
produce identical vector layouts.
"""

from __future__ import annotations

import logging
from typing import Any

from ml.feature_schema import (
    FEATURE_NAMES,
    FEATURE_DEFAULTS,
    DETECTOR_FEATURE_MAP,
    PAYLOAD_CATEGORY_MAP,
    SEVERITY_ORDINAL,
    NUM_FEATURES,
)

logger = logging.getLogger(__name__)


def _to_int(value: Any, default: float) -> int:
    """Coerce a value to int safely; invalid/None values fall back to default."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _to_float(value: Any, default: float) -> float:
    """Coerce a value to float safely; invalid/None values fall back to default."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def extract_features(finding: dict[str, Any]) -> list[float]:
    """Extract a feature vector from a finding dict.

    Parameters
    ----------
    finding : dict
        A finding produced by the scanner (may be a Pydantic .model_dump()
        result or a plain dict read from the database).

    Returns
    -------
    list[float]
        Feature vector of length ``NUM_FEATURES`` in the canonical order
        defined by ``FEATURE_NAMES``.
    """
    features: dict[str, float] = dict(FEATURE_DEFAULTS)
    evidence = finding.get('evidence') or {}

    # ── HTTP response characteristics ────────────────────────────────────
    features['status_code'] = _to_int(evidence.get('status_code', 200), 200)
    features['response_length'] = _to_int(evidence.get('response_length', 0), 0)
    features['response_time_ms'] = _to_float(evidence.get('response_time_ms', 0.0), 0.0)
    features['redirect_count'] = _to_int(evidence.get('redirect_count', 0), 0)

    # ── Parameter characteristics ────────────────────────────────────────
    param = finding.get('parameter', '')
    params = finding.get('parameters', []) or []
    features['param_count'] = len(params) if params else (1 if param else 0)
    features['param_in_query'] = int(bool(param and evidence.get('url', '')))
    features['param_in_body'] = int(bool(param and finding.get('method', 'GET') == 'POST'))

    # ── Payload category (one-hot) ───────────────────────────────────────
    detector = finding.get('detected_by', '')
    category = finding.get('category', '')
    payload_feature = PAYLOAD_CATEGORY_MAP.get(detector)
    if payload_feature:
        features[payload_feature] = 1
    elif category not in ('injection',):
        features['payload_passive'] = 1

    # ── Response behaviour ───────────────────────────────────────────────
    features['is_reflected'] = int(bool(evidence.get('reflected_unencoded') or evidence.get('is_reflected')))
    features['has_error_pattern'] = int(bool(evidence.get('error_pattern') or evidence.get('has_error_pattern')))
    features['baseline_differs'] = int(bool(evidence.get('baseline_differs')))
    features['content_type_html'] = int(
        'text/html' in str(evidence.get('content_type', '')).lower()
    )

    # ── Security header indicators ───────────────────────────────────────
    headers = evidence.get('headers', {})
    if isinstance(headers, dict):
        features['has_csp'] = int('content-security-policy' in {k.lower() for k in headers})
        features['has_hsts'] = int('strict-transport-security' in {k.lower() for k in headers})
        features['has_xframe'] = int('x-frame-options' in {k.lower() for k in headers})

    # ── Detector type (one-hot) ──────────────────────────────────────────
    det_feature = DETECTOR_FEATURE_MAP.get(detector)
    if det_feature:
        features[det_feature] = 1

    # ── Evidence completeness ────────────────────────────────────────────
    evidence_fields = [v for v in evidence.values() if v is not None and v != '' and v != {} and v != []]
    features['evidence_field_count'] = len(evidence_fields)
    features['has_url_evidence'] = int(bool(evidence.get('url')))
    features['has_payload_evidence'] = int(bool(evidence.get('payload') or evidence.get('marker')))
    features['has_snippet_evidence'] = int(bool(evidence.get('response_snippet')))

    # ── Severity ordinal ─────────────────────────────────────────────────
    features['severity_ordinal'] = SEVERITY_ORDINAL.get(str(finding.get('severity', 'info')).lower(), 0)

    # Build the final vector in canonical order
    vector = [float(features.get(name, FEATURE_DEFAULTS[name])) for name in FEATURE_NAMES]

    assert len(vector) == NUM_FEATURES, (
        f'Feature vector length {len(vector)} != expected {NUM_FEATURES}'
    )
    return vector


def extract_features_batch(findings: list[dict[str, Any]]) -> list[list[float]]:
    """Extract feature vectors for a list of findings.

    Returns a list of vectors (rows × features).
    """
    return [extract_features(f) for f in findings]
