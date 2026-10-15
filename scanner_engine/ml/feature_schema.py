"""Feature schema — single source of truth for ML feature extraction.

This module defines the exact feature names, order, types, and default values
used by both the training pipeline and the inference (classification) path.
Any change here automatically propagates to both sides, preventing schema
mismatches.

Feature schema version is bumped whenever the feature set changes. The model
serialization records which schema version it was trained on. Inference
rejects models trained on a different schema version to prevent silent
misclassification.
"""

from __future__ import annotations

SCHEMA_VERSION = '1.0.0'

# ─── Ordered feature definitions ────────────────────────────────────────────
# Each entry: (feature_name, dtype, default_value, description)
FEATURE_DEFINITIONS = [
    # HTTP response characteristics
    ('status_code',       'int',   200,   'HTTP status code of the detection request'),
    ('response_length',   'int',   0,     'Response body length in bytes'),
    ('response_time_ms',  'float', 0.0,   'Response time in milliseconds'),
    ('redirect_count',    'int',   0,     'Number of HTTP redirects followed'),

    # Parameter characteristics
    ('param_count',       'int',   0,     'Number of parameters tested'),
    ('param_in_query',    'int',   0,     '1 if the tested param is in query string, else 0'),
    ('param_in_body',     'int',   0,     '1 if the tested param is in POST body, else 0'),

    # Payload category (one-hot encoded)
    ('payload_xss',       'int',   0,     '1 if XSS payload was used'),
    ('payload_sqli',      'int',   0,     '1 if SQLi payload was used'),
    ('payload_redirect',  'int',   0,     '1 if open-redirect payload was used'),
    ('payload_traversal', 'int',   0,     '1 if path-traversal payload was used'),
    ('payload_passive',   'int',   0,     '1 if no active payload (header/cookie/CORS check)'),

    # Response behaviour
    ('is_reflected',      'int',   0,     '1 if the payload/marker was reflected in response'),
    ('has_error_pattern', 'int',   0,     '1 if a known error pattern was matched'),
    ('baseline_differs',  'int',   0,     '1 if response differs significantly from baseline'),
    ('content_type_html', 'int',   0,     '1 if response Content-Type is text/html'),

    # Security header indicators
    ('has_csp',           'int',   0,     '1 if Content-Security-Policy header is present'),
    ('has_hsts',          'int',   0,     '1 if Strict-Transport-Security header is present'),
    ('has_xframe',        'int',   0,     '1 if X-Frame-Options header is present'),

    # Detector type (one-hot encoded)
    ('det_security_headers',      'int', 0, '1 if finding from security_headers detector'),
    ('det_cookie_security',       'int', 0, '1 if finding from cookie_security detector'),
    ('det_cors',                  'int', 0, '1 if finding from cors detector'),
    ('det_http_methods',          'int', 0, '1 if finding from http_methods detector'),
    ('det_information_disclosure','int', 0, '1 if finding from information_disclosure detector'),
    ('det_directory_exposure',    'int', 0, '1 if finding from directory_exposure detector'),
    ('det_xss',                   'int', 0, '1 if finding from xss detector'),
    ('det_sqli',                  'int', 0, '1 if finding from sqli detector'),
    ('det_open_redirect',         'int', 0, '1 if finding from open_redirect detector'),
    ('det_path_traversal',        'int', 0, '1 if finding from path_traversal detector'),

    # Evidence completeness
    ('evidence_field_count', 'int', 0,  'Number of non-empty evidence fields'),
    ('has_url_evidence',     'int', 0,  '1 if evidence contains a URL'),
    ('has_payload_evidence', 'int', 0,  '1 if evidence contains the payload used'),
    ('has_snippet_evidence', 'int', 0,  '1 if evidence contains a response snippet'),

    # Severity as ordinal
    ('severity_ordinal',  'int',   0,   'Severity as ordinal: critical=4, high=3, medium=2, low=1, info=0'),
]

# Derived constants
FEATURE_NAMES = [f[0] for f in FEATURE_DEFINITIONS]
FEATURE_DEFAULTS = {f[0]: f[2] for f in FEATURE_DEFINITIONS}
FEATURE_DTYPES = {f[0]: f[1] for f in FEATURE_DEFINITIONS}
NUM_FEATURES = len(FEATURE_NAMES)

# Detector name → one-hot feature name mapping
DETECTOR_FEATURE_MAP = {
    'security_headers':      'det_security_headers',
    'cookie_security':       'det_cookie_security',
    'cors':                  'det_cors',
    'http_methods':          'det_http_methods',
    'information_disclosure':'det_information_disclosure',
    'directory_exposure':    'det_directory_exposure',
    'xss':                   'det_xss',
    'sqli':                  'det_sqli',
    'open_redirect':         'det_open_redirect',
    'path_traversal':        'det_path_traversal',
}

SEVERITY_ORDINAL = {
    'critical': 4,
    'high':     3,
    'medium':   2,
    'low':      1,
    'info':     0,
}

PAYLOAD_CATEGORY_MAP = {
    'xss':           'payload_xss',
    'sqli':          'payload_sqli',
    'open_redirect': 'payload_redirect',
    'path_traversal':'payload_traversal',
}
