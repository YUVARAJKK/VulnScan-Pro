"""Reflected XSS detection — marker-based, context-aware testing."""

from __future__ import annotations

import re
import html
from typing import TYPE_CHECKING

from .base import BaseDetector

if TYPE_CHECKING:
    from scanner_engine.core.http_client import HttpClient
    from scanner_engine.models.finding import Finding

# Unique, harmless markers used to detect reflection. The markers themselves
# contain NO executable payloads. Quote-bearing markers probe whether user
# input can break out of an HTML attribute; the '<' marker probes raw HTML
# injection (e.g. into <script> blocks or event handlers).
MARKERS = [
    '<vulnscanXSS>',       # raw HTML/tag-context probe
    'vulnscanXSS"y',       # double-quote attribute breakout probe
    "vulnscanXSS'z",       # single-quote attribute breakout probe
    'vulnscanXSSmarker',   # plain reflection probe
]

# Contexts where a reflected marker indicates a genuine XSS risk.
# Order matters — the first match wins (most specific first).
XSS_CONTEXTS = [
    (r'<script[^>]*>.*?{marker}.*?</script>', 'Inside <script> tag — direct JS execution context', 'high'),
    (r'on\w+\s*=\s*["\'][^>]*?{marker}', 'Inside event-handler attribute — direct JS execution context', 'high'),
    (r'href\s*=\s*["\'][^>]*?{marker}', 'Inside href attribute — potential javascript: URI injection', 'high'),
    (r'src\s*=\s*["\'][^>]*?{marker}', 'Inside src attribute — potential scriptable URI injection', 'high'),
    (r'<[^>]*{marker}[^>]*>', 'Inside an HTML tag attribute — attribute context', 'medium'),
    (r'<[^>]*>[^<]*{marker}[^<]*', 'Reflected in HTML body text — context depends on output encoding', 'low'),
]


class XssDetector(BaseDetector):
    """Detects reflected XSS vulnerabilities using marker-based testing."""

    name = 'xss'
    category = 'injection'

    async def detect(
        self,
        target_url: str,
        http_client: 'HttpClient',
        **kwargs,
    ) -> list['Finding']:
        findings: list[Finding] = []
        hostname = kwargs.get('hostname', target_url)
        endpoints: list = kwargs.get('endpoints', [])

        from scanner_engine.core.url_utils import add_params_to_url, extract_base_url
        base = extract_base_url(target_url)

        # If no endpoints discovered, test the base URL with common parameters
        test_urls = []
        if endpoints:
            for ep in endpoints[:50]:  # Limit to prevent too many requests
                params = ep.get('parameters', ['q', 'search', 'id', 'page', 'name', 'input'])
                for param in params[:3]:
                    test_urls.append((ep['url'], param))
        else:
            # Test base URL with common parameter names
            for param in ['q', 'search', 'id', 'page', 'name', 'input', 'callback', 'redirect']:
                test_urls.append((base, param))

        for url, param_name in test_urls[:30]:  # Limit total tests
            for marker in MARKERS[:2]:  # Use 2 markers
                try:
                    test_url = add_params_to_url(url, {param_name: marker})
                    resp = await http_client.get(test_url, follow_redirects=True)
                    body = resp.text or ''

                    # No reflection at all — nothing to report
                    if marker not in body:
                        continue

                    # If the marker only appears in its HTML-entity-encoded form,
                    # output encoding is active and there is no direct XSS context.
                    # (Only relevant for markers containing special characters.)
                    encoded_marker = html.escape(marker)
                    if encoded_marker != marker and marker not in body.replace(encoded_marker, ''):
                        continue

                    # Classify reflection context (most specific first)
                    context_info = None
                    severity = 'low'
                    confidence = 'low'
                    for ctx_pattern, ctx_desc, ctx_severity in XSS_CONTEXTS:
                        pattern = ctx_pattern.replace('{marker}', re.escape(marker))
                        if re.search(pattern, body, re.DOTALL | re.IGNORECASE):
                            context_info = ctx_desc
                            severity = ctx_severity
                            confidence = 'high' if ctx_severity == 'high' else 'medium'
                            break

                    # No recognised executable/attribute context — unverified reflection
                    if context_info is None:
                        context_info = 'Reflected in response body — no executable context proven'

                    findings.append(self._make_finding(
                        scan_id=kwargs.get('scan_id'),
                        title=f'Reflected XSS: {param_name} parameter' if severity != 'low' else f'Input Reflection: {param_name} parameter',
                        description=f'The parameter {param_name} reflects user input in the response. {context_info}.',
                        severity=severity,
                        cvss_score=6.1 if severity == 'high' else 4.7 if severity == 'medium' else 0.0,
                        affected_component=f'{hostname} ({param_name})',
                        endpoint=url,
                        parameter=param_name,
                        confidence=confidence,
                        remediation='Apply context-aware output encoding for all user-controlled data. Use a strict Content-Security-Policy and validate input against allowlists.',
                        evidence={
                            'marker': marker,
                            'param': param_name,
                            'context': context_info,
                            'url': test_url,
                            'reflected_unencoded': True,
                        },
                    ))
                    break  # One finding per parameter is enough

                except Exception:
                    continue

        return findings
