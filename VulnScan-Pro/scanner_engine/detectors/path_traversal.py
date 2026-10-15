"""Path traversal detection — OWASP A01:2021."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from .base import BaseDetector

if TYPE_CHECKING:
    from scanner_engine.core.http_client import HttpClient
    from scanner_engine.models.finding import Finding

# Indicators that a file was read
FILE_CONTENT_PATTERNS = [
    (r'(?i)root:.*?:0:0:', '/etc/passwd content'),
    (r'(?i)\[boot loader\]', 'Windows boot.ini content'),
    (r'(?i)\[operating systems\]', 'Windows boot.ini content'),
    (r'(?i)mysql:', '/etc/passwd mysql entry'),
]

TRAVERSAL_PAYLOADS = [
    '../../../etc/passwd',
    '..%2f..%2f..%2fetc/passwd',
    '....//....//....//etc/passwd',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd',
    '..\\..\\..\\windows\\system32\\config\\sam',
    '....\\\\....\\\\....\\\\windows\\system32\\config\\sam',
]

# Common parameters that might accept file paths
FILE_PARAMS = [
    'file', 'path', 'page', 'include', 'doc', 'document',
    'template', 'view', 'load', 'read', 'src', 'img',
    'image', 'style', 'script', 'config', 'lang',
]


class PathTraversalDetector(BaseDetector):
    """Detects path traversal / local file inclusion vulnerabilities."""

    name = 'path_traversal'
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

        # Build test URLs
        test_urls = []
        if endpoints:
            for ep in endpoints[:30]:
                params = ep.get('parameters', FILE_PARAMS[:4])
                for param in params:
                    test_urls.append((ep['url'], param))
        else:
            for param in FILE_PARAMS[:5]:
                test_urls.append((base, param))

        seen = set()
        for url, param_name in test_urls[:25]:
            key = f'{url}|{param_name}'
            if key in seen:
                continue
            seen.add(key)

            # Get baseline
            try:
                baseline_url = add_params_to_url(url, {param_name: 'test'})
                baseline_resp = await http_client.get(baseline_url, follow_redirects=True)
                baseline_body = baseline_resp.text or ''
                baseline_status = baseline_resp.status_code
                if baseline_status == 404:
                    continue
            except Exception:
                continue

            for payload in TRAVERSAL_PAYLOADS:
                try:
                    test_url = add_params_to_url(url, {param_name: payload})
                    resp = await http_client.get(test_url, follow_redirects=True)
                    body = resp.text or ''

                    # Check for file content patterns
                    for pattern, desc in FILE_CONTENT_PATTERNS:
                        if re.search(pattern, body):
                            findings.append(self._make_finding(
                                scan_id=kwargs.get('scan_id'),
                                title=f'Path Traversal: {param_name} parameter',
                                description=f'The {param_name} parameter is vulnerable to path traversal. Detected: {desc}.',
                                severity='critical',
                                cvss_score=9.1,
                                cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
                                affected_component=f'{hostname} ({param_name})',
                                endpoint=url,
                                parameter=param_name,
                                confidence='high',
                                remediation='Validate and sanitize file paths. Use a chroot jail or sandbox. Never use user input directly in file operations.',
                                evidence={
                                    'payload': payload,
                                    'content_pattern': desc,
                                    'url': test_url,
                                },
                            ))
                            break
                    else:
                        continue
                    break  # One finding per parameter

                    # Also check for error-based indicators
                    if resp.status_code == 200 and len(body) > len(baseline_body) * 1.5:
                        if any(kw in body.lower() for kw in ['no such file', 'file not found', 'cannot open']):
                            findings.append(self._make_finding(
                                scan_id=kwargs.get('scan_id'),
                                title=f'Path Traversal (error-based): {param_name}',
                                description=f'The {param_name} parameter may allow path traversal (server responds to path manipulation).',
                                severity='medium',
                                cvss_score=6.5,
                                affected_component=f'{hostname} ({param_name})',
                                endpoint=url,
                                parameter=param_name,
                                confidence='medium',
                                remediation='Validate and sanitize file paths.',
                                evidence={'payload': payload, 'url': test_url},
                            ))
                            break

                except Exception:
                    continue

        return findings
