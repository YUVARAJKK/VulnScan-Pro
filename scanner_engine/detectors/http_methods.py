"""Dangerous HTTP method detection — OWASP A05:2021."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import BaseDetector

if TYPE_CHECKING:
    from scanner_engine.core.http_client import HttpClient
    from scanner_engine.models.finding import Finding


class HttpMethodsDetector(BaseDetector):
    """Detects dangerous HTTP methods (TRACE, DELETE, PUT, OPTIONS leaking)."""

    name = 'http_methods'
    category = 'misconfig'

    DANGEROUS_METHODS = {
        'TRACE': {
            'severity': 'medium',
            'cvss': 5.0,
            'description': 'TRACE method enabled — allows Cross-Site Tracing (XST) attacks to steal cookies.',
            'fix': 'Disable TRACE method in web server configuration.',
        },
        'DELETE': {
            'severity': 'info',
            'cvss': 0.0,
            'description': 'DELETE method is publicly accessible.',
            'fix': 'Restrict DELETE to authenticated API endpoints only.',
        },
        'PUT': {
            'severity': 'info',
            'cvss': 0.0,
            'description': 'PUT method is publicly accessible.',
            'fix': 'Restrict PUT to authenticated API endpoints only.',
        },
    }

    async def detect(
        self,
        target_url: str,
        http_client: 'HttpClient',
        **kwargs,
    ) -> list['Finding']:
        findings: list[Finding] = []
        hostname = kwargs.get('hostname', target_url)

        from scanner_engine.core.url_utils import extract_base_url
        base = extract_base_url(target_url)

        # Check OPTIONS response
        try:
            resp = await http_client.options(base)
            allow = resp.headers.get('allow', '')
            if allow:
                methods = [m.strip().upper() for m in allow.split(',')]
                for method in ['TRACE', 'DELETE', 'PUT', 'PATCH']:
                    if method in methods:
                        info = self.DANGEROUS_METHODS.get(method, {})
                        findings.append(self._make_finding(
                            scan_id=kwargs.get('scan_id'),
                            title=f'Dangerous HTTP Method: {method}',
                            description=info.get('description', f'{method} method is enabled.'),
                            severity=info.get('severity', 'info'),
                            cvss_score=info.get('cvss', 0.0),
                            affected_component=f'{hostname} (HTTP Methods)',
                            endpoint=base,
                            remediation=info.get('fix', f'Disable {method} method.'),
                            evidence={'allow_header': allow, 'method': method},
                        ))
        except Exception:
            pass

        # Directly test TRACE
        try:
            resp = await http_client._request('TRACE', base)
            if resp.status_code == 200:
                findings.append(self._make_finding(
                    scan_id=kwargs.get('scan_id'),
                    title='TRACE Method Enabled — Cross-Site Tracing (XST)',
                    description='TRACE method echoes back request headers, enabling cookie theft via XST.',
                    severity='medium',
                    cvss_score=5.0,
                    affected_component=f'{hostname} (TRACE)',
                    endpoint=base,
                    remediation='Disable TRACE method in web server.',
                ))
        except Exception:
            pass

        return findings
