"""Open redirect detection — OWASP A01:2021."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import BaseDetector

if TYPE_CHECKING:
    from scanner_engine.core.http_client import HttpClient
    from scanner_engine.models.finding import Finding

REDIRECT_PARAMS = [
    'url', 'redirect', 'next', 'return', 'continue', 'dest',
    'destination', 'redir', 'redirect_url', 'redirect_uri',
    'return_url', 'return_to', 'goto', 'out', 'view', 'to',
    'ref', 'link', 'href', 'checkout_url', 'return_to',
]

REDIRECT_PAYLOADS = [
    'https://evil.com',
    '//evil.com',
]


class OpenRedirectDetector(BaseDetector):
    """Detects open redirect vulnerabilities."""

    name = 'open_redirect'
    category = 'misconfig'

    async def detect(
        self,
        target_url: str,
        http_client: 'HttpClient',
        **kwargs,
    ) -> list['Finding']:
        findings: list[Finding] = []
        hostname = kwargs.get('hostname', target_url)
        endpoints: list = kwargs.get('endpoints', [])

        from scanner_engine.core.url_utils import add_params_to_url, extract_base_url, is_same_domain
        base = extract_base_url(target_url)

        # Build test URLs
        test_urls = []
        if endpoints:
            for ep in endpoints[:30]:
                params = ep.get('parameters', REDIRECT_PARAMS[:5])
                for param in params:
                    test_urls.append((ep['url'], param))
        else:
            for param in REDIRECT_PARAMS[:6]:
                test_urls.append((base, param))

        seen = set()
        for url, param_name in test_urls[:30]:
            key = f'{url}|{param_name}'
            if key in seen:
                continue
            seen.add(key)

            for payload in REDIRECT_PAYLOADS:
                try:
                    test_url = add_params_to_url(url, {param_name: payload})
                    resp = await http_client.get(
                        test_url,
                        follow_redirects=False,
                        headers={'Host': hostname},
                    )

                    location = resp.headers.get('location', '')

                    # Check if response redirects to our payload
                    if resp.status_code in (301, 302, 303, 307, 308):
                        if payload in location or ('evil.com' in location):
                            if not is_same_domain(location, base):
                                findings.append(self._make_finding(
                                    scan_id=kwargs.get('scan_id'),
                                    title=f'Open Redirect: {param_name} parameter',
                                    description=f'The {param_name} parameter redirects to an external URL without validation.',
                                    severity='medium',
                                    cvss_score=6.1,
                                    affected_component=f'{hostname} ({param_name})',
                                    endpoint=url,
                                    parameter=param_name,
                                    confidence='high',
                                    remediation='Validate redirect targets against an allowlist of trusted domains.',
                                    evidence={
                                        'payload': payload,
                                        'location': location,
                                        'status_code': resp.status_code,
                                    },
                                ))
                                break

                    # Check meta-refresh and JavaScript redirects in body
                    body = resp.text or ''
                    if payload in body and ('url=' in body.lower() or 'location' in body.lower()):
                        if resp.status_code == 200:
                            findings.append(self._make_finding(
                                scan_id=kwargs.get('scan_id'),
                                title=f'Open Redirect (Client-side): {param_name} parameter',
                                description=f'The {param_name} parameter causes a client-side redirect to an external URL.',
                                severity='medium',
                                cvss_score=6.1,
                                affected_component=f'{hostname} ({param_name})',
                                endpoint=url,
                                parameter=param_name,
                                confidence='medium',
                                remediation='Validate redirect targets server-side.',
                                evidence={'payload': payload, 'body_snippet': body[:200]},
                            ))
                            break

                except Exception:
                    continue

        return findings
