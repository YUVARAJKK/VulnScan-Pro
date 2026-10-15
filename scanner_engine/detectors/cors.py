"""CORS misconfiguration detection — OWASP A01:2021."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import BaseDetector

if TYPE_CHECKING:
    from scanner_engine.core.http_client import HttpClient
    from scanner_engine.models.finding import Finding


class CorsDetector(BaseDetector):
    """Detects CORS misconfigurations including wildcard and origin reflection."""

    name = 'cors'
    category = 'misconfig'

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

        try:
            resp = await http_client.get(
                base,
                headers={'Origin': 'https://evil-attacker.com'},
                follow_redirects=True,
            )
            acao = resp.headers.get('access-control-allow-origin', '')
            acac = resp.headers.get('access-control-allow-credentials', '')

            if acao == '*':
                findings.append(self._make_finding(
                    scan_id=kwargs.get('scan_id'),
                    title='CORS Wildcard Origin: Access-Control-Allow-Origin: *',
                    description='Server allows ALL origins (CORS wildcard). Any website can make cross-origin requests.',
                    severity='medium',
                    cvss_score=5.4,
                    affected_component=f'{hostname} (CORS)',
                    remediation="Replace wildcard with specific allowed origins.",
                    evidence={'acao': acao},
                ))

            if 'evil-attacker.com' in (acao or ''):
                findings.append(self._make_finding(
                    scan_id=kwargs.get('scan_id'),
                    title='CORS Reflects Arbitrary Origins — CRITICAL',
                    description='Server reflects attacker-controlled origin in ACAO header. Combined with credentials, enables full CSRF and data theft.',
                    severity='critical',
                    cvss_score=9.1,
                    affected_component=f'{hostname} (CORS — Origin Reflection)',
                    endpoint=base,
                    remediation='Implement a CORS allowlist. Never reflect Origin without validation.',
                    evidence={'acao': acao, 'reflects_origin': True},
                ))

            if acao and acac.lower() == 'true':
                findings.append(self._make_finding(
                    scan_id=kwargs.get('scan_id'),
                    title='CORS Allows Credentials with Permissive Origin',
                    description=f'Server sets ACA-Credentials: true with {acao} origin. Enables cross-origin session theft.',
                    severity='high',
                    cvss_score=7.5,
                    affected_component=f'{hostname} (CORS Credentials)',
                    endpoint=base,
                    remediation='Never use ACA-Credentials: true with wildcard or reflected origins.',
                    evidence={'acao': acao, 'acac': acac},
                ))

        except Exception:
            pass

        return findings
