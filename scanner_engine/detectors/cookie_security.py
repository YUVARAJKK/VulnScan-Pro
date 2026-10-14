"""Cookie security flag analysis — OWASP A05:2021."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import BaseDetector

if TYPE_CHECKING:
    from scanner_engine.core.http_client import HttpClient
    from scanner_engine.models.finding import Finding


class CookieSecurityDetector(BaseDetector):
    """Detects missing security flags on cookies (HttpOnly, Secure, SameSite)."""

    name = 'cookie_security'
    category = 'headers'

    async def detect(
        self,
        target_url: str,
        http_client: 'HttpClient',
        **kwargs,
    ) -> list['Finding']:
        findings: list[Finding] = []
        hostname = kwargs.get('hostname', target_url)

        headers = None
        from scanner_engine.core.url_utils import extract_base_url
        base = extract_base_url(target_url)

        for scheme in ['https', 'http']:
            try:
                url = f'{scheme}://{base.split("://", 1)[1]}'
                resp = await http_client.get(url, follow_redirects=True)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                break
            except Exception:
                continue

        if not headers:
            return findings

        set_cookies_raw = headers.get('set-cookie', '')
        if not set_cookies_raw:
            return findings

        # Parse cookies (may be a single header or multiple)
        cookies = []
        if isinstance(set_cookies_raw, list):
            cookies = set_cookies_raw
        else:
            # Split on ', ' but be careful with attributes
            cookies = [c.strip() for c in set_cookies_raw.split('\n') if c.strip()]

        for cookie_str in cookies:
            cookie_name = cookie_str.split('=')[0].strip()
            lc = cookie_str.lower()

            if 'httponly' not in lc:
                findings.append(self._make_finding(
                    scan_id=kwargs.get('scan_id'),
                    title=f'Cookie Missing HttpOnly Flag: {cookie_name}',
                    description=f'Cookie "{cookie_name}" lacks HttpOnly — JavaScript can read it, enabling XSS session theft.',
                    severity='medium',
                    cvss_score=4.3,
                    affected_component=f'{hostname} (Cookie: {cookie_name})',
                    remediation=f"Set HttpOnly: res.cookie('{cookie_name}', value, {{ httpOnly: true }})",
                    evidence={'cookie': cookie_name, 'flag': 'httponly'},
                ))

            if 'secure' not in lc:
                findings.append(self._make_finding(
                    scan_id=kwargs.get('scan_id'),
                    title=f'Cookie Missing Secure Flag: {cookie_name}',
                    description=f'Cookie "{cookie_name}" lacks Secure flag — may be sent over unencrypted HTTP.',
                    severity='medium',
                    cvss_score=4.3,
                    affected_component=f'{hostname} (Cookie: {cookie_name})',
                    remediation=f"Add Secure flag: res.cookie('{cookie_name}', value, {{ secure: true }})",
                    evidence={'cookie': cookie_name, 'flag': 'secure'},
                ))

            if 'samesite' not in lc:
                findings.append(self._make_finding(
                    scan_id=kwargs.get('scan_id'),
                    title=f'Cookie Missing SameSite: {cookie_name}',
                    description=f'Cookie "{cookie_name}" has no SameSite attribute — vulnerable to CSRF.',
                    severity='low',
                    cvss_score=3.1,
                    affected_component=f'{hostname} (Cookie: {cookie_name})',
                    remediation="Add SameSite: res.cookie(name, value, { sameSite: 'strict' })",
                    evidence={'cookie': cookie_name, 'flag': 'samesite'},
                ))

        return findings
