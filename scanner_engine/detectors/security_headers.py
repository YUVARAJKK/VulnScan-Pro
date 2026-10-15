"""HTTP Security Headers detector — OWASP A05:2021 Security Misconfiguration."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from .base import BaseDetector

if TYPE_CHECKING:
    from scanner_engine.core.http_client import HttpClient
    from scanner_engine.models.finding import Finding

# Required security headers and their configs
REQUIRED_HEADERS = [
    {
        'key': 'strict-transport-security',
        'name': 'HSTS',
        'severity': 'medium',
        'cvss': 4.3,
        'owasp': 'A05:2021',
        'cwe': 'CWE-319',
        'mitre_technique': 'T1040',
        'mitre_tactic': 'Credential Access',
        'description': 'HSTS missing — browser connections may be downgraded to HTTP, enabling MITM attacks.',
        'fix': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    },
    {
        'key': 'content-security-policy',
        'name': 'CSP',
        'severity': 'medium',
        'cvss': 5.4,
        'owasp': 'A05:2021',
        'cwe': 'CWE-693',
        'mitre_technique': 'T1059.007',
        'mitre_tactic': 'Execution',
        'description': 'CSP missing — attackers can inject and execute arbitrary JavaScript (XSS).',
        'fix': "Add CSP header: Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'",
    },
    {
        'key': 'x-frame-options',
        'name': 'X-Frame-Options',
        'severity': 'medium',
        'cvss': 4.3,
        'owasp': 'A05:2021',
        'cwe': 'CWE-1021',
        'mitre_technique': 'T1185',
        'mitre_tactic': 'Credential Access',
        'description': 'X-Frame-Options missing — application can be embedded in iframes for clickjacking.',
        'fix': 'Add: X-Frame-Options: DENY (or use CSP frame-ancestors directive)',
    },
    {
        'key': 'x-content-type-options',
        'name': 'X-Content-Type-Options',
        'severity': 'low',
        'cvss': 3.1,
        'owasp': 'A05:2021',
        'cwe': 'CWE-16',
        'mitre_technique': 'T1190',
        'mitre_tactic': 'Initial Access',
        'description': 'Missing X-Content-Type-Options allows MIME-type sniffing.',
        'fix': 'Add: X-Content-Type-Options: nosniff',
    },
    {
        'key': 'referrer-policy',
        'name': 'Referrer-Policy',
        'severity': 'low',
        'cvss': 2.7,
        'owasp': 'A05:2021',
        'cwe': 'CWE-200',
        'mitre_technique': 'T1592',
        'mitre_tactic': 'Reconnaissance',
        'description': 'Missing Referrer-Policy leaks sensitive URL path information.',
        'fix': 'Add: Referrer-Policy: strict-origin-when-cross-origin',
    },
    {
        'key': 'permissions-policy',
        'name': 'Permissions-Policy',
        'severity': 'low',
        'cvss': 2.0,
        'owasp': 'A05:2021',
        'cwe': 'CWE-693',
        'mitre_technique': 'T1418',
        'mitre_tactic': 'Discovery',
        'description': 'Missing Permissions-Policy allows third-party scripts to access sensitive browser APIs.',
        'fix': 'Add: Permissions-Policy: camera=(), microphone=(), geolocation=()',
    },
]


class SecurityHeadersDetector(BaseDetector):
    """Detects missing or misconfigured HTTP security headers."""

    name = 'security_headers'
    category = 'headers'

    async def detect(
        self,
        target_url: str,
        http_client: 'HttpClient',
        **kwargs,
    ) -> list['Finding']:
        findings: list[Finding] = []
        hostname = kwargs.get('hostname', target_url)

        # Try HTTPS first, then HTTP
        headers = None
        base_url = target_url
        from scanner_engine.core.url_utils import extract_base_url
        base = extract_base_url(target_url)

        for scheme in ['https', 'http']:
            try:
                url = f'{scheme}://{base.split("://", 1)[1]}'
                resp = await http_client.get(url, follow_redirects=True)
                headers = resp.headers
                base_url = url
                break
            except Exception:
                continue

        if not headers:
            return findings

        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Check required headers
        for h in REQUIRED_HEADERS:
            if h['key'] not in headers_lower:
                findings.append(self._make_finding(
                    scan_id=kwargs.get('scan_id'),
                    title=f"Missing Security Header: {h['name']}",
                    description=h['description'],
                    severity=h['severity'],
                    cvss_score=h['cvss'],
                    affected_component=f"{hostname} (HTTP Headers)",
                    endpoint=base_url,
                    remediation=h['fix'],
                    references=f"OWASP {h['owasp']}",
                    mitre_technique=h['mitre_technique'],
                    mitre_tactic=h['mitre_tactic'],
                    evidence={'header': h['key'], 'owasp': h['owasp'], 'cwe': h['cwe']},
                ))

        # Check HSTS max-age
        hsts = headers_lower.get('strict-transport-security', '')
        if hsts:
            match = re.search(r'max-age=(\d+)', hsts, re.IGNORECASE)
            max_age = int(match.group(1)) if match else 0
            if max_age < 31536000:
                findings.append(self._make_finding(
                    scan_id=kwargs.get('scan_id'),
                    title='HSTS max-age Too Short',
                    description=f'HSTS max-age is {max_age}s — should be at least 31536000 (1 year).',
                    severity='low',
                    cvss_score=2.0,
                    affected_component=f"{hostname} (HSTS)",
                    endpoint=base_url,
                    remediation='Update HSTS: max-age=31536000; includeSubDomains; preload',
                    evidence={'current_max_age': max_age, 'recommended': 31536000},
                ))
            if 'includesubdomains' not in hsts.lower():
                findings.append(self._make_finding(
                    scan_id=kwargs.get('scan_id'),
                    title='HSTS Missing includeSubDomains',
                    description='HSTS does not include subdomains — subdomain connections can be downgraded.',
                    severity='info',
                    cvss_score=0.0,
                    affected_component=f"{hostname} (HSTS)",
                    endpoint=base_url,
                    remediation='Add includeSubDomains directive',
                ))

        # Check CSP for unsafe directives
        csp = headers_lower.get('content-security-policy', '')
        if csp:
            if "'unsafe-inline'" in csp:
                findings.append(self._make_finding(
                    scan_id=kwargs.get('scan_id'),
                    title="CSP Uses 'unsafe-inline' — XSS Risk",
                    description='CSP contains unsafe-inline, nullifying XSS protection.',
                    severity='medium',
                    cvss_score=5.4,
                    affected_component=f"{hostname} (CSP)",
                    endpoint=base_url,
                    remediation="Replace unsafe-inline with CSP nonces",
                    evidence={'csp': csp[:200]},
                ))
            if "'unsafe-eval'" in csp:
                findings.append(self._make_finding(
                    scan_id=kwargs.get('scan_id'),
                    title="CSP Uses 'unsafe-eval' — Code Injection Risk",
                    description='CSP contains unsafe-eval, allowing eval() and Function().',
                    severity='medium',
                    cvss_score=4.7,
                    affected_component=f"{hostname} (CSP)",
                    endpoint=base_url,
                    remediation='Remove unsafe-eval from CSP.',
                    evidence={'csp': csp[:200]},
                ))

        # Server / technology disclosure
        if 'server' in headers_lower:
            srv = headers_lower['server']
            version_match = re.search(r'(\d+\.\d+[\.\d]*)', srv)
            findings.append(self._make_finding(
                scan_id=kwargs.get('scan_id'),
                title=f'Server Version Disclosed: "{srv}"',
                description=f'Server header exposes "{srv}". MITRE ATT&CK T1592.',
                severity='low' if version_match else 'info',
                cvss_score=3.7 if version_match else 0.0,
                affected_component=f"{hostname} (Server Header)",
                endpoint=base_url,
                remediation='Suppress server version information.',
                mitre_technique='T1592',
                mitre_tactic='Reconnaissance',
                evidence={'server': srv, 'version': version_match.group(0) if version_match else None},
            ))

        if 'x-powered-by' in headers_lower:
            findings.append(self._make_finding(
                scan_id=kwargs.get('scan_id'),
                title=f'Technology Disclosed: X-Powered-By: "{headers_lower["x-powered-by"]}"',
                description=f'X-Powered-By header reveals technology stack (MITRE T1592).',
                severity='low',
                cvss_score=3.7,
                affected_component=f"{hostname} (X-Powered-By)",
                endpoint=base_url,
                remediation='Disable X-Powered-By header.',
                mitre_technique='T1592',
                mitre_tactic='Reconnaissance',
                evidence={'powered_by': headers_lower['x-powered-by']},
            ))

        return findings
