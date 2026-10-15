"""Information disclosure detection — server version, stack traces, debug info."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from .base import BaseDetector

if TYPE_CHECKING:
    from scanner_engine.core.http_client import HttpClient
    from scanner_engine.models.finding import Finding

# Patterns that indicate information disclosure
DEBUG_PATTERNS = [
    (r'(?i)stack\s*trace', 'Stack trace exposed in response'),
    (r'(?i)exception\s+at\s+', 'Exception details exposed'),
    (r'(?i)traceback\s*\(', 'Python traceback exposed'),
    (r'(?i)fatal\s+error', 'Fatal error message exposed'),
    (r'(?i)debug\s*mode', 'Debug mode information exposed'),
    (r'(?i)internal\s+server\s+error.*<', 'Internal error with HTML content'),
    (r'(?i)sql\s+error', 'SQL error message exposed'),
    (r'(?i)mysql_fetch', 'MySQL error exposed'),
    (r'(?i)ORA-\d{5}', 'Oracle error code exposed'),
    (r'(?i)postgresql.*error', 'PostgreSQL error exposed'),
    (r'(?i)x-debug', 'X-Debug header detected'),
    (r'(?i)phpinfo\(\)', 'phpinfo() output exposed'),
    (r'<title>.*(?:error|exception|traceback|debug).*</title>', 'Debug page title detected'),
]

SENSITIVE_PATHS = [
    '/.env',
    '/.git/config',
    '/.git/HEAD',
    '/wp-config.php.bak',
    '/config.php.bak',
    '/database.yml',
    '/.DS_Store',
    '/server-status',
    '/server-info',
    '/phpinfo.php',
    '/info.php',
    '/actuator',
    '/actuator/health',
    '/actuator/env',
    '/swagger-ui.html',
    '/api/swagger',
]


class InformationDisclosureDetector(BaseDetector):
    """Detects server version disclosure, stack traces, and debug information."""

    name = 'information_disclosure'
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

        # Check main response for debug patterns
        try:
            resp = await http_client.get(base, follow_redirects=True)
            body = resp.text[:10000] if resp.text else ''

            for pattern, desc in DEBUG_PATTERNS:
                if re.search(pattern, body):
                    findings.append(self._make_finding(
                        scan_id=kwargs.get('scan_id'),
                        title=f'Information Disclosure: {desc}',
                        description=f'{desc} on {hostname}. Attackers can use this to gather internal details.',
                        severity='low',
                        cvss_score=3.1,
                        affected_component=f'{hostname} (Response Body)',
                        endpoint=base,
                        remediation='Remove debug information from production responses.',
                        evidence={'pattern': pattern, 'match': desc},
                    ))
                    break  # One finding per response is enough

            # Check for HTTP 5xx errors exposed
            if resp.status_code >= 500:
                findings.append(self._make_finding(
                    scan_id=kwargs.get('scan_id'),
                    title=f'Server Error Exposed: HTTP {resp.status_code}',
                    description=f'Server returned {resp.status_code} error publicly — may expose internals.',
                    severity='low',
                    cvss_score=2.0,
                    affected_component=f'{hostname} (HTTP {resp.status_code})',
                    endpoint=base,
                    remediation='Configure custom error pages that hide server internals.',
                    evidence={'status_code': resp.status_code},
                ))
        except Exception:
            pass

        # Check sensitive paths
        for path in SENSITIVE_PATHS:
            try:
                url = f'{base}{path}'
                resp = await http_client.get(url, follow_redirects=False)
                if resp.status_code == 200 and len(resp.text or '') > 50:
                    findings.append(self._make_finding(
                        scan_id=kwargs.get('scan_id'),
                        title=f'Sensitive Path Exposed: {path}',
                        description=f'The path {path} is accessible and returns content. May expose sensitive information.',
                        severity='high',
                        cvss_score=7.5,
                        affected_component=f'{hostname}{path}',
                        endpoint=url,
                        remediation=f'Block access to {path} via web server configuration or WAF.',
                        evidence={'path': path, 'status_code': resp.status_code, 'content_length': len(resp.text or '')},
                    ))
            except Exception:
                continue

        return findings
