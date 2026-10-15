"""SQL injection detection — error-based and differential analysis approach.

No time-based (blind) payloads are sent: timing attacks are deliberately
excluded to keep the scanner non-destructive and fast.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from .base import BaseDetector

if TYPE_CHECKING:
    from scanner_engine.core.http_client import HttpClient
    from scanner_engine.models.finding import Finding

# SQL error patterns that indicate injection
SQL_ERROR_PATTERNS = [
    (r'(?i)you\s+have\s+an\s+error\s+in\s+your\s+sql\s+syntax', 'MySQL syntax error'),
    (r'(?i)mysql_fetch', 'MySQL fetch error'),
    (r'(?i)warning.*?mysql', 'MySQL warning'),
    (r'(?i)unclosed\s+quotation\s+mark', 'MSSQL unclosed quotation'),
    (r'(?i)microsoft\s+OLE\s+DB\s+provider', 'MSSQL OLE DB error'),
    (r'(?i)ORA-\d{5}', 'Oracle error'),
    (r'(?i)PostgreSQL.*?ERROR', 'PostgreSQL error'),
    (r'(?i)pg_query\(\)', 'PostgreSQL pg_query error'),
    (r'(?i)sqlite3\.OperationalError', 'SQLite error'),
    (r'(?i)SQLITE_ERROR', 'SQLite error'),
    (r'(?i)unrecognized\s+token:', 'SQLite unrecognized token'),
    (r'(?i)syntax\s+error\s+at\s+line', 'Generic SQL syntax error'),
    (r'(?i)supplied\s+argument\s+is\s+not\s+a\s+valid', 'PHP SQL error'),
    (r'(?i)Division\s+by\s+zero\s+in', 'SQL division by zero'),
    (r'(?i)Microsoft\s+Access\s+Driver', 'Access driver error'),
]

# Error-based payloads
ERROR_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "1' UNION SELECT NULL--",
    "1' AND '1'='1",
    "') OR ('1'='1",
]


class SqliDetector(BaseDetector):
    """Detects SQL injection vulnerabilities using differential and error-based analysis."""

    name = 'sqli'
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
            for ep in endpoints[:50]:
                params = ep.get('parameters', ['id', 'q', 'search', 'page', 'user', 'item'])
                for param in params[:3]:
                    test_urls.append((ep['url'], param))
        else:
            for param in ['id', 'q', 'search', 'page', 'user', 'item', 'cat', 'sort']:
                test_urls.append((base, param))

        for url, param_name in test_urls[:25]:
            try:
                # Get baseline response
                baseline_url = add_params_to_url(url, {param_name: '1'})
                baseline_resp = await http_client.get(baseline_url, follow_redirects=True)
                baseline_body = baseline_resp.text or ''
                baseline_len = len(baseline_body)
                baseline_status = baseline_resp.status_code

                # Check if the parameter exists and responds
                if baseline_status == 404 or baseline_len < 10:
                    continue

                # Error-based testing
                for payload in ERROR_PAYLOADS:
                    test_url = add_params_to_url(url, {param_name: payload})
                    resp = await http_client.get(test_url, follow_redirects=True)
                    body = resp.text or ''

                    for pattern, desc in SQL_ERROR_PATTERNS:
                        if re.search(pattern, body):
                            findings.append(self._make_finding(
                                scan_id=kwargs.get('scan_id'),
                                title=f'SQL Injection: {param_name} parameter ({desc})',
                                description=f'The parameter {param_name} appears vulnerable to SQL injection. Error pattern: {desc}.',
                                severity='critical',
                                cvss_score=9.8,
                                cvss_vector='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                                affected_component=f'{hostname} ({param_name})',
                                endpoint=url,
                                parameter=param_name,
                                confidence='high',
                                remediation='Use parameterized queries/prepared statements. Never concatenate user input into SQL.',
                                references='OWASP A03:2021',
                                mitre_technique='T1190',
                                mitre_tactic='Initial Access',
                                evidence={
                                    'payload': payload,
                                    'error_pattern': desc,
                                    'url': test_url,
                                },
                            ))
                            break
                    else:
                        continue
                    break  # One finding per parameter

                # Differential analysis — response size change
                for payload in ["' OR '1'='1", "' OR 1=1--"]:
                    test_url = add_params_to_url(url, {param_name: payload})
                    resp = await http_client.get(test_url, follow_redirects=True)
                    body = resp.text or ''

                    # Significant response size difference may indicate injection
                    if abs(len(body) - baseline_len) > baseline_len * 0.3 and len(body) > 100:
                        # Check it's not just an error page
                        has_sql_error = any(re.search(p, body) for p, _ in SQL_ERROR_PATTERNS)
                        if not has_sql_error and resp.status_code == baseline_status:
                            findings.append(self._make_finding(
                                scan_id=kwargs.get('scan_id'),
                                title=f'Potential SQL Injection: {param_name} (differential analysis)',
                                description=f'Response size changed significantly with SQL payload, suggesting possible injection.',
                                severity='medium',
                                cvss_score=6.5,
                                affected_component=f'{hostname} ({param_name})',
                                endpoint=url,
                                parameter=param_name,
                                confidence='medium',
                                remediation='Use parameterized queries/prepared statements.',
                                evidence={
                                    'payload': payload,
                                    'baseline_length': baseline_len,
                                    'test_length': len(body),
                                    'url': test_url,
                                },
                            ))
                            break

            except Exception:
                continue

        return findings
