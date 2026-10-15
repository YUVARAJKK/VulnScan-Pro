"""Directory listing and backup file exposure detection."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from .base import BaseDetector

if TYPE_CHECKING:
    from scanner_engine.core.http_client import HttpClient
    from scanner_engine.models.finding import Finding

DIRECTORY_LISTING_PATTERNS = [
    r'(?i)<title>\s*index\s+of\s*/',
    r'(?i)Index of /',
    r'(?i)<h1>Index of /',
    r'(?i)Directory listing for',
    r'(?i)>Parent Directory<',
]

BACKUP_EXTENSIONS = [
    '.bak', '.old', '.orig', '.save', '.swp', '.tmp',
    '.copy', '.backup', '~', '.sql', '.sql.gz', '.tar.gz',
]

BACKUP_FILES = [
    'web.config.bak', 'config.php.bak', 'wp-config.php.bak',
    'database.yml.bak', '.env.bak', 'settings.py.bak',
    'application.properties.bak', 'config.json.bak',
]


class DirectoryExposureDetector(BaseDetector):
    """Detects directory listings and backup file exposure."""

    name = 'directory_exposure'
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

        # Check for directory listing on root and common paths
        check_paths = ['/', '/images/', '/uploads/', '/files/', '/assets/', '/static/']
        for path in check_paths:
            try:
                resp = await http_client.get(f'{base}{path}', follow_redirects=True)
                body = resp.text[:5000] if resp.text else ''
                for pattern in DIRECTORY_LISTING_PATTERNS:
                    if re.search(pattern, body):
                        findings.append(self._make_finding(
                            scan_id=kwargs.get('scan_id'),
                            title=f'Directory Listing Enabled: {path}',
                            description=f'Web server serves directory listings at {path}. Exposes file structure to attackers.',
                            severity='medium',
                            cvss_score=5.3,
                            affected_component=f'{hostname}{path}',
                            endpoint=f'{base}{path}',
                            remediation='Disable directory listings in web server configuration.',
                            evidence={'path': path, 'pattern': pattern},
                        ))
                        break
            except Exception:
                continue

        # Check for backup files
        for file in BACKUP_FILES:
            try:
                resp = await http_client.get(f'{base}/{file}', follow_redirects=False)
                if resp.status_code == 200 and len(resp.text or '') > 20:
                    findings.append(self._make_finding(
                        scan_id=kwargs.get('scan_id'),
                        title=f'Backup File Exposed: {file}',
                        description=f'Backup file {file} is publicly accessible. May contain credentials or configuration.',
                        severity='high',
                        cvss_score=7.5,
                        affected_component=f'{hostname}/{file}',
                        endpoint=f'{base}/{file}',
                        remediation=f'Remove {file} from the web root and block access via WAF.',
                        evidence={'file': file, 'status_code': resp.status_code},
                    ))
            except Exception:
                continue

        return findings
