"""Scanner configuration."""

import os
from dataclasses import dataclass, field


@dataclass
class ScannerConfig:
    """Central configuration for the vulnerability scanner engine."""

    # Network
    timeout: int = 15
    max_redirects: int = 10
    max_concurrent_requests: int = 50
    rate_limit_per_second: float = 20.0
    http2: bool = True

    # Crawler
    crawler_max_depth: int = 3
    crawler_max_pages: int = 200
    crawler_max_time_seconds: int = 120
    crawler_respect_robots: bool = True

    # Port scanning
    port_scan_timeout: float = 2.0
    common_ports: list = field(default_factory=lambda: [
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
        993, 995, 1433, 1521, 3306, 3389, 5432, 5900,
        6379, 8080, 8443, 8888, 9200, 9300, 27017,
    ])

    # Detection
    xss_payloads: list = field(default_factory=lambda: [
        '<script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        "'-alert(1)-'",
        '<svg/onload=alert(1)>',
        'javascript:alert(1)',
        '{{7*7}}',
        '${7*7}',
    ])

    sqli_payloads: list = field(default_factory=lambda: [
        "' OR '1'='1",
        "' OR 1=1--",
        "1' UNION SELECT NULL--",
        "1; SELECT 1--",
        "' OR pg_sleep(5)--",
        "1' AND '1'='1",
    ])

    open_redirect_payloads: list = field(default_factory=lambda: [
        'https://evil.com',
        '//evil.com',
        '/\\evil.com',
        'https://evil%00.com',
    ])

    path_traversal_payloads: list = field(default_factory=lambda: [
        '../../../etc/passwd',
        '..%2f..%2f..%2fetc/passwd',
        '....//....//....//etc/passwd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd',
        '../../../windows/system32/config/sam',
    ])

    # Evidence
    min_confidence: str = 'low'  # low | medium | high
    evidence_max_length: int = 2000

    # User-Agent
    user_agent: str = (
        'VulnScanPro/3.0 (Security Scanner; +https://vulnscan-pro.local)'
    )

    # Database (override via env or CLI args)
    db_url: str = ''

    @classmethod
    def from_env(cls) -> 'ScannerConfig':
        cfg = cls()
        cfg.db_url = os.environ.get('SCANNER_DB_URL', cfg.db_url)
        cfg.timeout = int(os.environ.get('SCANNER_TIMEOUT', cfg.timeout))
        cfg.max_concurrent_requests = int(
            os.environ.get('SCANNER_MAX_CONCURRENT', cfg.max_concurrent_requests)
        )
        cfg.rate_limit_per_second = float(
            os.environ.get('SCANNER_RATE_LIMIT', cfg.rate_limit_per_second)
        )
        return cfg
