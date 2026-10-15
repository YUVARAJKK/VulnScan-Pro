"""Server and framework fingerprinting via response headers and body patterns."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.http_client import HttpClient

# Technology detection patterns
TECH_SIGNATURES = [
    # Server headers
    {'header': 'server', 'pattern': r'(?i)nginx', 'name': 'Nginx', 'category': 'Web Server'},
    {'header': 'server', 'pattern': r'(?i)apache', 'name': 'Apache', 'category': 'Web Server'},
    {'header': 'server', 'pattern': r'(?i)cloudflare', 'name': 'Cloudflare', 'category': 'CDN'},
    {'header': 'server', 'pattern': r'(?i) microsoft-iis', 'name': 'IIS', 'category': 'Web Server'},
    {'header': 'x-powered-by', 'pattern': r'(?i)express', 'name': 'Express.js', 'category': 'Framework'},
    {'header': 'x-powered-by', 'pattern': r'(?i)php', 'name': 'PHP', 'category': 'Language'},
    {'header': 'x-powered-by', 'pattern': r'(?i)asp\.net', 'name': 'ASP.NET', 'category': 'Framework'},
    {'header': 'x-powered-by', 'pattern': r'(?i)next\.js', 'name': 'Next.js', 'category': 'Framework'},

    # Body patterns
    {'body': r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress', 'name': 'WordPress', 'category': 'CMS'},
    {'body': r'<meta\s+name=["\']generator["\']\s+content=["\']Drupal', 'name': 'Drupal', 'category': 'CMS'},
    {'body': r'<meta\s+name=["\']generator["\']\s+content=["\']Joomla', 'name': 'Joomla', 'category': 'CMS'},
    {'body': r'__NEXT_DATA__', 'name': 'Next.js', 'category': 'Framework'},
    {'body': r'__NUXT__', 'name': 'Nuxt.js', 'category': 'Framework'},
    {'body': r'ng-version', 'name': 'Angular', 'category': 'Framework'},
    {'body': r'data-reactroot', 'name': 'React', 'category': 'Framework'},
    {'body': r'vue\.js|Vue\.component', 'name': 'Vue.js', 'category': 'Framework'},
    {'body': r'jquery[/.-]', 'name': 'jQuery', 'category': 'Library'},
    {'body': r'bootstrap[/.-]', 'name': 'Bootstrap', 'category': 'Library'},
    {'body': r'laravel', 'name': 'Laravel', 'category': 'Framework'},
    {'body': r'rails\.env', 'name': 'Ruby on Rails', 'category': 'Framework'},
    {'body': r'django', 'name': 'Django', 'category': 'Framework'},
    {'body': r'flask', 'name': 'Flask', 'category': 'Framework'},
    {'body': r'vbulletin', 'name': 'vBulletin', 'category': 'CMS'},
    {'body': r'magento', 'name': 'Magento', 'category': 'E-commerce'},
    {'body': r'shopify', 'name': 'Shopify', 'category': 'E-commerce'},
]


async def detect_technologies(
    target_url: str,
    http_client: 'HttpClient',
) -> list[dict]:
    """
    Detect technologies used by the target.
    Returns list of {name, category, evidence}.
    """
    from core.url_utils import extract_base_url
    base = extract_base_url(target_url)
    technologies = []

    try:
        resp = await http_client.get(base, follow_redirects=True)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.text or ''

        for sig in TECH_SIGNATURES:
            if 'header' in sig:
                header_val = headers.get(sig['header'].lower(), '')
                if re.search(sig['pattern'], header_val):
                    technologies.append({
                        'name': sig['name'],
                        'category': sig['category'],
                        'evidence': f'{sig["header"]}: {header_val}',
                    })
            elif 'body' in sig:
                if re.search(sig['body'], body, re.IGNORECASE):
                    match = re.search(sig['body'], body, re.IGNORECASE)
                    technologies.append({
                        'name': sig['name'],
                        'category': sig['category'],
                        'evidence': match.group(0)[:100] if match else '',
                    })

    except Exception:
        pass

    # Deduplicate
    seen = set()
    unique = []
    for tech in technologies:
        key = tech['name']
        if key not in seen:
            seen.add(key)
            unique.append(tech)

    return unique
