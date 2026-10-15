"""robots.txt and sitemap.xml parser."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from core.url_utils import extract_base_url, resolve_url

if TYPE_CHECKING:
    from core.http_client import HttpClient

logger = logging.getLogger(__name__)


async def fetch_robots_txt(
    target_url: str,
    http_client: 'HttpClient',
) -> dict:
    """
    Fetch and parse robots.txt.
    Returns {disallowed: [...], allowed: [...], sitemaps: [...], raw: str}.
    """
    base = extract_base_url(target_url)
    result = {'disallowed': [], 'allowed': [], 'sitemaps': [], 'raw': ''}

    try:
        resp = await http_client.get(f'{base}/robots.txt', follow_redirects=True)
        if resp.status_code != 200:
            return result

        raw = resp.text or ''
        result['raw'] = raw[:2000]

        for line in raw.splitlines():
            line = line.strip()
            if line.lower().startswith('disallow:'):
                path = line.split(':', 1)[1].strip()
                if path:
                    result['disallowed'].append(path)
            elif line.lower().startswith('allow:'):
                path = line.split(':', 1)[1].strip()
                if path:
                    result['allowed'].append(path)
            elif line.lower().startswith('sitemap:'):
                sitemap = line.split(':', 1)[1].strip()
                if sitemap:
                    result['sitemaps'].append(sitemap)

    except Exception as e:
        logger.debug(f'Failed to fetch robots.txt: {e}')

    return result


async def fetch_sitemap_urls(
    target_url: str,
    http_client: 'HttpClient',
    max_urls: int = 100,
) -> list[str]:
    """Fetch and parse sitemap.xml, returning discovered URLs."""
    base = extract_base_url(target_url)
    urls: list[str] = []

    # First try robots.txt for sitemap URLs
    robots = await fetch_robots_txt(target_url, http_client)
    sitemap_urls = robots.get('sitemaps', [])

    # Also try common sitemap locations
    if not sitemap_urls:
        sitemap_urls = [f'{base}/sitemap.xml', f'{base}/sitemap_index.xml']

    for sitemap_url in sitemap_urls[:3]:
        try:
            resp = await http_client.get(sitemap_url, follow_redirects=True)
            if resp.status_code != 200:
                continue

            body = resp.text or ''
            # Extract URLs from sitemap
            url_pattern = re.compile(r'<loc>\s*(.*?)\s*</loc>', re.IGNORECASE)
            for match in url_pattern.finditer(body):
                url = match.group(1).strip()
                if url and url.startswith('http'):
                    urls.append(url)
                    if len(urls) >= max_urls:
                        return urls

        except Exception as e:
            logger.debug(f'Failed to fetch sitemap {sitemap_url}: {e}')
            continue

    return urls
