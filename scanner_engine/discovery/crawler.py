"""BFS web crawler with depth and URL limits."""

from __future__ import annotations

import asyncio
import logging
import re
from collections import deque
from typing import TYPE_CHECKING
from urllib.parse import urlparse, urljoin

from config import ScannerConfig
from core.url_utils import normalize_url, is_same_domain, strip_fragment

if TYPE_CHECKING:
    from core.http_client import HttpClient

logger = logging.getLogger(__name__)


class Crawler:
    """BFS web crawler that discovers pages and endpoints within a target domain."""

    def __init__(self, config: ScannerConfig | None = None):
        self.config = config or ScannerConfig()
        self._visited: set[str] = set()
        self._queue: deque[tuple[str, int]] = deque()
        self._links: list[str] = []
        self._forms: list[dict] = []

    async def crawl(
        self,
        start_url: str,
        http_client: 'HttpClient',
    ) -> tuple[list[str], list[dict]]:
        """
        Crawl starting from start_url, returning (discovered_urls, discovered_forms).
        """
        base_domain = urlparse(start_url).netloc
        self._queue.append((normalize_url(start_url), 0))

        while self._queue and len(self._visited) < self.config.crawler_max_pages:
            url, depth = self._queue.popleft()

            if url in self._visited:
                continue
            if depth > self.config.crawler_max_depth:
                continue

            self._visited.add(url)

            try:
                resp = await http_client.get(url, follow_redirects=True)

                # Redirects must stay on the original target host (scope control)
                final_host = urlparse(str(resp.url)).netloc.lower()
                if final_host != base_domain:
                    logger.debug(f'Skipping {url} — redirected off-scope to {resp.url}')
                    continue

                content_type = resp.headers.get('content-type', '')

                # Only crawl HTML pages
                if 'text/html' not in content_type:
                    continue

                body = resp.text or ''
                self._links.append(url)

                # Extract links
                href_pattern = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
                for match in href_pattern.finditer(body):
                    href = match.group(1)
                    resolved = urljoin(url, href)
                    resolved = normalize_url(resolved)
                    resolved = strip_fragment(resolved)

                    parsed = urlparse(resolved)
                    if parsed.netloc == base_domain and parsed.scheme in ('http', 'https'):
                        if resolved not in self._visited:
                            self._queue.append((resolved, depth + 1))

                # Extract forms
                form_pattern = re.compile(
                    r'<form[^>]*action\s*=\s*["\']([^"\']*)["\'][^>]*>(.*?)</form>',
                    re.IGNORECASE | re.DOTALL,
                )
                for match in form_pattern.finditer(body):
                    action = match.group(1) or url
                    form_body = match.group(2)
                    method_match = re.search(r'method\s*=\s*["\'](\w+)["\']', form_body, re.IGNORECASE)
                    method = method_match.group(1).upper() if method_match else 'GET'

                    # Extract input names
                    inputs = re.findall(r'<input[^>]*name\s*=\s*["\']([^"\']+)["\']', form_body, re.IGNORECASE)

                    resolved_action = urljoin(url, action)
                    self._forms.append({
                        'url': normalize_url(resolved_action),
                        'method': method,
                        'parameters': inputs,
                    })

            except Exception as e:
                logger.debug(f'Crawl failed for {url}: {e}')
                continue

            # Rate limiting
            await asyncio.sleep(0.1)

        return self._links, self._forms
