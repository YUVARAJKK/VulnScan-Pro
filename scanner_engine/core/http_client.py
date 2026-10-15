"""Async HTTP client built on httpx with rate limiting and retry logic."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

from config import ScannerConfig

logger = logging.getLogger(__name__)

# Hostnames already confirmed safe for outbound probing (memoized to avoid
# re-resolving DNS on every redirect hop).
_SAFE_HOSTS: set[str] = set()


class UnsafeRedirectError(Exception):
    """Raised when a redirect would take the scan to a blocked/internal host."""


class RateLimiter:
    """Token-bucket rate limiter."""

    def __init__(self, rate: float):
        self.rate = rate
        self.tokens = rate
        self.last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
            self.last_refill = now

            if self.tokens < 1:
                wait = (1 - self.tokens) / self.rate
                await asyncio.sleep(wait)
                self.tokens = 0
            else:
                self.tokens -= 1


class HttpClient:
    """Async HTTP client with rate limiting, retries, and configurable timeouts."""

    def __init__(self, config: ScannerConfig | None = None):
        self.config = config or ScannerConfig()
        self._limiter = RateLimiter(self.config.rate_limit_per_second)
        self._semaphore = asyncio.Semaphore(self.config.max_concurrent_requests)
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> 'HttpClient':
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.timeout),
            follow_redirects=True,
            max_redirects=self.config.max_redirects,
            http2=self.config.http2,
            headers={'User-Agent': self.config.user_agent},
            verify=True,
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.aclose()

    @property
    def client(self) -> httpx.AsyncClient:
        assert self._client is not None, 'HttpClient must be used as async context manager'
        return self._client

    async def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
    ) -> httpx.Response:
        return await self._request('GET', url, headers=headers, follow_redirects=follow_redirects)

    async def head(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        return await self._request('HEAD', url, headers=headers)

    async def post(
        self,
        url: str,
        *,
        content: Any = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        return await self._request('POST', url, content=content, headers=headers)

    async def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        content: Any = None,
        follow_redirects: bool = True,
    ) -> httpx.Response:
        await self._limiter.acquire()
        async with self._semaphore:
            resp: httpx.Response | None = None
            for attempt in range(3):
                try:
                    resp = await self.client.request(
                        method,
                        url,
                        headers=headers,
                        content=content,
                        follow_redirects=follow_redirects,
                    )
                    break
                except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError) as e:
                    logger.debug(f'Request {method} {url} attempt {attempt+1} failed: {e}')
                    if attempt == 2:
                        raise
                    await asyncio.sleep(1 * (attempt + 1))

            if resp is None:  # Unreachable but keeps mypy happy
                raise httpx.ConnectError('All retries exhausted')

        # SSRF defense: re-validate every redirect hop that leaves the original
        # hostname. A public target must never redirect the scanner toward
        # private networks, loopback, or cloud metadata endpoints.
        if follow_redirects:
            self._validate_redirect_chain(url, resp)
        return resp

    def _validate_redirect_chain(self, original_url: str, resp: httpx.Response) -> None:
        """Ensure every redirect hop resolves to a public, scannable host."""
        from urllib.parse import urlparse

        history = list(getattr(resp, 'history', []) or [])
        hops = [h.url for h in history]
        hops.append(str(resp.url))

        try:
            origin_host = (urlparse(original_url).hostname or '').lower()
        except Exception:
            origin_host = ''

        for hop_url in hops:
            try:
                hop_host = (urlparse(str(hop_url)).hostname or '').lower()
            except Exception:
                continue
            if not hop_host or hop_host == origin_host:
                continue
            if hop_host in _SAFE_HOSTS:
                continue

            from core.ssrf_guard import validate_target
            is_safe, reason = validate_target(str(hop_url))
            if not is_safe:
                raise UnsafeRedirectError(
                    f'Redirect to blocked target blocked: {hop_url} — {reason}'
                )
            _SAFE_HOSTS.add(hop_host)
