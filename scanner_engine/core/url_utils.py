"""URL normalization, validation, and utility functions."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, urlencode

import tldextract


def normalize_url(url: str) -> str:
    """Normalize a URL: lowercase scheme/host, remove default ports, trailing slash."""
    parsed = urlparse(url)
    scheme = parsed.scheme.lower() or 'https'
    netloc = parsed.hostname.lower() if parsed.hostname else ''
    if parsed.port:
        default_port = 443 if scheme == 'https' else 80
        if parsed.port != default_port:
            netloc += f':{parsed.port}'
    path = parsed.path or '/'
    # Remove duplicate slashes (except after scheme)
    path = re.sub(r'/+', '/', path)
    return urlunparse((scheme, netloc, path, parsed.params, parsed.query, ''))


def extract_base_url(url: str) -> str:
    """Extract the base URL (scheme + host + port)."""
    parsed = urlparse(url)
    return f'{parsed.scheme}://{parsed.netloc}'


def get_domain(url: str) -> str:
    """Extract the registered domain (e.g. example.com from sub.example.com)."""
    ext = tldextract.extract(url)
    return f'{ext.domain}.{ext.suffix}' if ext.suffix else ext.domain


def get_subdomain(url: str) -> str:
    """Extract the full subdomain (e.g. www.example.com)."""
    parsed = urlparse(url)
    return parsed.hostname or ''


def is_same_domain(url1: str, url2: str) -> bool:
    """Check if two URLs share the same registered domain."""
    return get_domain(url1) == get_domain(url2)


def resolve_url(base: str, relative: str) -> str:
    """Resolve a relative URL against a base URL."""
    return normalize_url(urljoin(base, relative))


def add_params_to_url(url: str, params: dict[str, str]) -> str:
    """Append query parameters to a URL."""
    parsed = urlparse(url)
    existing = parse_qs(parsed.query)
    existing.update(params)
    new_query = urlencode({k: v for k, vs in existing.items() for v in (vs if isinstance(vs, list) else [vs])})
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))


def strip_fragment(url: str) -> str:
    """Remove the fragment from a URL."""
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, ''))


def is_valid_url(url: str) -> bool:
    """Check if a string is a valid HTTP(S) URL."""
    try:
        parsed = urlparse(url)
        return parsed.scheme in ('http', 'https') and bool(parsed.netloc)
    except Exception:
        return False
