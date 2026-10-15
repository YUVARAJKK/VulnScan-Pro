"""Python-side SSRF protection for defense-in-depth."""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# DEVELOPMENT/TEST ONLY: setting ALLOW_PRIVATE_SCAN_TARGETS=1 lets the engine
# scan local/intentional lab targets (e.g. DVWA on localhost). Never enable in
# production or on a publicly reachable deployment — it disables SSRF guards.
ALLOW_PRIVATE = os.environ.get('ALLOW_PRIVATE_SCAN_TARGETS') == '1'

# RFC reserved IPv4 ranges that should never be scanned
_PRIVATE_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('0.0.0.0/8'),
]

# Cloud metadata endpoints
_METADATA_HOSTS = {
    '169.254.169.254',
    'metadata.google.internal',
    '169.254.169.254.nip.io',
}

_BLOCKED_HOSTS = {
    'localhost',
    '0.0.0.0',
    '127.0.0.1',
    '::1',
    'metadata.google.internal',
}


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is in a private/reserved range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in network for network in _PRIVATE_RANGES)
    except ValueError:
        return True


def validate_target(url: str) -> tuple[bool, str]:
    """
    Validate that a scan target is safe to probe.
    Returns (is_safe, reason_if_unsafe).
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False, 'Invalid URL'

    if parsed.scheme not in ('http', 'https'):
        return False, f'Unsupported scheme: {parsed.scheme}'

    if ALLOW_PRIVATE:
        logger.warning('ALLOW_PRIVATE_SCAN_TARGETS is enabled — SSRF checks bypassed (dev/test only)')
        return True, ''

    hostname = parsed.hostname
    if not hostname:
        return False, 'No hostname in URL'

    # Check blocked hosts
    if hostname.lower() in _BLOCKED_HOSTS:
        return False, f'Blocked host: {hostname}'

    # Check cloud metadata
    if hostname in _METADATA_HOSTS or hostname.endswith('.metadata.google.internal'):
        return False, 'Cloud metadata endpoint blocked'

    # Resolve and check IP
    try:
        resolved = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
        for family, _, _, _, sockaddr in resolved:
            ip = sockaddr[0]
            if _is_private_ip(ip):
                return False, f'Target resolves to private IP: {ip}'
    except socket.gaierror:
        return False, f'Cannot resolve hostname: {hostname}'

    return True, ''


def is_safe_url(url: str) -> bool:
    """Quick check if a URL is safe to request."""
    is_safe, _ = validate_target(url)
    return is_safe
