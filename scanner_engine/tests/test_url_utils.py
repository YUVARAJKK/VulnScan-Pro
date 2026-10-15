"""Tests for URL utility functions."""

from core.url_utils import (
    normalize_url, extract_base_url, get_domain, get_subdomain,
    is_same_domain, resolve_url, is_valid_url, strip_fragment,
)


def test_normalize_url_lowercase():
    assert normalize_url('HTTPS://Example.COM/path') == 'https://example.com/path'


def test_normalize_url_trailing_slash():
    assert normalize_url('https://example.com/') == 'https://example.com/'


def test_extract_base_url():
    assert extract_base_url('https://example.com/path?q=1') == 'https://example.com'


def test_get_domain():
    assert get_domain('https://sub.example.com/path') == 'example.com'


def test_get_subdomain():
    assert get_subdomain('https://www.example.com/path') == 'www.example.com'


def test_is_same_domain():
    assert is_same_domain('https://a.example.com', 'https://b.example.com') is True
    assert is_same_domain('https://example.com', 'https://evil.com') is False


def test_resolve_url():
    result = resolve_url('https://example.com/a/b', '../c')
    assert result == 'https://example.com/c'


def test_is_valid_url():
    assert is_valid_url('https://example.com') is True
    assert is_valid_url('http://example.com/path') is True
    assert is_valid_url('not-a-url') is False
    assert is_valid_url('ftp://example.com') is False


def test_strip_fragment():
    assert strip_fragment('https://example.com/path#section') == 'https://example.com/path'
