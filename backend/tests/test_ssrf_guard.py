"""Unit tests for the SSRF guard (GHSA-3vh4-gvxx-wm2p).

The guard protects server-side fetches of ACME `directory_url` values. This
project uses only public ACME CAs, so every non-public IP must be rejected.
Tests avoid real network/DNS by using IP literals and scheme checks.
"""
import asyncio
import pytest

from utils.ssrf_guard import is_public_ip, assert_public_url, SSRFValidationError


# ---- is_public_ip -----------------------------------------------------------

@pytest.mark.parametrize("ip", [
    "8.8.8.8", "1.1.1.1", "93.184.216.34",  # public
])
def test_public_ips_allowed(ip):
    assert is_public_ip(ip) is True


@pytest.mark.parametrize("ip", [
    "127.0.0.1",            # loopback
    "10.0.0.5",             # RFC1918
    "172.19.0.1",           # RFC1918 (the SSRF PoC docker gateway)
    "192.168.1.1",          # RFC1918
    "169.254.169.254",      # link-local / cloud metadata
    "0.0.0.0",              # unspecified
    "::1",                  # IPv6 loopback
    "fe80::1",              # IPv6 link-local
    "::ffff:127.0.0.1",     # IPv4-mapped IPv6 loopback (R18c bypass)
    "::ffff:169.254.169.254",  # IPv4-mapped metadata
    "not-an-ip",            # garbage
])
def test_non_public_ips_rejected(ip):
    assert is_public_ip(ip) is False


# ---- assert_public_url ------------------------------------------------------

def _raises(url):
    with pytest.raises(SSRFValidationError):
        asyncio.run(assert_public_url(url))


def test_rejects_non_https_scheme():
    # The SSRF PoC used http:// against an internal listener.
    _raises("http://172.19.0.1:2121/internal-secret")
    _raises("http://8.8.8.8/")            # even a public IP over http is refused
    _raises("file:///etc/passwd")
    _raises("gopher://8.8.8.8/")


def test_rejects_private_ip_literals():
    _raises("https://127.0.0.1/")
    _raises("https://10.0.0.5/")
    _raises("https://169.254.169.254/latest/meta-data/")
    _raises("https://[::1]/")


def test_rejects_empty_or_hostless():
    _raises("")
    _raises("https://")


def test_allows_public_ip_literal_https():
    # A public IP literal over https must pass (no DNS needed).
    asyncio.run(assert_public_url("https://8.8.8.8/directory"))
