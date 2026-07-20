"""
SSRF guard for outbound HTTP fetches to user/DB-controlled URLs.

GHSA-3vh4-gvxx-wm2p: the ACME `directory_url` was fetched server-side with no
validation, turning the backend into a request-forwarding primitive against
loopback / RFC1918 / link-local / cloud-metadata IP space (and reflecting the
upstream JSON keys back to the caller).

The classification logic mirrors the hardened ACME diagnostics probe
(services/acme_diagnostics.py, R18b/R18c audits): unwrap IPv4-mapped IPv6, reject
loopback/link-local/private/multicast/reserved/unspecified, resolve DNS off the
event loop, and pin the aiohttp connector to IPv4 so the family the guard
classifies equals the family the connector dials (no dual-stack AAAA bypass).

Deployment note: this project uses ONLY public ACME CAs (e.g. Let's Encrypt), so
every non-public IP is rejected — there is no internal/private-IP CA to allow.
Residual: DNS rebinding between validate-time and fetch-time is not fully closed
(fetching by hostname keeps TLS cert validation working); the IPv4 pin +
https-only + admin-gating + internal-only exposure keep this residual low.
"""
import asyncio
import ipaddress
import socket
from typing import List
from urllib.parse import urlparse

import aiohttp

# Only https is legitimate for a public ACME directory URL.
_ALLOWED_SCHEMES = {"https"}


class SSRFValidationError(ValueError):
    """Raised when a URL fails SSRF validation (bad scheme or non-public host)."""


def is_public_ip(ip_str: str) -> bool:
    """Return True only for globally-routable IPv4/IPv6 addresses.

    Unwraps IPv4-mapped IPv6 (``::ffff:127.0.0.1``) before classification so an
    attacker-controlled AAAA record cannot smuggle loopback/metadata through the
    IPv6 checks.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except (ValueError, TypeError):
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_link_local or ip.is_private:
        return False
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return False
    return True


async def _resolve_ips(host: str, *, timeout: float = 5.0) -> List[str]:
    """Resolve `host` to IPv4 addresses without blocking the event loop."""
    loop = asyncio.get_running_loop()
    _, _, ips = await asyncio.wait_for(
        loop.run_in_executor(None, socket.gethostbyname_ex, host),
        timeout=timeout,
    )
    return ips or []


async def assert_public_url(url: str, *, timeout: float = 5.0) -> None:
    """Validate that `url` is safe to fetch server-side.

    Requirements: https scheme, and a host that either is a public IP literal or
    resolves entirely to public IPv4 addresses. Raises ``SSRFValidationError``
    otherwise. Intended to be called immediately before the outbound request,
    which MUST use ``safe_connector()`` and ``allow_redirects=False``.
    """
    if not url or not isinstance(url, str):
        raise SSRFValidationError("A URL is required")
    parsed = urlparse(url.strip())
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        raise SSRFValidationError(f"URL scheme must be https (got '{parsed.scheme or 'none'}')")
    host = parsed.hostname
    if not host:
        raise SSRFValidationError("URL has no host")

    # Literal IP host: classify directly, no DNS needed.
    try:
        ipaddress.ip_address(host)
        if not is_public_ip(host):
            raise SSRFValidationError(f"URL host {host} is not a public IP address")
        return
    except ValueError:
        pass  # hostname, not an IP literal -> resolve below

    try:
        ips = await _resolve_ips(host, timeout=timeout)
    except asyncio.TimeoutError:
        raise SSRFValidationError(f"DNS resolution timed out for {host}")
    except Exception as e:  # socket.gaierror etc.
        raise SSRFValidationError(f"DNS resolution failed for {host}: {e}")

    if not ips:
        raise SSRFValidationError(f"{host} did not resolve to any address")
    if not all(is_public_ip(ip) for ip in ips):
        raise SSRFValidationError(
            f"{host} resolves to a non-public IP {ips} — refusing to fetch (SSRF guard)"
        )


def safe_connector() -> aiohttp.TCPConnector:
    """IPv4-pinned aiohttp connector.

    Forces the connect family to match what :func:`assert_public_url` classified
    (closes the dual-stack AAAA bypass). TLS verification stays ON (default), so
    the request must target the validated hostname. Always combine with
    ``allow_redirects=False`` at the request call site.
    """
    return aiohttp.TCPConnector(family=socket.AF_INET)
