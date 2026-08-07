"""Issue #35 — ACME DNS-01 (v1.8.0): pluggable DNS provider package.

A small adapter layer so DNS-01 challenges can publish/clean up the
`_acme-challenge.<domain>` TXT record via different DNS providers. The interface is
additive at the RRset level (add/remove a single value by name+content, never
overwrite-by-name) so multiple coexisting values at one name (wildcard + apex) work.

Providers: manual (user publishes the TXT themselves), Cloudflare, and GoDaddy (v1.10.0). New
providers plug in via the registry without touching the orchestration.
"""
from .base import DnsProvider, DnsProviderError
from .registry import get_provider, list_providers, is_supported

__all__ = ["DnsProvider", "DnsProviderError", "get_provider", "list_providers", "is_supported"]
