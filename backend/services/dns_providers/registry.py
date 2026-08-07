"""DNS provider registry for ACME DNS-01 (Issue #35).

Single source of truth mapping a provider name -> class. The API serves the credential-field
schema from here (so the UI has no hardcoded provider fields) and validates inbound provider
names against this allow-list. Adding a provider = add it here; nothing else changes.
"""
from __future__ import annotations

from typing import Dict, List, Type

from .base import DnsProvider
from .cloudflare import CloudflareDNSProvider
from .godaddy import GoDaddyDNSProvider
from .manual import ManualDNSProvider

_PROVIDERS: Dict[str, Type[DnsProvider]] = {
    ManualDNSProvider.name: ManualDNSProvider,
    CloudflareDNSProvider.name: CloudflareDNSProvider,
    GoDaddyDNSProvider.name: GoDaddyDNSProvider,
}


def is_supported(name: str) -> bool:
    return name in _PROVIDERS


def get_provider(name: str, credentials: Dict[str, str] | None = None) -> DnsProvider:
    cls = _PROVIDERS.get(name)
    if cls is None:
        raise ValueError(f"Unsupported DNS provider: {name}")
    return cls(credentials or {})


def list_providers() -> List[Dict]:
    """Return the UI-facing provider catalog: name, label, automated flag, and credential schema."""
    out: List[Dict] = []
    for name, cls in _PROVIDERS.items():
        out.append(
            {
                "name": cls.name,
                "label": cls.label,
                "automated": cls.automated,
                "credential_fields": cls.credential_fields,
            }
        )
    return out
