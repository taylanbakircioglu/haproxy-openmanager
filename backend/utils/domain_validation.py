"""
Single source of truth for domain regex validation (M10).

Mirrored client-side at frontend/src/utils/validation.js. Both sides MUST be
updated together; the wizard's per-step validation relies on byte-identical
behaviour with the server-side rejection.

RFC 1035 / RFC 5890 hostname/domain label rules; allows leading wildcard '*.'.
"""

import re


DOMAIN_REGEX = re.compile(
    r"^(?:\*\.)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
MAX_DOMAIN_LENGTH = 253


def _looks_like_idn(value: str) -> bool:
    """Bulgu #42 (round-16 audit) — detect non-ASCII characters in the
    bare domain string so we can hand the operator a concrete
    actionable hint (encode to punycode) instead of an opaque "Invalid
    domain format". This intentionally does NOT include the existing
    `xn--` prefix in the suggestion path: those strings are already
    ASCII and pass the regex.
    """
    if not value or not isinstance(value, str):
        return False
    try:
        return any(ord(c) > 127 for c in value)
    except TypeError:
        return False


def validate_domain(value: str) -> str:
    """Validate + normalise (lowercase, stripped) a single domain.

    Raises ValueError on syntax errors. Returns the normalised value.
    """
    if not value or not isinstance(value, str):
        raise ValueError("Domain entries must be non-empty strings")
    d_norm = value.strip().lower()
    if not d_norm or len(d_norm) > MAX_DOMAIN_LENGTH:
        raise ValueError(f"Invalid domain length: '{value}' (max {MAX_DOMAIN_LENGTH} chars)")
    if ".." in d_norm or d_norm.startswith(".") or d_norm.endswith("."):
        raise ValueError(f"Invalid domain syntax: '{value}'")
    if not DOMAIN_REGEX.match(d_norm):
        # Bulgu #42 (round-16 audit) — give IDN/Unicode operators a
        # specific path forward instead of "Invalid domain format".
        # HAProxy's host header matching is byte-based; the canonical
        # path is to enter the punycode (`xn--…`) form, which the
        # browser already sends on the wire for Unicode addresses.
        if _looks_like_idn(value):
            try:
                ascii_form = value.strip().encode("idna").decode("ascii").lower()
                raise ValueError(
                    f"Invalid domain format: '{value}'. The wizard "
                    "requires ASCII-only (punycode) domain entries; "
                    f"enter '{ascii_form}' instead, which is the "
                    "browser's on-the-wire form of your Unicode "
                    "domain."
                )
            except UnicodeError:
                raise ValueError(
                    f"Invalid domain format: '{value}'. Unicode "
                    "(IDN) entries must first be encoded to punycode "
                    "(`xn--…`) — your input could not be encoded "
                    "automatically; re-check the spelling."
                )
        raise ValueError(f"Invalid domain format: '{value}'")
    return d_norm


def validate_domains(values):
    """Validate + normalise a list of domains, returning the normalised list."""
    return [validate_domain(d) for d in values]
