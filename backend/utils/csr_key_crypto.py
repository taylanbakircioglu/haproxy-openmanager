"""Issue #53 — at-rest encryption for the pending CSR private key (v1.10.1).

Mirrors the established Fernet + HKDF(SECRET_KEY) pattern already used for the VRRP secret
(services/keepalived_config.py), TOTP secrets (services/mfa_service.py) and DNS provider
credentials (utils/dns_credentials.py): prefer an explicit CSR_ENCRYPTION_KEY env var (enables
key rotation), else derive a stable key from SECRET_KEY via HKDF with its own versioned info
string, so a rotation of one secret class never affects another.

WHY this key and not every key in the system: the CSR private key is the one key that sits IDLE.
It is generated at CSR creation, waits for an external CA to sign the request (days to weeks),
and is destroyed the moment the signed certificate is imported — it is never transmitted to an
agent and never leaves the server. `ssl_certificates.private_key_content` and the ACME order keys
are different: agents must receive them in plaintext on every poll, so encrypting them at rest
buys nothing without an end-to-end redesign.

STORAGE: the Fernet token replaces the PEM in the SAME `ssl_csrs.private_key_pem` TEXT column.
No new column, no new table, and deliberately NO `SCHEMA_VERSION` bump — a bump would re-run the
migration sequence and re-seed the four built-in roles to their defaults (see UPGRADE_GUIDE.md),
which is a needless side effect for a storage-format change.

BACKWARD COMPATIBILITY: rows written before this release hold a raw PEM. `decrypt_csr_private_key`
detects those by their `-----BEGIN` header and returns them unchanged. The discriminator is exact,
not a heuristic: a Fernet token is base64url text and can never contain "-----". Legacy rows drain
naturally, since a CSR's key copy is NULLed on import.

KEY ROTATION: if SECRET_KEY rotates while CSR_ENCRYPTION_KEY is unset, previously stored keys
become undecryptable and `decrypt_csr_private_key` returns None. Callers MUST surface a clear
"delete this CSR and create a new one" error — the CSR is unusable at that point, because the
signed certificate can no longer be paired with its key.
"""
from __future__ import annotations

import base64
import logging
import os
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from config import SECRET_KEY

logger = logging.getLogger(__name__)

# A PEM private key always carries this header; a Fernet token is base64url and never can.
_PEM_MARKER = "-----BEGIN"

_fernet_instance: Optional[Fernet] = None


def _resolve_fernet_key() -> bytes:
    """Prefer an explicit CSR_ENCRYPTION_KEY; else derive from SECRET_KEY via HKDF with a
    versioned info string (so stored keys survive restarts)."""
    explicit = os.getenv("CSR_ENCRYPTION_KEY", "").strip()
    if explicit:
        try:
            Fernet(explicit.encode())
            return explicit.encode()
        except Exception as exc:  # noqa: BLE001
            logger.error("CSR_ENCRYPTION_KEY env var present but invalid: %s", exc)
    logger.warning(
        "CSR_ENCRYPTION_KEY not set; deriving the CSR private-key encryption key from SECRET_KEY. "
        "Set CSR_ENCRYPTION_KEY to a Fernet key to enable key rotation."
    )
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"csr-private-key-v1")
    derived = hkdf.derive(SECRET_KEY.encode("utf-8"))
    return base64.urlsafe_b64encode(derived)


def _get_fernet() -> Fernet:
    global _fernet_instance
    if _fernet_instance is None:
        _fernet_instance = Fernet(_resolve_fernet_key())
    return _fernet_instance


def reset_fernet_for_tests() -> None:
    """Test-only hook to force re-resolution after env mutation."""
    global _fernet_instance
    _fernet_instance = None


def is_encrypted(stored: Optional[str]) -> bool:
    """True when the stored value is a Fernet token rather than a legacy raw PEM.

    Single source of the format discriminator: `decrypt_csr_private_key` branches on this, so
    the "what does a stored value look like" rule is stated exactly once.
    """
    return bool(stored) and _PEM_MARKER not in stored


def encrypt_csr_private_key(pem: str) -> str:
    """Fernet-encrypt a PEM private key to a storable token string."""
    return _get_fernet().encrypt(pem.encode("utf-8")).decode("utf-8")


def decrypt_csr_private_key(stored: Optional[str]) -> Optional[str]:
    """Return the PEM private key for a stored value.

    Accepts BOTH shapes so an upgrade needs no data migration:
      - a raw PEM written before v1.10.1 -> returned unchanged
      - a Fernet token -> decrypted

    Returns None when the value is empty or cannot be decrypted (e.g. SECRET_KEY rotated without
    CSR_ENCRYPTION_KEY). Callers MUST treat None as "this CSR's key is unrecoverable" and tell the
    operator to delete it and create a new one; never fall through to a pairing attempt.
    """
    if not stored:
        return None
    if not is_encrypted(stored):
        return stored  # legacy plaintext row, pre-v1.10.1
    try:
        return _get_fernet().decrypt(stored.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        logger.warning("Failed to decrypt a stored CSR private key (invalid Fernet token)")
        return None
    except Exception as exc:  # noqa: BLE001
        logger.error("Unexpected error decrypting a stored CSR private key: %s", exc)
        return None
