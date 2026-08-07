"""Issue #53 (v1.10.1) — at-rest encryption for the pending CSR private key.

Pure logic: no DB, no network. Covers the round-trip, the backward-compatible read of rows
written before this release, the unrecoverable-key path after a key rotation, and a static
assertion that the write path can no longer store a raw PEM.
"""
import os
import re
from pathlib import Path

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-csr-encryption-unit-tests")

from cryptography.fernet import Fernet

from utils.csr_key_crypto import (
    decrypt_csr_private_key,
    encrypt_csr_private_key,
    is_encrypted,
    reset_fernet_for_tests,
)

_SAMPLE_PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n"
    "-----END PRIVATE KEY-----\n"
)


def test_roundtrip_and_ciphertext_does_not_contain_the_key():
    reset_fernet_for_tests()
    token = encrypt_csr_private_key(_SAMPLE_PEM)
    # The stored form must not be the PEM, and must not leak any recognisable fragment of it.
    assert token != _SAMPLE_PEM
    assert "-----BEGIN" not in token
    assert "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj" not in token
    assert decrypt_csr_private_key(token) == _SAMPLE_PEM


def test_is_encrypted_discriminates_token_from_legacy_pem():
    reset_fernet_for_tests()
    assert is_encrypted(encrypt_csr_private_key(_SAMPLE_PEM)) is True
    assert is_encrypted(_SAMPLE_PEM) is False
    assert is_encrypted("") is False
    assert is_encrypted(None) is False


def test_legacy_plaintext_row_is_read_unchanged():
    # Rows written before v1.10.1 hold a raw PEM. They must keep working with NO data migration,
    # otherwise upgrading would strand every CSR that is out for signature.
    reset_fernet_for_tests()
    assert decrypt_csr_private_key(_SAMPLE_PEM) == _SAMPLE_PEM


def test_empty_or_missing_value_returns_none():
    reset_fernet_for_tests()
    assert decrypt_csr_private_key(None) is None
    assert decrypt_csr_private_key("") is None


def test_key_rotation_makes_the_stored_key_unrecoverable_rather_than_wrong():
    """After a rotation the caller must get None, never a silently wrong key."""
    reset_fernet_for_tests()
    token = encrypt_csr_private_key(_SAMPLE_PEM)

    # Rotate: an explicit, different CSR_ENCRYPTION_KEY takes precedence over the derived one.
    previous = os.environ.get("CSR_ENCRYPTION_KEY")
    os.environ["CSR_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
    try:
        reset_fernet_for_tests()
        assert decrypt_csr_private_key(token) is None
    finally:
        if previous is None:
            os.environ.pop("CSR_ENCRYPTION_KEY", None)
        else:
            os.environ["CSR_ENCRYPTION_KEY"] = previous
        reset_fernet_for_tests()


def test_explicit_env_key_is_used_and_survives_reset():
    previous = os.environ.get("CSR_ENCRYPTION_KEY")
    key = Fernet.generate_key().decode()
    os.environ["CSR_ENCRYPTION_KEY"] = key
    try:
        reset_fernet_for_tests()
        token = encrypt_csr_private_key(_SAMPLE_PEM)
        # Decryptable with the same explicit key from a fresh instance...
        reset_fernet_for_tests()
        assert decrypt_csr_private_key(token) == _SAMPLE_PEM
        # ...and independently verifiable with the raw Fernet key.
        assert Fernet(key.encode()).decrypt(token.encode()).decode() == _SAMPLE_PEM
    finally:
        if previous is None:
            os.environ.pop("CSR_ENCRYPTION_KEY", None)
        else:
            os.environ["CSR_ENCRYPTION_KEY"] = previous
        reset_fernet_for_tests()


def test_derivation_uses_its_own_hkdf_info_string():
    """Each secret class derives an independent key, so rotating one never affects another."""
    src = (Path(__file__).resolve().parent.parent / "utils" / "csr_key_crypto.py").read_text()
    assert b"csr-private-key-v1".decode() in src
    # Must NOT reuse another class's info string.
    for foreign in ("dns-provider-creds-v1", "vip-vrrp-secret-v1", "mfa-totp-secret-v1"):
        assert foreign not in src, f"CSR key derivation must not reuse the {foreign} info string"


def test_write_path_stores_the_encrypted_form_not_the_pem():
    """Static pin: insert_csr_row must encrypt before the INSERT.

    A future refactor that passed bundle['private_key_pem'] straight through would silently
    reintroduce plaintext storage, and no unit test with a mocked connection would notice.
    """
    src = (Path(__file__).resolve().parent.parent / "services" / "csr_service.py").read_text()
    insert_fn = src[src.index("async def insert_csr_row("):]
    insert_fn = insert_fn[: insert_fn.index("\nasync def ")]
    assert "encrypt_csr_private_key(bundle['private_key_pem'])" in insert_fn
    # The raw PEM must not be a bind parameter of the INSERT itself.
    assert not re.search(r"^\s*bundle\['private_key_pem'\],\s*$", insert_fn, re.M)


def test_import_path_decrypts_and_fails_closed_on_unrecoverable_key():
    src = (Path(__file__).resolve().parent.parent / "services" / "csr_service.py").read_text()
    fn = src[src.index("async def import_signed_certificate("):]
    assert "decrypt_csr_private_key(row['private_key_pem'])" in fn
    # A None decrypt must raise rather than fall through to the key-match comparison.
    assert "cannot be decrypted" in fn
