"""
v1.9.0 CSR creation — pure-crypto tests for services/csr_service.py.

No mocks: every algorithm's output must parse with `cryptography` and the
CSR's public key must match the generated private key (the property the
whole import flow depends on).
"""
from types import SimpleNamespace

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from services.csr_service import csr_row_to_dict, diff_domains, generate_csr_bundle


def _payload(**overrides):
    base = dict(
        name="test-csr",
        common_name="www.example.com",
        organization=None,
        organizational_unit=None,
        locality=None,
        state=None,
        country=None,
        email=None,
        sans=[],
        key_algorithm="rsa-2048",
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _spki(key):
    return key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


@pytest.mark.parametrize(
    "algo,key_cls,key_check",
    [
        ("rsa-2048", rsa.RSAPrivateKey, lambda k: k.key_size == 2048),
        ("rsa-4096", rsa.RSAPrivateKey, lambda k: k.key_size == 4096),
        ("ecdsa-p256", ec.EllipticCurvePrivateKey, lambda k: k.curve.name == "secp256r1"),
        ("ecdsa-p384", ec.EllipticCurvePrivateKey, lambda k: k.curve.name == "secp384r1"),
    ],
)
def test_generate_bundle_all_algorithms(algo, key_cls, key_check):
    bundle = generate_csr_bundle(_payload(key_algorithm=algo))

    csr = x509.load_pem_x509_csr(bundle["csr_pem"].encode())
    key = serialization.load_pem_private_key(
        bundle["private_key_pem"].encode(), password=None
    )

    assert isinstance(key, key_cls)
    assert key_check(key)
    # The CSR must be signed by exactly this key.
    csr_spki = csr.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert csr_spki == _spki(key)
    assert csr.is_signature_valid
    # PKCS8, unencrypted — the agent concatenates cert+key into one PEM and
    # HAProxy cannot read passphrase-protected keys.
    assert bundle["private_key_pem"].startswith("-----BEGIN PRIVATE KEY-----")


def test_subject_contains_all_provided_fields():
    bundle = generate_csr_bundle(_payload(
        organization="Example Corp",
        organizational_unit="IT",
        locality="Istanbul",
        state="Marmara",
        country="TR",
        email="ops@example.com",
    ))
    csr = x509.load_pem_x509_csr(bundle["csr_pem"].encode())

    def _one(oid):
        attrs = csr.subject.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else None

    assert _one(NameOID.COMMON_NAME) == "www.example.com"
    assert _one(NameOID.ORGANIZATION_NAME) == "Example Corp"
    assert _one(NameOID.ORGANIZATIONAL_UNIT_NAME) == "IT"
    assert _one(NameOID.LOCALITY_NAME) == "Istanbul"
    assert _one(NameOID.STATE_OR_PROVINCE_NAME) == "Marmara"
    assert _one(NameOID.COUNTRY_NAME) == "TR"
    assert _one(NameOID.EMAIL_ADDRESS) == "ops@example.com"
    assert bundle["subject"] == {
        "O": "Example Corp", "OU": "IT", "L": "Istanbul",
        "ST": "Marmara", "C": "TR", "emailAddress": "ops@example.com",
    }


def test_subject_omits_empty_fields():
    bundle = generate_csr_bundle(_payload())
    csr = x509.load_pem_x509_csr(bundle["csr_pem"].encode())
    assert not csr.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    assert bundle["subject"] == {}


def test_sans_cn_first_and_deduped():
    bundle = generate_csr_bundle(_payload(
        common_name="www.example.com",
        sans=["api.example.com", "www.example.com", "api.example.com", "cdn.example.com"],
    ))
    assert bundle["sans"] == ["www.example.com", "api.example.com", "cdn.example.com"]

    csr = x509.load_pem_x509_csr(bundle["csr_pem"].encode())
    san_ext = csr.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    )
    dns_names = san_ext.value.get_values_for_type(x509.DNSName)
    assert dns_names == ["www.example.com", "api.example.com", "cdn.example.com"]


def test_wildcard_common_name_flows_into_san():
    bundle = generate_csr_bundle(_payload(common_name="*.example.com"))
    csr = x509.load_pem_x509_csr(bundle["csr_pem"].encode())
    san_ext = csr.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    )
    assert san_ext.value.get_values_for_type(x509.DNSName) == ["*.example.com"]


def test_diff_domains_reports_added_and_dropped():
    warnings = diff_domains(
        ["www.example.com", "api.example.com"],
        ["WWW.example.com", "cdn.example.com"],
    )
    assert len(warnings) == 2
    added = next(w for w in warnings if "added" in w)
    dropped = next(w for w in warnings if "dropped" in w)
    assert "cdn.example.com" in added
    assert "api.example.com" in dropped
    # Case-insensitive: www must NOT be reported in either direction.
    assert "www.example.com" not in added
    assert "www.example.com" not in dropped


def test_diff_domains_identical_sets_yield_no_warnings():
    assert diff_domains(["a.example.com"], ["A.EXAMPLE.COM"]) == []
    assert diff_domains([], []) == []


def test_csr_row_to_dict_never_exposes_private_key():
    row = {
        "id": 1,
        "name": "x",
        "private_key_pem": "-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----",
        "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nX\n-----END CERTIFICATE REQUEST-----",
        "subject": '{"O": "Example"}',
        "sans": '["a.example.com"]',
    }
    out = csr_row_to_dict(row)
    assert "private_key_pem" not in out
    assert "csr_pem" not in out          # lists exclude the PEM
    assert out["subject"] == {"O": "Example"}
    assert out["sans"] == ["a.example.com"]

    detail = csr_row_to_dict(row, include_pem=True)
    assert "private_key_pem" not in detail  # NEVER, even on detail
    assert detail["csr_pem"].startswith("-----BEGIN CERTIFICATE REQUEST-----")
