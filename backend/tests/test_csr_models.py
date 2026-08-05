"""
v1.9.0 CSR creation — Pydantic model validation tests (models/csr.py).

The CSR name shares the SSL certificate name's path-traversal contract
(Bulgu #21) with one deliberate tightening: max 100 chars, matching the
ssl_certificates.name VARCHAR(100) column.
"""
import pytest
from pydantic import ValidationError

from models.csr import SSLCSRCreate, SSLCSRImport

_CERT_PEM = "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----"


def _create(**overrides):
    base = dict(name="my-csr", common_name="www.example.com")
    base.update(overrides)
    return SSLCSRCreate(**base)


# ----------------------------------------------------------------------------
# SSLCSRCreate
# ----------------------------------------------------------------------------


def test_minimal_valid_create():
    m = _create()
    assert m.name == "my-csr"
    assert m.common_name == "www.example.com"
    assert m.key_algorithm == "rsa-2048"
    assert m.sans == []


@pytest.mark.parametrize("bad_name", [
    "../../etc/cron.d/evil",   # path traversal
    "a..b",                    # embedded ..
    ".hidden",                 # hidden filename
    "-flag",                   # CLI flag confusion
    "has space",
    "wild*card",
    "",
    "x" * 101,                 # VARCHAR(100) alignment — 200 is NOT allowed here
])
def test_name_rejects_unsafe_values(bad_name):
    with pytest.raises(ValidationError):
        _create(name=bad_name)


def test_name_accepts_100_chars():
    assert _create(name="x" * 100).name == "x" * 100


def test_common_name_wildcard_accepted_and_lowercased():
    m = _create(common_name="*.Example.COM")
    assert m.common_name == "*.example.com"


@pytest.mark.parametrize("bad_cn", [
    "",
    "under_score.example.com",      # _ is not LDH
    "*.*.example.com",              # wildcard only as leftmost single label
    "-leading.example.com",
    "a" * 70 + ".example.com",      # label > 63
    "cn-longer-than-64-chars-" + "x" * 45 + ".example.com",  # CN > 64 total
])
def test_common_name_rejects_invalid(bad_cn):
    with pytest.raises(ValidationError):
        _create(common_name=bad_cn)


def test_sans_normalised_deduped_and_capped():
    m = _create(sans=["API.example.com", "api.example.com", "cdn.example.com"])
    assert m.sans == ["api.example.com", "cdn.example.com"]

    with pytest.raises(ValidationError):
        _create(sans=[f"h{i}.example.com" for i in range(101)])


def test_country_normalised_or_rejected():
    assert _create(country="tr").country == "TR"
    assert _create(country=None).country is None
    for bad in ("TUR", "T", "1A"):
        with pytest.raises(ValidationError):
            _create(country=bad)


def test_subject_fields_reject_control_characters():
    with pytest.raises(ValidationError):
        _create(organization="Evil\x00Corp")
    with pytest.raises(ValidationError):
        _create(locality="line\nbreak")


def test_subject_fields_reject_overlength():
    with pytest.raises(ValidationError):
        _create(organization="x" * 65)


def test_key_algorithm_strict_enum():
    for good in ("rsa-2048", "rsa-4096", "ecdsa-p256", "ecdsa-p384"):
        assert _create(key_algorithm=good).key_algorithm == good
    for bad in ("rsa-1024", "rsa-8192", "ed25519", "2048", ""):
        with pytest.raises(ValidationError):
            _create(key_algorithm=bad)


def test_email_basic_validation():
    assert _create(email="ops@example.com").email == "ops@example.com"
    with pytest.raises(ValidationError):
        _create(email="not-an-email")


# ----------------------------------------------------------------------------
# SSLCSRImport
# ----------------------------------------------------------------------------


def test_import_minimal_global():
    m = SSLCSRImport(certificate_content=_CERT_PEM, is_global=True)
    assert m.usage_type == "frontend"
    assert m.name is None


def test_import_requires_clusters_when_not_global():
    with pytest.raises(ValidationError):
        SSLCSRImport(certificate_content=_CERT_PEM, is_global=False)
    with pytest.raises(ValidationError):
        SSLCSRImport(certificate_content=_CERT_PEM, is_global=False, cluster_ids=[])
    m = SSLCSRImport(certificate_content=_CERT_PEM, is_global=False, cluster_ids=[1])
    assert m.cluster_ids == [1]


def test_import_certificate_must_be_pem():
    with pytest.raises(ValidationError):
        SSLCSRImport(certificate_content="not a pem", is_global=True)
    with pytest.raises(ValidationError):
        SSLCSRImport(certificate_content="", is_global=True)


def test_import_certificate_size_capped():
    huge = _CERT_PEM + "A" * (64 * 1024 + 1)
    with pytest.raises(ValidationError):
        SSLCSRImport(certificate_content=huge, is_global=True)


def test_import_chain_optional_but_validated():
    m = SSLCSRImport(certificate_content=_CERT_PEM, is_global=True, chain_content="  ")
    assert m.chain_content is None
    with pytest.raises(ValidationError):
        SSLCSRImport(
            certificate_content=_CERT_PEM, is_global=True, chain_content="garbage"
        )


def test_import_name_override_shares_the_name_contract():
    m = SSLCSRImport(certificate_content=_CERT_PEM, is_global=True, name="renamed")
    assert m.name == "renamed"
    with pytest.raises(ValidationError):
        SSLCSRImport(certificate_content=_CERT_PEM, is_global=True, name="../evil")
    # Empty override collapses to None (falls back to the CSR's own name).
    m2 = SSLCSRImport(certificate_content=_CERT_PEM, is_global=True, name="  ")
    assert m2.name is None


def test_import_usage_type_enum():
    for good in ("frontend", "server"):
        assert SSLCSRImport(
            certificate_content=_CERT_PEM, is_global=True, usage_type=good
        ).usage_type == good
    with pytest.raises(ValidationError):
        SSLCSRImport(certificate_content=_CERT_PEM, is_global=True, usage_type="both")
