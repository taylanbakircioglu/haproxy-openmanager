"""
Pydantic models for the CSR (Certificate Signing Request) feature (v1.9.0).

A CSR row is the precursor of an ssl_certificates row: the backend generates
the private key + CSR locally, the operator has the CSR signed by an external
CA and then imports the signed certificate. The CSR `name` therefore obeys the
exact same path-traversal contract as the SSL certificate name (Bulgu #21) —
at import time it becomes /etc/ssl/haproxy/{name}.pem on every agent and is
shell-processed by the agent script as root.

The import model deliberately has NO private key field: the key never leaves
the server. It is stored on the ssl_csrs row at generation time and paired
with the signed certificate server-side.
"""

import re
from typing import List, Optional

from pydantic import BaseModel, field_validator, model_validator

KEY_ALGORITHMS = ('rsa-2048', 'rsa-4096', 'ecdsa-p256', 'ecdsa-p384')

# RFC 1035 LDH hostname, lowercase, optional single leftmost wildcard label.
# Single-label names are allowed (internal CAs routinely sign bare hostnames).
_DNS_NAME_PATTERN = re.compile(
    r'^(\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?'
    r'(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$'
)

# Reject control characters in free-text subject fields: they would be
# persisted, echoed into the UI / issuer column, and printed into agent logs
# via `openssl -subject` output.
_CONTROL_CHARS_PATTERN = re.compile(r'[\x00-\x1f\x7f]')

_MAX_SANS = 100
_MAX_CERT_PEM_BYTES = 64 * 1024       # a leaf certificate is ~2 KB; 64 KB is generous
_MAX_CHAIN_PEM_BYTES = 256 * 1024     # agents re-download all cert content every poll


def _validate_dns_name(value: str, field_label: str) -> str:
    v = (value or '').strip().lower()
    if not v:
        raise ValueError(f'{field_label} must not be empty')
    if len(v) > 253:
        raise ValueError(f'{field_label} must be 253 characters or fewer')
    if not _DNS_NAME_PATTERN.match(v):
        raise ValueError(
            f'{field_label} {value!r} is not a valid DNS name — lowercase '
            'letters, digits, hyphens and dots only; a wildcard is allowed '
            'only as the leftmost label (e.g. *.example.com).'
        )
    return v


def _validate_subject_text(value: Optional[str], field_label: str, max_len: int = 64) -> Optional[str]:
    if value is None:
        return None
    v = value.strip()
    if not v:
        return None
    if len(v) > max_len:
        raise ValueError(f'{field_label} must be {max_len} characters or fewer')
    if _CONTROL_CHARS_PATTERN.search(v):
        raise ValueError(f'{field_label} must not contain control characters')
    return v


def _validate_csr_name(v: str) -> str:
    """Mirror of SSLCertificateCreate.validate_name_no_path_traversal (Bulgu #21)
    with one deliberate tightening: max length 100, matching the
    ssl_certificates.name VARCHAR(100) column (the historical 200-char limit
    overflows the column and 500s — not replicated here)."""
    if v is None:
        raise ValueError('CSR name is required')
    stripped = v.strip()
    if not stripped:
        raise ValueError('CSR name must not be empty')
    if stripped != v:
        raise ValueError('CSR name must not contain leading/trailing whitespace')
    if len(stripped) > 100:
        raise ValueError('CSR name must be 100 characters or fewer')
    if not re.match(r'^[A-Za-z0-9_.-]+$', stripped):
        raise ValueError(
            f'CSR name={v!r} contains forbidden characters — only letters, '
            'digits, underscore, hyphen, and dot are allowed (the name becomes '
            'a filename component under /etc/ssl/haproxy/ at import).'
        )
    if '..' in stripped:
        raise ValueError(f'CSR name={v!r} must not contain ".." (path traversal)')
    if stripped.startswith('.'):
        raise ValueError(f'CSR name={v!r} must not start with "." (hidden filename)')
    if stripped.startswith('-'):
        raise ValueError(f'CSR name={v!r} must not start with "-" (CLI flag confusion)')
    return stripped


class SSLCSRCreate(BaseModel):
    name: str                                   # becomes the certificate name at import
    common_name: str
    organization: Optional[str] = None          # O
    organizational_unit: Optional[str] = None   # OU
    locality: Optional[str] = None              # L
    state: Optional[str] = None                 # ST
    country: Optional[str] = None               # C — exactly 2 letters
    email: Optional[str] = None                 # emailAddress
    sans: List[str] = []                        # DNS names; CN is auto-added server-side
    key_algorithm: str = 'rsa-2048'

    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        return _validate_csr_name(v)

    @field_validator('common_name')
    @classmethod
    def validate_common_name(cls, v):
        v = _validate_dns_name(v, 'Common Name')
        # RFC 5280 ub-common-name — many CAs reject CNs longer than 64 chars.
        if len(v) > 64:
            raise ValueError(
                'Common Name must be 64 characters or fewer (RFC 5280 upper '
                'bound) — put longer names in the SAN list instead.'
            )
        return v

    @field_validator('sans')
    @classmethod
    def validate_sans(cls, v):
        if not v:
            return []
        if len(v) > _MAX_SANS:
            raise ValueError(f'At most {_MAX_SANS} SAN entries are allowed')
        seen = set()
        result = []
        for entry in v:
            normalised = _validate_dns_name(entry, 'SAN entry')
            if normalised not in seen:
                seen.add(normalised)
                result.append(normalised)
        return result

    @field_validator('organization')
    @classmethod
    def validate_organization(cls, v):
        return _validate_subject_text(v, 'Organization (O)')

    @field_validator('organizational_unit')
    @classmethod
    def validate_organizational_unit(cls, v):
        return _validate_subject_text(v, 'Organizational Unit (OU)')

    @field_validator('locality')
    @classmethod
    def validate_locality(cls, v):
        return _validate_subject_text(v, 'Locality (L)')

    @field_validator('state')
    @classmethod
    def validate_state(cls, v):
        return _validate_subject_text(v, 'State/Province (ST)')

    @field_validator('country')
    @classmethod
    def validate_country(cls, v):
        # cryptography raises a bare ValueError for a non-2-char COUNTRY_NAME;
        # pre-validate so the operator gets a friendly 422 instead of a 500.
        if v is None:
            return None
        v = v.strip()
        if not v:
            return None
        if not re.match(r'^[A-Za-z]{2}$', v):
            raise ValueError('Country (C) must be exactly 2 letters (ISO 3166-1 alpha-2, e.g. TR, US)')
        return v.upper()

    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        v = _validate_subject_text(v, 'Email', max_len=254)
        if v is not None and ('@' not in v or v.startswith('@') or v.endswith('@')):
            raise ValueError('Email must be a valid address (missing or misplaced "@")')
        return v

    @field_validator('key_algorithm')
    @classmethod
    def validate_key_algorithm(cls, v):
        if v not in KEY_ALGORITHMS:
            raise ValueError(
                f'key_algorithm must be one of: {", ".join(KEY_ALGORITHMS)}'
            )
        return v


class SSLCSRImport(BaseModel):
    """Import the CA-signed certificate for a pending CSR. The private key is
    NOT part of the request — it is already stored on the CSR row."""
    certificate_content: str                    # PEM
    chain_content: Optional[str] = None         # PEM, optional
    usage_type: str = 'frontend'                # "frontend" or "server"
    is_global: bool = False
    cluster_ids: Optional[List[int]] = None
    # Escape hatch for name collisions that appeared AFTER the CSR was
    # created: overrides the CSR's reserved name for the certificate row.
    name: Optional[str] = None

    @field_validator('certificate_content')
    @classmethod
    def validate_certificate(cls, v):
        if not v or not v.strip():
            raise ValueError('Certificate content is required')
        v = v.strip()
        if len(v.encode('utf-8', errors='ignore')) > _MAX_CERT_PEM_BYTES:
            raise ValueError('Certificate content exceeds the 64 KB limit')
        if '-----BEGIN CERTIFICATE-----' not in v or '-----END CERTIFICATE-----' not in v:
            raise ValueError('Certificate must be in PEM format')
        return v

    @field_validator('chain_content')
    @classmethod
    def validate_chain(cls, v):
        if v and v.strip():
            v = v.strip()
            if len(v.encode('utf-8', errors='ignore')) > _MAX_CHAIN_PEM_BYTES:
                raise ValueError('Certificate chain exceeds the 256 KB limit')
            if '-----BEGIN CERTIFICATE-----' not in v or '-----END CERTIFICATE-----' not in v:
                raise ValueError('Certificate chain must be in PEM format')
            return v
        return None

    @field_validator('usage_type')
    @classmethod
    def validate_usage_type(cls, v):
        if v not in ['frontend', 'server']:
            raise ValueError('usage_type must be either "frontend" or "server"')
        return v

    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        if v is None or not str(v).strip():
            return None
        return _validate_csr_name(v)

    @model_validator(mode='after')
    def validate_cluster_selection(self):
        if not self.is_global and not self.cluster_ids:
            raise ValueError(
                'cluster_ids is required when is_global is false — pick at '
                'least one cluster or import the certificate as global.'
            )
        return self
