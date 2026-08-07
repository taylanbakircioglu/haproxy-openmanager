"""
csr_service: CSR (Certificate Signing Request) generation + signed-certificate
import (v1.9.0).

Flow:
  1. `generate_csr_bundle` builds a private key + CSR locally (pure crypto,
     no DB/IO — callers MUST run it via `asyncio.to_thread`: RSA-4096
     generation takes seconds and would stall the single-worker event loop).
  2. The bundle is persisted to `ssl_csrs` (`insert_csr_row`); the operator
     downloads the CSR PEM and has it signed by an external CA.
  3. `import_signed_certificate` pairs the CA response with the stored key,
     creates a normal `ssl_certificates` row (source='csr',
     last_config_status='PENDING' — agents never see it before Apply) and
     NULLs the key copy on the CSR row.

The CSR builder generalises the in-repo ACME reference
(services/acme_service.py finalize_order): PEM output instead of DER, full
subject instead of CN-only, ECDSA support, same PKCS8/NoEncryption key
serialisation (the agent concatenates cert+key+chain into one PEM and HAProxy
cannot read passphrase-protected keys).

Private keys are ENCRYPTED AT REST from v1.10.1 (Issue #53): the Fernet token
replaces the PEM in the same `ssl_csrs.private_key_pem` column, so there is no
schema change and no SCHEMA_VERSION bump. Rows written earlier hold a raw PEM
and are still read transparently — see utils/csr_key_crypto.py for the format
discriminator and the key-rotation caveat. The pending CSR key is the one key
in the system worth encrypting: it sits idle for the whole signing window and
is never transmitted, unlike ssl_certificates.private_key_content and the ACME
order keys, which agents must receive in plaintext on every poll.
The key is NEVER returned by any CSR API response — `csr_row_to_dict` strips
it unconditionally.
"""

import json
import logging
from typing import Any, Dict, List, Optional
from types import SimpleNamespace

import asyncpg
from fastapi import HTTPException

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from services import ssl_service
from utils.csr_key_crypto import decrypt_csr_private_key, encrypt_csr_private_key

logger = logging.getLogger(__name__)


_KEY_FACTORIES = {
    'rsa-2048': lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
    'rsa-4096': lambda: rsa.generate_private_key(public_exponent=65537, key_size=4096),
    'ecdsa-p256': lambda: ec.generate_private_key(ec.SECP256R1()),
    'ecdsa-p384': lambda: ec.generate_private_key(ec.SECP384R1()),
}

# (payload attribute, x509 OID, subject-JSON key)
_SUBJECT_OID_MAP = [
    ('organization', NameOID.ORGANIZATION_NAME, 'O'),
    ('organizational_unit', NameOID.ORGANIZATIONAL_UNIT_NAME, 'OU'),
    ('locality', NameOID.LOCALITY_NAME, 'L'),
    ('state', NameOID.STATE_OR_PROVINCE_NAME, 'ST'),
    ('country', NameOID.COUNTRY_NAME, 'C'),
    ('email', NameOID.EMAIL_ADDRESS, 'emailAddress'),
]


def generate_csr_bundle(payload: Any) -> Dict[str, Any]:
    """Generate a private key + CSR for a validated SSLCSRCreate payload.

    Pure CPU-bound crypto — no DB, no network. Callers must offload via
    `asyncio.to_thread` (see module docstring).

    Returns {'csr_pem', 'private_key_pem', 'sans', 'subject'}.
    """
    key = _KEY_FACTORIES[payload.key_algorithm]()

    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, payload.common_name)]
    subject_json: Dict[str, str] = {}
    for attr_name, oid, json_key in _SUBJECT_OID_MAP:
        value = getattr(payload, attr_name, None)
        if value and str(value).strip():
            cleaned = str(value).strip()
            attrs.append(x509.NameAttribute(oid, cleaned))
            subject_json[json_key] = cleaned

    # CN always first in the SAN list, then the extra names, deduped with
    # order preserved (mirrors the ACME flow where domains[0] is the CN).
    sans = list(dict.fromkeys([payload.common_name, *(payload.sans or [])]))

    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name(attrs))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in sans]),
            critical=False,
        )
    )
    csr = builder.sign(key, hashes.SHA256())

    return {
        'csr_pem': csr.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
        'private_key_pem': key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode('utf-8'),
        'sans': sans,
        'subject': subject_json,
    }


def diff_domains(csr_sans: Optional[List[str]], cert_domains: Optional[List[str]]) -> List[str]:
    """Human-readable warnings for SAN drift between the CSR and the signed
    certificate (case-insensitive set diff). CAs legitimately add/normalise
    SANs, so drift is WARN-only — the hard gate is the key match."""
    csr_set = {d.lower() for d in (csr_sans or []) if d}
    cert_set = {d.lower() for d in (cert_domains or []) if d}
    warnings: List[str] = []
    added = sorted(cert_set - csr_set)
    dropped = sorted(csr_set - cert_set)
    if added:
        warnings.append(
            f"The CA added domains that were not in the CSR: {', '.join(added)}"
        )
    if dropped:
        warnings.append(
            f"The CA dropped domains that were requested in the CSR: {', '.join(dropped)}"
        )
    return warnings


def _maybe_json_list(value: Any) -> List[str]:
    """asyncpg returns JSONB columns as str unless a codec is registered."""
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except Exception:
            return []
    return list(value) if value else []


def csr_row_to_dict(row: Any, include_pem: bool = False) -> Dict[str, Any]:
    """Row → API dict. ALWAYS strips private_key_pem — the key never leaves
    the server via a CSR endpoint. csr_pem included only on demand
    (detail/create responses, not lists)."""
    d = dict(row)
    d.pop('private_key_pem', None)
    if not include_pem:
        d.pop('csr_pem', None)
    for key in ('subject', 'sans'):
        if key in d and isinstance(d[key], str):
            try:
                d[key] = json.loads(d[key])
            except Exception:
                pass
    return d


async def assert_csr_name_available(conn, name: str) -> None:
    """Reject a CSR name that is already taken by an ACTIVE certificate or
    another PENDING CSR. Called BEFORE key generation (cheap fail-fast) and
    re-run inside `insert_csr_row` (the unique index closes the race)."""
    existing_cert = await conn.fetchval(
        "SELECT id FROM ssl_certificates WHERE name = $1 AND is_active = TRUE",
        name,
    )
    if existing_cert:
        raise HTTPException(
            status_code=400,
            detail=(
                f"An active SSL certificate named '{name}' already exists. "
                "The CSR name becomes the certificate name at import — choose "
                "a different name or remove the existing certificate first."
            ),
        )
    existing_csr = await conn.fetchval(
        "SELECT id FROM ssl_csrs WHERE name = $1 AND status = 'pending'",
        name,
    )
    if existing_csr:
        raise HTTPException(
            status_code=400,
            detail=(
                f"A pending CSR named '{name}' already exists (id={existing_csr}). "
                "Import or delete it first, or choose a different name."
            ),
        )


async def insert_csr_row(conn, payload: Any, bundle: Dict[str, Any], user_id: Optional[int]) -> int:
    """Persist a freshly generated CSR bundle. Returns the new csr id.

    Issue #53 (v1.10.1): the private key is Fernet-encrypted before it is stored. The token goes
    into the SAME private_key_pem TEXT column — no schema change — and is only ever decrypted
    in-process by import_signed_certificate. No CSR endpoint returns the column either way.
    """
    await assert_csr_name_available(conn, payload.name)
    stored_key = encrypt_csr_private_key(bundle['private_key_pem'])
    try:
        csr_id = await conn.fetchval(
            """
            INSERT INTO ssl_csrs
            (name, common_name, subject, sans, key_algorithm, csr_pem,
             private_key_pem, status, created_by)
            VALUES ($1, $2, $3::jsonb, $4::jsonb, $5, $6, $7, 'pending', $8)
            RETURNING id
            """,
            payload.name,
            payload.common_name,
            json.dumps(bundle['subject']),
            json.dumps(bundle['sans']),
            payload.key_algorithm,
            bundle['csr_pem'],
            stored_key,
            user_id,
        )
    except asyncpg.exceptions.UniqueViolationError:
        # uq_ssl_csrs_name_pending — a concurrent request won the name.
        raise HTTPException(
            status_code=400,
            detail=(
                f"A pending CSR named '{payload.name}' was just created by a "
                "concurrent request — choose a different name."
            ),
        )
    return csr_id


async def import_signed_certificate(conn, csr_id: int, imp: Any, user_id: Optional[int]) -> Dict[str, Any]:
    """Pair the CA-signed certificate with the stored CSR key and create the
    ssl_certificates row. Atomic: cert row + CSR state change commit together.

    Returns {'certificate_id', 'certificate_name', 'primary_domain',
    'warnings', 'reactivated'}. Raises HTTPException on every failure
    (404 missing, 409 already completed, 400 validation).
    """
    async with conn.transaction():
        # Row lock serialises concurrent imports AND a concurrent DELETE of
        # the same CSR; works across multiple uvicorn workers (DB-level lock).
        row = await conn.fetchrow(
            "SELECT * FROM ssl_csrs WHERE id = $1 FOR UPDATE", csr_id
        )
        if not row:
            raise HTTPException(status_code=404, detail="CSR not found")
        if row['status'] == 'completed':
            raise HTTPException(
                status_code=409,
                detail=(
                    f"CSR '{row['name']}' is already completed — certificate "
                    f"id {row['ssl_certificate_id']} was imported from it. "
                    "Create a new CSR to reissue."
                ),
            )
        if not row['private_key_pem']:
            raise HTTPException(
                status_code=500,
                detail=(
                    "Stored CSR private key is missing — the CSR row is "
                    "corrupt. Delete it and create a new CSR."
                ),
            )
        # Issue #53: the column holds a Fernet token from v1.10.1 on, and a raw PEM for rows
        # written before it. decrypt_csr_private_key accepts both, so no data migration is
        # needed. A None here means the token cannot be decrypted — SECRET_KEY was rotated
        # without CSR_ENCRYPTION_KEY set. Fail loudly: the key is gone, so the CA's certificate
        # can never be paired with it, and silently falling through would surface as the far
        # more confusing "certificate does not match this CSR's private key".
        stored_key = decrypt_csr_private_key(row['private_key_pem'])
        if not stored_key:
            raise HTTPException(
                status_code=500,
                detail=(
                    f"The stored private key for CSR '{row['name']}' cannot be decrypted. This "
                    "happens when SECRET_KEY was rotated while CSR_ENCRYPTION_KEY was not set. "
                    "The key is unrecoverable, so this CSR can no longer be completed — delete "
                    "it and create a new one (then have the new CSR signed)."
                ),
            )

        effective_name = getattr(imp, 'name', None) or row['name']

        # Parse the pasted certificate FIRST so a malformed/truncated CA
        # response gets the manual flow's 400, not a 500 from the key-match
        # step below (verify_certificate_key_match reports an unparseable
        # cert as match=None, which we treat as an integrity failure).
        from utils.ssl_parser import parse_ssl_certificate, verify_certificate_key_match
        precheck = parse_ssl_certificate(imp.certificate_content)
        if precheck.get('error'):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid SSL certificate: {precheck['error']}",
            )

        # THE defining check of this feature: the CA response must match the
        # key we generated. Deliberately stricter than create_cert_row's
        # lenient fallback — we generated this key ourselves, so an
        # unverifiable pair is an integrity failure, not operator input.
        match_result = verify_certificate_key_match(imp.certificate_content, stored_key)
        if match_result.get('match') is False:
            raise HTTPException(
                status_code=400,
                detail=(
                    "The signed certificate does not match this CSR's private "
                    "key — the CA response likely belongs to a different "
                    "CSR/key. Verify you pasted the certificate that was "
                    "issued for this exact CSR."
                ),
            )
        if match_result.get('match') is not True:
            raise HTTPException(
                status_code=500,
                detail=(
                    "Could not verify the certificate/key pair: "
                    f"{match_result.get('reason', 'unknown')}"
                ),
            )

        # Full parse/validation pipeline shared with the manual + wizard
        # flows: invalid PEM, bad chain and already-expired certs all 400.
        payload = SimpleNamespace(
            name=effective_name,
            certificate_content=imp.certificate_content,
            private_key_content=stored_key,
            chain_content=getattr(imp, 'chain_content', None),
            usage_type=getattr(imp, 'usage_type', 'frontend') or 'frontend',
        )
        fields = ssl_service._prepare_cert_fields(payload)

        # Global name uniqueness (ssl_certificates.cluster_id is always NULL
        # under the R38 schema, so name is effectively a global namespace).
        existing = await conn.fetchrow(
            "SELECT id, is_active FROM ssl_certificates WHERE name = $1 LIMIT 1",
            effective_name,
        )
        if existing and existing['is_active']:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"An active SSL certificate named '{effective_name}' "
                    "already exists (created after this CSR). Delete or "
                    "rename it, or pass a different `name` in the import "
                    "request — the CSR stays pending and can be re-imported."
                ),
            )

        reactivated = False
        if existing and not existing['is_active']:
            # Reactivate the soft-deleted row (mirrors create_cert_row):
            # preserves the row id so historical references keep working.
            await conn.execute(
                "DELETE FROM ssl_certificate_clusters WHERE ssl_certificate_id = $1",
                existing['id'],
            )
            await conn.execute(
                """
                UPDATE ssl_certificates
                SET is_active = TRUE,
                    last_config_status = 'PENDING',
                    certificate_content = $2,
                    private_key_content = $3,
                    chain_content = $4,
                    primary_domain = $5,
                    all_domains = $6::jsonb,
                    expiry_date = $7,
                    usage_type = $8,
                    issuer = $9,
                    fingerprint = $10,
                    status = $11,
                    days_until_expiry = $12,
                    source = 'csr',
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = $1
                """,
                existing['id'],
                fields['cert_content'],
                fields['private_key_content'],
                fields['chain_content'],
                fields['primary_domain'],
                json.dumps(fields['all_domains']),
                fields['expiry_date'],
                fields['usage_type'],
                fields['issuer'],
                fields['fingerprint'],
                fields['status'],
                fields['days_until_expiry'],
            )
            cert_id = existing['id']
            reactivated = True
            logger.info(
                f"csr_service.import_signed_certificate: reactivated "
                f"soft-deleted cert '{effective_name}' (id={cert_id}) for CSR {csr_id}"
            )
        else:
            cert_id = await conn.fetchval(
                """
                INSERT INTO ssl_certificates (
                    name, primary_domain, certificate_content, private_key_content,
                    chain_content, expiry_date, issuer, fingerprint, status,
                    days_until_expiry, all_domains, is_active, cluster_id,
                    last_config_status, usage_type, source
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb,
                    TRUE, NULL, 'PENDING', $12, 'csr'
                )
                RETURNING id
                """,
                effective_name,
                fields['primary_domain'],
                fields['cert_content'],
                fields['private_key_content'],
                fields['chain_content'],
                fields['expiry_date'],
                fields['issuer'],
                fields['fingerprint'],
                fields['status'],
                fields['days_until_expiry'],
                json.dumps(fields['all_domains']),
                fields['usage_type'],
            )

        # Cluster bindings: global = zero junction rows (existing convention).
        if not getattr(imp, 'is_global', False):
            for cluster_id in (getattr(imp, 'cluster_ids', None) or []):
                await ssl_service.ensure_cluster_junction(conn, cert_id, cluster_id)

        # Complete the CSR and destroy the key copy — the key now lives on
        # the certificate row only, like every other key in the system.
        await conn.execute(
            """
            UPDATE ssl_csrs
            SET status = 'completed',
                ssl_certificate_id = $2,
                private_key_pem = NULL,
                completed_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = $1
            """,
            csr_id,
            cert_id,
        )

    warnings = diff_domains(_maybe_json_list(row['sans']), fields['all_domains'])
    if reactivated:
        warnings.append(
            f"A soft-deleted certificate named '{effective_name}' was "
            f"reactivated (row id {cert_id}) — existing entities that still "
            "reference that id now serve the newly imported certificate."
        )

    return {
        'certificate_id': cert_id,
        'certificate_name': effective_name,
        'primary_domain': fields['primary_domain'],
        'warnings': warnings,
        'reactivated': reactivated,
    }
