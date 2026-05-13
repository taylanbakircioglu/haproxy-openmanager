"""
SSL Certificate PEM parsing utilities
"""
import re
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

logger = logging.getLogger(__name__)

def parse_ssl_certificate(cert_content: str) -> Dict[str, Any]:
    """
    Parse SSL certificate PEM content and extract domain, expiry date, and other details
    
    Args:
        cert_content: PEM format certificate content
        
    Returns:
        Dictionary containing parsed certificate information
    """
    try:
        # Clean up the certificate content
        cert_content = cert_content.strip()
        
        # Ensure proper PEM format
        if not cert_content.startswith('-----BEGIN CERTIFICATE-----'):
            cert_content = '-----BEGIN CERTIFICATE-----\n' + cert_content
        if not cert_content.endswith('-----END CERTIFICATE-----'):
            cert_content = cert_content + '\n-----END CERTIFICATE-----'
        
        # Parse the certificate using cryptography library
        cert_bytes = cert_content.encode('utf-8')
        certificate = x509.load_pem_x509_certificate(cert_bytes)
        
        # Extract domain names (Subject Alternative Names + Common Name)
        domains = []
        
        # Get SAN (Subject Alternative Names)
        try:
            san_extension = certificate.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_domains = [name.value for name in san_extension.value]
            domains.extend(san_domains)
        except x509.ExtensionNotFound:
            logger.debug("No SAN extension found in certificate")
        
        # Get Common Name from subject
        try:
            subject = certificate.subject
            cn = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if cn:
                common_name = cn[0].value
                if common_name not in domains:
                    domains.append(common_name)
        except Exception as e:
            logger.debug(f"Could not extract common name: {e}")
        
        # Primary domain (first one or common name)
        primary_domain = domains[0] if domains else "unknown"
        
        # Extract expiry date - use not_valid_after and force UTC timezone
        try:
            # Try not_valid_after first (more compatible)
            expiry_date = certificate.not_valid_after
            logger.info(f"🕐 Using not_valid_after: {expiry_date}, tzinfo: {expiry_date.tzinfo}")
        except AttributeError:
            # Fallback to not_valid_after_utc
            expiry_date = certificate.not_valid_after_utc
            logger.info(f"🕐 Using not_valid_after_utc: {expiry_date}, tzinfo: {expiry_date.tzinfo}")
        
        # Force timezone to UTC regardless of what we got
        if expiry_date.tzinfo is None:
            expiry_date = expiry_date.replace(tzinfo=timezone.utc)
            logger.info(f"🔧 Added UTC timezone: {expiry_date}")
        else:
            # Convert any timezone to UTC
            expiry_date = expiry_date.astimezone(timezone.utc)
            logger.info(f"🔧 Converted to UTC: {expiry_date}")
        
        # Extract issuer
        issuer_name = "Unknown"
        try:
            issuer = certificate.issuer
            org = issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
            if org:
                issuer_name = org[0].value
            else:
                cn = issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                if cn:
                    issuer_name = cn[0].value
        except Exception as e:
            logger.debug(f"Could not extract issuer: {e}")
        
        # Calculate certificate status
        now = datetime.now(timezone.utc)
        logger.debug(f"Now datetime: {now}, tzinfo: {now.tzinfo}")
        logger.debug(f"Expiry datetime: {expiry_date}, tzinfo: {expiry_date.tzinfo}")
        
        try:
            days_until_expiry = (expiry_date - now).days
            logger.debug(f"Days until expiry calculated: {days_until_expiry}")
        except Exception as e:
            logger.error(f"Error calculating days until expiry: {e}")
            # Fallback to 0 if calculation fails
            days_until_expiry = 0
        
        if days_until_expiry < 0:
            status = "expired"
        elif days_until_expiry < 30:
            status = "expiring_soon"
        else:
            status = "valid"
        
        # Get certificate fingerprint
        fingerprint = certificate.fingerprint(hashes.SHA256()).hex()
        
        return {
            "primary_domain": primary_domain,
            "all_domains": domains,
            "expiry_date": expiry_date,
            "issuer": issuer_name,
            "status": status,
            "days_until_expiry": days_until_expiry,
            "fingerprint": fingerprint,
            "serial_number": str(certificate.serial_number),
            "version": certificate.version.name
        }
        
    except Exception as e:
        logger.error(f"Failed to parse SSL certificate: {e}")
        return {
            "primary_domain": "parse_error",
            "all_domains": [],
            "expiry_date": None,
            "issuer": "Unknown",
            "status": "invalid",
            "days_until_expiry": 0,
            "fingerprint": "",
            "serial_number": "",
            "version": "unknown",
            "error": str(e)
        }

def validate_private_key(key_content: str) -> bool:
    """
    Validate private key PEM content
    
    Args:
        key_content: PEM format private key content
        
    Returns:
        Boolean indicating if key is valid
    """
    try:
        # Clean up the key content
        key_content = key_content.strip()
        
        # Try to parse as different key types
        key_bytes = key_content.encode('utf-8')
        
        # Try RSA private key
        try:
            serialization.load_pem_private_key(key_bytes, password=None)
            return True
        except Exception:
            pass
        
        # Try with password (empty password)
        try:
            serialization.load_pem_private_key(key_bytes, password=b'')
            return True
        except Exception:
            pass
        
        return False
        
    except Exception as e:
        logger.error(f"Failed to validate private key: {e}")
        return False

def validate_certificate_chain(chain_content: str) -> bool:
    """
    Validate certificate chain PEM content
    
    Args:
        chain_content: PEM format certificate chain content
        
    Returns:
        Boolean indicating if chain is valid
    """
    if not chain_content or not chain_content.strip():
        return True  # Chain is optional
    
    try:
        # Clean up the chain content
        chain_content = chain_content.strip()
        
        # Split multiple certificates in the chain
        cert_pattern = r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----'
        certificates = re.findall(cert_pattern, chain_content, re.DOTALL)
        
        if not certificates:
            return False
        
        # Validate each certificate in the chain
        for cert_pem in certificates:
            try:
                cert_bytes = cert_pem.encode('utf-8')
                x509.load_pem_x509_certificate(cert_bytes)
            except Exception:
                return False
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to validate certificate chain: {e}")
        return False

def verify_certificate_key_match(
    cert_content: str, private_key_content: str
) -> Dict[str, Any]:
    """Bulgu #23 (round-12 audit): verify cert public key == private key
    public key.

    Pre-fix the wizard / direct SSL upload route validated cert and
    key INDEPENDENTLY. An operator who pasted a cert for site A and
    the private key for site B (easy to mix up when juggling many
    PEMs) saw success and only learned about the mismatch at the
    agent's `haproxy -c`, which errors with:

        unable to load SSL private key from PEM file '...':
        crypto/x509/x509_cmp.c:...: X509_check_private_key:
        key values mismatch

    by which point the wizard had already created the cert row, the
    HTTPS frontend row, and the PENDING config version. Recovery
    required hunting through Apply Management to reject the version.

    Returns:
        {"match": bool, "reason": Optional[str]}
        - match=True  → cert and key share the same public key.
        - match=False → mismatch (cert/key are for different sites
          or the key was rotated without re-issuing the cert).
        - match=None  → could not compare (e.g. encrypted key,
          unsupported key type). Caller falls back to validate-key
          only (which already ran).
    """
    from cryptography.hazmat.primitives import serialization

    if not (cert_content or "").strip() or not (private_key_content or "").strip():
        return {"match": None, "reason": "empty cert or key content"}

    try:
        cert_bytes = cert_content.strip().encode("utf-8")
        certificate = x509.load_pem_x509_certificate(cert_bytes)
    except Exception as cert_err:
        return {"match": None, "reason": f"cert parse failed: {cert_err}"}

    key_bytes = private_key_content.strip().encode("utf-8")
    key_obj = None
    for password in (None, b""):
        try:
            key_obj = serialization.load_pem_private_key(
                key_bytes, password=password
            )
            break
        except Exception:
            continue
    if key_obj is None:
        return {"match": None, "reason": "key parse failed (encrypted?)"}

    try:
        cert_pub_der = certificate.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_pub_der = key_obj.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except Exception as compare_err:
        return {"match": None, "reason": f"public-key serialization failed: {compare_err}"}

    return {
        "match": cert_pub_der == key_pub_der,
        "reason": (
            None if cert_pub_der == key_pub_der
            else "cert public key differs from private key's public key"
        ),
    }


def domain_covered_by_cert(domain: str, cert_san_or_cn: list) -> bool:
    """Bulgu #25 (round-12 audit): check whether a `domain` is covered
    by any entry in the cert's SAN / Common-Name list, accounting for
    RFC 6125 single-label wildcards.

    HAProxy's SNI / cert matching follows RFC 6125 / RFC 9525:

      * Literal match: cert SAN `api.example.com` matches `api.example.com`.
      * Wildcard: cert SAN `*.example.com` matches `api.example.com`
        (single leftmost label) but does NOT match `api.sub.example.com`
        (two leftmost labels) and does NOT match the bare apex
        `example.com` (no leftmost label).

    Pre-fix the wizard let an operator deploy a site with
    `domains=['shop.example.com']` and a cert for `api.example.com`
    — HAProxy loads happily but every TLS handshake serves the wrong
    cert, browser shows NET::ERR_CERT_COMMON_NAME_INVALID, and the
    site is effectively down.
    """
    if not domain or not cert_san_or_cn:
        return False
    domain_lc = domain.lower().strip().rstrip(".")
    if not domain_lc:
        return False
    for cd in cert_san_or_cn:
        cd_lc = (cd or "").lower().strip().rstrip(".")
        if not cd_lc:
            continue
        if cd_lc == domain_lc:
            return True
        if cd_lc.startswith("*."):
            parent = cd_lc[2:]
            if not parent or "." not in parent:
                continue
            suffix = "." + parent
            if domain_lc.endswith(suffix):
                prefix = domain_lc[: -len(suffix)]
                if prefix and "." not in prefix:
                    return True
    return False


def find_uncovered_domains(domains: list, cert_san_or_cn: list) -> list:
    """Return the subset of `domains` NOT covered by any SAN/CN entry,
    preserving the input order so the error message lists them as
    the operator typed them.
    """
    if not domains:
        return []
    return [d for d in domains if not domain_covered_by_cert(d, cert_san_or_cn or [])]


def format_certificate_info(cert_info: Dict[str, Any]) -> str:
    """
    Format certificate information for display
    
    Args:
        cert_info: Parsed certificate information
        
    Returns:
        Formatted string for display
    """
    if cert_info.get("error"):
        return f"❌ Invalid Certificate: {cert_info['error']}"
    
    status_emoji = {
        "valid": "✅",
        "expiring_soon": "⚠️",
        "expired": "❌",
        "invalid": "❌"
    }
    
    emoji = status_emoji.get(cert_info["status"], "❓")
    domain = cert_info["primary_domain"]
    expiry = cert_info["expiry_date"]
    issuer = cert_info["issuer"]
    
    if expiry:
        expiry_str = expiry.strftime("%Y-%m-%d")
        days = cert_info["days_until_expiry"]
        return f"{emoji} {domain} | Expires: {expiry_str} ({days} days) | Issuer: {issuer}"
    else:
        return f"{emoji} {domain} | Issuer: {issuer}"
