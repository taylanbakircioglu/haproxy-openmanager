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
