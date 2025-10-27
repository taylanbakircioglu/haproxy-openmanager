from pydantic import BaseModel, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class SSLCertificateCreate(BaseModel):
    name: str
    certificate_content: str  # PEM format certificate
    private_key_content: str  # PEM format private key
    chain_content: Optional[str] = None  # PEM format certificate chain (optional)
    cluster_ids: Optional[List[int]] = None  # List of cluster IDs for multi-cluster support
    is_global: bool = False  # True for global SSL certificates
    
    @validator('certificate_content')
    def validate_certificate(cls, v):
        if not v or not v.strip():
            raise ValueError('Certificate content is required')
        
        # Basic PEM format check
        v = v.strip()
        if '-----BEGIN CERTIFICATE-----' not in v or '-----END CERTIFICATE-----' not in v:
            raise ValueError('Certificate must be in PEM format')
        
        return v
    
    @validator('private_key_content')
    def validate_private_key(cls, v):
        if not v or not v.strip():
            raise ValueError('Private key content is required')
        
        # Basic PEM format check
        v = v.strip()
        if '-----BEGIN' not in v or '-----END' not in v:
            raise ValueError('Private key must be in PEM format')
        
        return v
    
    @validator('chain_content')
    def validate_chain(cls, v):
        if v and v.strip():
            # Basic PEM format check for chain
            if '-----BEGIN CERTIFICATE-----' not in v or '-----END CERTIFICATE-----' not in v:
                raise ValueError('Certificate chain must be in PEM format')
        
        return v

class SSLCertificateUpdate(BaseModel):
    name: Optional[str] = None
    certificate_content: Optional[str] = None
    private_key_content: Optional[str] = None
    chain_content: Optional[str] = None
    cluster_id: Optional[int] = None

class SSLCertificate(BaseModel):
    id: int
    name: str
    domain: str  # Auto-parsed from certificate
    all_domains: List[str] = []  # All domains from SAN + CN
    certificate_content: str
    private_key_content: str
    chain_content: Optional[str] = None
    expiry_date: Optional[datetime] = None  # Auto-parsed from certificate
    issuer: Optional[str] = None  # Auto-parsed from certificate
    status: str  # 'valid', 'expiring_soon', 'expired', 'invalid'
    days_until_expiry: int = 0
    fingerprint: Optional[str] = None
    cluster_id: Optional[int] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    has_pending_config: bool = False
    
    # Certificate details for UI display
    certificate_info: Optional[Dict[str, Any]] = None

class SSLCertificateResponse(BaseModel):
    """Response model for SSL certificate API endpoints"""
    id: int
    name: str
    domain: str
    all_domains: List[str] = []
    status: str
    days_until_expiry: int = 0
    expiry_date: Optional[datetime] = None
    issuer: Optional[str] = None
    fingerprint: Optional[str] = None
    cluster_id: Optional[int] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    has_pending_config: bool = False