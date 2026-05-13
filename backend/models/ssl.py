from pydantic import BaseModel, field_validator, model_validator
from typing import Optional, List, Dict, Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class SSLCertificateCreate(BaseModel):
    name: str
    certificate_content: str  # PEM format certificate
    private_key_content: Optional[str] = None  # PEM format private key (optional for server SSL)
    chain_content: Optional[str] = None  # PEM format certificate chain (optional)
    cluster_ids: Optional[List[int]] = None  # List of cluster IDs for multi-cluster support
    is_global: bool = False  # True for global SSL certificates
    usage_type: str = "frontend"  # "frontend" or "server" - determines if private key is required
    
    @field_validator('usage_type')
    @classmethod
    def validate_usage_type(cls, v):
        if v not in ['frontend', 'server']:
            raise ValueError('usage_type must be either "frontend" or "server"')
        return v

    @field_validator('name')
    @classmethod
    def validate_name_no_path_traversal(cls, v):
        """Bulgu #21 (round-11 audit): SSL certificate `name` is interpolated
        into the on-disk certificate path:

            cert_path = f"/etc/ssl/haproxy/{ssl_cert['name']}.pem"

        and emitted into the rendered HAProxy config. The agent then
        runs `mv "$temp_cert_file" "$cert_file_path"` as root, which
        means a name like '../../tmp/evil' resolves to '/tmp/evil.pem'
        and lets an operator with ssl.create permission overwrite
        arbitrary `*.pem` files on the agent host. The trailing `.pem`
        suffix mitigates common exploit paths (cron.d, profile.d,
        authorized_keys) but is defense-only — the right fix is to
        constrain `name` at the API boundary. Mirror SSLChoice's
        constraints so the wizard and direct API give the same answer.
        """
        if v is None:
            return v
        stripped = v.strip()
        if not stripped:
            raise ValueError('SSL certificate name must not be empty')
        if stripped != v:
            raise ValueError('SSL certificate name must not contain leading/trailing whitespace')
        if len(stripped) > 200:
            raise ValueError('SSL certificate name must be 200 characters or fewer')
        import re as _re
        if not _re.match(r'^[A-Za-z0-9_.-]+$', stripped):
            raise ValueError(
                f'SSL certificate name={v!r} contains forbidden characters '
                '— only letters, digits, underscore, hyphen, and dot are '
                'allowed (the name is used as a filename component under '
                '/etc/ssl/haproxy/).'
            )
        if '..' in stripped:
            raise ValueError(f'SSL certificate name={v!r} must not contain ".." (path traversal)')
        if stripped.startswith('.'):
            raise ValueError(f'SSL certificate name={v!r} must not start with "." (hidden filename)')
        if stripped.startswith('-'):
            raise ValueError(f'SSL certificate name={v!r} must not start with "-" (CLI flag confusion)')
        return stripped

    @field_validator('certificate_content')
    @classmethod
    def validate_certificate(cls, v):
        if not v or not v.strip():
            raise ValueError('Certificate content is required')
        
        # Basic PEM format check
        v = v.strip()
        if '-----BEGIN CERTIFICATE-----' not in v or '-----END CERTIFICATE-----' not in v:
            raise ValueError('Certificate must be in PEM format')
        
        return v
    
    @model_validator(mode='after')
    def validate_private_key_based_on_usage(self):
        """Private key is required for frontend SSL, optional for server SSL"""
        usage_type = self.usage_type
        private_key = self.private_key_content
        
        if usage_type == 'frontend':
            # Frontend SSL requires private key
            if not private_key or not private_key.strip():
                raise ValueError('Private key is required for frontend SSL certificates')
            
            # Basic PEM format check
            private_key = private_key.strip()
            if '-----BEGIN' not in private_key or '-----END' not in private_key:
                raise ValueError('Private key must be in PEM format')
        elif usage_type == 'server':
            # Server SSL - private key is optional
            if private_key and private_key.strip():
                # If provided, validate format
                private_key = private_key.strip()
                if '-----BEGIN' not in private_key or '-----END' not in private_key:
                    raise ValueError('Private key must be in PEM format')
        
        return self
    
    @field_validator('chain_content')
    @classmethod
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
    usage_type: Optional[str] = None  # "frontend" or "server"
    
    @field_validator('usage_type')
    @classmethod
    def validate_usage_type(cls, v):
        if v is not None and v not in ['frontend', 'server']:
            raise ValueError('usage_type must be either "frontend" or "server"')
        return v

    # Bulgu #63 (round-22 audit) — the path-traversal guard previously
    # lived here as a strict Pydantic validator (Bulgu #21, round-11).
    # On UPDATE the manual SSL UI re-sends the existing `name` along
    # with the field the operator actually edited (usage_type /
    # cluster_id / content). If the existing certificate name was
    # imported BEFORE Bulgu #21 landed (or by a different upload path)
    # and contained a now-rejected character — e.g. legacy uploads
    # with `cert (1).pem`, `*.example.com`, `client cert.pem`, or
    # `wildcard.example.com` if dot was not yet escaped — every PUT
    # would 400 even though the operator was only changing usage
    # type or attaching the cert to another cluster. That mirrors
    # the Bulgu #62 lockout on frontends.
    #
    # The guard was moved into `routers/ssl.py::_assert_safe_cert_name`
    # and is now invoked by the create + update routes:
    #   * create: strict — rejects unsafe names outright (Bulgu #21
    #     contract preserved for fresh inserts).
    #   * update: skipped if `name` is unchanged from the DB row;
    #     enforced strictly only when the operator actually renames
    #     the certificate.

class SSLCertificate(BaseModel):
    id: int
    name: str
    domain: str  # Auto-parsed from certificate
    all_domains: List[str] = []  # All domains from SAN + CN
    certificate_content: str
    private_key_content: Optional[str] = None  # Optional for server SSL
    chain_content: Optional[str] = None
    expiry_date: Optional[datetime] = None  # Auto-parsed from certificate
    issuer: Optional[str] = None  # Auto-parsed from certificate
    status: str  # 'valid', 'expiring_soon', 'expired', 'invalid'
    days_until_expiry: int = 0
    fingerprint: Optional[str] = None
    cluster_id: Optional[int] = None
    usage_type: str = "frontend"  # "frontend" or "server"
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
    usage_type: str = "frontend"  # "frontend" or "server"
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    has_pending_config: bool = False