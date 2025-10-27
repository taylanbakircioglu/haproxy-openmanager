from pydantic import BaseModel, validator
from typing import Optional, List
import re
import ipaddress

class WAFRule(BaseModel):
    name: str
    rule_type: str  # 'rate_limit', 'ip_filter', 'header_filter', 'request_filter', 'geo_block', 'size_limit'
    action: str = 'block'  # 'block', 'allow', 'log', 'redirect'
    priority: int = 100
    is_active: bool = True
    config: dict  # This will hold all rule-specific configurations
    description: Optional[str] = None
    
    # Frontend associations (multiple) - optional during creation
    frontend_ids: Optional[List[int]] = None
    
    # CRITICAL VALIDATION RULES FOR HAPROXY WAF
    @validator('name')
    def validate_name(cls, v):
        if not v or not v.strip():
            raise ValueError('WAF rule name cannot be empty')
        
        # HAProxy ACL names cannot contain spaces or special characters
        if not re.match(r'^[a-zA-Z0-9_-]+$', v.strip()):
            raise ValueError('WAF rule name can only contain letters, numbers, underscore (_) and dash (-). Spaces and special characters are not allowed.')
        
        if len(v.strip()) > 50:
            raise ValueError('WAF rule name cannot exceed 50 characters')
            
        return v.strip()
    
    @validator('rule_type')
    def validate_rule_type(cls, v):
        valid_types = ['rate_limit', 'ip_filter', 'header_filter', 'request_filter', 'geo_block', 'size_limit', 'path_filter']
        if v not in valid_types:
            raise ValueError(f'Invalid rule type. Must be one of: {", ".join(valid_types)}')
        return v
    
    @validator('action')
    def validate_action(cls, v):
        valid_actions = ['block', 'allow', 'log', 'redirect']
        if v not in valid_actions:
            raise ValueError(f'Invalid action. Must be one of: {", ".join(valid_actions)}')
        return v
    
    @validator('priority')
    def validate_priority(cls, v):
        if not isinstance(v, int) or v < 1 or v > 1000:
            raise ValueError('Priority must be between 1 and 1000')
        return v
    

class WAFRuleUpdate(WAFRule):
    name: Optional[str] = None
    rule_type: Optional[str] = None
    action: Optional[str] = None
    priority: Optional[int] = None
    is_active: Optional[bool] = None
    config: Optional[dict] = None
    description: Optional[str] = None
    frontend_ids: Optional[List[int]] = None

class FrontendWAFRule(BaseModel):
    waf_rule_id: int
    is_active: bool = True

class SSLCertificate(BaseModel):
    name: str
    domain: str
    certificate_content: str
    private_key_content: str
    chain_content: Optional[str] = None
    expiry_date: Optional[str] = None 