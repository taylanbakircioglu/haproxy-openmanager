"""Issue #27 — HA/VIP (Keepalived) management (v1.7.0).

Pydantic request/response models for the VIP management API. Field validation
is strict because several values flow into a generated keepalived.conf and into
root-run agent commands — we reuse the same FORBIDDEN-metacharacter discipline as
models/agent.py (Bulgu #81) and validate the VIP as a real IPv4 address.

Pydantic idiom: the project runs pydantic>=2.5; this module uses the v2-native
@field_validator/@model_validator style (matching models/ssl.py).
"""
import ipaddress
from typing import List, Optional

from pydantic import BaseModel, field_validator, model_validator

# Shell/keepalived.conf metacharacters that must never appear in a value that
# reaches the generated config or a root-run agent command (mirrors
# models/agent.py:202, the Bulgu #81 convention).
_FORBIDDEN = set('$`;&|<>"\'\\\n\r\x00*?')


def _validate_iface(v: str) -> str:
    if not isinstance(v, str) or not v.strip():
        raise ValueError('network_interface must be a non-empty string')
    s = v.strip()
    if len(s) > 64:
        raise ValueError('network_interface too long (max 64 chars)')
    if any(c in _FORBIDDEN for c in s):
        raise ValueError('network_interface contains a forbidden character')
    # Linux iface names: letters, digits, and . _ - : @ (vlans/aliases/altnames)
    import re as _re
    if not _re.match(r'^[A-Za-z0-9][A-Za-z0-9._:@-]{0,63}$', s):
        raise ValueError(
            'network_interface must start alphanumeric and contain only '
            'letters, digits, and . _ - : @'
        )
    return s


def _validate_ipv4(v: str) -> str:
    if not isinstance(v, str) or not v.strip():
        raise ValueError('virtual_ip must be a non-empty string')
    s = v.strip()
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        raise ValueError(f'virtual_ip={v!r} is not a valid IP address')
    if addr.version != 4:
        raise ValueError('virtual_ip must be IPv4 — IPv6 VIPs are not supported yet')
    return s


# Issue #73: a VIP may carry further addresses in the same VRRP instance. 20 addresses in
# total keeps every advertisement within what VRRPv2 peers are known to accept.
MAX_ADDITIONAL_IPS = 19


class VIPAddressIn(BaseModel):
    address: str
    prefix_length: int = 24

    @field_validator('address')
    @classmethod
    def _addr(cls, v):
        return str(ipaddress.ip_address(_validate_ipv4(v)))

    @field_validator('prefix_length')
    @classmethod
    def _prefix(cls, v):
        if not isinstance(v, int) or not (1 <= v <= 32):
            raise ValueError('prefix_length must be an integer between 1 and 32 (IPv4)')
        return v


def _validate_additional_ips(extras: List['VIPAddressIn'], primary: Optional[str]) -> None:
    if len(extras) > MAX_ADDITIONAL_IPS:
        raise ValueError(f'a VIP may carry at most {MAX_ADDITIONAL_IPS} additional addresses')
    addrs = [e.address for e in extras]
    if len(set(addrs)) != len(addrs):
        raise ValueError('each additional address may appear only once')
    if primary is not None and str(ipaddress.ip_address(primary)) in addrs:
        raise ValueError('an additional address must differ from virtual_ip')


class VIPMemberIn(BaseModel):
    agent_id: int
    network_interface: str
    role: str = 'BACKUP'
    priority: int = 100

    @field_validator('network_interface')
    @classmethod
    def _iface(cls, v):
        return _validate_iface(v)

    @field_validator('role')
    @classmethod
    def _role(cls, v):
        u = (v or '').strip().upper()
        if u not in ('MASTER', 'BACKUP'):
            raise ValueError("role must be 'MASTER' or 'BACKUP'")
        return u

    @field_validator('priority')
    @classmethod
    def _priority(cls, v):
        if not isinstance(v, int) or not (1 <= v <= 254):
            raise ValueError('priority must be an integer between 1 and 254')
        return v


def _validate_members(members: List['VIPMemberIn']) -> List['VIPMemberIn']:
    # >=1 node: a single-node VIP is a keepalived-managed floating IP without failover
    # (valid, e.g. a one-box HAProxy that wants a stable VIP, or before a 2nd node is added).
    # Two or more nodes give actual VRRP failover. The UI flags the single-node case.
    if not members:
        raise ValueError('a VIP needs at least 1 member node')
    agent_ids = [m.agent_id for m in members]
    if len(set(agent_ids)) != len(agent_ids):
        raise ValueError('each node may appear at most once in a VIP')
    masters = [m for m in members if m.role == 'MASTER']
    if len(masters) != 1:
        raise ValueError('exactly one member must be MASTER')
    master_prio = masters[0].priority
    if any(m.role == 'BACKUP' and m.priority >= master_prio for m in members):
        raise ValueError('the MASTER must have a strictly higher priority than every BACKUP')
    return members


def _validate_auth_pass(v: Optional[str]) -> Optional[str]:
    if v is None or v == '':
        return None
    # keepalived PASS auth_pass is silently truncated to 8 chars (B-3) — reject longer
    # so MASTER/BACKUP never silently disagree.
    if not (1 <= len(v) <= 8):
        raise ValueError('auth_pass must be 1-8 characters (keepalived PASS limit)')
    if any(c in _FORBIDDEN for c in v):
        raise ValueError('auth_pass contains a forbidden character')
    # No whitespace: keepalived PASS auth_pass is a single token, and a whitespace-containing
    # secret would only partially redact in the masked config diff (review HIGH-2).
    if any(c.isspace() for c in v):
        raise ValueError('auth_pass must not contain whitespace')
    return v


class VIPCreate(BaseModel):
    name: str
    description: Optional[str] = None
    pool_id: int
    virtual_ip: str
    prefix_length: int = 24
    virtual_router_id: Optional[int] = None   # auto-allocated within the pool when omitted
    advert_int: int = 1
    auth_pass: Optional[str] = None           # plaintext on the wire; stored Fernet-encrypted
    use_unicast: bool = True
    track_haproxy: bool = True
    additional_ips: List[VIPAddressIn] = []
    members: List[VIPMemberIn]

    @field_validator('name')
    @classmethod
    def _name(cls, v):
        if not isinstance(v, str) or not v.strip():
            raise ValueError('name must be a non-empty string')
        s = v.strip()
        if len(s) > 255:
            raise ValueError('name too long (max 255 chars)')
        if any(c in _FORBIDDEN for c in s):
            raise ValueError('name contains a forbidden character')
        return s

    @field_validator('virtual_ip')
    @classmethod
    def _vip(cls, v):
        return _validate_ipv4(v)

    @field_validator('prefix_length')
    @classmethod
    def _prefix(cls, v):
        if not isinstance(v, int) or not (1 <= v <= 32):
            raise ValueError('prefix_length must be an integer between 1 and 32 (IPv4)')
        return v

    @field_validator('virtual_router_id')
    @classmethod
    def _vrid(cls, v):
        if v is None:
            return v
        if not isinstance(v, int) or not (1 <= v <= 255):
            raise ValueError('virtual_router_id must be an integer between 1 and 255')
        return v

    @field_validator('advert_int')
    @classmethod
    def _advert(cls, v):
        if not isinstance(v, int) or not (1 <= v <= 255):
            raise ValueError('advert_int must be an integer between 1 and 255 (seconds)')
        return v

    @field_validator('auth_pass')
    @classmethod
    def _auth(cls, v):
        return _validate_auth_pass(v)

    @model_validator(mode='after')
    def _members_consistent(self):
        _validate_members(self.members)
        _validate_additional_ips(self.additional_ips, self.virtual_ip)
        return self


class VIPUpdate(BaseModel):
    """All fields optional — only provided fields are changed. Any change sets the
    VIP back to last_config_status='PENDING' (router-side)."""
    name: Optional[str] = None
    description: Optional[str] = None
    virtual_ip: Optional[str] = None
    prefix_length: Optional[int] = None
    virtual_router_id: Optional[int] = None
    advert_int: Optional[int] = None
    auth_pass: Optional[str] = None           # provide only to rotate; omit to keep existing
    use_unicast: Optional[bool] = None
    track_haproxy: Optional[bool] = None
    additional_ips: Optional[List[VIPAddressIn]] = None   # None keeps them; [] clears them
    members: Optional[List[VIPMemberIn]] = None

    @field_validator('name')
    @classmethod
    def _name(cls, v):
        if v is None:
            return v
        if not v.strip():
            raise ValueError('name must be a non-empty string')
        s = v.strip()
        if len(s) > 255 or any(c in _FORBIDDEN for c in s):
            raise ValueError('name invalid (too long or forbidden character)')
        return s

    @field_validator('virtual_ip')
    @classmethod
    def _vip(cls, v):
        return _validate_ipv4(v) if v is not None else v

    @field_validator('prefix_length')
    @classmethod
    def _prefix(cls, v):
        if v is None:
            return v
        if not (1 <= v <= 32):
            raise ValueError('prefix_length must be 1-32 (IPv4)')
        return v

    @field_validator('virtual_router_id')
    @classmethod
    def _vrid(cls, v):
        if v is None:
            return v
        if not (1 <= v <= 255):
            raise ValueError('virtual_router_id must be 1-255')
        return v

    @field_validator('advert_int')
    @classmethod
    def _advert(cls, v):
        if v is None:
            return v
        if not (1 <= v <= 255):
            raise ValueError('advert_int must be 1-255 seconds')
        return v

    @field_validator('auth_pass')
    @classmethod
    def _auth(cls, v):
        return _validate_auth_pass(v)

    @model_validator(mode='after')
    def _members_consistent(self):
        if self.members is not None:
            _validate_members(self.members)
        if self.additional_ips is not None:
            _validate_additional_ips(self.additional_ips, self.virtual_ip)
        return self
