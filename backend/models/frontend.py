from pydantic import BaseModel, validator, ValidationError
from typing import List, Literal, Optional, Any
import re
import ipaddress
import os
import json


# Phase K Phase D follow-up (Bulgu #13) — shared helper that detects
# whether a HAProxy `use_backend` / `redirect` rule's condition
# references the same ACL in both positive AND negated form (e.g.
# `if acl1 !acl1`). HAProxy accepts the syntax but the predicate
# `X AND NOT X` is always false, so the rule never fires and traffic
# silently falls through to `default_backend`. Mirrors the same
# helper in `models/site_wizard.py::_detect_acl_contradiction` so
# the manual Frontend API and the wizard offer identical guarantees.
_FRONTEND_ACL_NAME_TOKEN = re.compile(r"^!?([A-Za-z_][\w.-]*)$")


def _frontend_has_acl_contradiction(directive: str) -> bool:
    """Return True if `directive` (a full use_backend / redirect
    rule string) contains both `X` and `!X` token for the same ACL
    name."""
    pos: set = set()
    neg: set = set()
    for raw in directive.split():
        if raw in ('if', 'unless'):
            continue
        m = _FRONTEND_ACL_NAME_TOKEN.match(raw)
        if not m:
            continue
        name = m.group(1)
        if raw.startswith('!'):
            neg.add(name)
        else:
            pos.add(name)
    return bool(pos & neg)


class FrontendConfig(BaseModel):
    name: str
    bind_address: str = "*"
    bind_port: int
    default_backend: Optional[str] = None
    mode: str = "http"
    ssl_enabled: bool = False
    ssl_certificate_id: Optional[int] = None  # DEPRECATED: Use ssl_certificate_ids instead (backward compatibility)
    ssl_certificate_ids: Optional[List[int]] = None  # PREFERRED: Multiple SSL certificates support
    ssl_port: Optional[int] = None  # DEPRECATED: SSL uses bind_port now (backward compatibility)
    ssl_cert_path: Optional[str] = None
    ssl_cert: Optional[str] = None
    # R18b audit fix: default to None (not "optional") so an OMITTED
    # field on PUT/POST means "don't add a verify directive" rather
    # than silently switching the bind to `verify optional`. The pre-
    # R18b default broke round-trips: an operator could clear the
    # ssl_verify Select in FrontendManagement, the cleared value got
    # dropped from the JSON payload, and Pydantic re-applied
    # "optional" — exactly the behaviour the cleared selection was
    # meant to undo. The HAProxy config generator already treats
    # NULL/empty as "omit", so None is the correct default.
    #
    # PR-2 (R11.B): tighten the type to a strict Literal aligned with
    # what the HAProxy config generator can actually emit. Pre-PR-2
    # `Optional[str]` accepted any value (e.g. legacy `'true'`,
    # `'false'`, `'1'`) which the generator then attempted to render
    # verbatim as `bind ... ssl ... verify true` — a HAProxy fatal
    # parser error. The Literal also unifies the contract with the
    # wizard's `SSLChoice.ssl_verify` so manual + wizard create paths
    # accept the same set. Empty strings from the React form are
    # coerced to None by `_coerce_ssl_verify_empty_to_none` below.
    ssl_verify: Optional[Literal["none", "optional", "required"]] = None
    
    # SSL Advanced Options (bind SSL parameters)
    ssl_alpn: Optional[str] = None  # Application-Layer Protocol Negotiation (e.g., "h2,http/1.1")
    ssl_npn: Optional[str] = None   # Next Protocol Negotiation (legacy)
    ssl_ciphers: Optional[str] = None  # Cipher suite list
    ssl_ciphersuites: Optional[str] = None  # TLS 1.3 cipher suites
    ssl_min_ver: Optional[str] = None  # Minimum TLS version (SSLv3, TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3)
    ssl_max_ver: Optional[str] = None  # Maximum TLS version
    ssl_strict_sni: Optional[bool] = False  # Strict SNI requirement
    acl_rules: Any = []
    redirect_rules: Any = []
    use_backend_rules: Any = []  # Changed from Optional[str] to Any for list support
    request_headers: Optional[str] = None
    response_headers: Optional[str] = None
    options: Optional[str] = None
    tcp_request_rules: Optional[str] = None
    timeout_client: Optional[int] = None
    timeout_http_request: Optional[int] = None
    rate_limit: Optional[int] = None
    compression: bool = False
    log_separate: bool = False
    monitor_uri: Optional[str] = None
    cluster_id: Optional[int] = None
    maxconn: Optional[int] = None
    
    # Data transformation to handle string arrays from frontend
    @validator('acl_rules', pre=True, always=True)  
    def parse_acl_rules(cls, v):
        if isinstance(v, str):
            v = v.strip()
            # Handle JSON string (e.g., "[]" or "[\"rule1\", \"rule2\"]")
            if v.startswith('[') and v.endswith(']'):
                try:
                    parsed = json.loads(v)
                    if isinstance(parsed, list):
                        return parsed
                except (json.JSONDecodeError, ValueError):
                    pass
            # Handle newline-separated string
            if v:
                return [rule.strip() for rule in v.split('\n') if rule.strip()]
        elif isinstance(v, list):
            return v
        return []
    
    @validator('redirect_rules', pre=True, always=True)  
    def parse_redirect_rules(cls, v):
        if isinstance(v, str):
            v = v.strip()
            # Handle JSON string (e.g., "[]" or "[\"rule1\", \"rule2\"]")
            if v.startswith('[') and v.endswith(']'):
                try:
                    parsed = json.loads(v)
                    if isinstance(parsed, list):
                        return parsed
                except (json.JSONDecodeError, ValueError):
                    pass
            # Handle newline-separated string
            if v:
                return [rule.strip() for rule in v.split('\n') if rule.strip()]
        elif isinstance(v, list):
            return v
        return []
    
    @validator('use_backend_rules', pre=True, always=True)
    def parse_use_backend_rules(cls, v):
        if isinstance(v, str):
            v = v.strip()
            # Handle JSON string (e.g., "[]" or "[\"rule1\", \"rule2\"]")
            if v.startswith('[') and v.endswith(']'):
                try:
                    parsed = json.loads(v)
                    if isinstance(parsed, list):
                        return parsed
                except (json.JSONDecodeError, ValueError):
                    pass
            # Handle newline-separated string
            if v:
                return [rule.strip() for rule in v.split('\n') if rule.strip()]
        elif isinstance(v, list):
            return v
        return []
    
    # CRITICAL VALIDATION RULES FOR HAPROXY
    @validator('name')
    def validate_name(cls, v):
        if not v or not v.strip():
            raise ValueError('Frontend name cannot be empty')

        # HAProxy names cannot contain spaces or special characters
        if not re.match(r'^[a-zA-Z0-9_.-]+$', v.strip()):
            raise ValueError('Frontend name can only contain letters, numbers, dot (.), underscore (_) and dash (-). Spaces and special characters are not allowed.')

        # Bulgu #69 (round-22 audit) — align the manual frontend-name
        # length cap with the wizard's `_FRONTEND_NAME_REGEX`, which
        # allows up to 64 characters
        # (`^[a-zA-Z][a-zA-Z0-9_-]{0,63}$`). Pre-fix the manual model
        # capped at 50, so a wizard-created frontend with a 51-64
        # character name (legal at CREATE) would 422 on the very
        # first manual PUT — the same Bulgu #62 "wizard accepted /
        # manual rejects" lockout pattern. HAProxy itself imposes
        # no fixed identifier length cap; 64 is a defensive ceiling
        # that mirrors typical operating-system PATH_MAX components
        # while staying generous for prefixed names like
        # `tenant-acme-app-frontend-https`.
        if len(v.strip()) > 64:
            raise ValueError('Frontend name cannot exceed 64 characters')

        return v.strip()
    
    @validator('bind_address')
    def validate_bind_address(cls, v):
        if not v or v.strip() == '*':
            return '*'  # Wildcard is valid
        
        v = v.strip()
        
        # Check if it's a valid IPv4 or IPv6 address
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            # Check if it's a hostname (basic validation)
            if re.match(r'^[a-zA-Z0-9.-]+$', v) and len(v) <= 253:
                return v
            raise ValueError(f'Invalid bind address: {v}. Must be a valid IP address, hostname, or * for wildcard.')
    
    @validator('bind_port')
    def validate_bind_port(cls, v):
        if not isinstance(v, int) or v < 1 or v > 65535:
            raise ValueError('Port must be between 1 and 65535')
        
        # Check for commonly problematic ports
        if v < 1024:
            # This is just a warning, not an error - some setups might need privileged ports
            pass
            
        return v
    
    @validator('default_backend')
    def validate_default_backend(cls, v):
        if v and not re.match(r'^[a-zA-Z0-9_.-]+$', v.strip()):
            raise ValueError('Default backend name can only contain letters, numbers, dot (.), underscore (_) and dash (-)')
        return v.strip() if v else None
    
    @validator('ssl_certificate_id')
    def validate_ssl_certificate_id(cls, v):
        if v is not None and (not isinstance(v, int) or v < 1):
            raise ValueError('SSL certificate ID must be a positive integer')
        return v

    @validator('ssl_verify', pre=True)
    def coerce_ssl_verify_empty_to_none(cls, v):
        """PR-2 (R11.B) + R11-audit-1 (FIX-1): React form Select widgets
        clear to '' (empty string) but the strict Literal would reject
        that. Coerce the empty string and the legacy sentinels written
        by older clients into None so the generator omits the directive.

        FIX-1 (R11-audit-1): the pre-fix branch only matched lowercase
        canonical values (`'none'`/`'optional'`/`'required'`). External
        API clients sometimes send uppercase (`'OPTIONAL'`, `'NONE'`)
        which the Literal would then REJECT — even though the lowercase
        equivalent is a valid value. The behaviour was inconsistent
        with the sister coercer in `models/site_wizard.py::SSLChoice`
        (mode='before') which already lowercases canonical values.
        Now `frontend.py` matches the same case-insensitive contract.
        """
        if v is None:
            return None
        if isinstance(v, str):
            stripped = v.strip().lower()
            if stripped in ("", "[]", "{}", "null"):
                return None
            if stripped in ("none", "optional", "required"):
                return stripped
        return v
    
    @validator('ssl_certificate_ids', pre=True, always=True)
    def validate_ssl_certificate_ids(cls, v, values):
        """
        Validate multiple SSL certificate IDs and handle backward compatibility
        If ssl_certificate_ids is None but ssl_certificate_id exists, convert to array
        """
        # If ssl_certificate_ids provided, validate it
        if v is not None:
            if isinstance(v, list):
                # Validate each ID
                for cert_id in v:
                    if not isinstance(cert_id, int) or cert_id < 1:
                        raise ValueError(f'SSL certificate ID must be a positive integer, got: {cert_id}')
                return v
            elif isinstance(v, int):
                # Single ID provided as int, convert to array
                if v < 1:
                    raise ValueError('SSL certificate ID must be a positive integer')
                return [v]
            else:
                raise ValueError('ssl_certificate_ids must be a list of integers or a single integer')
        
        # Backward compatibility: If ssl_certificate_ids is None but ssl_certificate_id exists, convert it
        ssl_cert_id = values.get('ssl_certificate_id')
        if ssl_cert_id is not None and ssl_cert_id > 0:
            return [ssl_cert_id]
        
        return []
    
    @validator('ssl_port')
    def validate_ssl_port(cls, v):
        """DEPRECATED: ssl_port is maintained for backward compatibility only"""
        if v is not None and (not isinstance(v, int) or v < 1 or v > 65535):
            raise ValueError('SSL port must be between 1 and 65535')
        return v
    
    @validator('ssl_cert_path')
    def validate_ssl_cert_path(cls, v):
        if not v:
            return None
        
        v = v.strip()
        
        # Basic path validation
        if not v.startswith('/'):
            raise ValueError('SSL certificate path must be an absolute path starting with /')
        
        # Check for dangerous characters
        if '..' in v or ';' in v or '|' in v:
            raise ValueError('SSL certificate path contains invalid characters')
            
        return v
    
    # Bulgu #66 (round-22 audit) — align manual FrontendConfig
    # numeric bounds with the wizard's `FrontendStep` bounds. Pre-
    # fix the manual model used much tighter ranges than what the
    # wizard accepted:
    #
    #   field                  manual (pre-fix)        wizard
    #   timeout_client         1000 ..   3_600_000     100 .. 86_400_000
    #   timeout_http_request   1000 ..     300_000     100 .. 86_400_000
    #   maxconn                   1 ..     100_000       1 ..  1_000_000
    #   rate_limit                1 ..      10_000       0 ..  1_000_000
    #
    # A frontend that the wizard accepted at create time could
    # therefore 422 on the very first PUT from the FrontendManagement
    # UI — the model rejected the legacy value before the
    # route-level grandfathering (#62) could even run. Same Bulgu
    # #62 pattern: operator changes port → blocked on an unrelated
    # field they didn't author. The new ranges mirror the wizard
    # exactly so the two entry points agree byte-for-byte. Each
    # field already passes through HAProxy's own `haproxy -c`
    # check at apply time as the ultimate ceiling.
    @validator('timeout_client')
    def validate_timeout_client(cls, v):
        if v is not None and (v < 100 or v > 86_400_000):
            raise ValueError(
                'Client timeout must be between 100ms and 86400000ms (24h)'
            )
        return v

    @validator('timeout_http_request')
    def validate_timeout_http_request(cls, v):
        if v is not None and (v < 100 or v > 86_400_000):
            raise ValueError(
                'HTTP request timeout must be between 100ms and 86400000ms (24h)'
            )
        return v

    @validator('rate_limit')
    def validate_rate_limit(cls, v):
        if v is not None and (v < 0 or v > 1_000_000):
            raise ValueError(
                'Rate limit must be between 0 and 1000000 requests (0 = disabled)'
            )
        return v

    @validator('maxconn')
    def validate_maxconn(cls, v):
        if v is not None and (v < 1 or v > 1_000_000):
            raise ValueError(
                'Max connections must be between 1 and 1000000'
            )
        return v
    
    @validator('ssl_min_ver', 'ssl_max_ver')
    def validate_tls_version(cls, v):
        if v is not None:
            valid_versions = ['SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']
            if v not in valid_versions:
                raise ValueError(f'Invalid TLS version: {v}. Must be one of: {", ".join(valid_versions)}')
        return v
    
    @validator('ssl_alpn')
    def validate_alpn(cls, v):
        # Bulgu #65 (round-22 audit) — pre-fix this validator
        # rejected anything not in a fixed whitelist of HTTP / SPDY
        # tokens. RFC 7301 explicitly states ALPN identifiers are
        # 1-255 octet opaque tokens; HAProxy passes them through
        # to OpenSSL without enforcing a list. Operators with
        # legacy frontends carrying non-HTTP ALPN values such as
        # `postgres`, `imap`, `smtp`, `acme-tls/1`, or vendor-
        # specific identifiers were locked out of editing any
        # unrelated field (port / max conn / default backend) —
        # the FrontendManagement UI re-sends the existing
        # `ssl_alpn` value verbatim and the model 422-ed the PUT.
        #
        # The validator now accepts any token matching the
        # RFC-7301-compatible character class (printable ASCII
        # minus separators, length 1-255). The helpful "use h2
        # not http/2" hint is retained because that's a real
        # operator typo we want to catch.
        if v is None or not v.strip():
            return v
        protocols = [p.strip() for p in v.split(',')]
        token_re = re.compile(r"^[A-Za-z0-9][A-Za-z0-9./_+-]{0,254}$")
        common_typos = {'http/2', 'http2', 'http-2'}
        for proto in protocols:
            if not proto:
                continue
            if proto.lower() in common_typos:
                raise ValueError(
                    f'Invalid ALPN protocol: {proto}. '
                    f'For HTTP/2, use "h2" (not "{proto}").'
                )
            if not token_re.match(proto):
                raise ValueError(
                    f'Invalid ALPN protocol token: "{proto}". '
                    f'Per RFC 7301 each comma-separated entry '
                    f'must be 1-255 characters of letters / digits '
                    f'/ "." / "/" / "_" / "+" / "-" and must start '
                    f'with a letter or digit.'
                )
        return v

    @validator('ssl_npn')
    def validate_npn(cls, v):
        # Bulgu #65 (round-22 audit) — same relaxation as ssl_alpn.
        # NPN is the deprecated predecessor of ALPN (RFC 7301
        # obsoletes it); HAProxy still accepts any opaque token.
        if v is None or not v.strip():
            return v
        protocols = [p.strip() for p in v.split(',')]
        token_re = re.compile(r"^[A-Za-z0-9][A-Za-z0-9./_+-]{0,254}$")
        for proto in protocols:
            if proto and not token_re.match(proto):
                raise ValueError(
                    f'Invalid NPN protocol token: "{proto}". '
                    f'Use 1-255 characters of letters / digits / '
                    f'"." / "/" / "_" / "+" / "-" starting with a '
                    f'letter or digit.'
                )
        return v
        
    @validator('acl_rules')
    def validate_acl_rules(cls, v):
        if not v:
            return []

        validated_rules = []
        for rule in v:
            rule = rule.strip()
            if not rule:
                continue

            # Basic ACL syntax validation
            if not re.match(r'^[a-zA-Z0-9_.-]+\s+', rule):
                raise ValueError(f'Invalid ACL rule syntax: "{rule}". Must start with ACL name followed by condition.')

            # Bulgu #64 (round-22 audit) — the previous danger-pattern
            # list was `['system', 'exec', 'eval', '$(', '`']` and
            # rejected the substring anywhere in the rule. That broke
            # legitimate ACL names like `acl is_system hdr(host) -i
            # internal.example.com`, `acl my_subsystem path_beg /sub`,
            # `acl block_executable path_end .exe`, etc. HAProxy has
            # no `system`/`exec`/`eval` directive — those words carry
            # no runtime semantics inside a rendered config, so the
            # check was over-cautious and a false-positive trap on
            # the UPDATE path (legacy rows could not be edited).
            # `$(` and backtick stay because they're shell-substitution
            # markers that don't appear in any legitimate HAProxy
            # directive shape.
            if any(dangerous in rule.lower() for dangerous in ['$(', '`']):
                raise ValueError(f'ACL rule contains potentially dangerous content: "{rule}"')

            # Phase K Phase D follow-up (Bulgu #12 round 3) — reject
            # the HAProxy `-f <file>` pattern-file flag here too so the
            # manual Frontend API mirrors the wizard's parity rule.
            # HAProxy OpenManager does not provision pattern files
            # onto the HAProxy node filesystem, so any `-f /path/...`
            # reference will fail HAProxy's `-c` parse at apply time
            # with "failed to open pattern file". Reject up-front so
            # operators get the same actionable error from both the
            # manual page and the wizard.
            if re.search(r"(^|\s)-f(\s|$)", rule):
                raise ValueError(
                    f'ACL rule "{rule}" uses the HAProxy `-f <file>` '
                    "pattern-file flag, which is not supported in "
                    "HAProxy OpenManager: the product does not "
                    "provision pattern files onto the HAProxy node "
                    "filesystem, so the reference would fail at "
                    "reload time. Use inline values instead "
                    "(e.g. `src 10.0.0.0/24` rather than "
                    "`src -f /etc/haproxy/admins.lst`)."
                )

            validated_rules.append(rule)

        return validated_rules
    
    @validator('redirect_rules')
    def validate_redirect_rules_syntax(cls, v):
        if not v:
            return []

        # Bulgu #62 (round-22 audit) — defensively tolerate dict-shaped
        # redirect rules (the wizard's `_build_redirect_rules` stores
        # the auto-generated HTTP→HTTPS redirect as
        # `{"type": "scheme", "scheme": "https", "code": 301,
        # "condition": "…"}`). Pre-fix this loop called `rule.strip()`
        # unconditionally and crashed with AttributeError on dicts,
        # 422-ing every wizard-created frontend the operator tried to
        # edit from the FrontendManagement UI. Now the loop accepts
        # both shapes: strings are syntax-validated, dicts are passed
        # through (their structure was already validated by the
        # wizard's own `_validate_redirect_rules` field validator
        # and is round-tripped through HAProxy by the renderer's
        # `_format_redirect_rule`).
        validated_rules = []
        for rule in v:
            if isinstance(rule, dict):
                validated_rules.append(rule)
                continue
            if not isinstance(rule, str):
                continue
            rule = rule.strip()
            if not rule:
                continue

            # Basic redirect syntax validation
            valid_redirects = ['location', 'prefix', 'scheme']
            if not any(rule.startswith(redirect_type) for redirect_type in valid_redirects):
                raise ValueError(f'Invalid redirect rule: "{rule}". Must start with: location, prefix, or scheme.')

            # Phase K Phase D follow-up (Bulgu #12 round 3) —
            # mirror the wizard's `-f <file>` guard here. The
            # `X !X` contradiction check used to live alongside
            # this guard, but Bulgu #62 (round-22 audit) moved
            # it into the route handler so updates can grandfather
            # legacy rules created before the contradiction guard
            # landed. See `routers/frontend.py::_collect_routing_rule_contradictions`.
            if re.search(r"(^|\s)-f(\s|$)", rule):
                raise ValueError(
                    f'Redirect rule "{rule}" uses the HAProxy `-f <file>` '
                    "pattern-file flag, which is not supported in "
                    "HAProxy OpenManager: the product does not provision "
                    "pattern files onto the HAProxy node filesystem."
                )

            validated_rules.append(rule)

        return validated_rules

    @validator('use_backend_rules')
    def validate_use_backend_rules_syntax(cls, v):
        """Phase K Phase D follow-up (Bulgu #12 round 3) — manual
        Frontend API parity guard: reject `-f <file>` references
        and dangerous shell patterns.

        Bulgu #62 (round-22 audit) — the `X !X` contradiction check
        previously lived here but moved into the route handler so
        the UPDATE path can grandfather legacy rules created before
        the contradiction guard landed (e.g. wizard-created frontends
        from a pre-Bulgu-#13 build). The handler-level enforcement
        keeps POST strict (hard reject) and lets PUT pass through
        unchanged grandfathered rules with a soft warning.
        """
        if not v:
            return []
        validated_rules = []
        for rule in v:
            if not isinstance(rule, str):
                continue
            rule = rule.strip()
            if not rule:
                continue
            # Bulgu #64 (round-22 audit) — same relaxation as
            # `validate_acl_rules`: drop the 'system'/'exec'/'eval'
            # substring tripwires (false-positive on legitimate names
            # like `is_system`, `subsystem`, `executable`) and keep
            # only `$(` and backtick (shell-substitution markers
            # that have no legitimate place in a HAProxy directive).
            if any(dangerous in rule.lower() for dangerous in ['$(', '`']):
                raise ValueError(
                    f'use_backend rule contains potentially dangerous '
                    f'content: "{rule}"'
                )
            if re.search(r"(^|\s)-f(\s|$)", rule):
                raise ValueError(
                    f'use_backend rule "{rule}" uses the HAProxy '
                    "`-f <file>` pattern-file flag, which is not "
                    "supported in HAProxy OpenManager: the product "
                    "does not provision pattern files onto the HAProxy "
                    "node filesystem."
                )
            validated_rules.append(rule)
        return validated_rules