from fastapi import APIRouter, HTTPException, Request, Header
from typing import Any, List, Optional, Tuple
import logging
import re
import time
import hashlib
import json

from models import FrontendConfig
from models.frontend import _frontend_has_acl_contradiction
from database.connection import get_database_connection, close_database_connection
from utils.activity_log import log_user_activity
from services.haproxy_config import generate_haproxy_config_for_cluster

router = APIRouter(prefix="/api/frontends", tags=["frontends"])
logger = logging.getLogger(__name__)


# Bulgu #62 (round-22 audit) — handler-level enforcement of the
# `X !X` self-contradiction guard. Pre-fix this check lived inside
# the `FrontendConfig` Pydantic validators (Bulgu #13) and ran on
# EVERY operation — including UPDATE. Frontends created before the
# guard landed could carry stale contradictory rules (or were
# inserted via a pre-Bulgu-#13 wizard build). After the guard
# landed those frontends became unupdate-able from the
# FrontendManagement UI: the operator opened the Edit modal to
# change an unrelated field (port, max conn, default_backend), the
# UI re-sent the full rule list verbatim, the model validator hit
# the legacy `X !X` rule, and Save 400-ed with a contradiction
# error the operator had not authored.
#
# The handler-level helpers below restore the strict POST behaviour
# and let PUT GRANDFATHER rules that are unchanged from the existing
# DB row: new or modified contradictions still hard-reject (400),
# stale ones only emit a warning so the operator can fix at their
# own pace without being locked out of unrelated edits.


_NORMALISE_RULE_PREFIX_RE = re.compile(
    r"^\s*(?:use_backend|redirect)\s+", re.IGNORECASE,
)
_NORMALISE_RULE_WS_RE = re.compile(r"\s+")


def _normalize_rule_string(s: str) -> str:
    """Bulgu #62 follow-up (round-22 hot-fix) — collapse whitespace
    and strip the `use_backend ` / `redirect ` directive prefix so
    a rule that round-trips through the FE's ACLRuleBuilder (which
    parses the rule into a structured object and re-serialises
    without the prefix) signs to the same value as the version
    still sitting in the DB.

    Without this normalisation the grandfathering check on UPDATE
    silently fails: every PUT looks like a NEW rule even when the
    operator hasn't touched the routing section. Mirrors the JS
    `normalizeRuleString` helper in
    `frontend/src/components/FrontendManagement.js`.
    """
    if not isinstance(s, str):
        return ""
    stripped = _NORMALISE_RULE_PREFIX_RE.sub("", s, count=1)
    return _NORMALISE_RULE_WS_RE.sub(" ", stripped).strip()


def _rule_to_signature(rule: Any) -> Optional[str]:
    """Reduce a redirect/use_backend/acl rule entry to a stable string
    key used for grandfathered-vs-new comparison.

    `acl_rules` and `use_backend_rules` are always strings. The
    wizard's auto-generated HTTP→HTTPS redirect lives in
    `redirect_rules` as a dict (`{type, scheme, code, condition,
    ...}`). For dicts we use `json.dumps(..., sort_keys=True)` so
    semantically equal dicts collapse to the same key regardless of
    Python's insertion-order.

    Strings are normalised via `_normalize_rule_string` so a rule
    that round-trips through the FE (where the ACLRuleBuilder
    strips the `use_backend ` / `redirect ` prefix on serialise)
    still matches the version stored in the DB.
    """
    if isinstance(rule, str):
        normalised = _normalize_rule_string(rule)
        return f"str::{normalised}" if normalised else None
    if isinstance(rule, dict):
        try:
            return "dict::" + json.dumps(rule, sort_keys=True, default=str)
        except (TypeError, ValueError):
            return None
    return None


def _decode_db_rules_jsonb(raw) -> List[Any]:
    """JSONB column → Python list (handles str/list/None)."""
    if not raw:
        return []
    if isinstance(raw, str):
        try:
            decoded = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return []
    else:
        decoded = raw
    return decoded if isinstance(decoded, list) else []


def _rule_contradiction_text(rule: Any) -> Optional[str]:
    """Return the string used to evaluate the `X !X` contradiction
    for a given rule entry. Strings are checked directly; for
    dict-shaped redirect rules the `condition` / `if` field is the
    relevant text. Returns None for entries that have no
    contradiction-relevant payload."""
    if isinstance(rule, str):
        return rule
    if isinstance(rule, dict):
        cond = rule.get("condition") or rule.get("if")
        return cond if isinstance(cond, str) else None
    return None


def _collect_routing_rule_contradictions(
    rules: List[Any], origin_label: str,
) -> List[Tuple[str, Any]]:
    """Return `[(origin_label, offending_rule), ...]` for every entry
    in `rules` whose contradiction text triggers
    `_frontend_has_acl_contradiction`."""
    out: List[Tuple[str, Any]] = []
    for r in rules or []:
        txt = _rule_contradiction_text(r)
        if txt and _frontend_has_acl_contradiction(txt):
            out.append((origin_label, r))
    return out


def _format_contradiction_error(
    conflicts: List[Tuple[str, Any]],
) -> str:
    """Build the human-facing 400 message listing every conflicting
    rule. Used by both the POST handler (strict) and the PUT
    handler (only for new/modified rules)."""
    lines = [
        "One or more routing / redirect rules contain the same "
        "ACL in both positive AND negated form (e.g. "
        "`if acl1 !acl1`). HAProxy accepts the syntax but "
        "`X AND NOT X` is always false, so the rule never fires "
        "and traffic silently falls through to `default_backend`. "
        "Remove one of the two tokens before saving."
    ]
    for label, rule in conflicts[:10]:
        snippet = rule if isinstance(rule, str) else _rule_to_signature(rule)
        if snippet and len(snippet) > 160:
            snippet = snippet[:157] + "..."
        lines.append(f"  - {label}: {snippet}")
    if len(conflicts) > 10:
        lines.append(f"  (+{len(conflicts) - 10} more)")
    return "\n".join(lines)


def _enforce_routing_rule_contradictions(
    frontend: FrontendConfig,
    *,
    grandfathered_signatures: Optional[set] = None,
) -> List[str]:
    """Walk `use_backend_rules` and `redirect_rules` on the payload,
    collect any `X !X` self-contradictions, and:

    * raise HTTPException(400) when the conflicting rule is NEW or
      MODIFIED relative to `grandfathered_signatures` (or whenever
      the caller passes `grandfathered_signatures=None`, meaning
      strict mode for POST), OR
    * return them as a list of warning strings when the rule
      already existed verbatim in the DB row (UPDATE
      grandfathering).

    `grandfathered_signatures` is the union of `_rule_to_signature`
    outputs for the existing DB row's `use_backend_rules` and
    `redirect_rules` columns. Passing `None` means "treat every
    contradiction as new" (POST / strict path).
    """
    use_be = frontend.use_backend_rules or []
    redirect = frontend.redirect_rules or []
    conflicts = (
        _collect_routing_rule_contradictions(use_be, "use_backend_rules")
        + _collect_routing_rule_contradictions(redirect, "redirect_rules")
    )
    if not conflicts:
        return []

    if grandfathered_signatures is None:
        # POST / strict path — every contradiction blocks.
        raise HTTPException(
            status_code=400,
            detail=_format_contradiction_error(conflicts),
        )

    # PUT / grandfathered path — split into NEW vs UNCHANGED.
    blocking: List[Tuple[str, Any]] = []
    warnings: List[str] = []
    for label, rule in conflicts:
        sig = _rule_to_signature(rule)
        if sig and sig in grandfathered_signatures:
            warnings.append(
                f"Grandfathered {label} entry contains a "
                f"self-contradictory `X !X` condition that pre-dated "
                f"this validation. The rule never fires; fix it at "
                f"your convenience. (rule: "
                f"{rule if isinstance(rule, str) else sig[:160]})"
            )
        else:
            blocking.append((label, rule))
    if blocking:
        raise HTTPException(
            status_code=400,
            detail=_format_contradiction_error(blocking),
        )
    return warnings

def filter_httpchk_from_options(options: Optional[str]) -> Optional[str]:
    """
    Filter out 'option httpchk' directives from options field.
    These are not applicable to frontends (health checks are for backends).
    
    Args:
        options: Multi-line string containing HAProxy option directives
        
    Returns:
        Filtered options string without 'option httpchk' lines, or None if empty
    """
    if not options:
        return options
    
    # Split by newline, filter out httpchk lines, rejoin
    filtered_lines = [
        line for line in options.split('\n')
        if line.strip() and 'httpchk' not in line.lower()
    ]
    
    # Return None if no lines remain after filtering
    if not filtered_lines:
        return None
        
    return '\n'.join(filtered_lines)


async def validate_user_cluster_access(user_id: int, cluster_id: int, conn):
    """Validate that user has access to the specified cluster"""
    # Check if cluster exists
    cluster_exists = await conn.fetchval("""
        SELECT id FROM haproxy_clusters WHERE id = $1
    """, cluster_id)
    
    if not cluster_exists:
        raise HTTPException(
            status_code=404, 
            detail="Cluster not found"
        )
    
    # Check if user is admin - admins can access everything
    is_admin = await conn.fetchval("""
        SELECT is_admin FROM users WHERE id = $1
    """, user_id)
    
    if is_admin:
        logger.info(f"Admin user {user_id} granted access to cluster {cluster_id}")
        return True
    
    # Check if user_pool_access table exists (for backward compatibility)
    table_exists = await conn.fetchval("""
        SELECT EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_name = 'user_pool_access'
        )
    """)
    
    if not table_exists:
        # Fallback to basic validation if table doesn't exist yet
        logger.warning("user_pool_access table not found, using basic cluster validation")
        return True
    
    # Check if expires_at column exists (for backward compatibility)
    expires_at_exists = await conn.fetchval("""
        SELECT EXISTS (
            SELECT 1 FROM information_schema.columns 
            WHERE table_name = 'user_pool_access' AND column_name = 'expires_at'
        )
    """)
    
    # Regular users need explicit pool access
    if expires_at_exists:
        user_access = await conn.fetchrow("""
            SELECT upa.access_level, hc.id, hc.name
            FROM haproxy_clusters hc
            JOIN haproxy_cluster_pools hcp ON hc.pool_id = hcp.id
            JOIN user_pool_access upa ON hcp.id = upa.pool_id
            WHERE upa.user_id = $1 AND hc.id = $2 AND upa.is_active = TRUE
            AND (upa.expires_at IS NULL OR upa.expires_at > CURRENT_TIMESTAMP)
        """, user_id, cluster_id)
    else:
        # Fallback query without expires_at column
        user_access = await conn.fetchrow("""
            SELECT upa.access_level, hc.id, hc.name
            FROM haproxy_clusters hc
            JOIN haproxy_cluster_pools hcp ON hc.pool_id = hcp.id
            JOIN user_pool_access upa ON hcp.id = upa.pool_id
            WHERE upa.user_id = $1 AND hc.id = $2 AND upa.is_active = TRUE
        """, user_id, cluster_id)
    
    if not user_access:
        raise HTTPException(
            status_code=403, 
            detail="You don't have access to this cluster. Please contact your administrator."
        )
    
    logger.info(f"User {user_id} granted {user_access['access_level']} access to cluster {cluster_id}")
    return True

@router.get("", summary="Get All Frontends", response_description="List of frontend configurations")
async def get_frontends(
    cluster_id: Optional[int] = None,
    include_inactive: bool = False,
    authorization: str = Header(None),
):
    """
    # Get All Frontends
    
    Retrieve all frontend configurations (HAProxy listeners). Frontends define how HAProxy receives incoming traffic.
    
    ## Query Parameters
    - **cluster_id** (optional): Filter frontends by cluster ID
    
    ## Example Request
    ```bash
    curl -X GET "{BASE_URL}/api/frontends?cluster_id=1" \\
      -H "Authorization: Bearer eyJhbGciOiJIUz..."
    ```
    
    ## Example Response
    ```json
    [
      {
        "id": 1,
        "name": "web-frontend",
        "bind_address": "*",
        "bind_port": 443,
        "mode": "http",
        "cluster_id": 1,
        "default_backend": "web-backend",
        "ssl_enabled": true,
        "ssl_certificate_id": 1,
        "https_redirect": true,
        "created_at": "2024-01-15T10:30:00Z"
      }
    ]
    ```
    
    ## Frontend Purpose
    - Define listen addresses and ports
    - SSL/TLS termination
    - Request routing to backends
    - HTTP to HTTPS redirection
    """
    try:
        # R18c audit fix (round 6 #1 — KRITIK info leak): require
        # an authenticated caller. Pre-fix the endpoint accepted
        # anonymous GETs and returned the FULL listener layout
        # (bind addresses, SSL cert IDs, ACL rules, redirect rules,
        # use_backend rules) for every cluster. With wizard-created
        # rows now in the table, any unauthenticated reader could
        # enumerate the platform's complete frontend inventory.
        # The frontend already attaches the JWT via axios defaults,
        # so requiring auth is non-breaking; reverse-proxy
        # deployments that previously relied on perimeter auth
        # gain defense in depth.
        from auth_middleware import get_current_user_from_token
        await get_current_user_from_token(authorization)
        conn = await get_database_connection()
        
        if cluster_id:
            # Filter by cluster_id when provided (only active frontends)
            # Debug: Check if ssl_certificate_id column exists
            ssl_cert_id_exists = await conn.fetchval("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'frontends' AND column_name = 'ssl_certificate_id'
                )
            """)
            logger.info(f"FRONTEND DEBUG: ssl_certificate_id column exists: {ssl_cert_id_exists}")
            
            if ssl_cert_id_exists:
                frontends = await conn.fetch("""
                    SELECT id, name, bind_address, bind_port, default_backend, mode, 
                           ssl_enabled, ssl_certificate_id, ssl_certificate_ids, ssl_port, ssl_cert_path, ssl_cert, ssl_verify,
                           ssl_alpn, ssl_npn, ssl_ciphers, ssl_ciphersuites, ssl_min_ver, ssl_max_ver, ssl_strict_sni,
                           acl_rules, redirect_rules, use_backend_rules,
                           request_headers, response_headers, options, tcp_request_rules,
                           timeout_client, timeout_http_request,
                           rate_limit, compression, log_separate, monitor_uri,
                           maxconn, is_active, created_at, updated_at, cluster_id, last_config_status
                    FROM frontends 
                    WHERE (cluster_id = $1 OR cluster_id IS NULL)
                    ORDER BY name
                """, cluster_id)
            else:
                # Fallback query without ssl_certificate_id
                logger.warning("FRONTEND DEBUG: ssl_certificate_id column missing, using fallback query")
                frontends = await conn.fetch("""
                    SELECT id, name, bind_address, bind_port, default_backend, mode, 
                           ssl_enabled, ssl_cert_path, ssl_cert, ssl_verify,
                           ssl_alpn, ssl_npn, ssl_ciphers, ssl_ciphersuites, ssl_min_ver, ssl_max_ver, ssl_strict_sni,
                           acl_rules, redirect_rules, use_backend_rules,
                           request_headers, response_headers, options, tcp_request_rules,
                           timeout_client, timeout_http_request,
                           rate_limit, compression, log_separate, monitor_uri,
                           maxconn, is_active, created_at, updated_at, cluster_id, last_config_status
                    FROM frontends 
                    WHERE (cluster_id = $1 OR cluster_id IS NULL)
                    ORDER BY name
                """, cluster_id)
        else:
            # Debug: Check if ssl_certificate_id column exists for global query
            ssl_cert_id_exists = await conn.fetchval("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'frontends' AND column_name = 'ssl_certificate_id'
                )
            """)
            logger.info(f"FRONTEND DEBUG (Global): ssl_certificate_id column exists: {ssl_cert_id_exists}")
            
            if ssl_cert_id_exists:
                # include_inactive parameter controls deleted entity visibility
                # Default FALSE: Only show active frontends (prevents phantom deleted entities)
                # Set TRUE: Apply Management shows all including deleted for pending change visibility
                # This matches backend GET behavior for consistency
                if include_inactive:
                    frontends = await conn.fetch("""
                        SELECT id, name, bind_address, bind_port, default_backend, mode,
                               ssl_enabled, ssl_certificate_id, ssl_certificate_ids, ssl_port, ssl_cert_path, ssl_cert, ssl_verify,
                               ssl_alpn, ssl_npn, ssl_ciphers, ssl_ciphersuites, ssl_min_ver, ssl_max_ver, ssl_strict_sni,
                               acl_rules, redirect_rules, use_backend_rules,
                               request_headers, response_headers, options, tcp_request_rules,
                               timeout_client, timeout_http_request,
                               rate_limit, compression, log_separate, monitor_uri,
                               maxconn, is_active, created_at, updated_at, cluster_id, last_config_status
                        FROM frontends ORDER BY name
                    """)
                else:
                    frontends = await conn.fetch("""
                        SELECT id, name, bind_address, bind_port, default_backend, mode,
                               ssl_enabled, ssl_certificate_id, ssl_certificate_ids, ssl_port, ssl_cert_path, ssl_cert, ssl_verify,
                               ssl_alpn, ssl_npn, ssl_ciphers, ssl_ciphersuites, ssl_min_ver, ssl_max_ver, ssl_strict_sni,
                               acl_rules, redirect_rules, use_backend_rules,
                               request_headers, response_headers, options, tcp_request_rules,
                               timeout_client, timeout_http_request,
                               rate_limit, compression, log_separate, monitor_uri,
                               maxconn, is_active, created_at, updated_at, cluster_id, last_config_status
                        FROM frontends WHERE is_active = TRUE ORDER BY name
                    """)
            else:
                # Fallback query without ssl_certificate_id
                logger.warning("FRONTEND DEBUG (Global): ssl_certificate_id column missing, using fallback query")
                if include_inactive:
                    frontends = await conn.fetch("""
                        SELECT id, name, bind_address, bind_port, default_backend, mode,
                               ssl_enabled, ssl_cert_path, ssl_cert, ssl_verify,
                               ssl_alpn, ssl_npn, ssl_ciphers, ssl_ciphersuites, ssl_min_ver, ssl_max_ver, ssl_strict_sni,
                               acl_rules, redirect_rules, use_backend_rules,
                               request_headers, response_headers, options, tcp_request_rules,
                               timeout_client, timeout_http_request,
                               rate_limit, compression, log_separate, monitor_uri,
                               maxconn, is_active, created_at, updated_at, cluster_id, last_config_status
                        FROM frontends ORDER BY name
                    """)
                else:
                    frontends = await conn.fetch("""
                        SELECT id, name, bind_address, bind_port, default_backend, mode,
                               ssl_enabled, ssl_cert_path, ssl_cert, ssl_verify,
                               ssl_alpn, ssl_npn, ssl_ciphers, ssl_ciphersuites, ssl_min_ver, ssl_max_ver, ssl_strict_sni,
                               acl_rules, redirect_rules, use_backend_rules,
                               request_headers, response_headers, options, tcp_request_rules,
                               timeout_client, timeout_http_request,
                               rate_limit, compression, log_separate, monitor_uri,
                               maxconn, is_active, created_at, updated_at, cluster_id, last_config_status
                        FROM frontends WHERE is_active = TRUE ORDER BY name
                    """)
        
        # Check for pending configurations by cluster
        pending_frontend_ids = set()
        if frontends:
            cluster_ids = [f["cluster_id"] for f in frontends if f["cluster_id"]]
            if cluster_ids:
                try:
                    # Check for frontend-specific pending changes using entity ID in version name
                    # Exclude WAF changes as they don't require Frontend page Apply
                    # CRITICAL: Validate frontend actually belongs to version's cluster (prevent orphan versions)
                    pending_configs = await conn.fetch("""
                        SELECT DISTINCT 
                            CASE 
                                WHEN version_name ~ 'frontend-[0-9]+-' THEN 
                                    SUBSTRING(version_name FROM 'frontend-([0-9]+)-')::int
                                ELSE NULL
                            END as frontend_id,
                            cluster_id as version_cluster_id
                        FROM config_versions 
                        WHERE cluster_id = ANY($1) AND status = 'PENDING'
                        AND version_name ~ 'frontend-[0-9]+-'
                        AND version_name NOT LIKE 'waf-%'
                    """, cluster_ids)
                    
                    # Validate each frontend_id belongs to version's cluster (orphan detection)
                    for pc in pending_configs:
                        if pc["frontend_id"]:
                            frontend_cluster = await conn.fetchval("""
                                SELECT cluster_id FROM frontends WHERE id = $1
                            """, pc["frontend_id"])
                            
                            # Only add if frontend exists in the version's cluster
                            if frontend_cluster == pc["version_cluster_id"]:
                                pending_frontend_ids.add(pc["frontend_id"])
                            else:
                                logger.warning(f"ORPHAN VERSION: frontend-{pc['frontend_id']}-* in cluster {pc['version_cluster_id']} references frontend from cluster {frontend_cluster}")
                except Exception as e:
                    logger.warning(f"FRONTEND API: Failed to check pending configs: {e}")
                    pending_frontend_ids = set()
        
        await close_database_connection(conn)
        
        # Debug: Log SSL-enabled frontends before returning
        ssl_frontends = [f for f in frontends if f.get("ssl_enabled")]
        if ssl_frontends:
            logger.info(f"FRONTEND API DEBUG: Returning {len(ssl_frontends)} SSL-enabled frontends:")
            for f in ssl_frontends:
                logger.info(f"SSL FRONTEND: {f['name']} - ssl_enabled: {f.get('ssl_enabled')}, ssl_certificate_id: {f.get('ssl_certificate_id')}, ssl_certificate_ids: {f.get('ssl_certificate_ids')}, ssl_port: {f.get('ssl_port')}")
        
        # CRITICAL: Parse JSONB fields that may come as strings
        def parse_jsonb_field(value, default=[]):
            """Parse JSONB field that may be string or already parsed"""
            if value is None:
                return default
            if isinstance(value, list):
                return value
            if isinstance(value, str):
                try:
                    import json as json_lib
                    return json_lib.loads(value)
                except:
                    return default
            return default
        
        return {
            "frontends": [
                {
                    "id": f["id"],
                    "name": f["name"],
                    "bind_address": f["bind_address"],
                    "bind_port": f["bind_port"],
                    "default_backend": f["default_backend"],
                    "mode": f["mode"],
                    "ssl_enabled": f.get("ssl_enabled", False),
                    "ssl_certificate_id": f.get("ssl_certificate_id"),
                    "ssl_certificate_ids": parse_jsonb_field(f.get("ssl_certificate_ids"), []),
                    "ssl_port": f.get("ssl_port"),
                    "ssl_cert_path": f.get("ssl_cert_path"),
                    "ssl_cert": f.get("ssl_cert"),
                    # R18b audit fix: return ssl_verify verbatim (None
                    # stays None). Pre-fix this masked NULL → "optional",
                    # which the FrontendManagement edit form then sent
                    # back on save and SILENTLY persisted as "optional"
                    # — flipping operator intent ("verify clause omitted")
                    # to ("verify optional"). The HAProxy config
                    # generator already guards on a sentinel-empty
                    # value before appending the verify directive, so
                    # NULL → omitted is the correct round-trip.
                    "ssl_verify": f.get("ssl_verify"),
                    # CRITICAL FIX: Include SSL advanced options (bind SSL parameters)
                    "ssl_alpn": f.get("ssl_alpn"),
                    "ssl_npn": f.get("ssl_npn"),
                    "ssl_ciphers": f.get("ssl_ciphers"),
                    "ssl_ciphersuites": f.get("ssl_ciphersuites"),
                    "ssl_min_ver": f.get("ssl_min_ver"),
                    "ssl_max_ver": f.get("ssl_max_ver"),
                    "ssl_strict_sni": f.get("ssl_strict_sni", False),
                    "acl_rules": parse_jsonb_field(f.get("acl_rules"), []),
                    "redirect_rules": parse_jsonb_field(f.get("redirect_rules"), []),
                    "use_backend_rules": parse_jsonb_field(f.get("use_backend_rules"), []),
                    "request_headers": f.get("request_headers"),
                    "response_headers": f.get("response_headers"),
                    "options": f.get("options"),
                    "tcp_request_rules": f.get("tcp_request_rules"),
                    "timeout_client": f.get("timeout_client"),
                    "timeout_http_request": f.get("timeout_http_request"),
                    "rate_limit": f.get("rate_limit"),
                    "compression": f.get("compression", False),
                    "log_separate": f.get("log_separate", False),
                    "monitor_uri": f.get("monitor_uri"),
                    "maxconn": f.get("maxconn"),
                    "is_active": f["is_active"],
                    "last_config_status": f.get("last_config_status") or "APPLIED",
                    "created_at": f["created_at"].isoformat().replace('+00:00', 'Z') if f["created_at"] else None,
                    "updated_at": f["updated_at"].isoformat().replace('+00:00', 'Z') if f["updated_at"] else None,
                    "cluster_id": f.get("cluster_id"),
                    "has_pending_config": (
                        # CRITICAL FIX: Same as backend.py logic for consistency
                        # Problem: Frontend with is_active=FALSE and last_config_status='APPLIED' was showing as pending
                        # Solution: Inactive frontend is only pending if last_config_status is PENDING, not APPLIED
                        (
                            (f["id"] in pending_frontend_ids) or 
                            (f.get("last_config_status") == "PENDING") or 
                            (not f.get("is_active", True) and f.get("last_config_status") == "PENDING")
                        ) and 
                        (f.get("last_config_status") != "REJECTED") and 
                        not (not f.get("is_active", True) and f.get("last_config_status") == "APPLIED")
                    )
                } for f in frontends
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("")
async def create_frontend(frontend: FrontendConfig, request: Request, authorization: str = Header(None)):
    """Create new frontend configuration with cluster synchronization"""
    try:
        # Get current user for activity logging
        from auth_middleware import get_current_user_from_token, check_user_permission
        current_user = await get_current_user_from_token(authorization)
        
        # Check permission for frontend create
        has_permission = await check_user_permission(current_user["id"], "frontends", "create")
        if not has_permission:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions: frontends.create required"
            )
        
        conn = await get_database_connection()

        # Bulgu #62 (round-22 audit) — strict X !X reject on CREATE.
        # No existing row to grandfather against; every contradiction
        # blocks. Mirrors the wizard's `_detect_acl_contradiction`
        # gate (Bulgu #13) so both create paths reject the same
        # shape.
        _enforce_routing_rule_contradictions(frontend, grandfathered_signatures=None)

        # Validate cluster access for multi-cluster security
        if frontend.cluster_id:
            await validate_user_cluster_access(current_user['id'], frontend.cluster_id, conn)
        
        # CRITICAL: Check for reserved names that conflict with common HAProxy listen sections
        # Agent preserves existing listen blocks (e.g., 'listen stats') from local config
        # Creating frontends with these names causes "proxy has same name" errors
        reserved_names = {'stats', 'haproxy-stats', 'haproxy_stats', 'monitoring', 'admin', 'health', 'status'}
        if frontend.name.lower() in reserved_names:
            await close_database_connection(conn)
            raise HTTPException(
                status_code=400, 
                detail=f"Frontend name '{frontend.name}' is reserved. It conflicts with common HAProxy "
                       f"listen sections (e.g., 'listen stats'). Please choose a different name."
            )
        
        # DYNAMIC COLLISION CHECK: Check against agents' preserved listen blocks
        # Agents report their local listen blocks via config-sync, we check for conflicts here
        # NOTE: Wrapped in try-except for backwards compatibility (column may not exist before migration)
        if frontend.cluster_id:
            try:
                collision_check = await conn.fetch("""
                    SELECT a.name as agent_name, a.preserved_listen_blocks
                    FROM agents a
                    JOIN haproxy_clusters hc ON hc.pool_id = a.pool_id
                    WHERE hc.id = $1 AND a.preserved_listen_blocks IS NOT NULL
                """, frontend.cluster_id)
                
                for agent in collision_check:
                    listen_blocks = agent['preserved_listen_blocks'] or []
                    if isinstance(listen_blocks, str):
                        try:
                            listen_blocks = json.loads(listen_blocks)
                        except:
                            listen_blocks = []
                    
                    # Case-insensitive comparison (HAProxy proxy names are case-insensitive)
                    listen_blocks_lower = [lb.lower() for lb in listen_blocks if isinstance(lb, str)]
                    if frontend.name.lower() in listen_blocks_lower:
                        await close_database_connection(conn)
                        raise HTTPException(
                            status_code=400,
                            detail=f"Frontend name '{frontend.name}' conflicts with an existing 'listen {frontend.name}' "
                                   f"block on agent '{agent['agent_name']}'. Either rename this frontend or remove the "
                                   f"listen block from the agent's local HAProxy configuration."
                        )
            except HTTPException:
                raise  # Re-raise HTTP exceptions (collision detected)
            except Exception as e:
                # Column may not exist yet (before migration) - skip check gracefully
                logger.debug(f"Dynamic collision check skipped: {e}")
        
        # Check if frontend name already exists in the same cluster (only active frontends)
        existing = await conn.fetchrow("""
            SELECT id FROM frontends 
            WHERE name = $1 AND (cluster_id = $2 OR cluster_id IS NULL) AND is_active = TRUE
        """, frontend.name, frontend.cluster_id)
        if existing:
            await close_database_connection(conn)
            raise HTTPException(status_code=400, detail=f"Frontend '{frontend.name}' already exists")
        
        # ENTERPRISE DUAL-MODE: Save ssl_certificate_ids (NEW) and ssl_certificate_id (OLD - backward compat)
        # Convert ssl_certificate_ids to JSONB for database
        ssl_cert_ids_json = json.dumps(frontend.ssl_certificate_ids) if frontend.ssl_certificate_ids else '[]'
        
        # Filter out 'option httpchk' from options field (not applicable to frontends)
        filtered_options = filter_httpchk_from_options(frontend.options)
        if filtered_options != frontend.options and frontend.options:
            logger.info(f"Frontend '{frontend.name}': Filtered 'option httpchk' from options field. Health checks are for backends.")
        
        # Insert new frontend with all form fields (including SSL advanced options)
        frontend_id = await conn.fetchval("""
            INSERT INTO frontends (
                name, bind_address, bind_port, default_backend, mode, 
                ssl_enabled, ssl_certificate_id, ssl_certificate_ids, ssl_port, ssl_cert_path, ssl_cert, ssl_verify,
                ssl_alpn, ssl_npn, ssl_ciphers, ssl_ciphersuites, ssl_min_ver, ssl_max_ver, ssl_strict_sni,
                acl_rules, redirect_rules, use_backend_rules,
                request_headers, response_headers, options, tcp_request_rules, timeout_client, timeout_http_request,
                rate_limit, compression, log_separate, monitor_uri,
                cluster_id, maxconn, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, CURRENT_TIMESTAMP) 
            RETURNING id
        """, frontend.name, frontend.bind_address, frontend.bind_port, 
            frontend.default_backend, frontend.mode, frontend.ssl_enabled,
            frontend.ssl_certificate_id, ssl_cert_ids_json, frontend.ssl_port, frontend.ssl_cert_path, frontend.ssl_cert, frontend.ssl_verify,
            frontend.ssl_alpn, frontend.ssl_npn, frontend.ssl_ciphers, frontend.ssl_ciphersuites, 
            frontend.ssl_min_ver, frontend.ssl_max_ver, frontend.ssl_strict_sni,
            json.dumps(frontend.acl_rules or []), json.dumps(frontend.redirect_rules or []), json.dumps(frontend.use_backend_rules or []),
            frontend.request_headers, frontend.response_headers, filtered_options, frontend.tcp_request_rules, frontend.timeout_client, frontend.timeout_http_request,
            frontend.rate_limit, frontend.compression, frontend.log_separate, frontend.monitor_uri,
            frontend.cluster_id, frontend.maxconn)
        
        # If cluster_id provided, create new config version for agents
        sync_results = []
        if frontend.cluster_id:
            try:
                # Generate new HAProxy config
                config_content = await generate_haproxy_config_for_cluster(frontend.cluster_id)
                
                # Create new config version
                config_hash = hashlib.sha256(config_content.encode()).hexdigest()
                version_name = f"frontend-{frontend_id}-create-{int(time.time())}"
                
                # Get system admin user ID for created_by (fresh DB has admin with ID 1)
                admin_user_id = await conn.fetchval("SELECT id FROM users WHERE username = 'admin' LIMIT 1") or 1
                
                # Try with status field first, fallback to old behavior if field doesn't exist
                try:
                    config_version_id = await conn.fetchval("""
                        INSERT INTO config_versions 
                        (cluster_id, version_name, config_content, checksum, created_by, is_active, status)
                        VALUES ($1, $2, $3, $4, $5, FALSE, 'PENDING')
                        RETURNING id
                    """, frontend.cluster_id, version_name, config_content, config_hash, admin_user_id)
                    
                    logger.info(f"APPLY WORKFLOW: Created PENDING config version {version_name} for cluster {frontend.cluster_id}")
                    # Mark entity config status as PENDING for UI
                    await conn.execute("UPDATE frontends SET last_config_status = 'PENDING' WHERE id = $1", frontend_id)
                    
                    # Don't notify agents yet - wait for manual Apply
                    sync_results = [{'node': 'pending', 'success': True, 'version': version_name, 'status': 'PENDING', 'message': 'Changes created. Click Apply to activate.'}]
                    
                except Exception as status_error:
                    logger.warning(f"FALLBACK: Status field not available, using old immediate-apply behavior: {status_error}")
                    # Fallback to old behavior without status field
                    config_version_id = await conn.fetchval("""
                        INSERT INTO config_versions 
                        (cluster_id, version_name, config_content, checksum, created_by, is_active)
                        VALUES ($1, $2, $3, $4, $5, TRUE)
                        RETURNING id
                    """, frontend.cluster_id, version_name, config_content, config_hash, admin_user_id)
                    
                    # Deactivate previous versions for this cluster
                    await conn.execute("""
                        UPDATE config_versions 
                        SET is_active = FALSE 
                        WHERE cluster_id = $1 AND id != $2
                    """, frontend.cluster_id, config_version_id)
                    
                    # Use old notification behavior - notify agents immediately
                    from agent_notifications import notify_agents_config_change
                    sync_results = await notify_agents_config_change(frontend.cluster_id, version_name)
                    logger.info(f"FALLBACK: Using immediate-apply, agents notified")
                
            except Exception as e:
                logger.error(f"Cluster config update failed for frontend {frontend.name}: {e}")
                # Still return success for database save, but with sync warning
                sync_results = [{'node': 'cluster', 'success': False, 'error': str(e)}]
        
        await close_database_connection(conn)
        
        # Log user activity
        if current_user and current_user.get('id'):
            await log_user_activity(
                user_id=current_user['id'],
                action='create',
                resource_type='frontend',
                resource_id=str(frontend_id),
                details={
                    'frontend_name': frontend.name,
                    'bind_address': frontend.bind_address,
                    'bind_port': frontend.bind_port,
                    'cluster_id': frontend.cluster_id,
                    'sync_results': len(sync_results)
                },
                ip_address=str(request.client.host) if request.client else None,
                user_agent=request.headers.get('user-agent')
            )
        
        return {
            "message": f"Frontend '{frontend.name}' created successfully",
            "id": frontend_id,
            "frontend": frontend.dict(),
            "sync_results": sync_results
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{frontend_id}/config-versions")
async def get_frontend_config_versions(frontend_id: int, authorization: str = Header(None)):
    """Get config version history for a specific frontend"""
    try:
        # Verify user authentication
        from auth_middleware import get_current_user_from_token
        current_user = await get_current_user_from_token(authorization)
        
        conn = await get_database_connection()
        
        # Get frontend info first
        frontend_info = await conn.fetchrow("""
            SELECT f.id, f.name, c.name as cluster_name, f.cluster_id
            FROM frontends f
            LEFT JOIN haproxy_clusters c ON f.cluster_id = c.id
            WHERE f.id = $1
        """, frontend_id)
        
        if not frontend_info:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Frontend not found")
        
        # Get all APPLIED config versions that are related to this frontend
        versions = await conn.fetch("""
            SELECT cv.id, cv.version_name, cv.description, cv.status, cv.is_active,
                   cv.created_at, cv.file_size, cv.checksum,
                   u.username as created_by_username
            FROM config_versions cv
            LEFT JOIN users u ON cv.created_by = u.id
            WHERE cv.cluster_id = $1 AND cv.status = 'APPLIED'
            AND cv.version_name ~ $2
            ORDER BY cv.created_at DESC
        """, frontend_info['cluster_id'], f'^frontend-{frontend_id}-')
        
        await close_database_connection(conn)
        
        # Format the response
        formatted_versions = []
        for version in versions:
            formatted_versions.append({
                "id": version["id"],
                "version_name": version["version_name"],
                "description": version["description"] or "Frontend configuration update",
                "type": "Frontend",
                "status": version["status"],
                "is_active": version["is_active"],
                "created_at": version["created_at"].isoformat().replace('+00:00', 'Z') if version["created_at"] else None,
                "created_by": version["created_by_username"] or "System",
                "file_size": version["file_size"],
                "checksum": version["checksum"][:8] + "..." if version["checksum"] else "No checksum"
            })
        
        return {
            "versions": formatted_versions,
            "entity_info": {
                "entityName": frontend_info["name"],
                "clusterName": frontend_info["cluster_name"] or "No Cluster",
                "clusterId": frontend_info["cluster_id"]
            }
        }
        
    except Exception as e:
        logger.error(f"Error fetching frontend config versions: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/{frontend_id}")
async def update_frontend(frontend_id: int, frontend: FrontendConfig, request: Request, authorization: str = Header(None)):
    """Update existing frontend configuration with cluster synchronization"""
    try:
        # Get current user for activity logging
        from auth_middleware import get_current_user_from_token, check_user_permission
        current_user = await get_current_user_from_token(authorization)
        
        # Check permission for frontend update
        has_permission = await check_user_permission(current_user["id"], "frontends", "update")
        if not has_permission:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions: frontends.update required"
            )
        
        conn = await get_database_connection()
        
        # PHASE 2: Get FULL frontend record for snapshot (all fields)
        # CRITICAL: We need ALL fields for rollback, not just SSL fields
        existing = await conn.fetchrow("""
            SELECT * FROM frontends WHERE id = $1
        """, frontend_id)
        if not existing:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Frontend not found")

        # Bulgu #62 (round-22 audit) — UPDATE path: grandfather any
        # `use_backend_rules` / `redirect_rules` entry that is
        # IDENTICAL to what's already stored in the DB row. Only
        # NEW or MODIFIED rules with `X !X` self-contradictions
        # block the save. Stale entries (e.g. created by a pre-
        # Bulgu-#13 wizard build, or by a direct API caller) emit
        # a warning instead so the operator can change unrelated
        # fields (port / max conn / default_backend) without first
        # having to rewrite legacy routing rules.
        grandfathered_signatures: set = set()
        for r in _decode_db_rules_jsonb(existing["use_backend_rules"]):
            sig = _rule_to_signature(r)
            if sig:
                grandfathered_signatures.add(sig)
        for r in _decode_db_rules_jsonb(existing["redirect_rules"]):
            sig = _rule_to_signature(r)
            if sig:
                grandfathered_signatures.add(sig)
        contradiction_warnings = _enforce_routing_rule_contradictions(
            frontend, grandfathered_signatures=grandfathered_signatures,
        )
        for w in contradiction_warnings:
            logger.warning(
                f"FRONTEND UPDATE id={frontend_id} name={frontend.name}: {w}"
            )

        # Validate cluster access for multi-cluster security
        cluster_id = existing['cluster_id'] or frontend.cluster_id
        if cluster_id:
            await validate_user_cluster_access(current_user['id'], cluster_id, conn)
        
        # Check if name is being changed and if new name already exists
        if frontend.name != existing["name"]:
            # CRITICAL: Check for reserved names on rename
            reserved_names = {'stats', 'haproxy-stats', 'haproxy_stats', 'monitoring', 'admin', 'health', 'status'}
            if frontend.name.lower() in reserved_names:
                await close_database_connection(conn)
                raise HTTPException(
                    status_code=400,
                    detail=f"Frontend name '{frontend.name}' is reserved. It conflicts with common HAProxy "
                           f"listen sections (e.g., 'listen stats'). Please choose a different name."
                )
            
            # CRITICAL: Check for collision with agent listen blocks on rename
            # NOTE: Wrapped in try-except for backwards compatibility
            if cluster_id:
                try:
                    collision_check = await conn.fetch("""
                        SELECT a.name as agent_name, a.preserved_listen_blocks
                        FROM agents a
                        JOIN haproxy_clusters hc ON hc.pool_id = a.pool_id
                        WHERE hc.id = $1 AND a.preserved_listen_blocks IS NOT NULL
                    """, cluster_id)
                    
                    for agent in collision_check:
                        listen_blocks = agent['preserved_listen_blocks'] or []
                        if isinstance(listen_blocks, str):
                            try:
                                listen_blocks = json.loads(listen_blocks)
                            except:
                                listen_blocks = []
                        
                        # Case-insensitive comparison (HAProxy proxy names are case-insensitive)
                        listen_blocks_lower = [lb.lower() for lb in listen_blocks if isinstance(lb, str)]
                        if frontend.name.lower() in listen_blocks_lower:
                            await close_database_connection(conn)
                            raise HTTPException(
                                status_code=400,
                                detail=f"Frontend name '{frontend.name}' conflicts with an existing 'listen' block "
                                       f"on agent '{agent['agent_name']}'. Choose a different name."
                            )
                except HTTPException:
                    raise  # Re-raise HTTP exceptions
                except Exception as e:
                    logger.debug(f"Dynamic collision check skipped on update: {e}")
            
            name_exists = await conn.fetchrow("SELECT id FROM frontends WHERE name = $1 AND id != $2", frontend.name, frontend_id)
            if name_exists:
                await close_database_connection(conn)
                raise HTTPException(status_code=400, detail=f"Frontend name '{frontend.name}' already exists")
        
        # CRITICAL FIX: Preserve SSL configuration if not explicitly changed
        # If SSL is currently enabled but incoming data has ssl_enabled=False or ssl_certificate_id=None,
        # check if this is an intentional change or just missing data from the form
        # Preserve existing SSL config if incoming SSL fields are None/False but existing config has SSL enabled
        preserve_ssl_config = False
        if existing['ssl_enabled'] and existing['ssl_certificate_id']:
            # If existing has SSL enabled, but incoming data doesn't have ssl_enabled or has it as False with None certificate_id
            if not frontend.ssl_enabled and not frontend.ssl_certificate_id:
                # This appears to be unintentional loss of SSL config - preserve it
                preserve_ssl_config = True
                logger.warning(f"FRONTEND UPDATE FIX: Preserving SSL config for frontend {frontend.name} (ssl_certificate_id={existing['ssl_certificate_id']})")
        
        # Use preserved values if needed
        if preserve_ssl_config:
            ssl_enabled = existing['ssl_enabled']
            ssl_certificate_id = existing['ssl_certificate_id']
            ssl_port = existing['ssl_port'] if existing['ssl_port'] else frontend.ssl_port
            ssl_cert_path = existing['ssl_cert_path']
            ssl_cert = existing['ssl_cert']
            ssl_verify = existing['ssl_verify'] if existing['ssl_verify'] else frontend.ssl_verify
            logger.info(f"PRESERVED SSL CONFIG: ssl_enabled={ssl_enabled}, ssl_certificate_id={ssl_certificate_id}, ssl_port={ssl_port}")
        else:
            ssl_enabled = frontend.ssl_enabled
            ssl_certificate_id = frontend.ssl_certificate_id
            ssl_port = frontend.ssl_port
            ssl_cert_path = frontend.ssl_cert_path
            ssl_cert = frontend.ssl_cert
            ssl_verify = frontend.ssl_verify
        
        # Debug SSL certificate assignment
        logger.info(f"FRONTEND UPDATE DEBUG: Incoming - ssl_enabled={frontend.ssl_enabled}, ssl_certificate_id={frontend.ssl_certificate_id}, ssl_certificate_ids={frontend.ssl_certificate_ids}, ssl_port={frontend.ssl_port}")
        logger.info(f"FRONTEND UPDATE DEBUG: Final - ssl_enabled={ssl_enabled}, ssl_certificate_id={ssl_certificate_id}, ssl_port={ssl_port}")
        
        # ENTERPRISE DUAL-MODE: Save ssl_certificate_ids (NEW) and ssl_certificate_id (OLD - backward compat)
        ssl_cert_ids_json = json.dumps(frontend.ssl_certificate_ids) if frontend.ssl_certificate_ids else '[]'
        
        # Filter out 'option httpchk' from options field (not applicable to frontends)
        filtered_options = filter_httpchk_from_options(frontend.options)
        if filtered_options != frontend.options and frontend.options:
            logger.info(f"Frontend '{frontend.name}': Filtered 'option httpchk' from options field. Health checks are for backends.")
        
        # Update frontend with all form fields (including SSL advanced options)
        await conn.execute("""
            UPDATE frontends SET 
                name = $1, bind_address = $2, bind_port = $3, 
                default_backend = $4, mode = $5, ssl_enabled = $6,
                ssl_certificate_id = $7, ssl_certificate_ids = $8, ssl_port = $9, ssl_cert_path = $10, ssl_cert = $11, ssl_verify = $12,
                ssl_alpn = $13, ssl_npn = $14, ssl_ciphers = $15, ssl_ciphersuites = $16, ssl_min_ver = $17, ssl_max_ver = $18, ssl_strict_sni = $19,
                acl_rules = $20, redirect_rules = $21, use_backend_rules = $22,
                request_headers = $23, response_headers = $24, options = $25, tcp_request_rules = $26, timeout_client = $27, timeout_http_request = $28,
                rate_limit = $29, compression = $30, log_separate = $31, monitor_uri = $32,
                cluster_id = $33, maxconn = $34, updated_at = CURRENT_TIMESTAMP
            WHERE id = $35
        """, frontend.name, frontend.bind_address, frontend.bind_port, 
            frontend.default_backend, frontend.mode, ssl_enabled,
            ssl_certificate_id, ssl_cert_ids_json, ssl_port, ssl_cert_path, ssl_cert, ssl_verify,
            frontend.ssl_alpn, frontend.ssl_npn, frontend.ssl_ciphers, frontend.ssl_ciphersuites,
            frontend.ssl_min_ver, frontend.ssl_max_ver, frontend.ssl_strict_sni,
            json.dumps(frontend.acl_rules or []), json.dumps(frontend.redirect_rules or []), json.dumps(frontend.use_backend_rules or []),
            frontend.request_headers, frontend.response_headers, filtered_options, frontend.tcp_request_rules, frontend.timeout_client, frontend.timeout_http_request,
            frontend.rate_limit, frontend.compression, frontend.log_separate, frontend.monitor_uri,
            frontend.cluster_id, frontend.maxconn, frontend_id)
            
        # Debug: Check what was actually saved
        updated_frontend = await conn.fetchrow("""
            SELECT ssl_enabled, ssl_certificate_id, ssl_certificate_ids, ssl_port 
            FROM frontends WHERE id = $1
        """, frontend_id)
        logger.info(f"FRONTEND UPDATE RESULT: {dict(updated_frontend)}")
        
        # Additional debug: Check the full record to see what changed
        full_record = await conn.fetchrow("""
            SELECT id, name, ssl_enabled, ssl_certificate_id, ssl_certificate_ids, ssl_port, last_config_status, updated_at
            FROM frontends WHERE id = $1
        """, frontend_id)
        logger.info(f"FRONTEND FULL RECORD AFTER UPDATE: {dict(full_record)}")
        
        # If cluster_id provided, create new config version for agents
        sync_results = []
        if frontend.cluster_id:
            try:
                # Generate new HAProxy config
                config_content = await generate_haproxy_config_for_cluster(frontend.cluster_id)
                
                # Create new config version
                config_hash = hashlib.sha256(config_content.encode()).hexdigest()
                version_name = f"frontend-{frontend_id}-update-{int(time.time())}"
                
                # Get system admin user ID for created_by
                admin_user_id = await conn.fetchval("SELECT id FROM users WHERE username = 'admin' LIMIT 1") or 1
                
                # PHASE 2: Create entity snapshot for rollback
                from utils.entity_snapshot import save_entity_snapshot
                
                # Prepare new values for snapshot (only changed fields)
                new_values = {
                    "name": frontend.name,
                    "bind_address": frontend.bind_address,
                    "bind_port": frontend.bind_port,
                    "default_backend": frontend.default_backend,
                    "mode": frontend.mode,
                    "ssl_enabled": ssl_enabled,
                    "ssl_certificate_id": ssl_certificate_id,
                    "ssl_certificate_ids": ssl_cert_ids_json,
                    "ssl_port": ssl_port,
                    "ssl_cert_path": ssl_cert_path,
                    "ssl_cert": ssl_cert,
                    "ssl_verify": ssl_verify,
                    "acl_rules": json.dumps(frontend.acl_rules or []),
                    "redirect_rules": json.dumps(frontend.redirect_rules or []),
                    "use_backend_rules": json.dumps(frontend.use_backend_rules or []),
                    "request_headers": frontend.request_headers,
                    "response_headers": frontend.response_headers,
                    "options": filtered_options,
                    "tcp_request_rules": frontend.tcp_request_rules,
                    "timeout_client": frontend.timeout_client,
                    "timeout_http_request": frontend.timeout_http_request,
                    "rate_limit": frontend.rate_limit,
                    "compression": frontend.compression,
                    "log_separate": frontend.log_separate,
                    "monitor_uri": frontend.monitor_uri,
                    "cluster_id": frontend.cluster_id,
                    "maxconn": frontend.maxconn
                }
                
                entity_snapshot_metadata = await save_entity_snapshot(
                    conn=conn,
                    entity_type="frontend",
                    entity_id=frontend_id,
                    old_values=existing,  # Full record from line 604
                    new_values=new_values,
                    operation="UPDATE"
                )
                
                logger.info(f"FRONTEND UPDATE DEBUG: entity_snapshot_metadata keys={list(entity_snapshot_metadata.keys()) if entity_snapshot_metadata else 'EMPTY'}")
                logger.info(f"FRONTEND UPDATE DEBUG: entity_snapshot exists={('entity_snapshot' in entity_snapshot_metadata) if entity_snapshot_metadata else False}")
                
                # Get pre-apply snapshot (for diff viewer)
                old_config = await conn.fetchval("""
                    SELECT config_content FROM config_versions 
                    WHERE cluster_id = $1 AND status = 'APPLIED' AND is_active = TRUE
                    ORDER BY created_at DESC LIMIT 1
                """, frontend.cluster_id)
                
                # Merge metadata: pre_apply_snapshot + entity_snapshot
                metadata = {
                    "pre_apply_snapshot": old_config or "",  # For diff viewer
                    **entity_snapshot_metadata  # For rollback
                }
                
                logger.info(f"FRONTEND UPDATE DEBUG: Final metadata keys={list(metadata.keys())}")
                logger.info(f"FRONTEND UPDATE DEBUG: metadata has entity_snapshot={'entity_snapshot' in metadata}")
                
                # Try with status field first, fallback to old behavior if field doesn't exist
                try:
                    config_version_id = await conn.fetchval("""
                        INSERT INTO config_versions 
                        (cluster_id, version_name, config_content, checksum, created_by, is_active, status, metadata)
                        VALUES ($1, $2, $3, $4, $5, FALSE, 'PENDING', $6)
                        RETURNING id
                    """, frontend.cluster_id, version_name, config_content, config_hash, admin_user_id,
                         json.dumps(metadata) if metadata else None)
                    
                    logger.info(f"APPLY WORKFLOW: Created PENDING config version {version_name} for cluster {frontend.cluster_id}")
                    # Mark entity config status as PENDING for UI
                    await conn.execute("UPDATE frontends SET last_config_status = 'PENDING' WHERE id = $1", frontend_id)
                    
                    # Don't notify agents yet - wait for manual Apply
                    sync_results = [{'node': 'pending', 'success': True, 'version': version_name, 'status': 'PENDING', 'message': 'Changes updated. Click Apply to activate.'}]
                    
                except Exception as status_error:
                    logger.warning(f"FALLBACK: Status field not available, using old immediate-apply behavior: {status_error}")
                    # Fallback to old behavior without status field
                    config_version_id = await conn.fetchval("""
                        INSERT INTO config_versions 
                        (cluster_id, version_name, config_content, checksum, created_by, is_active)
                        VALUES ($1, $2, $3, $4, $5, TRUE)
                        RETURNING id
                    """, frontend.cluster_id, version_name, config_content, config_hash, admin_user_id)
                    
                    # Deactivate previous versions for this cluster
                    await conn.execute("""
                        UPDATE config_versions 
                        SET is_active = FALSE 
                        WHERE cluster_id = $1 AND id != $2
                    """, frontend.cluster_id, config_version_id)
                    
                    # Use old notification behavior - notify agents immediately
                    from agent_notifications import notify_agents_config_change
                    sync_results = await notify_agents_config_change(frontend.cluster_id, version_name)
                    logger.info(f"FALLBACK: Using immediate-apply, agents notified")
                
            except Exception as e:
                logger.error(f"Cluster config update failed for frontend {frontend.name}: {e}")
                # Still return success for database save, but with sync warning
                sync_results = [{'node': 'cluster', 'success': False, 'error': str(e)}]
        
        await close_database_connection(conn)
        
        # Log user activity
        if current_user and current_user.get('id'):
            await log_user_activity(
                user_id=current_user['id'],
                action='update',
                resource_type='frontend',
                resource_id=str(frontend_id),
                details={
                    'frontend_name': frontend.name,
                    'bind_address': frontend.bind_address,
                    'bind_port': frontend.bind_port,
                    'cluster_id': frontend.cluster_id,
                    'sync_results': len(sync_results)
                },
                ip_address=str(request.client.host) if request.client else None,
                user_agent=request.headers.get('user-agent')
            )
        
        response: dict = {
            "message": f"Frontend '{frontend.name}' updated successfully",
            "sync_results": sync_results,
        }
        # Bulgu #62 (round-22 audit) — surface grandfathered
        # contradiction warnings so the UI can render a non-blocking
        # yellow toast on the next refresh. The save SUCCEEDED; the
        # warnings only flag latent legacy data the operator may
        # want to clean up at their convenience.
        if contradiction_warnings:
            response["warnings"] = contradiction_warnings
        return response
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/{frontend_id}")
async def delete_frontend(frontend_id: int, request: Request, authorization: str = Header(None)):
    """Delete frontend configuration with cluster synchronization"""
    try:
        # Get current user for activity logging
        from auth_middleware import get_current_user_from_token, check_user_permission
        current_user = await get_current_user_from_token(authorization)
        
        # Check permission for frontend delete
        has_permission = await check_user_permission(current_user["id"], "frontends", "delete")
        if not has_permission:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions: frontends.delete required"
            )
        
        conn = await get_database_connection()
        
        # Check if frontend exists and get cluster_id and default_backend
        frontend = await conn.fetchrow("SELECT name, cluster_id, is_active, default_backend FROM frontends WHERE id = $1", frontend_id)
        if not frontend:
            await close_database_connection(conn)
            raise HTTPException(status_code=404, detail="Frontend not found")
        
        # Validate cluster access for multi-cluster security
        if frontend['cluster_id']:
            await validate_user_cluster_access(current_user['id'], frontend['cluster_id'], conn)
        
        cluster_id = frontend['cluster_id']
        frontend_name = frontend['name']
        is_already_inactive = not frontend['is_active']
        
        # CRITICAL FIX: If frontend is already inactive (soft-deleted), do HARD DELETE
        # Problem: Soft-deleted frontends remain in DB and block unique constraint
        # Solution: Hard delete inactive frontends and all related data
        if is_already_inactive:
            logger.warning(f"FRONTEND DELETE: Frontend '{frontend_name}' (id={frontend_id}) is already inactive. Performing HARD DELETE.")
            
            # Hard delete: Remove all traces from database
            # 1. Delete WAF rule associations
            await conn.execute("DELETE FROM frontend_waf_rules WHERE frontend_id = $1", frontend_id)
            
            # 2. Delete related config versions (optional - depends on your data retention policy)
            if cluster_id is not None:
                await conn.execute("""
                    DELETE FROM config_versions 
                    WHERE cluster_id = $1 
                    AND (version_name LIKE $2 OR config_content LIKE $3)
                """, cluster_id, f"%frontend-{frontend_id}-%", f"%frontend {frontend_name}%")
            
            # 3. Delete the frontend itself (HARD DELETE)
            await conn.execute("DELETE FROM frontends WHERE id = $1", frontend_id)
            
            await close_database_connection(conn)
            
            logger.info(f"FRONTEND DELETE: Hard deleted inactive frontend '{frontend_name}' and all related data")
            return {"message": f"Inactive frontend '{frontend_name}' has been permanently deleted from database"}
        
        logger.info(f"Frontend delete: frontend_id={frontend_id}, name={frontend_name}, cluster_id={cluster_id}")
        
        # Handle dependencies properly before deletion
        # Check if frontend has a default backend configured
        backend_dependency = None
        if frontend.get('default_backend'):
            # Check if the backend still exists
            backend_exists = await conn.fetchval("""
                SELECT name FROM backends 
                WHERE name = $1 AND is_active = TRUE
            """, frontend['default_backend'])
            if backend_exists:
                backend_dependency = frontend['default_backend']
        
        # If frontend uses a backend, suggest deleting the backend first
        if backend_dependency:
            await close_database_connection(conn)
            raise HTTPException(
                status_code=400, 
                detail=f"Cannot delete frontend '{frontend_name}': it uses backend '{backend_dependency}'. Please delete the backend first, then the frontend will be automatically updated."
            )
        
        # Remove WAF rule associations (cascade delete)
        waf_rules_removed_rows = await conn.fetch("""
            DELETE FROM frontend_waf_rules 
            WHERE frontend_id = $1 
            RETURNING *
        """, frontend_id)
        waf_rules_removed = len(waf_rules_removed_rows)
        
        # Soft delete frontend - mark as inactive and set PENDING
        await conn.execute(
            "UPDATE frontends SET is_active = FALSE, last_config_status = 'PENDING', updated_at = CURRENT_TIMESTAMP WHERE id = $1", 
            frontend_id
        )
        
        # If cluster_id provided, create new config version for agents
        sync_results = []
        if cluster_id:
            try:
                # Generate new HAProxy config without this frontend
                config_content = await generate_haproxy_config_for_cluster(cluster_id)
                
                # Create new config version
                config_hash = hashlib.sha256(config_content.encode()).hexdigest()
                version_name = f"frontend-{frontend_id}-delete-{int(time.time())}"
                
                # Get system admin user ID for created_by
                admin_user_id = await conn.fetchval("SELECT id FROM users WHERE username = 'admin' LIMIT 1") or 1
                
                # Try with status field first, fallback to old behavior if field doesn't exist
                try:
                    config_version_id = await conn.fetchval("""
                        INSERT INTO config_versions 
                        (cluster_id, version_name, config_content, checksum, created_by, is_active, status)
                        VALUES ($1, $2, $3, $4, $5, FALSE, 'PENDING')
                        RETURNING id
                    """, cluster_id, version_name, config_content, config_hash, admin_user_id)
                    
                    logger.info(f"APPLY WORKFLOW: Created PENDING config version {version_name} for cluster {cluster_id}")
                    
                    # Don't notify agents yet - wait for manual Apply
                    sync_results = [{'node': 'pending', 'success': True, 'version': version_name, 'status': 'PENDING', 'message': 'Frontend deletion created. Click Apply to activate.'}]
                    
                except Exception as status_error:
                    logger.warning(f"FALLBACK: Status field not available, using old immediate-apply behavior: {status_error}")
                    # Fallback to old behavior without status field
                    config_version_id = await conn.fetchval("""
                        INSERT INTO config_versions 
                        (cluster_id, version_name, config_content, checksum, created_by, is_active)
                        VALUES ($1, $2, $3, $4, $5, TRUE)
                        RETURNING id
                    """, cluster_id, version_name, config_content, config_hash, admin_user_id)
                    
                    # Deactivate previous versions for this cluster
                    await conn.execute("""
                        UPDATE config_versions 
                        SET is_active = FALSE 
                        WHERE cluster_id = $1 AND id != $2
                    """, cluster_id, config_version_id)
                    
                    # Use old notification behavior - notify agents immediately
                    from agent_notifications import notify_agents_config_change
                    sync_results = await notify_agents_config_change(cluster_id, version_name)
                    logger.info(f"FALLBACK: Using immediate-apply, agents notified")
                
            except Exception as e:
                logger.error(f"Cluster config update failed after deleting frontend {frontend['name']}: {e}")
                # Still return success for database save, but with sync warning
                sync_results = [{'node': 'cluster', 'success': False, 'error': str(e)}]
        
        await close_database_connection(conn)
        
        # Log user activity
        if current_user and current_user.get('id'):
            await log_user_activity(
                user_id=current_user['id'],
                action='delete',
                resource_type='frontend',
                resource_id=str(frontend_id),
                details={
                    'frontend_name': frontend['name'],
                    'cluster_id': cluster_id,
                    'sync_results': len(sync_results)
                },
                ip_address=str(request.client.host) if request.client else None,
                user_agent=request.headers.get('user-agent')
            )
        
        # Prepare user-friendly success message
        success_parts = [f"Frontend '{frontend_name}' deleted successfully"]
        if waf_rules_removed > 0:
            success_parts.append(f"{waf_rules_removed} WAF rule association(s) also removed")
        
        success_message = ". ".join(success_parts) + "."
        
        return {
            "message": success_message,
            "sync_results": sync_results
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 