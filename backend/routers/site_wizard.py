"""
v1.5.0 Feature B (Issue #14): New Site Setup Wizard router.

The `Proxied Host` brand name was retired in favour of `Site` for
the user-facing surface; this module file (`routers/site_wizard.py`)
and the API URL prefix (`/api/sites`) follow the new naming. The
legacy URL prefix `/api/proxied-hosts` is preserved as a backward-
compat alias (registered at app-mount time in `main.py`) so any
external integrator still pointing at the old slug keeps working
during a transition window.

Endpoints (plural prefix `/api/sites`):
- GET    /api/sites/suggest                 - smart-default suggestions
- POST   /api/sites/preflight-acme          - run ACME diagnostics shape
- POST   /api/sites/preview                 - non-mutating diff preview
- POST   /api/sites                         - atomic multi-entity create
- POST   /api/sites/drafts                  - save wizard draft (PEM stripped)
- GET    /api/sites/drafts                  - list current user's drafts
- DELETE /api/sites/drafts/{draft_id}       - delete a draft

Legacy alias (deprecated, hidden from OpenAPI):
- /api/proxied-hosts/* → 308 redirect to /api/sites/*

The atomic create flow is ordered:
    1. Pre-create collision checks (R35/M12 + M43/R60)
    2. backend_service.create_backend_row
    3. backend_service.create_server_row * N
    4. SSL branch by mode:
         acme     -> NO ssl row written (R16); HTTPS frontend deferred
         upload   -> ssl_service.create_cert_row + HTTPS frontend
         existing -> ssl_service.select_existing_cert + HTTPS frontend
         none     -> skip
    5. HTTP frontend (always)
    6. config_versions PENDING with metadata.bulk_snapshots + pre_apply_snapshot
       (version_name = 'bulk-site-create-{ts}'; the legacy
        prefix 'bulk-proxied-host-create-{ts}' is still
        recognised by the cluster reject path for backward
        compat with already-applied versions)
    7. POST-COMMIT:
         a) apply_immediately=true -> apply_service.apply_cluster_pending
         b) ssl.mode='acme'        -> letsencrypt_service.create_order_staged
                                      with post_completion_actions JSONB
         c) extend metadata.bulk_snapshots to include the staged
            letsencrypt_order id (R43/M27)
"""

import json
import logging
import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from asyncpg.exceptions import (
    ForeignKeyViolationError,
    UndefinedColumnError,
    UndefinedTableError,
    UniqueViolationError,
)
from fastapi import APIRouter, Header, HTTPException
from pydantic import ValidationError

from auth_middleware import check_user_permission, get_current_user_from_token
from database.connection import close_database_connection, get_database_connection
from models.site_wizard import (
    SiteCreate,
    SiteDraftCreate,
    SitePreflightAcme,
    SSLChoice,
    _strip_pem_from_payload,
)
from services.acme_diagnostics import run_checks
from services.backend_service import create_backend_row, create_server_row
from services.frontend_service import check_bind_port_collision, create_frontend_row
from services.ssl_service import (
    create_cert_row,
    ensure_cluster_junction,
    select_existing_cert,
    validate_server_ca_bundle_eligibility,
)
from services.letsencrypt_service import create_order_staged
from utils.activity_log import record_event

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/sites",
    # The HTTP prefix is `/api/sites` to match the user-visible "Site
    # Wizard" rebrand. The legacy `/api/proxied-hosts/*` slug is
    # preserved as a hidden 308-redirect alias on `main.py` so existing
    # external integrators / runbooks continue to work during the
    # transition window.
    tags=["Sites (New Site Wizard)"],
)

_RATE_LIMIT_PER_MIN = 5


def _now_ts() -> int:
    return int(time.time())


async def _validate_user_cluster_access(user_id: int, cluster_id: int, conn) -> None:
    """Mirror of routers/frontend.py:validate_user_cluster_access (admin
    bypass + user_pool_access table check). Raises HTTPException on denial.
    """
    cluster_exists = await conn.fetchval(
        "SELECT id FROM haproxy_clusters WHERE id = $1", cluster_id
    )
    if not cluster_exists:
        raise HTTPException(status_code=404, detail="Cluster not found")

    is_admin = await conn.fetchval("SELECT is_admin FROM users WHERE id = $1", user_id)
    if is_admin:
        return

    table_exists = await conn.fetchval(
        """
        SELECT EXISTS (
            SELECT 1 FROM information_schema.tables WHERE table_name = 'user_pool_access'
        )
        """
    )
    if not table_exists:
        return

    user_access = await conn.fetchrow(
        """
        SELECT upa.access_level
        FROM haproxy_clusters hc
        JOIN haproxy_cluster_pools hcp ON hc.pool_id = hcp.id
        JOIN user_pool_access upa ON hcp.id = upa.pool_id
        WHERE upa.user_id = $1 AND hc.id = $2 AND upa.is_active = TRUE
          AND (upa.expires_at IS NULL OR upa.expires_at > CURRENT_TIMESTAMP)
        """,
        user_id,
        cluster_id,
    )
    if not user_access:
        raise HTTPException(
            status_code=403,
            detail="You don't have access to this cluster.",
        )


async def _can_use_wizard(user_id: int, *, current_user: Optional[dict] = None) -> bool:
    """Bug A fix: drafts + suggest are PERSONAL/UTILITY — every authenticated
    user may keep their own draft work and probe wizard helpers. Granular
    RBAC (`frontend.create`, `ssl.create`, etc.) still gates the actual
    create endpoint; this wider check just lets the user reach the wizard
    UI without a 403 wall when they hold a read-only role or are
    mid-permission-rotation.

    R12 perf fix: previously this helper called `check_user_permission`
    up to 6 times in sequence — each call opened a fresh DB connection
    and ran a roles-query — so on every drafts list / save / preview the
    backend issued up to 6 separate Postgres round-trips. Now we:
      * short-circuit on `current_user.is_admin` (no query at all), and
      * fall back to a single `get_user_permissions` call and decide in
        memory.

    Returns True if the user is admin OR has ANY of the host-management
    permissions.
    """
    # Admin shortcut — get_current_user_from_token already populates
    # `is_admin` from the users table; if the caller passes the user dict
    # we can skip the roles roundtrip entirely.
    if current_user and current_user.get("is_admin"):
        return True

    try:
        from auth_middleware import get_user_permissions
        perms = await get_user_permissions(user_id)
    except Exception:
        # On error treat as denied; the existing endpoints already have
        # broader auth checks, so failing closed is safe here.
        return False

    # R18c round 10 (CRITICAL): seeded role permissions in
    # database/migrations.py use the PLURAL resource names — `frontends`,
    # `backends`, `ssl` — to match the CRUD routers (frontend.py /
    # backend.py / ssl.py). Pre-round-10 this loop checked SINGULAR
    # `frontend` / `backend` / `ssl`, which never existed in any seeded
    # role's permissions JSONB. Result: every non-admin user got
    # `_can_use_wizard=False` regardless of how many wizard-eligible
    # permissions their role granted, and the R18c-#7 admin bypass was
    # the ONLY thing keeping the feature operable. The fix here aligns
    # the resource keys with the rest of the codebase. `ssl` was already
    # in the right namespace (ssl.* is the seeded form for both the
    # wizard and the SSL Management page).
    candidate_perms = (
        ("frontends", "read"),
        ("frontends", "create"),
        ("ssl", "read"),
        ("ssl", "create"),
        ("backends", "create"),
        ("backends", "read"),
    )
    for resource, action in candidate_perms:
        if perms.get(resource, {}).get(action, False):
            return True
    return False


async def _enforce_rate_limit(conn, user_id: int, action: str) -> None:
    """Per-user-per-minute rate limit driven by user_activity_logs.

    Phase D/I rebrand: the action_name emitted by activity_logger
    moved from `proxied_host_*` to `site_*` for the same logical
    operation (e.g. `site_acme_preflight` is the post-rebrand name
    of the preflight log row). The rate-limit COUNT(*) must look at
    BOTH names so:
      - the limit cannot be bypassed by an attacker who picks the
        legacy action_name (it is no longer emitted, but defensive),
      - operators whose recent log rows pre-date the rename are still
        counted (a deploy roll happens mid-minute and we don't want
        a sudden burst of free quota for an in-flight session).

    The caller passes the canonical `site_*` action; we derive the
    legacy `proxied_host_*` companion automatically when the action
    starts with `site_` so callers don't have to track both names.
    """
    aliases = [action]
    if action.startswith("site_"):
        legacy = "proxied_host_" + action[len("site_"):]
        aliases.append(legacy)
    cnt = await conn.fetchval(
        """
        SELECT COUNT(*) FROM user_activity_logs
        WHERE user_id = $1 AND action = ANY($2::text[])
          AND created_at >= NOW() - INTERVAL '60 seconds'
        """,
        user_id,
        aliases,
    )
    if cnt is not None and cnt >= _RATE_LIMIT_PER_MIN:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: {action} allowed {_RATE_LIMIT_PER_MIN}/min",
        )


async def _resolve_default_acme_account(conn) -> Optional[int]:
    """Round 12 explicit fix: pick the most-recent valid ACME account."""
    return await conn.fetchval(
        """
        SELECT id FROM letsencrypt_accounts
        WHERE status = 'valid'
        ORDER BY created_at DESC
        LIMIT 1
        """
    )


async def _find_cluster_port80_http_frontend(
    conn, cluster_id: int, exclude_name: Optional[str] = None
) -> Optional[dict]:
    """Bulgu #34 (round-15 audit) — return a dict describing the cluster's
    existing port-80 HTTP-mode frontend, if any, so the wizard can decide
    whether the new site needs its own port-80 binding.

    The renderer (services/haproxy_config.py:974-978) injects the
    `/.well-known/acme-challenge/` ACL + `use_backend
    _acme_challenge_backend` into EVERY HTTP-mode frontend in a cluster
    with `acme_enabled=true`. So when the cluster already has SOME HTTP
    frontend listening on port 80, Let's Encrypt's HTTP-01 probe lands
    on THAT frontend and the agent serves the token regardless of which
    domain LE asked for — the new wizard frontend does NOT need to be
    on port 80.

    Returns the most-relevant row (any active HTTP-mode frontend bound to
    *:80 or to any of the cluster agents' addresses on :80) or None.

    `exclude_name` lets the caller skip the frontend currently being
    created/extended (useful for preflight UI hints).
    """
    rows = await conn.fetch(
        """
        SELECT id, name, bind_address, bind_port, mode
        FROM frontends
        WHERE cluster_id = $1
          AND is_active = TRUE
          AND mode = 'http'
          AND bind_port = 80
          AND ($2::text IS NULL OR name <> $2)
        ORDER BY bind_address ASC, id ASC
        LIMIT 1
        """,
        cluster_id,
        exclude_name,
    )
    if rows:
        r = rows[0]
        return {
            "id": r["id"],
            "name": r["name"],
            "bind_address": r["bind_address"],
            "bind_port": r["bind_port"],
            "mode": r["mode"],
        }
    return None


async def _validate_acme_port80_reachable(
    conn, body: SiteCreate
) -> Optional[str]:
    """Bulgu #34 (round-15 audit) — cluster-aware HTTP-01 reachability check.

    The legacy SiteCreate model rejected ANY ACME payload that did not
    bind on port 80 outright. That blanket rule didn't fit the canonical
    enterprise pattern (one shared port-80 frontend host-routing many
    sites), so operators on multi-tenant clusters could not use ACME at
    all from the wizard.

    Returns:
      * None when the payload is acceptable for ACME.
      * An actionable human-readable error string otherwise.

    The route handler converts the non-None return into an HTTPException.
    Both `create_site` and `preview_create` use it so the message is
    consistent across preview and submit.
    """
    if body.ssl.mode != "acme":
        return None
    if body.frontend.bind_port == 80:
        # The wizard's own new frontend will serve the challenge.
        return None
    # Non-80 wizard frontend → the cluster MUST already have a port-80
    # HTTP frontend that the renderer is auto-injecting the ACME ACL
    # into. Otherwise LE's HTTP-01 probe has nowhere to land.
    existing = await _find_cluster_port80_http_frontend(
        conn, body.cluster_id, exclude_name=body.frontend.name
    )
    if existing is None:
        return (
            f"ssl.mode='acme' with frontend.bind_port={body.frontend.bind_port} "
            f"requires the cluster to already have a port-80 HTTP frontend "
            "that Let's Encrypt's HTTP-01 probe can reach. Cluster "
            f"{body.cluster_id} has no such frontend, so the order would "
            "fail at validation. Options: "
            "(a) set frontend.bind_port=80 so the wizard's new frontend "
            "serves the challenge itself, or "
            "(b) first create / activate a shared port-80 HTTP frontend "
            "on this cluster (Frontends UI → Add), then re-run the "
            "wizard with your preferred non-standard bind port, or "
            "(c) switch ssl.mode to 'upload' / 'existing' (no HTTP-01 "
            "challenge needed)."
        )
    # The renderer only injects the ACME ACL when cluster.acme_enabled
    # is on. The route handler checks the flag separately (and gives a
    # dedicated error), so we only need to verify reachability here.
    return None


_HOST_ACL_RE = re.compile(
    # Captures hdr(host)[,lower] [-i] tokens followed by domain values
    # until the next ACL flag/EOL. Examples this MUST match:
    #   acl host_x hdr(host) -i example.com
    #   acl host_x hdr(host),lower example.com www.example.com
    #   acl host_x hdr_dom(host) example.com
    #   acl host_x req.hdr(host) -i example.com
    r"\b(?:hdr|req\.hdr|hdr_dom|hdr_str|hdr_beg|hdr_end|hdr_reg)\s*"
    r"\(\s*host\s*\)(?:\s*,\s*[a-z_]+)*\s+(?:-[a-zA-Z]+\s+)*"
    r"(?P<values>[^#\n]+)",
    re.IGNORECASE,
)


def _extract_host_values_from_acl(rule: str) -> List[str]:
    """Bulgu #37 (round-16 audit) — coarse parser for host-match values
    inside a single HAProxy `acl …` directive string.

    The wizard stores `acl_rules` as a JSONB list of operator-typed
    directive strings (e.g. `host_example hdr(host) -i example.com
    www.example.com`). To detect when a new wizard site claims a
    domain that ANOTHER active frontend in the same cluster already
    routes, we parse out the values following `hdr(host)` / its
    aliases.

    The parser intentionally errs on the side of OVER-collecting (we
    surface the operator with the matched ACL string anyway, so a
    false positive turns into a clear warning rather than a silent
    miss). Tokens beginning with `-` (HAProxy flags) and tokens
    consumed by trailing match keywords (`if`, `unless`) are dropped
    so we don't mistake `if`/`unless` for domain values.

    Returns the lowercased deduped value list.
    """
    if not rule or not isinstance(rule, str):
        return []
    match = _HOST_ACL_RE.search(rule)
    if not match:
        return []
    raw = match.group("values").strip()
    out: List[str] = []
    seen: set = set()
    for tok in raw.split():
        if not tok:
            continue
        low = tok.lower()
        # Stop at trailing match operator keywords (the wizard doesn't
        # emit these inline with the values, but operator-typed
        # `acl_rules` strings might).
        if low in ("if", "unless", "or", "and", "&&", "||"):
            break
        # Drop HAProxy flags (-i, -m, -f, ...). These can appear
        # MID-value list if the operator chained two patterns; we
        # treat that as the end-of-value.
        if low.startswith("-"):
            continue
        # Strip wrapping quotes (operators sometimes quote domains).
        cleaned = low.strip('"').strip("'")
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        out.append(cleaned)
    return out


async def _find_cluster_domain_routing_collisions(
    conn, cluster_id: int, domains: List[str], exclude_frontend_name: Optional[str] = None
) -> List[dict]:
    """Bulgu #37 (round-16 audit) — scan the cluster's existing frontends
    for `acl … hdr(host) … <domain>` matches against the wizard's new
    domain list.

    Two sites in the same cluster claiming the same Host-header value
    create undefined routing — HAProxy picks the first frontend that
    binds the matching address:port, and once a request lands there
    the `default_backend` (or use_backend ACL hit order) decides. The
    wizard's new frontend on a different port wouldn't directly
    collide, but the OPERATOR likely thinks the new site is the
    authoritative routing target — wrong.

    Returns a list of `{frontend_id, frontend_name, acl_rule,
    conflicting_domains}` dicts (empty when no collisions). Each entry
    is human-readable so the caller can surface it directly as a
    warning / blocking_error.
    """
    if not domains:
        return []
    domain_lookup = {d.lower(): d for d in domains}
    # Bulgu #53 (round-18 audit) — also scan `use_backend_rules`.
    #
    # Operators can express host-based routing two equivalent ways:
    #
    #   (A) name the ACL separately and reference it:
    #       acl_rules = ["host_x hdr(host) -i example.com"]
    #       use_backend_rules = ["mybe if host_x"]
    #
    #   (B) inline the host condition directly inside use_backend:
    #       use_backend_rules = ["mybe if { hdr(host) -i example.com }"]
    #
    # The pre-round-18 collision scan only walked `acl_rules`, so form
    # (B) on an existing frontend would never match the new wizard
    # site's domain list — silently allowing two frontends to both
    # answer for `example.com`.
    #
    # `redirect_rules` and `tcp_request_rules` can carry the same
    # inline hdr(host) pattern. Both are extracted here so the
    # scan covers every place a routing decision is taken on the
    # Host: header.
    rows = await conn.fetch(
        """
        SELECT id, name, acl_rules, use_backend_rules,
               redirect_rules, tcp_request_rules
        FROM frontends
        WHERE cluster_id = $1
          AND is_active = TRUE
          AND ($2::text IS NULL OR name <> $2)
        """,
        cluster_id,
        exclude_frontend_name,
    )

    def _decode_jsonb_list(raw) -> List:
        """JSONB → Python list (handles str/list/None)."""
        if not raw:
            return []
        try:
            if isinstance(raw, str):
                decoded = json.loads(raw)
            else:
                decoded = raw
        except (json.JSONDecodeError, TypeError):
            return []
        return decoded if isinstance(decoded, list) else []

    def _row_field(row, key):
        """Defensive accessor — asyncpg Records and dict-like stubs
        both expose `row[key]`, but a row that was built with a SELECT
        list missing one of the new round-18 columns would raise
        KeyError. Treat 'missing' as 'no rule of that origin'."""
        try:
            return row[key]
        except (KeyError, IndexError):
            return None

    collisions: List[dict] = []
    for r in rows:
        # Merge every source of host conditions on this frontend into
        # a single (origin_label, rule_string) sequence. The label is
        # surfaced in the warning so the operator knows WHERE the
        # conflicting rule lives on the offending frontend.
        candidates: List[tuple] = []
        for rule in _decode_jsonb_list(_row_field(r, "acl_rules")):
            if isinstance(rule, str):
                candidates.append(("acl_rules", rule))
        for rule in _decode_jsonb_list(_row_field(r, "use_backend_rules")):
            if isinstance(rule, str):
                candidates.append(("use_backend_rules", rule))
        for rule in _decode_jsonb_list(_row_field(r, "redirect_rules")):
            # redirect_rules can be either operator-typed strings or
            # dict objects with `{"condition": "..."}`. Coerce both.
            if isinstance(rule, str):
                candidates.append(("redirect_rules", rule))
            elif isinstance(rule, dict):
                cond = rule.get("condition") or rule.get("if") or ""
                if isinstance(cond, str) and cond:
                    candidates.append(("redirect_rules", cond))
        for rule in _decode_jsonb_list(_row_field(r, "tcp_request_rules")):
            if isinstance(rule, str):
                candidates.append(("tcp_request_rules", rule))

        if not candidates:
            continue
        for origin, rule in candidates:
            host_values = _extract_host_values_from_acl(rule)
            if not host_values:
                continue
            conflicting = sorted(
                set(host_values) & set(domain_lookup.keys())
            )
            if conflicting:
                collisions.append({
                    "frontend_id": r["id"],
                    "frontend_name": r["name"],
                    "acl_rule": rule.strip(),
                    "rule_origin": origin,
                    "conflicting_domains": conflicting,
                })
    return collisions


async def _find_pending_acme_order_overlap(
    conn, domains: List[str], exclude_order_id: Optional[int] = None
) -> List[dict]:
    """Bulgu #38 (round-16 audit) — detect open ACME orders that
    already cover any of the wizard's domains.

    Both Let's Encrypt rate-limits and the agent's order-completion
    state machine assume each domain is in AT MOST ONE active order
    at a time. Two wizard runs racing the same domain produce:
      * duplicate LE orders (counts against the 300-new-orders /
        3-hour limit unnecessarily);
      * duplicate cert rows once both complete;
      * undefined `use_backend` order for the deferred HTTPS frontend
        create action.

    Active statuses we treat as overlapping:
      * 'wizard_staged' — saved by the wizard, agent not yet
        confirmed.
      * 'pending'       — LE has the order, awaiting validation.
      * 'processing'    — finalize in flight.
      * 'ready'         — finalize permitted but not yet run.
      * 'valid_pending_apply' — cert downloaded, HTTPS frontend create
        still queued.

    Returns `[{order_id, status, overlapping_domains, created_at}]`
    (empty when no overlap).
    """
    if not domains:
        return []
    rows = await conn.fetch(
        """
        SELECT id, status, domains, created_at
        FROM letsencrypt_orders
        WHERE status IN (
            'wizard_staged', 'pending', 'processing', 'ready',
            'valid_pending_apply'
        )
          AND ($2::bigint IS NULL OR id <> $2)
          AND EXISTS (
              SELECT 1 FROM jsonb_array_elements_text(domains) AS d
              WHERE LOWER(d) = ANY($1::text[])
          )
        ORDER BY created_at DESC
        """,
        [d.lower() for d in domains],
        exclude_order_id,
    )
    overlaps: List[dict] = []
    domain_lookup = {d.lower() for d in domains}
    for r in rows:
        order_domains_raw = r["domains"]
        try:
            if isinstance(order_domains_raw, str):
                order_domains = json.loads(order_domains_raw)
            else:
                order_domains = order_domains_raw
        except (json.JSONDecodeError, TypeError):
            order_domains = []
        if not isinstance(order_domains, list):
            continue
        order_lower = {str(d).lower() for d in order_domains}
        overlap = sorted(order_lower & domain_lookup)
        if not overlap:
            continue
        overlaps.append({
            "order_id": r["id"],
            "status": r["status"],
            "overlapping_domains": overlap,
            "created_at": str(r["created_at"]) if r["created_at"] else None,
        })
    return overlaps


def _describe_reachable_urls(body: "SiteCreate") -> List[str]:
    """Bulgu #39 (round-16 audit) — spell out the URLs operators can
    actually reach the new site at, given the wizard's chosen ports.

    When `frontend.bind_port != 80` or `ssl.https_bind_port != 443` the
    site is NOT reachable at the bare `http(s)://<domain>` URL a
    browser bookmarks by default. Operators on multi-tenant clusters
    (where the default ports are already taken by shared frontends)
    routinely don't realise this until end-users complain. Surfacing
    the concrete URLs at preview time makes the implication
    impossible to miss.

    Returns a list of human-readable URL hints, one per domain × port
    combination the wizard will actually expose.
    """
    out: List[str] = []
    http_port = body.frontend.bind_port
    https_port = body.ssl.https_bind_port if body.ssl.mode != "none" else None
    for d in (body.domains or [])[:5]:  # cap to 5 to keep banners short
        # Skip wildcards in the URL hint (browsers don't request them).
        d_show = d.replace("*.", "")
        if body.frontend.mode == "http":
            if http_port == 80:
                out.append(f"http://{d_show}/")
            else:
                out.append(f"http://{d_show}:{http_port}/")
        if https_port is not None:
            if https_port == 443:
                out.append(f"https://{d_show}/")
            else:
                out.append(f"https://{d_show}:{https_port}/")
    return out


def _explain_bind_collision(
    *,
    bind_address: str,
    bind_port: int,
    colliding_frontend_id: int,
    ssl_mode: str,
    is_https: bool = False,
) -> str:
    """Bulgu #35 (round-15 audit) — actionable bind-collision message.

    Pre-fix the wizard surfaced collisions with the bare line:

        Bind *:80 already used (frontend id=522)

    which left the operator guessing what to do. Two valid workflows
    exist on a multi-tenant cluster — pick a different port for the
    new frontend, or extend the existing frontend to also host this
    domain — and the operator should see both. The message also
    explains the special ACME case: when the existing port-80 frontend
    on the cluster ALREADY routes /.well-known/acme-challenge/, the
    operator can use ACME on a different port without losing
    auto-issuance.
    """
    base = (
        f"Bind {bind_address}:{bind_port} is already used by frontend "
        f"id={colliding_frontend_id} in this cluster."
    )
    is_default_http = (bind_port == 80 and not is_https)
    is_default_https = (bind_port == 443 and is_https)
    hints: List[str] = []
    if is_default_http:
        hints.append(
            "(a) change frontend.bind_port to a free port (e.g. 8080). "
            "On ACME mode the cluster's existing port-80 frontend will "
            "still serve the Let's Encrypt HTTP-01 challenge for your "
            "domain — your new frontend does not need to be on port 80."
        )
    elif is_default_https:
        hints.append(
            "(a) change ssl.https_bind_port to a free port (e.g. 8443). "
            "Browser traffic to https://<domain> defaults to port 443, "
            "so a non-443 HTTPS bind means clients have to type "
            "`:8443` explicitly — useful for internal sites or "
            "test environments."
        )
    else:
        hints.append(
            "(a) pick a different bind port that is free on this cluster."
        )
    hints.append(
        f"(b) extend the existing frontend id={colliding_frontend_id} "
        "with a host-based routing rule (Frontends UI → edit → Add "
        "ACL + use_backend) so it forwards your new domain to the "
        "wizard-created backend. This is the canonical multi-tenant "
        "HAProxy pattern."
    )
    if ssl_mode == "acme" and is_default_http:
        hints.append(
            "(c) if you are not married to ACME for this site, switch "
            "ssl.mode to 'upload' or 'existing' which uses any free "
            "port and skips the port-80 HTTP-01 step."
        )
    return base + " Options: " + " ".join(hints)


def _build_redirect_rules(payload: SiteCreate) -> List[dict]:
    """M19: expand https_redirect=true into a redirect_rules JSONB row.

    R11.A-1 fix: pre-fix this row carried both a `type:'scheme'` and a
    `location:<url>` field. HAProxy's `redirect scheme` directive
    only accepts a literal scheme name (`https`/`http`) — passing a
    URL there made the agent's `haproxy -c` reject the config with a
    parser error. The `location` field is reserved for
    `redirect location <URL>`. Emit the canonical scheme-redirect
    payload (`scheme` + `code` + `condition`); the generator's
    `_format_redirect_rule` reads `scheme` directly.

    Bulgu #29 (round-13 audit) — ACME HTTP-01 challenge defence.
    Pre-fix the auto-generated condition was simply ``!{ ssl_fc }``
    (redirect ALL plain-HTTP traffic to HTTPS). On an ssl.mode='acme'
    site that combination produced a self-defeating config:

      1. The wizard creates an HTTP frontend on :80 (mandatory for
         HTTP-01).
      2. The wizard also enables the scheme→https redirect on the
         same frontend.
      3. The agent emits `acl is_acme_challenge path_beg
         /.well-known/acme-challenge/` + `use_backend
         _acme_challenge_backend if is_acme_challenge` — BUT
         HAProxy processes `redirect` rules BEFORE `use_backend`
         in the request-analysis phase.
      4. LE's validator fetches
         `http://<domain>/.well-known/acme-challenge/<token>` and
         the HTTP frontend immediately returns
         `301 https://<domain>/.well-known/acme-challenge/<token>`.
      5. LE follows the 301 to the HTTPS port — but in ACME mode
         the HTTPS frontend is DEFERRED until issuance succeeds
         (`_execute_post_completion_actions`). Nothing is listening
         on :443 yet, so the follow-up handshake times out and the
         order fails with an opaque "fetching … failed" error.

    Fix: render the canonical scheme→https redirect with an extra
    `!{ path_beg /.well-known/acme-challenge/ }` clause so the
    redirect SKIPS challenge paths and HAProxy falls through to the
    `use_backend _acme_challenge_backend` line emitted in the
    `use_be` bucket. The exclusion is harmless on non-ACME sites
    (no one legitimately probes `/.well-known/acme-challenge/<token>`
    on a plain HTTP site, and even if they did the response is
    semantically equivalent to a 301-then-404). HAProxy's `if A B`
    grammar is an implicit AND, matching the legacy single-clause
    behaviour for every non-challenge request.
    """
    if payload.frontend.https_redirect:
        return [
            {
                "type": "scheme",
                "scheme": "https",
                "code": 301,
                "condition": (
                    "!{ ssl_fc } "
                    "!{ path_beg /.well-known/acme-challenge/ }"
                ),
            }
        ]
    return list(payload.frontend.redirect_rules or [])


# ---------------------------------------------------------------------------
# Phase K Phase C — shared candidate-config synthesizer for the dry-run gate
# ---------------------------------------------------------------------------


def _build_candidate_fragment(body: SiteCreate) -> str:
    """Render the wizard's would-be entities as a HAProxy config fragment.

    This is the dry-run twin of what
    `services/haproxy_config.py::generate_haproxy_config_for_cluster`
    would emit if the rows had already been INSERTed. We hand-render
    a minimal-but-shape-correct frontend / backend / HTTPS frontend
    block from the request body so the dry-run can run
    `HAProxyConfigValidator` without DB writes.

    The fragment is intentionally conservative — it covers every
    field that affects the validator's heuristic checks (binds,
    `default_backend`, `verify required`, ssl `crt`, HSTS / strict-
    sni, ACL / use_backend / redirect rules) but not every cosmetic
    rendering detail. The agent's `haproxy -c -f` on apply remains
    the ultimate source of truth.
    """
    from services.haproxy_config import _format_redirect_rule

    fe = body.frontend
    be = body.backend
    ssl = body.ssl
    lines: List[str] = ["", "# ─── Wizard candidate fragment (dry-run preview) ───"]

    # ─── HTTP frontend ────────────────────────────────────────────
    lines.append(f"frontend {fe.name}")
    lines.append(f"    mode {fe.mode}")
    lines.append(f"    bind {fe.bind_address}:{fe.bind_port}")
    if fe.maxconn:
        lines.append(f"    maxconn {fe.maxconn}")
    if fe.timeout_client:
        lines.append(f"    timeout client {fe.timeout_client}ms")
    if fe.timeout_http_request:
        lines.append(f"    timeout http-request {fe.timeout_http_request}ms")
    if fe.compression:
        lines.append("    compression algo gzip")
    if fe.monitor_uri:
        lines.append(f"    monitor-uri {fe.monitor_uri}")
    if fe.options:
        for raw in fe.options.splitlines():
            stripped = raw.strip()
            if stripped:
                lines.append(f"    {stripped}")
    if fe.mode == "tcp" and fe.tcp_request_rules:
        for raw in fe.tcp_request_rules.splitlines():
            stripped = raw.strip()
            if stripped:
                lines.append(f"    {stripped}")
    # Bulgu #19 (round-9 audit): the wizard's `request_headers` /
    # `response_headers` fields carry FULL HAProxy directive lines —
    # the operator pastes lines like:
    #
    #     http-request add-header X-Forwarded-Proto https
    #     http-request set-header X-Real-IP %[src]
    #
    # (the FrontendManagement / BulkConfigImport UIs both document
    # this format in the textarea placeholder, and the real renderer
    # at `services/haproxy_config.py:1063-1074` emits each line
    # VERBATIM with 4-space indent).
    #
    # Pre-fix the dry-run twin PREFIXED every line with
    # `    http-request set-header` / `    http-response set-header`,
    # which produced double-prefixed garbage like:
    #
    #     http-request set-header http-request set-header X-Real-IP …
    #
    # That broke validator heuristic checks during Step 5 and
    # surfaced as misleading "directive may not be valid" warnings on
    # configurations that were actually fine. Emitting the lines
    # verbatim makes the dry-run preview a true twin of the real
    # render path.
    if fe.request_headers:
        for raw in fe.request_headers.splitlines():
            stripped = raw.strip()
            if stripped:
                lines.append(f"    {stripped}")
    if fe.response_headers:
        for raw in fe.response_headers.splitlines():
            stripped = raw.strip()
            if stripped:
                lines.append(f"    {stripped}")
    for rule in (fe.acl_rules or []):
        if isinstance(rule, str) and rule.strip():
            lines.append(f"    acl {rule.strip()}")
    for rule in _build_redirect_rules(body):
        formatted = _format_redirect_rule(rule)
        if formatted:
            # `_format_redirect_rule` already returns a 4-space-indented
            # `redirect …` line.
            lines.append(formatted)
    for rule in (fe.use_backend_rules or []):
        if isinstance(rule, str) and rule.strip():
            lines.append(f"    use_backend {rule.strip()}")
    lines.append(f"    default_backend {be.name}")

    # ─── HTTPS frontend (upload / existing only — ACME's HTTPS bind is
    #     created post-completion, so we omit it from the dry-run to
    #     match what create_site would actually persist for ACME) ───
    if ssl.mode in ("upload", "existing"):
        https_name = f"{fe.name}{ssl.https_frontend_name_suffix or '-https'}"
        cert_path = f"/etc/ssl/haproxy/{(ssl.name or fe.name)}.pem"
        bind_parts: List[str] = [
            f"{fe.bind_address}:{ssl.https_bind_port}",
            "ssl",
            "crt",
            cert_path,
        ]
        if ssl.ssl_alpn:
            bind_parts.append(f"alpn {ssl.ssl_alpn}")
        if ssl.ssl_min_ver:
            bind_parts.append(f"ssl-min-ver {ssl.ssl_min_ver}")
        if ssl.ssl_max_ver:
            bind_parts.append(f"ssl-max-ver {ssl.ssl_max_ver}")
        if ssl.ssl_ciphers:
            bind_parts.append(f"ciphers {ssl.ssl_ciphers}")
        if ssl.ssl_ciphersuites:
            bind_parts.append(f"ciphersuites {ssl.ssl_ciphersuites}")
        if ssl.ssl_strict_sni:
            bind_parts.append("strict-sni")
        if ssl.ssl_verify:
            bind_parts.append(f"verify {ssl.ssl_verify}")
        lines.append("")
        lines.append(f"frontend {https_name}")
        lines.append(f"    mode {fe.mode}")
        lines.append(f"    bind {' '.join(bind_parts)}")
        if ssl.hsts_enabled:
            hsts_parts = [f"max-age={ssl.hsts_max_age}"]
            if ssl.hsts_include_subdomains:
                hsts_parts.append("includeSubDomains")
            if ssl.hsts_preload:
                hsts_parts.append("preload")
            hsts_value = "; ".join(hsts_parts)
            lines.append(
                f'    http-response set-header Strict-Transport-Security "{hsts_value}"'
            )
        for rule in (fe.acl_rules or []):
            if isinstance(rule, str) and rule.strip():
                lines.append(f"    acl {rule.strip()}")
        for rule in (fe.use_backend_rules or []):
            if isinstance(rule, str) and rule.strip():
                lines.append(f"    use_backend {rule.strip()}")
        lines.append(f"    default_backend {be.name}")

    # ─── Backend ──────────────────────────────────────────────────
    lines.append("")
    lines.append(f"backend {be.name}")
    lines.append(f"    mode {be.mode}")
    if be.balance_method:
        lines.append(f"    balance {be.balance_method}")
    if getattr(be, "cookie_name", None):
        # Bulgu #19 (round-9 audit): include cookie_options in the
        # dry-run so the validator's heuristic that examines the full
        # `cookie <name> <opts>` line sees the same string the real
        # renderer will produce at apply time.
        cookie_line = f"    cookie {be.cookie_name} insert indirect nocache"
        cookie_opts = (getattr(be, "cookie_options", None) or "").strip()
        if cookie_opts and cookie_opts not in ('[]', '{}', 'null', 'None'):
            # Strip the canonical defaults already emitted above so we
            # don't repeat them when the operator's `cookie_options`
            # carries the canonical form too.
            cookie_line = f"    cookie {be.cookie_name} {cookie_opts}"
        lines.append(cookie_line)
    if getattr(be, "timeout_connect", None):
        lines.append(f"    timeout connect {be.timeout_connect}ms")
    if getattr(be, "timeout_server", None):
        lines.append(f"    timeout server {be.timeout_server}ms")
    # Bulgu #19 (round-9 audit): mirror the real renderer's emission
    # of backend-level header injections so the dry-run can catch any
    # operator-typed directive that would only trigger a validator
    # warning at apply time (e.g. `option httpchk` accidentally
    # pasted into `request_headers` instead of `options`).
    if getattr(be, "request_headers", None):
        for raw in be.request_headers.splitlines():
            stripped = raw.strip()
            if stripped and stripped not in ('[]', '{}', 'null', 'None'):
                lines.append(f"    {stripped}")
    if getattr(be, "response_headers", None):
        for raw in be.response_headers.splitlines():
            stripped = raw.strip()
            if stripped and stripped not in ('[]', '{}', 'null', 'None'):
                lines.append(f"    {stripped}")

    for s in body.servers:
        server_parts: List[str] = [
            f"server {s.server_name}",
            f"{s.server_address}:{s.server_port}",
        ]
        if s.weight is not None:
            server_parts.append(f"weight {s.weight}")
        if s.check_enabled:
            chk = ["check"]
            if s.check_port:
                chk.append(f"port {s.check_port}")
            if s.inter:
                chk.append(f"inter {s.inter}")
            if s.fall:
                chk.append(f"fall {s.fall}")
            if s.rise:
                chk.append(f"rise {s.rise}")
            server_parts.append(" ".join(chk))
        if s.max_connections:
            server_parts.append(f"maxconn {s.max_connections}")
        lines.append(f"    {' '.join(server_parts)}")

    return "\n".join(lines) + "\n"


async def _synthesize_candidate_haproxy_config(
    body: SiteCreate,
    conn,
    *,
    entities_already_inserted: bool = False,
) -> str:
    """Render the candidate HAProxy config for a wizard payload.

    Two callers, two paths — same helper:

    * `entities_already_inserted=True` (create_site post-insert
      validation gate): the wizard's INSERTs are already in the active
      transaction, so the cluster's renderer sees them. Just return
      the renderer's output.
    * `entities_already_inserted=False` (preview dry-run gate): the
      INSERTs have not happened. Render the cluster's CURRENT config
      and append a candidate fragment derived from `body` so the
      validator sees the post-create shape without any DB writes.

    Both paths share this helper so the dry-run gate and the apply
    gate can never silently desync. Pinned by
    `tests/test_site_wizard_phase_k.py::
    test_phase_k_create_site_and_preview_use_same_synthesis_helper`.
    """
    from services.haproxy_config import generate_haproxy_config_for_cluster

    existing = await generate_haproxy_config_for_cluster(body.cluster_id, conn)
    if entities_already_inserted:
        return existing
    return existing + _build_candidate_fragment(body)


# ---------------------------------------------------------------------------
# GET /suggest
# ---------------------------------------------------------------------------


@router.get("/suggest")
async def suggest_defaults(
    cluster_id: int,
    domain: Optional[str] = None,
    authorization: str = Header(None),
):
    """Smart-default suggestions for the wizard form.

    Returns suggested backend/frontend names derived from the first domain
    plus a default backend port (80 if user typed an HTTP host, else 8080).
    """
    current_user = await get_current_user_from_token(authorization)
    if not await _can_use_wizard(current_user["id"], current_user=current_user):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    conn = await get_database_connection()
    try:
        await _validate_user_cluster_access(current_user["id"], cluster_id, conn)

        slug = "newhost"
        if domain:
            base = domain.replace("*.", "").split(".")
            slug = (base[0] or "newhost")[:32].lower()
            slug = "".join(c if (c.isalnum() or c in ("-", "_")) else "-" for c in slug)
            if slug.startswith("_"):
                slug = "h-" + slug.lstrip("_")
            if not slug or not slug[0].isalpha():
                slug = "h-" + slug

        return {
            "backend_name": f"be-{slug}",
            "frontend_name": f"fe-{slug}",
            "https_frontend_name": f"fe-{slug}-https",
            "backend_port_suggestion": 8080,
            "ssl_certificate_name_suggestion": f"cert-{slug}",
        }
    finally:
        await close_database_connection(conn)


# ---------------------------------------------------------------------------
# POST /preflight-acme
# ---------------------------------------------------------------------------


@router.post("/preflight-acme")
async def preflight_acme(
    body: SitePreflightAcme,
    authorization: str = Header(None),
):
    """Run pre-create ACME diagnostics for the proposed domains+cluster."""
    current_user = await get_current_user_from_token(authorization)
    if not await check_user_permission(
        current_user["id"], "ssl", "read", current_user=current_user
    ):
        raise HTTPException(status_code=403, detail="Insufficient permissions: ssl.read required")

    conn = await get_database_connection()
    try:
        await _validate_user_cluster_access(current_user["id"], body.cluster_id, conn)
        # Phase D/I: canonical action name post-rebrand. The
        # _enforce_rate_limit helper auto-aliases this to its legacy
        # `proxied_host_acme_preflight` companion so a deploy mid-minute
        # cannot bypass the limit.
        await _enforce_rate_limit(conn, current_user["id"], "site_acme_preflight")

        account_id = await _resolve_default_acme_account(conn)
        if not account_id:
            raise HTTPException(
                status_code=409,
                detail="No valid ACME account exists. Configure Let's Encrypt before using ACME mode.",
            )

        results = await run_checks(
            conn,
            domains=body.domains,
            cluster_ids=[body.cluster_id],
            account_id=account_id,
        )
        return {
            "cluster_id": body.cluster_id,
            "domains": body.domains,
            "checks": results,
            "generated_at": datetime.utcnow().isoformat() + "Z",
        }
    finally:
        await close_database_connection(conn)


# ---------------------------------------------------------------------------
# POST /preview
# ---------------------------------------------------------------------------


@router.post("/preview")
async def preview_create(
    body: SiteCreate,
    authorization: str = Header(None),
    validate_haproxy_config: bool = False,
):
    """Read-only diff preview. Returns the entities that WOULD be created
    plus collision warnings. Performs NO writes.

    Phase K Phase C: when `validate_haproxy_config=true` (passed as a
    query string parameter to keep the existing `SiteCreate` body
    schema untouched), the endpoint additionally synthesises the
    candidate HAProxy config via `_synthesize_candidate_haproxy_config`
    and runs `HAProxyConfigValidator` over it. The validation result
    is returned as a `validation` block inside the same 200 OK
    envelope (the response is `200` even when the validation finds
    errors — the wizard frontend renders them inline; the actual
    `POST /api/sites` is the gate that 422s on errors).
    """
    current_user = await get_current_user_from_token(authorization)
    if not await _can_use_wizard(current_user["id"], current_user=current_user):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    conn = await get_database_connection()
    try:
        await _validate_user_cluster_access(current_user["id"], body.cluster_id, conn)

        # Phase K Phase C: rate-limit ONLY the dry-run code path so
        # legacy callers (e.g. `SiteDrafts.handlePreview` which never
        # sets the flag) keep their unrestricted preview budget. The
        # dry-run is much heavier (config render + heuristic
        # validator) and is auto-fired on every Step 4 entry — without
        # this guard a stuck retry loop in the wizard could hammer the
        # validator. Limit matches `_RATE_LIMIT_PER_MIN=5` used by
        # preflight_acme.
        if validate_haproxy_config:
            await _enforce_rate_limit(conn, current_user["id"], "site_previewed")
            logger.info(
                "WIZARD: dry-run /preview ENTER "
                f"user_id={current_user['id']} cluster_id={body.cluster_id} "
                f"ssl_mode={body.ssl.mode}"
            )

        warnings: List[str] = []

        # Phase 4 (R11-audit): preview must surface the same reserved-name
        # rule the create endpoint hard-blocks on, so operators see the
        # warning UP FRONT (before they invest time filling the wizard
        # only to be 400'd at submit). Same reserved set as the
        # `body.frontend.name`/`body.backend.name` guards in
        # create_site (Phase 3).
        _PREVIEW_RESERVED_NAMES = {
            "stats", "haproxy-stats", "haproxy_stats",
            "monitoring", "admin", "health", "status",
        }
        if body.frontend.name.lower() in _PREVIEW_RESERVED_NAMES:
            warnings.append(
                f"Frontend name '{body.frontend.name}' is reserved "
                "(collides with HAProxy listen sections like 'listen "
                "stats') and will be rejected at create time"
            )
        if body.backend.name.lower() in _PREVIEW_RESERVED_NAMES:
            warnings.append(
                f"Backend name '{body.backend.name}' is reserved "
                "(collides with HAProxy listen sections like 'listen "
                "stats') and will be rejected at create time"
            )

        # Backend name collision
        be_existing = await conn.fetchval(
            "SELECT id FROM backends WHERE name=$1 AND cluster_id=$2 AND is_active=TRUE",
            body.backend.name,
            body.cluster_id,
        )
        if be_existing:
            warnings.append(f"Backend '{body.backend.name}' already exists in cluster")

        # Frontend name collision
        fe_existing = await conn.fetchval(
            "SELECT id FROM frontends WHERE name=$1 AND cluster_id=$2 AND is_active=TRUE",
            body.frontend.name,
            body.cluster_id,
        )
        if fe_existing:
            warnings.append(f"Frontend '{body.frontend.name}' already exists in cluster")

        # Bind-port collision (HTTP frontend)
        # Bulgu #36 (round-15 audit) — collisions are BLOCKING at submit
        # time (`create_site` raises 400). Surfacing them as plain
        # `warnings` previously left operators wondering whether they
        # could proceed; they almost always could NOT. The preview now
        # adds the same row to a dedicated `blocking_errors` list AND
        # the legacy `warnings` array so existing callers keep working
        # while the wizard UI can highlight the blocker explicitly.
        blocking_errors: List[str] = []
        bind_collision = await check_bind_port_collision(
            conn,
            body.cluster_id,
            body.frontend.bind_address,
            body.frontend.bind_port,
        )
        if bind_collision:
            # Bulgu #35 (round-15 audit) — same actionable message both
            # at preview and at submit.
            msg = _explain_bind_collision(
                bind_address=body.frontend.bind_address,
                bind_port=body.frontend.bind_port,
                colliding_frontend_id=bind_collision,
                ssl_mode=body.ssl.mode,
                is_https=False,
            )
            warnings.append(msg)
            blocking_errors.append(msg)

        # Bulgu #11 / R12 fix: HTTPS frontend pre-check warnings for ALL
        # https-creating modes — upload, existing AND acme. acme used to
        # defer this to post-completion; surfacing it as a preview
        # warning lets the user fix the conflict before burning an LE
        # rate-limit quota.
        if body.ssl.mode in ("upload", "existing", "acme"):
            https_suffix = body.ssl.https_frontend_name_suffix or "-https"
            https_fe_name = f"{body.frontend.name}{https_suffix}"
            https_name_existing = await conn.fetchval(
                "SELECT id FROM frontends WHERE name=$1 AND cluster_id=$2 AND is_active=TRUE",
                https_fe_name, body.cluster_id,
            )
            if https_name_existing:
                msg = (
                    f"HTTPS frontend name '{https_fe_name}' already exists in "
                    f"cluster (frontend id={https_name_existing}). Adjust "
                    "ssl.https_frontend_name_suffix or frontend.name; "
                    "this is a hard block at submit time."
                )
                warnings.append(msg)
                blocking_errors.append(msg)
            https_bind_existing = await check_bind_port_collision(
                conn, body.cluster_id, body.frontend.bind_address, body.ssl.https_bind_port,
            )
            if https_bind_existing:
                msg = _explain_bind_collision(
                    bind_address=body.frontend.bind_address,
                    bind_port=body.ssl.https_bind_port,
                    colliding_frontend_id=https_bind_existing,
                    ssl_mode=body.ssl.mode,
                    is_https=True,
                )
                warnings.append(msg)
                blocking_errors.append(msg)

        # Bulgu #34 (round-15 audit) — cluster-aware ACME port-80
        # reachability preflight at preview time. If the operator
        # picked a non-80 bind for ACME, surface immediately whether
        # the cluster has another port-80 HTTP frontend that LE can
        # land on. Without one, submit will 400 — better to know
        # before clicking Create.
        if body.ssl.mode == "acme":
            acme_reach_err = await _validate_acme_port80_reachable(conn, body)
            if acme_reach_err:
                warnings.append(acme_reach_err)
                blocking_errors.append(acme_reach_err)

        # Bulgu #37 (round-16 audit) — cross-frontend domain ACL
        # collision detection. Two sites in the same cluster claiming
        # the same Host-header value via separate frontends produce
        # ambiguous routing; operators rarely realise this until end
        # users hit the wrong backend. Surface every overlap so the
        # operator can either de-duplicate the domain list or extend
        # the existing frontend instead of creating a new site.
        domain_collisions = await _find_cluster_domain_routing_collisions(
            conn, body.cluster_id, body.domains,
            exclude_frontend_name=body.frontend.name,
        )
        for col in domain_collisions:
            msg = (
                f"Domain {', '.join(col['conflicting_domains'])} is "
                f"already routed by frontend '{col['frontend_name']}' "
                f"(id={col['frontend_id']}) in this cluster via ACL: "
                f"`{col['acl_rule']}`. Creating a second site for the "
                "same host produces ambiguous routing — extend that "
                "frontend's `use_backend` rules instead of creating a "
                "new site, OR drop the conflicting domain from this "
                "wizard."
            )
            warnings.append(msg)
            blocking_errors.append(msg)

        # Bulgu #38 (round-16 audit) — pending ACME order overlap.
        # Detect open Let's Encrypt orders that already cover any of
        # the wizard's domains so the operator doesn't burn an LE
        # rate-limit quota on a doomed second order.
        if body.ssl.mode == "acme":
            acme_overlaps = await _find_pending_acme_order_overlap(
                conn, body.domains,
            )
            for ov in acme_overlaps:
                msg = (
                    f"Let's Encrypt order id={ov['order_id']} "
                    f"(status={ov['status']}, created {ov['created_at']}) "
                    f"already covers domain(s) "
                    f"{', '.join(ov['overlapping_domains'])}. Issuing a "
                    "second order for the same domain wastes an LE rate-"
                    "limit slot and produces a duplicate cert. Wait for "
                    "the existing order to finalise, OR cancel it via "
                    f"the LE Orders page, before re-running this wizard."
                )
                warnings.append(msg)
                blocking_errors.append(msg)

        # Bulgu #39 (round-16 audit) — non-default port URL hint.
        # When the wizard's chosen ports differ from 80/443, browsers
        # navigating to the bare `http(s)://<domain>` won't reach the
        # new site. Operators on multi-tenant clusters with the
        # default ports already taken routinely don't realise this
        # until end-users complain — surface the actual reachable
        # URLs prominently. (Informational, not blocking — a non-80
        # bind is sometimes intentional, e.g. for internal-only
        # services.)
        if (
            body.frontend.bind_port != 80
            or (body.ssl.mode != "none" and body.ssl.https_bind_port != 443)
        ):
            urls = _describe_reachable_urls(body)
            if urls:
                warnings.append(
                    "Non-default port(s) selected — clients must use the "
                    f"explicit URL(s): {', '.join(urls)}. Browsers do "
                    "not auto-append non-80/443 ports, so bare "
                    "http(s)://<domain> bookmarks WILL NOT reach this "
                    "frontend. If you need vanity URLs (port 80 / 443) "
                    "extend the existing shared frontend on the desired "
                    "port instead of creating a separate one."
                )

        # Bulgu #40 (round-16 audit) — HSTS includeSubDomains scope.
        # `Strict-Transport-Security` with `includeSubDomains` is a
        # one-way commitment: browsers cache the decision for max-age
        # seconds and refuse to fall back to HTTP for ANY subdomain.
        # When the wizard's domain list contains a deep apex (e.g.
        # `example.com` rather than `app.example.com`), the lock-in
        # affects every existing AND future subdomain in the tree.
        # Operators rarely realise the blast radius until an
        # unrelated subdomain breaks weeks later.
        if (
            body.ssl.mode in ("upload", "existing", "acme")
            and getattr(body.ssl, "hsts_enabled", False)
            and getattr(body.ssl, "hsts_include_subdomains", False)
        ):
            apex_like = [
                d for d in (body.domains or [])
                if d and not d.startswith("*.") and d.count(".") <= 1
            ]
            if apex_like:
                warnings.append(
                    "HSTS includeSubDomains is enabled for apex-like "
                    f"domain(s) {', '.join(apex_like)}. ALL subdomains "
                    "of these names will be locked to HTTPS for "
                    f"max-age={getattr(body.ssl, 'hsts_max_age', 0)}s; "
                    "browsers refuse HTTP fallback even for subdomains "
                    "that are not (yet) HTTPS-ready. Drop "
                    "hsts_include_subdomains if you have non-HTTPS "
                    "subdomains, or shorten max-age while migrating."
                )
            if getattr(body.ssl, "hsts_preload", False):
                warnings.append(
                    "HSTS preload is enabled. Submission to the "
                    "browser preload list "
                    "(https://hstspreload.org/) is MANUAL and SLOW to "
                    "reverse — removal can take months. Confirm the "
                    "preload-list prerequisites (max-age >= 31536000, "
                    "includeSubDomains, valid HTTPS for ALL subdomains) "
                    "before clicking Create."
                )

        # Bulgu #41 (round-16 audit) — server address:port duplication.
        # HAProxy accepts two `server <name> 10.0.0.1:80` lines under
        # the same backend (it routes them as independent slots), but
        # in practice this is almost always a copy/paste typo — the
        # second slot adds load to the same upstream while inflating
        # health-check traffic and slot accounting. Surface as a soft
        # warning (not blocking) — the existing comment in
        # reject_duplicate_server_names explicitly notes the address-
        # port-duplicate case can be intentional for canary aliases.
        if body.servers:
            seen_addr_port: dict = {}
            dup_pairs: List[str] = []
            for s in body.servers:
                key = (
                    (s.server_address or "").strip().lower(),
                    int(s.server_port),
                )
                if not key[0]:
                    continue
                if key in seen_addr_port:
                    dup_pairs.append(
                        f"{seen_addr_port[key]}+{s.server_name}={key[0]}:{key[1]}"
                    )
                else:
                    seen_addr_port[key] = s.server_name
            if dup_pairs:
                warnings.append(
                    f"Multiple servers point to the same address:port "
                    f"({', '.join(dup_pairs)}). HAProxy accepts this "
                    "but it doubles health-check load and rarely "
                    "matches intent — if this is a canary alias keep "
                    "it; otherwise drop the duplicate."
                )

        # preserved_listen_blocks NAME collision check (M43/R60 — name-only,
        # NOT bind regex; agent stores names as JSONB array of strings).
        preserved_rows = await conn.fetch(
            """
            SELECT preserved_listen_blocks
            FROM agents a
            JOIN haproxy_clusters hc ON hc.pool_id = a.pool_id
            WHERE hc.id = $1 AND a.preserved_listen_blocks IS NOT NULL
            """,
            body.cluster_id,
        )
        all_preserved_names = set()
        for r in preserved_rows:
            raw = r["preserved_listen_blocks"]
            try:
                names = json.loads(raw) if isinstance(raw, str) else (raw or [])
            except json.JSONDecodeError:
                names = []
            for name in names:
                if isinstance(name, str):
                    all_preserved_names.add(name.lower())
        if body.backend.name.lower() in all_preserved_names:
            warnings.append(
                f"Backend name '{body.backend.name}' collides with an agent-preserved listen block"
            )
        if body.frontend.name.lower() in all_preserved_names:
            warnings.append(
                f"Frontend name '{body.frontend.name}' collides with an agent-preserved listen block"
            )

        # ACME mode: ensure account + warn on apply_immediately requirement
        if body.ssl.mode == "acme":
            # Bulgu #60 (round-20 audit) — preview must validate the
            # OPERATOR-PROVIDED account_id, not just the auto-resolved
            # default. Pre-fix the preview only ran
            # `_resolve_default_acme_account` regardless of whether the
            # operator had explicitly chosen an account on the wizard
            # form. So if the operator picked an account that has been
            # deactivated / revoked since they opened the wizard, the
            # preview cheerfully returned `would_create=...` and the
            # operator only discovered the dead account at submit time
            # (400 from create_site's per-account validity check).
            #
            # Mirror the create_site validity gate here:
            #   - explicit account_id  → SELECT id, status FROM
            #     letsencrypt_accounts WHERE id = $1; warn if missing
            #     or status != 'valid'.
            #   - no explicit account  → fall back to
            #     `_resolve_default_acme_account` and warn if NULL.
            if body.ssl.account_id is not None:
                explicit_acc = await conn.fetchrow(
                    "SELECT id, status FROM letsencrypt_accounts WHERE id = $1",
                    body.ssl.account_id,
                )
                if explicit_acc is None:
                    warnings.append(
                        f"ssl.account_id={body.ssl.account_id} not found. "
                        "Submit will be rejected (400). Pick a different "
                        "account from Let's Encrypt → Accounts or clear "
                        "the field to auto-pick the latest valid account."
                    )
                elif (explicit_acc["status"] or "").lower() != "valid":
                    warnings.append(
                        f"ssl.account_id={body.ssl.account_id} has "
                        f"status='{explicit_acc['status']}' (not 'valid'). "
                        "Submit will be rejected (400). Re-register or "
                        "rotate the account, or clear the field to "
                        "auto-pick the latest valid account."
                    )
            else:
                acc = await _resolve_default_acme_account(conn)
                if not acc:
                    warnings.append(
                        "ssl.mode='acme' requires at least one valid letsencrypt_accounts row"
                    )
            # Bulgu #32 (round-13 audit) — surface the cluster-level
            # `acme_enabled` flag UP FRONT in preview. The create
            # endpoint hard-rejects ssl.mode='acme' on a cluster with
            # acme_enabled=false with a 400, because the HAProxy
            # config generator only injects the
            # `/.well-known/acme-challenge` ACL/use_backend block
            # when the flag is true (see haproxy_config.py:975).
            # Pre-fix preview returned a clean "would_create" envelope
            # in that case and the operator only discovered the
            # cluster-level block at submit — sometimes after burning
            # several rate-limited preview cycles on a broken config.
            # Emit a warning so step 4 of the wizard surfaces the
            # block before the operator clicks Create.
            cluster_acme_row = await conn.fetchrow(
                "SELECT acme_enabled FROM haproxy_clusters WHERE id = $1",
                body.cluster_id,
            )
            if cluster_acme_row and not cluster_acme_row.get("acme_enabled"):
                warnings.append(
                    f"cluster_id={body.cluster_id} has acme_enabled=false. "
                    "Submit will be rejected (400) — the cluster's HAProxy "
                    "config will not route /.well-known/acme-challenge/ "
                    "requests, so HTTP-01 validation cannot succeed. "
                    "Enable ACME on this cluster (Cluster Settings → "
                    "ACME) or switch ssl.mode to upload/existing/none."
                )

        # Bulgu #55 (round-19 audit) — warn when apply_immediately=true
        # against a cluster that has zero online agents.
        #
        # Pre-fix path:
        #   1. Wizard inserts backend/server/frontend rows successfully.
        #   2. apply_cluster_pending consolidates them into an APPLIED
        #      config_versions row.
        #   3. notify_agents_config_change tries to push to all agents
        #      — with zero online agents, no agent gets the new config.
        #   4. The DB now says the version is APPLIED but the running
        #      HAProxy nodes have no knowledge of the new site.
        #   5. The operator's request returned 200 (everything looked
        #      fine), but http://newsite.example.com/ returns 404 from
        #      the unmodified HAProxy node, with no indication WHY.
        #
        # We can't hard-block (legitimate cause: pre-staged config for a
        # maintenance window where agents are intentionally down), so
        # surface this as a WARNING. ACME mode is even worse — the LE
        # order will be staged but the challenge ACL never lands on any
        # HAProxy, the order's HTTP-01 validation fails after 24h and
        # the wizard_staged timeout cleanup invalidates it.
        if body.apply_immediately:
            online_agent_count = await conn.fetchval(
                """
                SELECT COUNT(*)::int
                FROM agents a
                JOIN haproxy_clusters c ON c.pool_id = a.pool_id
                WHERE c.id = $1
                  AND a.enabled = TRUE
                  AND a.status = 'online'
                """,
                body.cluster_id,
            ) or 0
            if online_agent_count == 0:
                msg = (
                    f"cluster_id={body.cluster_id} has 0 online agents. "
                    "apply_immediately=true will mark the new config "
                    "version as APPLIED in the database, but no HAProxy "
                    "node will receive it until at least one agent comes "
                    "back online and pulls the version. The site will "
                    "return 404 from the running HAProxy until then."
                )
                if body.ssl.mode == "acme":
                    msg += (
                        " ACME mode is especially risky in this state: "
                        "the LE HTTP-01 challenge cannot be answered "
                        "while agents are offline, and the order will "
                        "eventually be invalidated by the wizard_staged "
                        "24h timeout."
                    )
                warnings.append(msg)

        # Phase K Phase C: optional HAProxy dry-run validation. We
        # synthesise the candidate config, run the heuristic
        # validator, and bucket results by severity. A validator
        # crash returns `is_valid: null` + `validator_error` (matches
        # `create_site`'s non-fatal posture at site_wizard.py:1118-
        # 1124). The endpoint always returns HTTP 200 regardless of
        # severity — the wizard frontend renders errors inline next
        # to the existing `would_create` echo and keeps Create
        # disabled while errors are present. The actual gate stays
        # `POST /api/sites` itself, which 422s on real errors.
        validation_block: Optional[Dict[str, Any]] = None
        if validate_haproxy_config:
            t0 = time.time()
            try:
                from utils.haproxy_validator import (
                    HAProxyConfigValidator,
                    ValidationLevel,
                )
                candidate = await _synthesize_candidate_haproxy_config(
                    body, conn, entities_already_inserted=False
                )
                # Phase K Phase D follow-up (Bulgu #12): the wizard
                # candidate / cluster synthesis intentionally OMITS the
                # global+defaults blocks (the agent merges them with
                # its local copy on disk at apply time). Pass
                # `partial_fragment=True` so the heuristic validator
                # suppresses the "Missing 'global' section" WARNING —
                # otherwise every dry-run shows a spurious warning
                # even though the agent's real `haproxy -c` parse is
                # perfectly happy with the merged result.
                report = HAProxyConfigValidator().validate_config(
                    candidate, partial_fragment=True
                )

                def _serialize(r):
                    return {
                        "line": getattr(r, "line_number", None),
                        "section": getattr(r, "section", None),
                        "message": getattr(r, "message", ""),
                        "directive": getattr(r, "directive", None),
                        "suggestion": getattr(r, "suggestion", None),
                    }

                errs = [_serialize(r) for r in report.results
                        if r.level == ValidationLevel.ERROR][:50]
                warns = [_serialize(r) for r in report.results
                         if r.level == ValidationLevel.WARNING][:50]
                infos = [_serialize(r) for r in report.results
                         if r.level in (ValidationLevel.INFO, ValidationLevel.SUGGESTION)][:50]
                validation_block = {
                    "is_valid": bool(report.is_valid),
                    "error_count": int(getattr(report, "error_count", len(errs))),
                    "warning_count": int(getattr(report, "warning_count", len(warns))),
                    "errors": errs,
                    "warnings": warns,
                    "infos": infos,
                }
                logger.info(
                    "WIZARD: dry-run /preview EXIT "
                    f"user_id={current_user['id']} cluster_id={body.cluster_id} "
                    f"errors={len(errs)} warnings={len(warns)} "
                    f"duration_ms={int((time.time() - t0) * 1000)}"
                )
            except Exception as val_err:
                logger.warning(
                    "WIZARD: dry-run /preview validator crashed "
                    f"(non-fatal, user sees `unavailable` state): {val_err}"
                )
                validation_block = {
                    "is_valid": None,
                    "error_count": 0,
                    "warning_count": 0,
                    "errors": [],
                    "warnings": [],
                    "infos": [],
                    "validator_error": str(val_err)[:512],
                }

        # R18b audit fix (parity B): preview must echo every wizard
        # field that affects the persisted entity / generated HAProxy
        # config. Pre-fix the response only echoed the bare name +
        # bind tuple, so an operator could see "looks fine" while the
        # actual create added (or omitted) ssl_verify, per-server
        # ssl_certificate_id (CA bundle), TLS min/max etc. The
        # purpose of preview is to BUILD TRUST in what create does;
        # asymmetric output defeats it.
        # Phase K Phase D (Bulgu #4): full-parity preview payload.
        # Pre-fix the wizard returned a minimal subset of fields, so
        # an operator who set per-server check timings, backend
        # cookie persistence, frontend maxconn, HSTS, or
        # ciphersuites had NO visibility on the SiteDrafts preview
        # modal that those values would actually be applied. The
        # purpose of preview is "show me everything that will land
        # on disk so I can audit it before Apply Management". Echo
        # every operator-settable field that affects the persisted
        # entity / rendered HAProxy config — UI side then picks
        # which to render (it can collapse defaults if it wants).
        # Backward compat: existing keys keep the same shape, only
        # additive new keys.
        return {
            "would_create": {
                "cluster_id": body.cluster_id,
                "domains": list(body.domains or []),
                "backend": {
                    "name": body.backend.name,
                    "balance_method": body.backend.balance_method,
                    "mode": body.backend.mode,
                    # R18c Phase K Phase D additive fields
                    "cookie_name": getattr(body.backend, "cookie_name", None),
                    "timeout_connect": getattr(body.backend, "timeout_connect", None),
                    "timeout_server": getattr(body.backend, "timeout_server", None),
                    "http_check_method": getattr(body.backend, "http_check_method", None),
                    "http_check_uri": getattr(body.backend, "http_check_uri", None),
                    "options": getattr(body.backend, "options", None),
                },
                "servers": [
                    {
                        "server_name": s.server_name,
                        "server_address": s.server_address,
                        "server_port": s.server_port,
                        "weight": s.weight,
                        "check_enabled": s.check_enabled,
                        "ssl_enabled": s.ssl_enabled,
                        "ssl_verify": s.ssl_verify,
                        "ssl_certificate_id": s.ssl_certificate_id,
                        "ssl_min_ver": s.ssl_min_ver,
                        "ssl_max_ver": s.ssl_max_ver,
                        # R18c Phase K Phase D additive fields
                        "max_connections": getattr(s, "max_connections", None),
                        "inter": getattr(s, "inter", None),
                        "fall": getattr(s, "fall", None),
                        "rise": getattr(s, "rise", None),
                        "check_port": getattr(s, "check_port", None),
                        "backup_server": getattr(s, "backup_server", None),
                        "cookie_value": getattr(s, "cookie_value", None),
                        "ssl_sni": getattr(s, "ssl_sni", None),
                        "ssl_ciphers": getattr(s, "ssl_ciphers", None),
                    }
                    for s in body.servers
                ],
                "frontend_http": {
                    "name": body.frontend.name,
                    "bind": f"{body.frontend.bind_address}:{body.frontend.bind_port}",
                    "mode": body.frontend.mode,
                    # R18c Phase K Phase D additive fields
                    "maxconn": getattr(body.frontend, "maxconn", None),
                    "timeout_client": getattr(body.frontend, "timeout_client", None),
                    "timeout_http_request": getattr(body.frontend, "timeout_http_request", None),
                    "compression_enabled": getattr(body.frontend, "compression_enabled", None),
                    "monitor_uri": getattr(body.frontend, "monitor_uri", None),
                    "https_redirect": getattr(body.frontend, "https_redirect", None),
                    "acl_rules_count": len(getattr(body.frontend, "acl_rules", []) or []),
                    "use_backend_rules_count": len(getattr(body.frontend, "use_backend_rules", []) or []),
                    "redirect_rules_count": len(getattr(body.frontend, "redirect_rules", []) or []),
                    "options": getattr(body.frontend, "options", None),
                },
                "frontend_https": (
                    {
                        "name": f"{body.frontend.name}{body.ssl.https_frontend_name_suffix or '-https'}",
                        "bind": f"{body.frontend.bind_address}:{body.ssl.https_bind_port}",
                        "deferred": body.ssl.mode == "acme",
                        "ssl_alpn": body.ssl.ssl_alpn,
                        "ssl_min_ver": body.ssl.ssl_min_ver,
                        "ssl_max_ver": body.ssl.ssl_max_ver,
                        "ssl_ciphers": body.ssl.ssl_ciphers,
                        "ssl_strict_sni": body.ssl.ssl_strict_sni,
                        # R18 minimum-parity field: inbound mTLS verify mode.
                        "ssl_verify": body.ssl.ssl_verify,
                        # R18 minimum-parity field: existing-cert id (none in upload/acme).
                        "ssl_certificate_id": body.ssl.ssl_certificate_id,
                        # R18c Phase K Phase D additive fields
                        "ssl_ciphersuites": getattr(body.ssl, "ssl_ciphersuites", None),
                    }
                    if body.ssl.mode in ("upload", "existing", "acme")
                    else None
                ),
                "ssl_mode": body.ssl.mode,
                "https_redirect_rules": _build_redirect_rules(body),
                # R18b round 2 audit fix: HSTS shaping lives on
                # `SSLChoice` (body.ssl.hsts_*), NOT on `FrontendStep`.
                # Pre-fix the preview pulled from `body.frontend` —
                # which has no hsts_* attrs — so the dict was always
                # `{enabled: False, max_age: None, ...}` regardless of
                # the operator's actual selection. The actual create
                # path correctly reads from `body.ssl` (see line ~764),
                # so preview disagreed with create.
                "hsts": {
                    "enabled": getattr(body.ssl, "hsts_enabled", False),
                    "max_age": getattr(body.ssl, "hsts_max_age", None),
                    "include_subdomains": getattr(body.ssl, "hsts_include_subdomains", False),
                    "preload": getattr(body.ssl, "hsts_preload", False),
                },
            },
            "warnings": warnings,
            # Bulgu #36 (round-15 audit) — preview surfaces explicit
            # blocker errors (collision + cluster-state failures the
            # submit endpoint hard-rejects) so the wizard UI can grey
            # out Create instead of letting the user click through into
            # an unexpected 400. Empty list means "preview is clean".
            "blocking_errors": blocking_errors,
            "apply_immediately": body.apply_immediately,
            "version_name_template": "bulk-site-create-<ts>",
            "validation": validation_block,
        }
    finally:
        await close_database_connection(conn)


# ---------------------------------------------------------------------------
# POST /  (atomic create — Section 6.2 of plan)
# ---------------------------------------------------------------------------


def _entity_snapshot(entity_type: str, entity_id: int) -> dict:
    """CREATE-style snapshot for bulk_snapshots metadata. Compatible with
    rollback_entity_from_snapshot's expected shape."""
    return {
        "entity_snapshot": {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "operation": "CREATE",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "old_values": {},
            "new_values": {},
            "changed_fields": [],
        }
    }


@router.post("")
async def create_site(
    body: SiteCreate,
    authorization: str = Header(None),
):
    """Atomic multi-entity create for a new site (Issue #14).

    Returns one of these statuses:
      - created_pending                -> all entities created, version PENDING (apply_immediately=false)
      - created_applied                -> all entities created + apply succeeded
      - created_pending_apply_failed   -> entities created, PENDING version exists, apply failed
      - applied_acme_staging_failed    -> entities created+applied, but ACME staging failed (rare)
    """
    current_user = await get_current_user_from_token(authorization)
    user_id = current_user["id"]

    # Composite RBAC: backend+frontend create, plus apply.execute when applying.
    # R18c round 7 (Bulgu 1): pass current_user so admin bypass skips the
    # extra is_admin DB roundtrip (4 calls below).
    # R18c round 10 (CRITICAL): seeded permissions are PLURAL
    # (`frontends.create`, `backends.create`); see _can_use_wizard for
    # the full rationale. SSL is already singular by design.
    for resource, action in (("backends", "create"), ("frontends", "create"), ("ssl", "create")):
        if not await check_user_permission(user_id, resource, action, current_user=current_user):
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient permissions: {resource}.{action} required",
            )
    if body.apply_immediately and not await check_user_permission(
        user_id, "apply", "execute", current_user=current_user
    ):
        raise HTTPException(
            status_code=403, detail="Insufficient permissions: apply.execute required"
        )

    conn = await get_database_connection()
    try:
        await _validate_user_cluster_access(user_id, body.cluster_id, conn)

        # ----- Pre-create checks (must succeed before transaction)

        # Phase 3 (R11-audit follow-up): reserved-name check parity with
        # `routers/frontend.py::create_frontend` and
        # `routers/backend.py::create_backend`. These names collide with
        # the well-known `listen stats` / `listen monitoring` blocks that
        # agents preserve from local config; manual create endpoints
        # already 400 on these. The wizard now refuses them too instead
        # of letting the apply-time `haproxy -c` fail with the
        # confusing "proxy has same name" error.
        _RESERVED_NAMES = {
            "stats", "haproxy-stats", "haproxy_stats",
            "monitoring", "admin", "health", "status",
        }
        if body.frontend.name.lower() in _RESERVED_NAMES:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Frontend name '{body.frontend.name}' is reserved. "
                    "It conflicts with common HAProxy listen sections "
                    "(e.g. 'listen stats'). Please choose a different name."
                ),
            )
        if body.backend.name.lower() in _RESERVED_NAMES:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Backend name '{body.backend.name}' is reserved. "
                    "It conflicts with common HAProxy listen sections "
                    "(e.g. 'listen stats'). Please choose a different name."
                ),
            )

        be_collision = await conn.fetchval(
            "SELECT id FROM backends WHERE name=$1 AND cluster_id=$2 AND is_active=TRUE",
            body.backend.name,
            body.cluster_id,
        )
        if be_collision:
            raise HTTPException(
                status_code=400, detail=f"Backend '{body.backend.name}' already exists"
            )
        fe_collision = await conn.fetchval(
            "SELECT id FROM frontends WHERE name=$1 AND cluster_id=$2 AND is_active=TRUE",
            body.frontend.name,
            body.cluster_id,
        )
        if fe_collision:
            raise HTTPException(
                status_code=400, detail=f"Frontend '{body.frontend.name}' already exists"
            )

        bind_collision = await check_bind_port_collision(
            conn, body.cluster_id, body.frontend.bind_address, body.frontend.bind_port
        )
        if bind_collision:
            # Bulgu #35 (round-15 audit) — actionable collision message.
            raise HTTPException(
                status_code=400,
                detail=_explain_bind_collision(
                    bind_address=body.frontend.bind_address,
                    bind_port=body.frontend.bind_port,
                    colliding_frontend_id=bind_collision,
                    ssl_mode=body.ssl.mode,
                    is_https=False,
                ),
            )

        # Bulgu #11 / R12 fix: pre-check HTTPS frontend name + bind port
        # collisions for ALL https-creating modes — upload, existing, AND
        # acme. Previously acme deferred this to _execute_post_completion_
        # actions which only runs after Let's Encrypt has issued the cert
        # (potentially many minutes later). Detecting the collision up
        # front lets the user fix it before they spend an LE rate-limit
        # quota on a doomed order.
        if body.ssl.mode in ("upload", "existing", "acme"):
            https_suffix = body.ssl.https_frontend_name_suffix or "-https"
            https_fe_name = f"{body.frontend.name}{https_suffix}"
            https_name_collision = await conn.fetchval(
                "SELECT id FROM frontends WHERE name=$1 AND cluster_id=$2 AND is_active=TRUE",
                https_fe_name,
                body.cluster_id,
            )
            if https_name_collision:
                raise HTTPException(
                    status_code=400,
                    detail=f"HTTPS frontend name '{https_fe_name}' already exists "
                    f"(adjust ssl.https_frontend_name_suffix or frontend.name)",
                )
            https_bind_collision = await check_bind_port_collision(
                conn, body.cluster_id, body.frontend.bind_address, body.ssl.https_bind_port
            )
            if https_bind_collision:
                # Bulgu #35 (round-15 audit) — actionable HTTPS collision message.
                raise HTTPException(
                    status_code=400,
                    detail=_explain_bind_collision(
                        bind_address=body.frontend.bind_address,
                        bind_port=body.ssl.https_bind_port,
                        colliding_frontend_id=https_bind_collision,
                        ssl_mode=body.ssl.mode,
                        is_https=True,
                    ),
                )

        # ACME mode: resolve account UP FRONT so the post-commit step has it
        acme_account_id: Optional[int] = None
        if body.ssl.mode == "acme":
            # R18c audit fix (round 5 #4 — KRITIK functional): refuse
            # to stage an ACME order if the target cluster has
            # `acme_enabled=false`. PRE-FIX the wizard happily
            # created the wizard_staged order, but the HAProxy
            # config generator only injects the
            # `/.well-known/acme-challenge` routing block when the
            # cluster's `acme_enabled` flag is true (see
            # haproxy_config.py:357). With the flag off, the agent
            # reload deployed a config that did NOT route challenge
            # requests, so the order's HTTP-01 validation failed and
            # the operator saw a generic "ACME order failed" with no
            # hint that the cluster's own toggle was the cause. The
            # explicit 400 here makes the misconfiguration visible
            # at submit time so the operator can flip the toggle on
            # the cluster page before re-submitting.
            cluster_acme_row = await conn.fetchrow(
                "SELECT acme_enabled FROM haproxy_clusters WHERE id = $1",
                body.cluster_id,
            )
            if cluster_acme_row and not cluster_acme_row.get("acme_enabled"):
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"cluster_id={body.cluster_id} has acme_enabled=false. "
                        "Wizard cannot stage an ACME order: the HAProxy config "
                        "for this cluster will not route /.well-known/acme-challenge "
                        "requests, so the HTTP-01 validation would always fail. "
                        "Enable ACME on the cluster (Cluster Management → ACME "
                        "settings) before retrying, or pick a different SSL mode."
                    ),
                )
            # Bulgu #34 (round-15 audit) — cluster-aware port-80 reachability.
            # Now that the model-level `bind_port=80` requirement has been
            # relaxed for multi-tenant clusters, the route handler is the
            # last gate. If the new frontend is on a non-80 port we must
            # confirm SOME other port-80 HTTP frontend exists in the
            # cluster — otherwise LE's HTTP-01 probe has nowhere to land.
            acme_reach_error = await _validate_acme_port80_reachable(conn, body)
            if acme_reach_error:
                raise HTTPException(status_code=400, detail=acme_reach_error)

            # Bulgu #38 (round-16 audit) — pending ACME order overlap.
            # Block submit when another in-flight order already covers
            # any of the wizard's domains so the operator doesn't race
            # two orders against the same LE rate-limit slot.
            acme_overlaps = await _find_pending_acme_order_overlap(
                conn, body.domains,
            )
            if acme_overlaps:
                first = acme_overlaps[0]
                raise HTTPException(
                    status_code=409,
                    detail=(
                        f"Domain(s) "
                        f"{', '.join(first['overlapping_domains'])} are "
                        f"already in an active Let's Encrypt order "
                        f"(id={first['order_id']}, "
                        f"status={first['status']}, "
                        f"created {first['created_at']}). Wait for it to "
                        "finalise, OR cancel it via the LE Orders page, "
                        "before re-running this wizard. Re-issuing a "
                        "second cert for the same names burns an LE "
                        "rate-limit slot and leaves duplicate cert rows "
                        "behind."
                    ),
                )

        # Bulgu #37 (round-16 audit) — cross-frontend domain ACL
        # collision. Applies to ALL SSL modes (not just ACME) because
        # the same Host: header on two different frontends produces
        # ambiguous routing regardless of TLS termination. Hard-block
        # here so the operator sees the conflict at submit time.
        domain_collisions = await _find_cluster_domain_routing_collisions(
            conn, body.cluster_id, body.domains,
            exclude_frontend_name=body.frontend.name,
        )
        if domain_collisions:
            first = domain_collisions[0]
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Domain(s) "
                    f"{', '.join(first['conflicting_domains'])} are "
                    f"already routed by frontend '{first['frontend_name']}' "
                    f"(id={first['frontend_id']}) via ACL "
                    f"`{first['acl_rule']}`. Two sites in the same "
                    "cluster claiming the same Host header produce "
                    "undefined routing. Either remove the overlapping "
                    "domain from this wizard, or extend the existing "
                    "frontend with a new `use_backend` rule instead of "
                    "creating a second site."
                ),
            )
            if body.ssl.account_id is not None:
                # R13 fix: validate user-supplied account_id BEFORE we
                # rely on it. Previously `body.ssl.account_id or
                # _resolve_default_acme_account()` accepted any truthy
                # int — so account_id=999 (deleted / from another tenant
                # / typo) silently bypassed validation and surfaced as
                # an FK violation deep inside create_order_staged, which
                # the user only saw as a generic 500 long after submit.
                row = await conn.fetchrow(
                    """
                    SELECT id, status FROM letsencrypt_accounts
                    WHERE id = $1
                    """,
                    body.ssl.account_id,
                )
                if not row:
                    raise HTTPException(
                        status_code=400,
                        detail=f"ssl.account_id={body.ssl.account_id} does not exist",
                    )
                if row["status"] and row["status"] != "valid":
                    raise HTTPException(
                        status_code=400,
                        detail=f"ssl.account_id={body.ssl.account_id} is not valid "
                        f"(status='{row['status']}'). Pick a different account or "
                        "leave the field empty to auto-pick the latest valid one.",
                    )
                acme_account_id = body.ssl.account_id
            else:
                acme_account_id = await _resolve_default_acme_account(conn)
            if not acme_account_id:
                raise HTTPException(
                    status_code=409,
                    detail="No valid ACME account exists. Configure Let's Encrypt first.",
                )

        # preserved_listen_blocks NAME collision (M43/R60)
        preserved_rows = await conn.fetch(
            """
            SELECT preserved_listen_blocks
            FROM agents a
            JOIN haproxy_clusters hc ON hc.pool_id = a.pool_id
            WHERE hc.id = $1 AND a.preserved_listen_blocks IS NOT NULL
            """,
            body.cluster_id,
        )
        preserved_names = set()
        for r in preserved_rows:
            raw = r["preserved_listen_blocks"]
            try:
                names = json.loads(raw) if isinstance(raw, str) else (raw or [])
            except json.JSONDecodeError:
                names = []
            for n in names:
                if isinstance(n, str):
                    preserved_names.add(n.lower())
        if body.backend.name.lower() in preserved_names:
            raise HTTPException(
                status_code=400,
                detail=f"Backend name '{body.backend.name}' collides with an agent-preserved listen block",
            )
        if body.frontend.name.lower() in preserved_names:
            raise HTTPException(
                status_code=400,
                detail=f"Frontend name '{body.frontend.name}' collides with an agent-preserved listen block",
            )

        # Capture pre_apply_snapshot (current applied config) for reject path
        pre_apply_snapshot_row = await conn.fetchrow(
            """
            SELECT config_content FROM config_versions
            WHERE cluster_id = $1 AND status = 'APPLIED' AND config_content IS NOT NULL
            ORDER BY created_at DESC LIMIT 1
            """,
            body.cluster_id,
        )
        pre_apply_snapshot = (pre_apply_snapshot_row or {}).get("config_content") or ""

        ts = _now_ts()
        # Phase D: version-name rename `bulk-proxied-host-create-{ts}`
        # → `bulk-site-create-{ts}` to match the user-visible "Site"
        # rebrand. The reject path on `cluster.py` recognises BOTH
        # prefixes so historical APPLIED versions (created before this
        # rename) keep behaving correctly during reject/undo.
        version_name = f"bulk-site-create-{ts}"
        bulk_snapshots: List[dict] = []
        created_ids: Dict[str, Any] = {}

        # ----- Atomic transaction
        async with conn.transaction():
            # Bulgu #54 (round-19 audit) — serialize concurrent wizard
            # creates against the SAME cluster.
            #
            # Pre-fix the bind-port / frontend-name / HTTPS-bind-port
            # collision checks (lines ~1813-1864) ran OUTSIDE this
            # transaction. Two operators (or the same operator's two
            # browser tabs) submitting wizards back-to-back against the
            # same cluster could both pass the pre-flight check (no
            # row exists yet for either), both enter their own
            # transactions, and both INSERT — there is NO UNIQUE
            # constraint on (cluster_id, bind_address, bind_port), so
            # the second INSERT silently succeeds and the cluster ends
            # up with two frontends bound to the same port. The next
            # apply's `haproxy -c` fails with "duplicate bind" and
            # blocks ALL subsequent applies on the cluster until an
            # operator manually deletes one of the rows.
            #
            # Acquire a cluster-scoped transactional advisory lock as
            # the FIRST statement of the wizard's create transaction.
            # `pg_advisory_xact_lock` automatically releases on COMMIT
            # or ROLLBACK so we never need to remember to unlock.
            # Namespace key 18181819 (round-19 specific) avoids
            # colliding with the existing draft-cap lock (18181818).
            # Concurrent wizard runs for DIFFERENT clusters proceed
            # in parallel; only the same-cluster races serialise.
            await conn.execute(
                "SELECT pg_advisory_xact_lock($1, $2)",
                18181819, int(body.cluster_id),
            )

            # Bulgu #54 (round-19 audit) — re-check bind / name
            # collisions INSIDE the lock. The pre-flight checks
            # at lines ~1813-1864 already ran before this point
            # (so unrelated callers get fast 400s without waiting
            # for the lock), but a concurrent wizard transaction
            # that committed between the pre-flight and the lock
            # acquisition could have introduced a colliding row.
            # Re-running the same helpers under the lock is cheap
            # (indexed lookups) and closes the race.
            late_bind = await check_bind_port_collision(
                conn, body.cluster_id, body.frontend.bind_address, body.frontend.bind_port
            )
            if late_bind:
                raise HTTPException(
                    status_code=409,
                    detail=_explain_bind_collision(
                        bind_address=body.frontend.bind_address,
                        bind_port=body.frontend.bind_port,
                        colliding_frontend_id=late_bind,
                        ssl_mode=body.ssl.mode,
                        is_https=False,
                    ),
                )
            late_fe_name = await conn.fetchval(
                "SELECT id FROM frontends WHERE name=$1 AND cluster_id=$2 AND is_active=TRUE",
                body.frontend.name, body.cluster_id,
            )
            if late_fe_name:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        f"Frontend '{body.frontend.name}' was created by "
                        "another request just now. Pick a different "
                        "name and resubmit."
                    ),
                )
            if body.ssl.mode in ("upload", "existing", "acme"):
                _https_suffix = body.ssl.https_frontend_name_suffix or "-https"
                _https_fe_name = f"{body.frontend.name}{_https_suffix}"
                late_https_name = await conn.fetchval(
                    "SELECT id FROM frontends WHERE name=$1 AND cluster_id=$2 AND is_active=TRUE",
                    _https_fe_name, body.cluster_id,
                )
                if late_https_name:
                    raise HTTPException(
                        status_code=409,
                        detail=(
                            f"HTTPS frontend '{_https_fe_name}' was "
                            "created by another request just now. "
                            "Adjust ssl.https_frontend_name_suffix or "
                            "frontend.name and resubmit."
                        ),
                    )
                late_https_bind = await check_bind_port_collision(
                    conn, body.cluster_id, body.frontend.bind_address, body.ssl.https_bind_port
                )
                if late_https_bind:
                    raise HTTPException(
                        status_code=409,
                        detail=_explain_bind_collision(
                            bind_address=body.frontend.bind_address,
                            bind_port=body.ssl.https_bind_port,
                            colliding_frontend_id=late_https_bind,
                            ssl_mode=body.ssl.mode,
                            is_https=True,
                        ),
                    )

            be_id = await create_backend_row(conn, body.backend, body.cluster_id, mark_pending=True)
            created_ids["backend_id"] = be_id
            bulk_snapshots.append(_entity_snapshot("backend", be_id))

            server_ids: List[int] = []
            for idx, srv in enumerate(body.servers):
                # R18b audit fix (round 4 #C): per-server CA-bundle
                # `ssl_certificate_id` (HAProxy `ca-file` for upstream
                # verification) bypassed cluster scoping pre-R18b.
                # Mirror the listing/`select_existing_cert` rule so a
                # cluster-A operator cannot reference a cluster-B-only
                # cert id and silently use it as the upstream CA bundle.
                srv_cert_id = getattr(srv, "ssl_certificate_id", None)
                if srv_cert_id is not None:
                    eligible = await validate_server_ca_bundle_eligibility(
                        conn, srv_cert_id, body.cluster_id
                    )
                    if not eligible:
                        raise HTTPException(
                            status_code=400,
                            detail=(
                                f"server[{idx}].ssl_certificate_id={srv_cert_id} "
                                f"is not visible to cluster {body.cluster_id}. "
                                "Pick a cert that is global or already bound to "
                                "this cluster."
                            ),
                        )
                sid = await create_server_row(
                    conn, be_id, body.backend.name, body.cluster_id, srv, mark_pending=True
                )
                server_ids.append(sid)
                bulk_snapshots.append(_entity_snapshot("server", sid))
            created_ids["server_ids"] = server_ids

            # Phase 3 (R11-audit follow-up): drop `option httpchk` from the
            # frontend `options` block. `option httpchk` is a backend-only
            # health-check directive — when it appears under a frontend
            # the agent reload emits a warning. `routers/frontend.py`
            # already strips it via `filter_httpchk_from_options`; the
            # wizard now mirrors that behaviour so a draft populated by
            # an operator who blindly copied `option httpchk` from a
            # template still produces a clean, warning-free config.
            def _filter_httpchk_from_options(options: Optional[str]) -> Optional[str]:
                if not options:
                    return options
                kept = [
                    line for line in options.splitlines()
                    if line.strip().lower() != "option httpchk"
                ]
                return "\n".join(kept) if kept else None

            _frontend_options_filtered = _filter_httpchk_from_options(body.frontend.options)

            # Wire backend as default_backend for the HTTP frontend
            http_frontend_payload = body.frontend.model_copy(update={
                "default_backend": body.backend.name,
                "redirect_rules": _build_redirect_rules(body),
                "https_redirect": False,  # already expanded into redirect_rules
                "options": _frontend_options_filtered,
            })

            ssl_certificate_id_for_https: Optional[int] = None
            if body.ssl.mode == "upload":
                # Bulgu #25 (round-12 audit): verify the uploaded cert's
                # SAN/CN entries cover EVERY wizard domain. Pre-fix the
                # wizard happily deployed a cert for site-A while the
                # operator's wizard listed site-B in `domains` — HAProxy
                # served the wrong cert and every browser TLS handshake
                # failed with NET::ERR_CERT_COMMON_NAME_INVALID. We
                # parse the PEM once here (and `create_cert_row` parses
                # it again — the duplicate is cheap and keeps the two
                # call sites independent).
                from utils.ssl_parser import (
                    parse_ssl_certificate as _parse_cert,
                    find_uncovered_domains,
                )
                _cert_info = _parse_cert(body.ssl.certificate_content or "")
                if not _cert_info.get("error"):
                    _cert_domains = _cert_info.get("all_domains") or []
                    uncovered = find_uncovered_domains(list(body.domains or []), _cert_domains)
                    if uncovered:
                        raise HTTPException(
                            status_code=400,
                            detail=(
                                f"SSL certificate does not cover the following wizard "
                                f"domain(s): {', '.join(uncovered)}. Cert SAN/CN list: "
                                f"{', '.join(_cert_domains) or '(empty)'}. Either upload "
                                "a cert whose SAN list includes every wizard domain "
                                "(wildcards like '*.example.com' match a single label) "
                                "or remove the uncovered domain(s) from the wizard."
                            ),
                        )

                cert_payload_obj = type("_CertObj", (), {})()
                cert_payload_obj.name = body.ssl.name or f"cert-{body.backend.name}-{ts}"
                cert_payload_obj.certificate_content = body.ssl.certificate_content or ""
                cert_payload_obj.private_key_content = body.ssl.private_key_content or ""
                cert_payload_obj.chain_content = body.ssl.chain_content or None
                cert_payload_obj.primary_domain = (body.domains or [None])[0]
                cert_payload_obj.all_domains = list(body.domains)
                cert_payload_obj.usage_type = "frontend"

                cert_id = await create_cert_row(conn, cert_payload_obj, body.cluster_id)
                ssl_certificate_id_for_https = cert_id
                created_ids["ssl_certificate_id"] = cert_id
                bulk_snapshots.append(_entity_snapshot("ssl_certificate", cert_id))
            elif body.ssl.mode == "existing":
                if not body.ssl.ssl_certificate_id:
                    raise HTTPException(
                        status_code=400,
                        detail="ssl.mode='existing' requires ssl_certificate_id",
                    )
                resolved = await select_existing_cert(
                    conn, body.ssl.ssl_certificate_id, body.cluster_id
                )
                if not resolved:
                    raise HTTPException(
                        status_code=400,
                        detail=f"ssl_certificate_id {body.ssl.ssl_certificate_id} not found / inactive",
                    )

                # Bulgu #25 (round-12 audit) — existing-cert branch: read
                # the cert's stored SAN list from the ssl_certificates
                # row and apply the same coverage check as the upload
                # branch above. Pre-fix an operator could pick a cert
                # for site-A and run the wizard for site-B's domain;
                # the wizard would bind the HTTPS frontend to the
                # wrong cert and surface a runtime TLS-handshake
                # failure rather than a clean 400 at submit time.
                from utils.ssl_parser import find_uncovered_domains
                _cert_row = await conn.fetchrow(
                    "SELECT all_domains, status, days_until_expiry, primary_domain "
                    "FROM ssl_certificates WHERE id = $1",
                    resolved,
                )
                if _cert_row:
                    try:
                        _stored_domains = _cert_row["all_domains"]
                        if isinstance(_stored_domains, str):
                            import json as _json
                            _stored_domains = _json.loads(_stored_domains)
                        _stored_domains = list(_stored_domains or [])
                    except Exception:
                        _stored_domains = []
                    # Fall back to primary_domain if SAN list is unset
                    # (older imports lack it).
                    if not _stored_domains and _cert_row["primary_domain"]:
                        _stored_domains = [_cert_row["primary_domain"]]
                    if _stored_domains:
                        uncovered = find_uncovered_domains(
                            list(body.domains or []), _stored_domains
                        )
                        if uncovered:
                            raise HTTPException(
                                status_code=400,
                                detail=(
                                    f"Existing SSL certificate id={resolved} does not "
                                    f"cover the following wizard domain(s): "
                                    f"{', '.join(uncovered)}. Cert SAN/CN list: "
                                    f"{', '.join(_stored_domains)}. Pick a different "
                                    "certificate or remove the uncovered domain(s)."
                                ),
                            )
                    # Bulgu #24 (round-12 audit) — existing-cert branch:
                    # also reject if the chosen cert is already expired,
                    # mirroring the upload-mode rejection in create_cert_row.
                    if (_cert_row["status"] or "").lower() == "expired":
                        raise HTTPException(
                            status_code=400,
                            detail=(
                                f"Existing SSL certificate id={resolved} is expired "
                                f"({_cert_row['days_until_expiry']} days past notAfter). "
                                "Pick a non-expired certificate or upload a fresh one."
                            ),
                        )

                ssl_certificate_id_for_https = resolved
                created_ids["ssl_certificate_id"] = resolved

            # HTTP frontend is always created
            http_fe_id = await create_frontend_row(
                conn,
                http_frontend_payload,
                body.cluster_id,
                ssl_certificate_id=None,
                ssl_enabled=False,
                mark_pending=True,
            )
            created_ids["http_frontend_id"] = http_fe_id
            bulk_snapshots.append(_entity_snapshot("frontend", http_fe_id))

            # HTTPS frontend for upload/existing modes (acme defers it)
            if body.ssl.mode in ("upload", "existing") and ssl_certificate_id_for_https:
                # v1.5.0 advanced TLS: pass ALPN, TLS versions, ciphers, HSTS
                # tuning through to create_frontend_row (which already supports
                # ssl_alpn / ssl_ciphers / ssl_strict_sni / etc.).
                #
                # R12 fix: idempotent HSTS injection. If the user already wrote
                # a Strict-Transport-Security directive into response_headers
                # (e.g. resumed from a draft, or hand-crafted advanced rules),
                # do NOT append a second one — duplicate headers confuse some
                # clients and inflate the HAProxy config.
                hsts_response_headers = body.frontend.response_headers or ""
                _hsts_already_present = (
                    "strict-transport-security" in hsts_response_headers.lower()
                )
                if body.ssl.hsts_enabled and not _hsts_already_present:
                    hsts_value = f"max-age={body.ssl.hsts_max_age}"
                    if body.ssl.hsts_include_subdomains:
                        hsts_value += "; includeSubDomains"
                    if body.ssl.hsts_preload:
                        hsts_value += "; preload"
                    hsts_line = f'http-response set-header Strict-Transport-Security "{hsts_value}"'
                    hsts_response_headers = (
                        (hsts_response_headers + "\n" + hsts_line)
                        if hsts_response_headers
                        else hsts_line
                    )
                https_payload = body.frontend.model_copy(update={
                    "default_backend": body.backend.name,
                    "redirect_rules": [],
                    "https_redirect": False,
                    "response_headers": hsts_response_headers or None,
                    # Phase 3: same `option httpchk` strip on the HTTPS
                    # frontend payload (it inherits `body.frontend.options`).
                    "options": _frontend_options_filtered,
                })
                # Inject TLS tuning fields onto the payload (FrontendStep does
                # not declare them, but create_frontend_row reads them via
                # getattr — set them as ad-hoc attrs).
                for attr_name, attr_val in (
                    ("ssl_alpn", body.ssl.ssl_alpn),
                    ("ssl_ciphers", body.ssl.ssl_ciphers),
                    ("ssl_ciphersuites", body.ssl.ssl_ciphersuites),
                    ("ssl_min_ver", body.ssl.ssl_min_ver),
                    ("ssl_max_ver", body.ssl.ssl_max_ver),
                    ("ssl_strict_sni", body.ssl.ssl_strict_sni),
                    # R17 minimum-parity: mTLS client cert auth on HTTPS bind.
                    # Manual frontend create endpoint accepts this; wizard now
                    # surfaces it via SSLChoice.ssl_verify so enterprise users
                    # don't have to drop down to manual create just for mTLS.
                    ("ssl_verify", body.ssl.ssl_verify),
                ):
                    object.__setattr__(https_payload, attr_name, attr_val)
                suffix = body.ssl.https_frontend_name_suffix or "-https"
                https_name = f"{body.frontend.name}{suffix}"
                https_fe_id = await create_frontend_row(
                    conn,
                    https_payload,
                    body.cluster_id,
                    ssl_certificate_id=ssl_certificate_id_for_https,
                    ssl_enabled=True,
                    bind_port_override=body.ssl.https_bind_port,
                    name_override=https_name,
                    mark_pending=True,
                )
                created_ids["https_frontend_id"] = https_fe_id
                bulk_snapshots.append(_entity_snapshot("frontend", https_fe_id))

            # Generate fresh HAProxy config + checksum for the new version.
            #
            # R18c audit fix (round 1 #4 — KRITIK): pass the active
            # transaction connection. Pre-fix the call obtained a
            # SECOND pooled connection, which under PostgreSQL READ
            # COMMITTED cannot see the uncommitted INSERTs that
            # just created the wizard's backend / servers / HTTP
            # frontend / HTTPS frontend in this same transaction.
            # Result: the freshly-built config_versions snapshot
            # OMITTED the wizard-created entities, so the operator's
            # subsequent apply re-deployed a config without the new
            # site even though the wizard returned "created
            # successfully". This silent inconsistency was the root
            # of the "wizard says success but agent reload doesn't
            # show new bind" class of reports.
            try:
                # Phase K Phase C: route through the shared candidate
                # synthesizer so the dry-run gate (`/preview` with
                # `validate_haproxy_config=true`) and the apply gate
                # (this `create_site` block) can never silently
                # desync. Pinned by
                # `tests/test_site_wizard_phase_k.py::
                # test_phase_k_create_site_and_preview_use_same_synthesis_helper`.
                config_content = await _synthesize_candidate_haproxy_config(
                    body, conn, entities_already_inserted=True
                )
            except Exception as cfg_err:
                logger.error(f"WIZARD: config gen failed: {cfg_err}")
                config_content = ""

            # Phase 2 (PR-5): pre-persist HAProxy config validation gate.
            # Generation already applies the in-line safeguards
            # (`_apply_bind_ssl_verify`, `_format_redirect_rule`,
            # `_categorize_haproxy_directive` bucket order, stick-table
            # dedup) so the rendered config is structurally sound. As a
            # defence-in-depth pass we ALSO run HAProxyConfigValidator on
            # the generated string and ABORT the transaction if any
            # ERROR-level diagnostic fires — the user-stated rule is "UI
            # must not allow operations that fail haproxy validation",
            # so we refuse to persist a config_versions row that would
            # not reload cleanly. A validator crash is non-fatal (the
            # apply-time `haproxy -c` on the agent is the ultimate
            # gate); we only block on real ERROR-level findings.
            if config_content:
                try:
                    from utils.haproxy_validator import (
                        HAProxyConfigValidator,
                        ValidationLevel,
                    )
                    # Phase K Phase D follow-up (Bulgu #12): same as
                    # the /preview dry-run — the wizard's synthesised
                    # cluster config is a PARTIAL fragment that the
                    # agent merges with its local global+defaults at
                    # reload time. Skip the global/defaults missing-
                    # section diagnostics so the apply-time gate does
                    # not refuse to persist a perfectly valid wizard
                    # output on a spurious WARNING (the gate currently
                    # only blocks on ERROR-level, but emitting WARN
                    # noise still leaks to the operator-visible
                    # response trail and the version-history page).
                    _val_report = HAProxyConfigValidator().validate_config(
                        config_content, partial_fragment=True
                    )
                    _val_errors = [
                        r for r in _val_report.results
                        if r.level == ValidationLevel.ERROR
                    ]
                    if _val_errors:
                        _err_payload = [
                            {
                                "line": e.line_number,
                                "section": e.section,
                                "message": e.message,
                                "directive": e.directive,
                            }
                            for e in _val_errors[:20]  # cap response payload size
                        ]
                        logger.error(
                            "WIZARD: pre-persist haproxy validation FAILED: "
                            f"{len(_val_errors)} error(s) — first: {_err_payload[0]}"
                        )
                        raise HTTPException(
                            status_code=422,
                            detail={
                                "error": "haproxy_validation_failed",
                                "message": (
                                    f"Generated HAProxy configuration would fail "
                                    f"validation ({len(_val_errors)} error(s)). "
                                    "The wizard refused to persist a config that "
                                    "would not reload cleanly. Adjust the inputs "
                                    "and try again."
                                ),
                                "errors": _err_payload,
                            },
                        )
                except HTTPException:
                    raise  # propagate so the transaction rolls back
                except Exception as _val_err:
                    # Validator itself crashed — non-fatal. The apply-time
                    # `haproxy -c` on the agent will catch any real syntax
                    # issue; do NOT block create on a defensive-validator
                    # bug.
                    logger.warning(
                        f"WIZARD: pre-persist validator crashed "
                        f"(non-fatal, apply-time haproxy -c remains the ultimate "
                        f"gate): {_val_err}"
                    )

            import hashlib
            config_hash = hashlib.sha256(config_content.encode()).hexdigest()

            metadata = {
                "wizard": "site_create",
                "version": "v1.5.0",
                "created_by_user_id": user_id,
                "ssl_mode": body.ssl.mode,
                "domains": list(body.domains),
                "bulk_snapshots": bulk_snapshots,
                "pre_apply_snapshot": pre_apply_snapshot,
            }

            config_version_id = await conn.fetchval(
                """
                INSERT INTO config_versions
                    (cluster_id, version_name, config_content, checksum, created_by,
                     is_active, status, description, metadata)
                VALUES ($1, $2, $3, $4, $5, FALSE, 'PENDING', $6, $7::jsonb)
                RETURNING id
                """,
                body.cluster_id,
                version_name,
                config_content,
                config_hash,
                user_id,
                f"Wizard-created site '{body.backend.name}' for {', '.join(body.domains)}",
                json.dumps(metadata),
            )
            created_ids["config_version_id"] = config_version_id

        # ----- POST-COMMIT actions
        response_status = "created_pending"
        apply_result: Optional[Dict[str, Any]] = None
        acme_order_id: Optional[int] = None
        acme_staging_error: Optional[str] = None

        if body.apply_immediately:
            try:
                from services.apply_service import apply_cluster_pending
                apply_result = await apply_cluster_pending(
                    body.cluster_id, user_id=user_id
                )
                response_status = "created_applied"
            except Exception as apply_err:
                logger.error(f"WIZARD: apply failed for cluster {body.cluster_id}: {apply_err}")
                response_status = "created_pending_apply_failed"
                apply_result = {"error": str(apply_err)}

        # ACME staging — only after apply succeeded (so version_name is real)
        if body.ssl.mode == "acme" and response_status == "created_applied":
            try:
                # Re-acquire the connection for the post-commit work; we
                # already closed our transaction above.
                post_conn = await get_database_connection()
                try:
                    suffix = body.ssl.https_frontend_name_suffix or "-https"
                    https_name = f"{body.frontend.name}{suffix}"

                    # Build the deferred HTTPS frontend payload that
                    # _complete_certificate's post_completion_actions will
                    # execute once the cert is downloaded.
                    # v1.5.0 advanced TLS: persist HSTS + ALPN + TLS tuning
                    # in the deferred frontend_config so post-completion
                    # action creates a properly-configured HTTPS frontend.
                    # R12 fix: idempotent (skip if user already wrote HSTS).
                    hsts_acme_headers = body.frontend.response_headers or ""
                    _hsts_already = (
                        "strict-transport-security" in hsts_acme_headers.lower()
                    )
                    if body.ssl.hsts_enabled and not _hsts_already:
                        hsts_value = f"max-age={body.ssl.hsts_max_age}"
                        if body.ssl.hsts_include_subdomains:
                            hsts_value += "; includeSubDomains"
                        if body.ssl.hsts_preload:
                            hsts_value += "; preload"
                        hsts_line = f'http-response set-header Strict-Transport-Security "{hsts_value}"'
                        hsts_acme_headers = (
                            (hsts_acme_headers + "\n" + hsts_line)
                            if hsts_acme_headers
                            else hsts_line
                        )
                    deferred_https_action = {
                        # v1.5.0 R12: bumped schema_version to 2 to signal
                        # that the new advanced fields (ssl_alpn / hsts /
                        # tls versions / etc.) are present. Reader treats
                        # missing keys as None so v1 actions still execute
                        # cleanly post-upgrade.
                        "type": "create_frontend",
                        "schema_version": 2,
                        "frontend_config": {
                            # core
                            "name": https_name,
                            "mode": body.frontend.mode,
                            "bind_address": body.frontend.bind_address,
                            "bind_port": body.ssl.https_bind_port,
                            "default_backend": body.backend.name,
                            "ssl_enabled": True,
                            "cluster_id": body.cluster_id,
                            "_auto_apply": True,
                            "_user_id": user_id,
                            # advanced TLS (HAProxy 2.4+) — read by
                            # frontend_service.create_frontend_row via
                            # getattr on the SimpleNamespace shim assembled
                            # in routers/letsencrypt.py::
                            # _execute_post_completion_actions.
                            "ssl_alpn": body.ssl.ssl_alpn,
                            "ssl_ciphers": body.ssl.ssl_ciphers,
                            "ssl_ciphersuites": body.ssl.ssl_ciphersuites,
                            "ssl_min_ver": body.ssl.ssl_min_ver,
                            "ssl_max_ver": body.ssl.ssl_max_ver,
                            "ssl_strict_sni": body.ssl.ssl_strict_sni,
                            # R17 minimum-parity: mTLS client cert auth.
                            "ssl_verify": body.ssl.ssl_verify,
                            # frontend tuning + headers (HSTS lands here)
                            "response_headers": hsts_acme_headers or None,
                            "request_headers": body.frontend.request_headers,
                            "compression": body.frontend.compression,
                            "log_separate": body.frontend.log_separate,
                            "monitor_uri": body.frontend.monitor_uri,
                            "maxconn": body.frontend.maxconn,
                            "rate_limit": body.frontend.rate_limit,
                            "timeout_client": body.frontend.timeout_client,
                            "timeout_http_request": body.frontend.timeout_http_request,
                            "options": body.frontend.options,
                            "tcp_request_rules": body.frontend.tcp_request_rules,
                            # routing — explicitly empty for the HTTPS sibling
                            # (matches the upload/existing branch above).
                            "redirect_rules": [],
                            "acl_rules": list(body.frontend.acl_rules or []),
                            "use_backend_rules": list(body.frontend.use_backend_rules or []),
                        },
                    }

                    # Bulgu #30 fix: gate the staged order on the CONSOLIDATED
                    # version name (`apply-consolidated-{ts}`), which is what
                    # the agent reports back via /config-applied. The original
                    # PENDING version (`bulk-site-create-{ts}`) is
                    # marked APPLIED+is_active=FALSE by apply_pending_changes
                    # and never appears in agents.applied_config_version, so
                    # comparing against it would block promotion forever.
                    gating_version_name = (
                        (apply_result or {}).get("latest_version") or version_name
                    )

                    acme_order_id = await create_order_staged(
                        post_conn,
                        account_id=acme_account_id,
                        domains=list(body.domains),
                        cluster_ids=[body.cluster_id],
                        post_completion_actions=[deferred_https_action],
                        pending_apply_version_name=gating_version_name,
                        created_by=user_id,
                    )

                    # Extend the version metadata so reject force-delete
                    # also cleans this staged order. (R43/M27)
                    await post_conn.execute(
                        """
                        UPDATE config_versions
                        SET metadata = jsonb_set(
                            COALESCE(metadata, '{}'::jsonb),
                            '{bulk_snapshots}',
                            COALESCE(metadata->'bulk_snapshots', '[]'::jsonb)
                            || $2::jsonb,
                            true
                        )
                        WHERE id = $1
                        """,
                        config_version_id,
                        json.dumps([_entity_snapshot("letsencrypt_order", acme_order_id)]),
                    )

                    await record_event(
                        acme_order_id,
                        "wizard_staged",
                        severity="INFO",
                        message=f"Wizard staged ACME order for {', '.join(body.domains)}",
                        details={
                            "version_name": version_name,
                            "gating_version_name": gating_version_name,
                            "cluster_id": body.cluster_id,
                            "user_id": user_id,
                        },
                        conn=post_conn,
                    )
                finally:
                    await close_database_connection(post_conn)
            except Exception as acme_err:
                logger.error(f"WIZARD: ACME staging failed: {acme_err}")
                response_status = "applied_acme_staging_failed"
                acme_staging_error = str(acme_err)

        # R18b audit fix (round 6 #15): the activity-logger middleware
        # only records 2xx HTTP responses with the bare status code.
        # The wizard create endpoint can return 200 with a `status`
        # body of `created_pending_apply_failed` or
        # `applied_acme_staging_failed` — the audit trail then claims
        # "wizard succeeded" while the operator's downstream apply or
        # ACME staging failed. Emit an explicit user_activity_logs row
        # capturing the wizard outcome so the audit trail reflects
        # reality regardless of HTTP status interpretation by the
        # generic middleware.
        #
        # R18b round 7 refinement: the emit is fire-and-forget via
        # `asyncio.create_task`. Pre-fix the awaited call added a
        # secondary DB INSERT to the wizard's tail latency. The audit
        # log helper already swallows its own exceptions and the
        # response data is fully prepared; spawning the task lets
        # the wizard return as soon as the transaction is committed.
        try:
            import asyncio as _asyncio
            from utils.activity_log import log_user_activity as _log_user_activity
            _asyncio.create_task(_log_user_activity(
                user_id=user_id,
                action="wizard_create_site",
                resource_type="site",
                resource_id=str(version_name) if version_name else None,
                details={
                    "wizard_status": response_status,
                    "cluster_id": body.cluster_id,
                    "domains": body.domains,
                    "ssl_mode": body.ssl.mode,
                    "version_name": version_name,
                    "apply_immediately": body.apply_immediately,
                    "acme_order_id": acme_order_id,
                    "acme_staging_error": acme_staging_error,
                    "apply_error": (
                        apply_result.get("error")
                        if isinstance(apply_result, dict) else None
                    ),
                },
            ))
        except Exception as audit_err:
            # Audit logging must never break the main flow.
            logger.debug(f"WIZARD: audit log emit failed: {audit_err}")

        return {
            "status": response_status,
            "version_name": version_name,
            "created_ids": created_ids,
            "apply_result": apply_result,
            "acme_order_id": acme_order_id,
            "acme_staging_error": acme_staging_error,
        }
    except HTTPException:
        raise
    except ValidationError as ve:
        # 422 envelope (R57/M38) — return field-level errors
        raise HTTPException(status_code=422, detail=ve.errors())
    except UndefinedColumnError as uce:
        # R18c audit fix (round 1 #3): if migrations are behind on a
        # rolling deploy, the wizard's INSERTs may reference columns
        # that haven't been added yet (e.g. backend_servers
        # `ssl_certificate_id`, frontends advanced TLS columns).
        # Pre-fix this surfaced as an unguarded asyncpg error inside
        # `except Exception` → 500 with raw column-name leakage. Map
        # to 503 with the same "run migrations" hint as the missing-
        # table case so operators have one consistent recovery
        # signal regardless of whether the schema gap is a column or
        # a table.
        msg = str(uce)
        logger.error(f"WIZARD: undefined column on create (migration lag?): {msg}")
        raise HTTPException(
            status_code=503,
            detail=(
                "A required column is missing — the database appears to "
                "be behind on migrations. Run the backend migration step "
                "before creating wizard sites."
            ),
        )
    except UndefinedTableError as ute:
        # R18b audit fix (round 5 #B): if the API process is brought
        # up against a database where `run_all_migrations` has not
        # finished (e.g. mid-rolling-deploy, or an operator restored a
        # snapshot from before R18 schema changes), the SSL eligibility
        # query touches `ssl_certificate_clusters` which may not exist
        # yet and the wizard surfaces a generic 500 with a raw asyncpg
        # message — operator has no actionable signal. Map to 503 with
        # a "run migrations" hint so the operator immediately knows
        # the cause and remediation.
        msg = str(ute)
        logger.error(f"WIZARD: undefined table on create (migration lag?): {msg}")
        raise HTTPException(
            status_code=503,
            detail=(
                "A required table is missing — the database appears to "
                "be behind on migrations (likely `ssl_certificate_clusters` "
                "or another R18+ schema artefact). Run the backend "
                "migration step before creating wizard sites."
            ),
        )
    except ForeignKeyViolationError as fve:
        # R18b audit fix (round 4 #E): a cert / cluster / backend the
        # wizard relied on was deleted between pre-flight validation
        # and the FK enforcement on INSERT. The transaction rolls
        # back cleanly (no partial state), but pre-fix the operator
        # saw a generic 500. 409 with a hint maps the race to a
        # retry-with-fresh-state action instead of a "service broken"
        # signal.
        msg = str(fve)
        logger.info(f"WIZARD: FK violation on create: {msg}")
        raise HTTPException(
            status_code=409,
            detail=(
                "A referenced entity (SSL certificate, cluster, or "
                "backend) was deleted while the wizard was creating "
                "this site. Reload the wizard and reselect dependent "
                "fields, then retry."
            ),
        )
    except UniqueViolationError as uve:
        # R18b audit fix (round 3 #4): TWO operators racing the same
        # wizard-host name on the same cluster both pass the
        # `is_active=TRUE` pre-flight collision check and enter the
        # transaction; the SECOND insert hits the UNIQUE(name,
        # cluster_id) constraint. Pre-fix that bubbled up as a
        # generic 500 with no operator-actionable detail. The same
        # constraint also fires when a soft-deleted (is_active=FALSE)
        # row still occupies the (name, cluster_id) tuple — pre-flight
        # only checks active rows. 409 with a precise hint maps the
        # race to "pick a different name" instead of "something
        # broke".
        msg = str(uve)
        logger.info(f"WIZARD: name conflict on create: {msg}")
        if "backends_name_cluster_id_key" in msg or 'backends_name' in msg:
            detail = (
                "A backend with this name already exists on the cluster "
                "(possibly soft-deleted). Pick a different backend name "
                "or restore/permanently-delete the existing row."
            )
        elif "frontends_name_cluster_id_key" in msg or "frontends_name" in msg:
            detail = (
                "A frontend with this name already exists on the cluster "
                "(possibly soft-deleted). Pick a different frontend name "
                "or restore/permanently-delete the existing row."
            )
        else:
            detail = (
                "A wizard entity with this name already exists on the "
                "cluster (UNIQUE constraint). Pick a different name."
            )
        raise HTTPException(status_code=409, detail=detail)
    except Exception as e:
        # R18c round 10 (M3): pre-round-10 we surfaced `detail=str(e)` to
        # the client, which leaks SQL fragments, internal identifiers,
        # exception class names, and occasionally file paths to the
        # browser. Log the full exception server-side with a correlation
        # id (uuid4) so an operator can find the matching server log
        # entry from the toast they see in the UI; return a stable
        # generic detail to keep info disclosure low.
        import uuid
        correlation_id = uuid.uuid4().hex[:12]
        logger.exception(
            "WIZARD: unexpected failure [correlation_id=%s] user_id=%s: %s",
            correlation_id, user_id, e,
        )
        raise HTTPException(
            status_code=500,
            detail=(
                "Wizard create failed unexpectedly. Please retry; if the "
                f"error persists contact the platform team and reference "
                f"correlation id {correlation_id} (server logs)."
            ),
        )
    finally:
        await close_database_connection(conn)


# ---------------------------------------------------------------------------
# Drafts CRUD
# ---------------------------------------------------------------------------


@router.post("/drafts")
async def save_draft(
    body: SiteDraftCreate,
    authorization: str = Header(None),
):
    current_user = await get_current_user_from_token(authorization)
    user_id = current_user["id"]
    if not await _can_use_wizard(user_id, current_user=current_user):
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions: at least one of frontend.read/create, "
            "ssl.read/create or backend.create is required to use the wizard",
        )

    sanitized = _strip_pem_from_payload(body.payload or {})

    conn = await get_database_connection()
    try:
        # R14 hardening (#R14-1): cap drafts per user. Without a cap a
        # single user can grow wizard_drafts indefinitely (within the 30d
        # retention window). 50 active drafts per user is generous for
        # human use and bounded for the table.
        #
        # R18 audit fix: the COUNT and INSERT below ran sequentially on
        # the same connection but were NOT wrapped in a transaction, so
        # two parallel saves could both observe count=49 and both
        # insert ⇒ the cap was advisory only. We now wrap both
        # statements in a single transaction AND take a per-user
        # advisory lock for the duration. The advisory lock key is
        # derived from `user_id` and a stable namespace constant so
        # admins doing parallel work on different users are not
        # serialised against each other.
        async with conn.transaction():
            # Stable namespace tag for "wizard_drafts cap" — chosen
            # arbitrary but deterministic. Postgres advisory locks
            # take two int4 args; we use (namespace, user_id).
            await conn.execute("SELECT pg_advisory_xact_lock($1, $2)", 18181818, int(user_id))
            # Phase I: dual-filter — accept BOTH the post-rebrand
            # `site` value and the legacy `proxied_host` value so the
            # 50-draft cap still counts pre-rename drafts owned by
            # this user. The `(user_id, wizard_type, updated_at)`
            # composite index handles the IN-list as a B-tree
            # bitmap merge so the cap check stays O(log n).
            existing = await conn.fetchval(
                """
                SELECT COUNT(*)::int FROM wizard_drafts
                WHERE user_id = $1
                  AND wizard_type IN ('site', 'proxied_host')
                  AND expires_at > NOW()
                """,
                user_id,
            )
            if existing is not None and existing >= 50:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "You already have 50 active wizard drafts. Delete some "
                        "from 'Site Drafts' before saving a new one."
                    ),
                )

            # Bulgu #1 fix: return the REAL expires_at from the DB default
            # (created_at + INTERVAL '30 days') instead of NOW(). Otherwise the
            # frontend prompts users that the draft expires today.
            # Phase I: new INSERTs land with the canonical `site`
            # value (matches the schema-level DEFAULT post-migration).
            # The list/delete paths use IN ('site', 'proxied_host')
            # so pre-rename drafts owned by the same user still
            # surface in the listing — no row-level UPDATE migration
            # is needed (existing rows are untouched).
            row = await conn.fetchrow(
                """
                INSERT INTO wizard_drafts (user_id, wizard_type, title, payload)
                VALUES ($1, 'site', $2, $3::jsonb)
                RETURNING id, expires_at, created_at, updated_at
                """,
                user_id,
                body.title,
                json.dumps(sanitized),
            )
        def _iso(d):
            return d.isoformat().replace("+00:00", "Z") if d else None
        return {
            "id": row["id"],
            "title": body.title,
            "expires_at": _iso(row["expires_at"]),
            "created_at": _iso(row["created_at"]),
            "updated_at": _iso(row["updated_at"]),
        }
    finally:
        await close_database_connection(conn)


@router.get("/drafts")
async def list_drafts(authorization: str = Header(None)):
    current_user = await get_current_user_from_token(authorization)
    user_id = current_user["id"]
    if not await _can_use_wizard(user_id, current_user=current_user):
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions: at least one of frontend.read/create, "
            "ssl.read/create or backend.create is required to use the wizard",
        )

    conn = await get_database_connection()
    try:
        # Phase I: dual-filter so drafts saved before the Site
        # rebrand (wizard_type='proxied_host') still appear in the
        # operator's draft list alongside post-rebrand drafts
        # (wizard_type='site').
        rows = await conn.fetch(
            """
            SELECT id, title, payload, expires_at, created_at, updated_at
            FROM wizard_drafts
            WHERE user_id = $1
              AND wizard_type IN ('site', 'proxied_host')
              AND expires_at > NOW()
            ORDER BY updated_at DESC
            """,
            user_id,
        )

        # R18c round 7 (Bulgu 4): augment each draft with ssl_cert_summary
        # when ssl.mode='existing' and a referenced cert id is present.
        # Operators reported that the drafts list showed a generic "30
        # days" expiry (the draft TTL) instead of the SELECTED ssl
        # certificate's actual expiry — confusing on a screen mixing two
        # unrelated countdowns. We now JOIN ssl_certificates in a single
        # batch query (no N+1) so the UI can render the proper cert
        # name, status and expiry mirroring FrontendManagement's SSL/TLS
        # column.
        def _payload(r):
            p = r["payload"]
            if isinstance(p, str):
                try:
                    return json.loads(p)
                except Exception:
                    return {}
            return p or {}

        cert_ids = set()
        parsed_payloads = []
        for r in rows:
            p = _payload(r)
            parsed_payloads.append(p)
            ssl_obj = p.get("ssl") if isinstance(p, dict) else None
            if isinstance(ssl_obj, dict) and ssl_obj.get("mode") == "existing":
                cid = ssl_obj.get("ssl_certificate_id")
                if isinstance(cid, int):
                    cert_ids.add(cid)

        cert_map = {}
        if cert_ids:
            cert_rows = await conn.fetch(
                """
                SELECT id, name, primary_domain AS domain, expiry_date,
                       days_until_expiry, status
                FROM ssl_certificates
                WHERE id = ANY($1::int[]) AND is_active = TRUE
                """,
                list(cert_ids),
            )
            cert_map = {c["id"]: c for c in cert_rows}

        drafts_out = []
        for r, p in zip(rows, parsed_payloads):
            ssl_cert_summary = None
            ssl_obj = p.get("ssl") if isinstance(p, dict) else None
            if isinstance(ssl_obj, dict) and ssl_obj.get("mode") == "existing":
                cid = ssl_obj.get("ssl_certificate_id")
                if isinstance(cid, int):
                    c = cert_map.get(cid)
                    if c:
                        ssl_cert_summary = {
                            "id": c["id"],
                            "name": c["name"],
                            "domain": c["domain"],
                            "expiry_date": (
                                c["expiry_date"].isoformat().replace("+00:00", "Z")
                                if c["expiry_date"] else None
                            ),
                            "days_until_expiry": c["days_until_expiry"],
                            "status": c["status"],
                        }
                    else:
                        # Cert was deleted or marked inactive after the
                        # draft was saved. Tell the UI explicitly so it
                        # can warn the operator instead of silently
                        # falling back to "no cert".
                        ssl_cert_summary = {"id": cid, "deleted": True}

            drafts_out.append({
                "id": r["id"],
                "title": r["title"],
                # R18c round 8 (Bulgu A): asyncpg has no JSONB codec
                # registered on the pool, so r["payload"] comes back as a
                # raw JSON string. Returning the string verbatim caused
                # the drafts UI to render `r.payload?.domains` as
                # undefined (it's `string.domains`, not `dict.domains`),
                # which is why the table showed empty Domains/Cluster
                # columns AND why Resume sent the wizard a string that
                # JSON.parse turned back into a string — never hydrating
                # the form. We always return a parsed dict so the FE
                # contract is stable regardless of asyncpg behaviour.
                "payload": p if isinstance(p, dict) else {},
                "ssl_cert_summary": ssl_cert_summary,
                "expires_at": r["expires_at"].isoformat().replace("+00:00", "Z") if r["expires_at"] else None,
                "created_at": r["created_at"].isoformat().replace("+00:00", "Z") if r["created_at"] else None,
                "updated_at": r["updated_at"].isoformat().replace("+00:00", "Z") if r["updated_at"] else None,
            })

        return {"drafts": drafts_out}
    finally:
        await close_database_connection(conn)


@router.delete("/drafts/{draft_id}")
async def delete_draft(draft_id: int, authorization: str = Header(None)):
    current_user = await get_current_user_from_token(authorization)
    user_id = current_user["id"]
    if not await _can_use_wizard(user_id, current_user=current_user):
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions: at least one of frontend.read/create, "
            "ssl.read/create or backend.create is required to use the wizard",
        )

    conn = await get_database_connection()
    try:
        # R18b audit fix (round 6 #11): use DELETE ... RETURNING to
        # detect 0-rows-affected reliably. Pre-fix the route relied
        # on `result.endswith("0")`, which silently became "draft
        # deleted OK" if asyncpg's status string format ever
        # changed (e.g. driver upgrade returned bytes instead of
        # str, or future asyncpg versions changed "DELETE 0" to a
        # different shape). RETURNING returns an explicit row when
        # the delete fired, NULL when it didn't — unambiguous.
        deleted_id = await conn.fetchval(
            "DELETE FROM wizard_drafts WHERE id = $1 AND user_id = $2 RETURNING id",
            draft_id,
            user_id,
        )
        if deleted_id is None:
            raise HTTPException(status_code=404, detail="Draft not found")
        return {"deleted": draft_id}
    finally:
        await close_database_connection(conn)
