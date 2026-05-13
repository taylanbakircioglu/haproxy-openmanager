import asyncio
import logging
import hashlib
import time
import json
import urllib.parse
from typing import Optional, List, Dict, Any
from database.connection import get_database_connection, close_database_connection

logger = logging.getLogger(__name__)


def _format_redirect_rule(rule: Any) -> Optional[str]:
    """Render a single redirect rule into a HAProxy `redirect ...` line.

    R11.A-1 fix (PR-1 hotfix): pre-fix the generator stringified dicts
    via ``str(rule)``, which produced parser-fatal output like
    ``redirect {'type': 'scheme', 'code': 301, ...}``. The wizard's
    ``_build_redirect_rules`` always emits dicts, so every wizard-
    generated HTTPS redirect failed agent reload at the apply stage.

    Schema accepted (forward + backward compatible):

    - ``{type: 'scheme', scheme: 'https', code: 301, condition: ...}``
    - ``{type: 'location', location: 'http://...', code: 302, ...}``
    - ``{type: 'prefix', prefix: '/v2', code: 301, ...}``
    - Plain string (legacy raw HAProxy fragment, e.g.
      ``"scheme https if !{ ssl_fc }"``).

    Returns ``None`` for entries that should be skipped (empty,
    invalid type, missing required field for the chosen type).
    The returned line is already indented with 4 spaces so callers can
    drop it straight into the frontend block.
    """
    if rule is None:
        return None

    if isinstance(rule, dict):
        rtype = (rule.get("type") or "").strip().lower()
        code = rule.get("code")
        condition = (rule.get("condition") or "").strip()

        if rtype == "scheme":
            scheme = (rule.get("scheme") or "https").strip()
            if scheme not in ("http", "https"):
                logger.warning(
                    f"REDIRECT: ignoring invalid scheme '{scheme}' "
                    "(only 'http' or 'https' allowed for redirect scheme)"
                )
                return None
            parts = ["redirect scheme", scheme]
        elif rtype == "location":
            url = (rule.get("location") or "").strip()
            if not url:
                logger.warning(
                    "REDIRECT: ignoring redirect type=location with empty 'location' field"
                )
                return None
            parts = ["redirect location", url]
        elif rtype == "prefix":
            prefix = (rule.get("prefix") or rule.get("location") or "").strip()
            if not prefix:
                logger.warning(
                    "REDIRECT: ignoring redirect type=prefix with empty 'prefix' field"
                )
                return None
            parts = ["redirect prefix", prefix]
        else:
            logger.warning(
                f"REDIRECT: ignoring unknown redirect type '{rtype}' "
                "(expected: scheme | location | prefix)"
            )
            return None

        if code is not None:
            try:
                parts.append(f"code {int(code)}")
            except (TypeError, ValueError):
                logger.warning(f"REDIRECT: invalid 'code' value {code!r}, dropping")
        if condition:
            # R11-audit-2 (FIX-2): defend against double 'if' when the
            # caller already wrote `condition='if !{ ssl_fc }'`. Without
            # this guard the rendered line would be
            # ``redirect ... if if !{ ssl_fc }`` which HAProxy rejects
            # as a parser error. Mirrors the legacy string-rule branch
            # below (which never prepends 'if').
            cond_lower = condition.lstrip().lower()
            if cond_lower.startswith("if ") or cond_lower.startswith("unless "):
                parts.append(condition)
            else:
                parts.append(f"if {condition}")

        return "    " + " ".join(parts)

    # Legacy string entries (e.g. "scheme https if !{ ssl_fc }").
    # FIX-11 (R11-audit round 2): some legacy DB rows from earlier
    # releases stored the FULL `redirect ...` line including the
    # leading 'redirect ' keyword. Without this guard the helper
    # would prepend a second 'redirect ', producing the parser-
    # fatal `redirect redirect scheme https ...`. Strip a leading
    # `redirect` token (with OR without trailing space — `"redirect"`
    # alone after `.strip()` no longer carries the trailing space)
    # so both legacy variants render to a single, syntactically
    # valid line and a naked keyword cleanly returns None.
    s = str(rule).strip()
    if not s or s in ("[]", "{}", "null", "None"):
        return None
    s_lower = s.lower()
    if s_lower == "redirect" or s_lower.startswith("redirect "):
        # Strip the keyword (and any whitespace following it).
        # `"redirect"` alone reduces to `""` → return None below.
        s = s[len("redirect"):].lstrip()
        if not s:
            return None
    return f"    redirect {s}"


def _normalize_haproxy_config_text_for_diff(text: str) -> str:
    """Apply renderer-side normalizations to an already-rendered HAProxy
    config text so that diffs between two versions surface ONLY
    operator-intent changes — not renderer evolution.

    Why this exists
    ---------------
    The `config_versions` table stores the verbatim rendered config
    at the time each version was created. When the renderer is then
    improved (e.g. Bulgu #13 added `http-request track-sc<N> <fetch>`
    dedup and stripped per-server `cookie <name>` when the parent
    backend has no `cookie_name`), the PREVIOUS-version text was
    written with the OLD renderer and the CURRENT-version text is
    written with the NEW renderer. `difflib.unified_diff` then
    surfaces those renderer-driven differences as `+`/`-` lines on
    entities the operator never touched, which is extremely
    confusing — especially when the operator's actual change was
    just "add one new frontend".

    The fix: run BOTH sides of the diff through this normalization
    pass first. After normalization, two configs that differ only
    by renderer-evolution will compare equal and the diff will
    surface ONLY the operator's actual changes.

    Normalizations applied (must match the renderer):

      1. **`http-request track-sc<N> <fetch>` dedup within a
         section.** The (counter, fetch) tuple uniquely identifies
         the tracker; identical signatures within the same
         frontend / listen block collapse to the first occurrence.

      2. **`cookie <name>` strip on `server` lines whose parent
         backend has no top-level `cookie` directive.** Matches the
         renderer guard added for Bulgu #13 (per-server cookie value
         is silently broken stickiness without a backend-level
         `cookie_name`).

    Safety
    ------
    - Idempotent: running this on an already-normalized config
      produces the same config (set membership / strip both
      handle re-application).
    - Section-scoped: dedup tracker signatures reset on every new
      section header so unrelated frontends don't cross-pollute.
    - Conservative: only the two transformations above are applied;
      we do NOT rewrite ACLs, reorder buckets, or touch operator-
      authored content. Lines we don't recognise pass through verbatim.

    Args:
        text: Full rendered HAProxy config as a single string.

    Returns:
        Normalized config text. Empty / None input passes through.
    """
    if not text:
        return text

    lines = text.split('\n')

    # ── Pass 1: scan for `cookie` directives that license per-server
    # `cookie <value>` attributes. Bulgu #13 strips per-server
    # cookies whose parent block has no licensing directive; we
    # mirror that decision here.
    #
    # HAProxy semantics (docs section 4.1 — keyword matrix):
    #
    #     The `cookie` directive may appear in `defaults`, `frontend`,
    #     `listen`, AND `backend` sections. A `cookie` in `defaults`
    #     is INHERITED by every subsequent `backend` and `listen` so
    #     they no longer need to repeat it. A `cookie` inside a
    #     `frontend` is unusual and applies to that frontend only.
    #
    # Tracking is therefore per-section (backend + listen) PLUS one
    # global flag for defaults inheritance. We DO NOT track frontends
    # because per-server cookie attributes only exist on `server`
    # lines, which only exist in `backend` / `listen`.
    cookie_licensed_sections: set = set()
    defaults_has_cookie = False
    cur_section_kind: Optional[str] = None
    cur_section_name: Optional[str] = None
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        is_indented = line.startswith((' ', '\t'))
        if not is_indented and not stripped.startswith('#'):
            parts = stripped.split()
            if not parts:
                continue
            kind = parts[0]
            if kind in ('frontend', 'backend', 'listen', 'global', 'defaults'):
                cur_section_kind = kind
                # `defaults` and `global` need no name. `frontend`,
                # `backend`, `listen` carry the entity name as the
                # second token (which is what we key the licensed
                # set off).
                cur_section_name = parts[1] if (
                    kind in ('frontend', 'backend', 'listen')
                    and len(parts) >= 2
                ) else None
            else:
                cur_section_kind = None
                cur_section_name = None
        elif (
            cur_section_kind in ('backend', 'listen', 'defaults')
            and not stripped.startswith('#')
            and stripped.startswith('cookie ')
        ):
            # Top-level `cookie ...` directive — this is the cookie_name
            # directive that licenses per-server `cookie <value>` lines.
            if cur_section_kind == 'defaults':
                defaults_has_cookie = True
            elif cur_section_name is not None:
                cookie_licensed_sections.add((cur_section_kind, cur_section_name))

    # ── Pass 2: emit normalized lines. ──────────────────────
    out: List[str] = []
    cur_section_kind = None
    cur_section_name = None
    # Per-section state for track-sc<N> dedup
    cur_track_sigs: set = set()
    for raw in lines:
        line = raw
        stripped = line.strip()
        is_indented = line.startswith((' ', '\t'))

        # Detect section boundary (top-level non-comment directive
        # starts a new section)
        if stripped and not is_indented and not stripped.startswith('#'):
            parts = stripped.split()
            if parts and parts[0] in ('frontend', 'backend', 'listen', 'global', 'defaults'):
                cur_section_kind = parts[0]
                cur_section_name = parts[1] if (
                    parts[0] in ('frontend', 'backend', 'listen')
                    and len(parts) >= 2
                ) else None
                cur_track_sigs = set()
            else:
                cur_section_kind = None
                cur_section_name = None

        # ── Normalization 1: track-sc<N> dedup (frontend/listen). ──
        # HAProxy semantics: `http-request track-sc<N>` only exists
        # in `frontend` / `listen` sections. The (counter, fetch)
        # tuple uniquely identifies the tracker.
        if (
            cur_section_kind in ('frontend', 'listen')
            and stripped.startswith('http-request track-sc')
        ):
            tparts = stripped.split()
            if len(tparts) >= 3:
                sig = (tparts[1], tparts[2])
                if sig in cur_track_sigs:
                    # Skip this duplicate.
                    continue
                cur_track_sigs.add(sig)

        # ── Normalization 2: strip per-server `cookie <value>` when
        # the parent section (backend OR listen) has no licensing
        # `cookie` directive AND `defaults` does not declare one
        # for inheritance. ──
        #
        # Conservative: when in doubt (defaults declares cookie, or
        # section declares cookie), we KEEP the per-server cookie.
        # Stripping is only applied when we are SURE no licensing
        # path exists.
        section_licenses_cookie = (
            defaults_has_cookie
            or (
                cur_section_kind in ('backend', 'listen')
                and cur_section_name is not None
                and (cur_section_kind, cur_section_name) in cookie_licensed_sections
            )
        )
        if (
            cur_section_kind in ('backend', 'listen')
            and cur_section_name is not None
            and not section_licenses_cookie
            and is_indented
            and stripped.startswith('server ')
        ):
            tokens = stripped.split()
            new_tokens: List[str] = []
            i = 0
            while i < len(tokens):
                tok = tokens[i]
                # HAProxy server-line layout:
                #   server <name> <address>[:port] [keyword <value>]*
                #
                # The `cookie <value>` pair is ALWAYS a keyword pair
                # in the trailing parameters — it can never appear
                # at i=1 (that's the server name) or i=2 (the
                # address). Guarding with i >= 3 protects against
                # legitimate corner cases where an operator named a
                # server `cookie` or used `cookie:port` as a
                # hostname.
                if tok == 'cookie' and i >= 3 and i + 1 < len(tokens):
                    # Drop `cookie <value>` pair. HAProxy syntax:
                    # the cookie attribute value is exactly one
                    # token.
                    i += 2
                    continue
                new_tokens.append(tok)
                i += 1
            # Preserve original leading whitespace so indentation
            # stays consistent with the rest of the block.
            leading_len = len(line) - len(line.lstrip())
            line = (line[:leading_len]) + ' '.join(new_tokens)

        out.append(line)

    return '\n'.join(out)


def _categorize_haproxy_directive(line: str) -> str:
    """Classify a single emitted HAProxy directive line into its
    correct frontend-block emission category for ordering purposes.

    R2.3 / R3.3 (PR-1 hotfix): HAProxy parser emits soft warnings
    when ``http-request`` rules appear after ``use_backend`` /
    ``default_backend``, or when ``tcp-request`` appears after
    ``http-request``. Some warnings (``stick-table already declared``,
    ``http-request placed after use_backend``) escalate to fatal in
    strict mode. We classify each directive once and reorder before
    flushing to ``config_lines`` so the rendered config matches the
    canonical HAProxy ordering:

        bind → mode → option → timeout → maxconn → monitor-uri →
        compression → log → stick-table → tcp-request → acl →
        http-request → http-response → redirect → use_backend →
        default_backend

    Comments (``# ...``) are routed to the same category as the next
    directive heuristically (they keep their semantic anchor in the
    rendered output). Unknown directives default to 'prelude' so
    they appear early; the validator surfaces them as warnings.
    """
    s = line.strip()
    if not s:
        return "prelude"
    # Strip the indent for prefix matching
    if s.startswith("#"):
        # Heuristic: comments containing WAF / filter / rate-limit /
        # custom-condition keywords stick to the `acl` bucket so they
        # are emitted next to the rule they describe (operator UX —
        # otherwise the comment lands at the top of the frontend block
        # and the rule lands lower down, making the rendered config
        # confusing). Mode-mismatch warnings emitted by the
        # default_backend branch use the 'BACKEND-MODE-WARNING' marker
        # below and are routed into `default_be` so they sit right
        # next to the `default_backend` directive they refer to.
        cmt = s.lower()
        if "backend-mode-warning" in cmt:
            # FIX-10 (R11-audit round 2): mode-mismatch warnings must
            # emit next to the default_backend directive, not at the
            # top of the frontend block.
            return "default_be"
        if (
            "waf rule:" in cmt
            or "ip filter" in cmt
            or "rate limit" in cmt
            or "header filter" in cmt
            or "request filter" in cmt
            # FIX-9 (R11-audit round 2): WAF custom-comment keywords
            # that the original heuristic missed. Pre-fix the
            # `# Log Message:`, `# Custom Log:`, `# Custom Condition
            # for ...` and size_limit log markers landed in 'prelude'
            # (top of the block) while their rules landed in
            # 'http_req' (later) — visually disconnected.
            or "log message:" in cmt
            or "custom log:" in cmt
            or "custom condition for" in cmt
            or "filter log:" in cmt
        ):
            return "acl"
        return "prelude"
    if s.startswith("acl "):
        return "acl"
    if s.startswith("stick-table") or s.startswith("stick "):
        return "stick"
    if s.startswith("tcp-request"):
        return "tcp_req"
    if s.startswith("http-request"):
        return "http_req"
    if s.startswith("http-response"):
        return "http_resp"
    if s.startswith("redirect "):
        return "redirect"
    if s.startswith("use_backend"):
        return "use_be"
    if s.startswith("default_backend"):
        return "default_be"
    if (
        s.startswith("option ")
        or s.startswith("timeout ")
        or s.startswith("maxconn ")
        or s.startswith("compression ")
        or s.startswith("monitor-uri")
        or s.startswith("log ")
        or s.startswith("description ")
        or s.startswith("disabled")
        or s.startswith("enabled")
    ):
        return "prelude"
    return "prelude"


def _resolve_frontend_client_ca_path(
    frontend: Dict[str, Any], cluster_id: Optional[int] = None
) -> Optional[str]:
    """Return the client-CA bundle path for bind-side mTLS, or None.

    Forward-path placeholder for PR-7 (`ssl_client_ca_certificate_id`
    column). Until that column exists we always return None — callers
    treat None as "no CA configured", which combined with
    ``ssl_verify ∈ {required, optional}`` triggers the safeguard
    that suppresses the `verify` directive (see
    `_apply_bind_ssl_verify`). When PR-7 lands this helper will look
    up the cert via the same query as `_get_ssl_certificate_path` but
    filtered by ``usage_type IN ('client_ca', 'frontend')``.
    """
    return None


def _apply_bind_ssl_verify(
    bind_line: str, frontend: Dict[str, Any], cluster_id: Optional[int] = None
) -> str:
    """Append `verify <mode>` (and `ca-file <path>` when needed) to a bind line.

    R11.A-2 (PR-1 hotfix): bind-side `verify required|optional` requires
    a `ca-file <path>` argument — without it HAProxy emits the fatal
    ALERT::

        Proxy 'X': verify is enabled but no CA file specified for bind '...'

    Pre-fix the generator emitted ``verify <mode>`` verbatim regardless
    of whether a client-CA bundle was resolvable, breaking every
    frontend that had ``ssl_verify ∈ {required, optional}`` (the
    column DEFAULT was 'optional' until PR-2). Symmetric to the
    server-side downgrade in the `backend ... server` block.

    Behaviour:

    - ``ssl_verify`` empty / ``'none'`` → no directive appended.
    - ``ssl_verify == 'required' | 'optional'`` and a client-CA path is
      resolvable → emit ``ca-file <path> verify <mode>``.
    - ``ssl_verify == 'required' | 'optional'`` and NO client-CA path →
      emit nothing, log ERROR with frontend name + cluster id so apply
      diagnostics surface the cause.
    - Unknown ``ssl_verify`` value → emit nothing, log WARNING.
    """
    raw = frontend.get("ssl_verify")
    if raw is None:
        return bind_line
    val = str(raw).strip().lower()
    if val in ("", "none", "[]", "{}", "null"):
        return bind_line
    if val not in ("required", "optional"):
        logger.warning(
            f"BIND SSL_VERIFY: frontend '{frontend.get('name')}' has "
            f"unknown ssl_verify value '{raw}' — skipping verify directive."
        )
        return bind_line

    client_ca_path = _resolve_frontend_client_ca_path(frontend, cluster_id)
    if not client_ca_path:
        # FIX-12 (R11-audit round 2): the prior message hinted at a
        # "Frontend Management → Advanced TLS" UI path that does not
        # yet exist (it lands with PR-7 of the rollout). Operators
        # following the hint hit a dead end and assumed the safeguard
        # was a bug. Switched to a hint that is ALWAYS actionable on
        # the current release: clear the column or set it to 'none'.
        # The forward-compat hint that PR-7 will introduce a proper
        # client-CA bundle field is preserved as a follow-up note.
        logger.error(
            f"BIND SSL_VERIFY DOWNGRADE: frontend '{frontend.get('name')}' "
            f"(cluster_id={cluster_id}) requested ssl_verify='{val}' but "
            "no client-CA bundle is resolvable. Skipping the 'verify' "
            "directive on the bind line to prevent fatal HAProxy ALERT "
            "'verify is enabled but no CA file specified'. To clear "
            "this diagnostic, either set ssl_verify='none' on the "
            "frontend or wait for the upcoming "
            "ssl_client_ca_certificate_id column (PR-7) which will "
            "let you bind a client-CA bundle for inbound mTLS."
        )
        return bind_line

    return bind_line + f" ca-file {client_ca_path} verify {val}"


async def _get_ssl_certificate_path(frontend: Dict[str, Any], cluster_id: int, db_conn: Any) -> Optional[str]:
    """
    Get SSL certificate path for frontend based on ssl_certificate_id
    Returns the path where agent should place the certificate file
    """
    try:
        ssl_cert_id = frontend.get('ssl_certificate_id')
        logger.info(f"SSL PATH DEBUG: Frontend '{frontend.get('name')}' ssl_certificate_id: {ssl_cert_id}, cluster_id: {cluster_id}")
        if not ssl_cert_id:
            logger.warning(f"SSL PATH DEBUG: No ssl_certificate_id found for frontend '{frontend.get('name')}'")
            return None
        
        # Get SSL certificate info - Check both global and cluster-specific certificates
        ssl_cert = await db_conn.fetchrow("""
            SELECT DISTINCT s.name, s.primary_domain as domain, s.fingerprint
            FROM ssl_certificates s
            LEFT JOIN ssl_certificate_clusters scc ON s.id = scc.ssl_certificate_id
            WHERE s.id = $1 AND s.is_active = TRUE
            AND (s.cluster_id IS NULL OR scc.cluster_id = $2)
        """, ssl_cert_id, cluster_id)
        
        logger.info(f"SSL PATH DEBUG: Query result for cert_id {ssl_cert_id}, cluster {cluster_id}: {ssl_cert}")
        
        if not ssl_cert:
            logger.warning(f"SSL certificate with ID {ssl_cert_id} not found for cluster {cluster_id}")
            return None
        
        # Generate certificate file path that agent will use
        # Format: /etc/ssl/haproxy/{cert_name}.pem
        cert_filename = f"{ssl_cert['name']}.pem"
        cert_path = f"/etc/ssl/haproxy/{cert_filename}"
        
        logger.debug(f"SSL certificate path for frontend '{frontend['name']}': {cert_path}")
        return cert_path
        
    except Exception as e:
        logger.error(f"Error getting SSL certificate path: {e}")
        return None

async def generate_haproxy_config_for_cluster(cluster_id: int, conn: Optional[Any] = None) -> str:
    """
    Generates a complete HAProxy configuration for a given cluster ID.
    It can optionally use an existing database connection to operate within a transaction.
    """
    db_conn = None
    try:
        # Use the provided connection if available, otherwise create a new one
        db_conn = conn or await get_database_connection()
        
        # Get cluster-specific settings
        cluster_info = await db_conn.fetchrow("SELECT * FROM haproxy_clusters WHERE id = $1", cluster_id)
        if not cluster_info:
            logger.error(f"Config Generation: Cluster with ID {cluster_id} not found.")
            return "# Error: Cluster not found"
            
        stats_socket_path = cluster_info.get('stats_socket_path', '/run/haproxy/admin.sock')
        
        # Check if any agents in this cluster are running on macOS/Darwin
        darwin_agents = await db_conn.fetchrow("""
            SELECT COUNT(*) as count FROM agents 
            WHERE (platform = 'darwin' OR operating_system LIKE '%macOS%' OR operating_system LIKE '%Darwin%')
            AND pool_id IN (SELECT pool_id FROM haproxy_clusters WHERE id = $1)
        """, cluster_id)
        
        is_macos_cluster = darwin_agents['count'] > 0 if darwin_agents else False

        # Get all active frontends for this cluster
        frontends = await db_conn.fetch(
            "SELECT * FROM frontends WHERE cluster_id = $1 AND is_active = TRUE ORDER BY name", 
            cluster_id
        )
        
        # Get all active backends for this cluster
        backends = await db_conn.fetch(
            "SELECT * FROM backends WHERE cluster_id = $1 AND is_active = TRUE ORDER BY name", 
            cluster_id
        )
        
        # Get all active WAF rules associated with frontends in this cluster
        # CRITICAL: Include both APPLIED and PENDING rules during config generation
        # CRITICAL: Exclude WAF rules marked for deletion (is_active = FALSE)
        waf_rules_records = await db_conn.fetch("""
            SELECT w.*, array_agg(fw.frontend_id) as frontend_ids
            FROM waf_rules w
            JOIN frontend_waf_rules fw ON w.id = fw.waf_rule_id
            WHERE w.is_active = TRUE AND fw.frontend_id IN (SELECT id FROM frontends WHERE cluster_id = $1)
            GROUP BY w.id
        """, cluster_id)

        # Get cluster-global WAF rules (no explicit frontend assignments). Apply to all frontends.
        # CRITICAL: Include both APPLIED and PENDING rules during config generation
        # CRITICAL: Exclude WAF rules marked for deletion (is_active = FALSE)
        cluster_global_waf_rules = await db_conn.fetch(
            """
            SELECT w.*
            FROM waf_rules w
            WHERE w.is_active = TRUE
              AND (w.cluster_id = $1 OR w.cluster_id IS NULL)
              AND NOT EXISTS (
                    SELECT 1 FROM frontend_waf_rules fwr WHERE fwr.waf_rule_id = w.id
              )
            ORDER BY w.priority, w.name
            """,
            cluster_id,
        )

        # CRITICAL FIX: Check for pending delete operations and exclude those WAF rules
        # Find WAF rules that are marked for deletion but still active in database
        pending_delete_waf_ids = set()
        try:
            pending_delete_versions = await db_conn.fetch("""
                SELECT version_name FROM config_versions 
                WHERE cluster_id = $1 AND status = 'PENDING' AND version_name ~ '^waf-[0-9]+-delete-'
            """, cluster_id)
            import re
            for version in pending_delete_versions:
                match = re.search(r'^waf-(\d+)-delete-', version['version_name'])
                if match:
                    pending_delete_waf_ids.add(int(match.group(1)))
            
            if pending_delete_waf_ids:
                logger.info(f"Config Generation: Excluding {len(pending_delete_waf_ids)} WAF rules pending deletion: {pending_delete_waf_ids}")
        except Exception as e:
            logger.warning(f"Config Generation: Failed to check pending delete WAF rules: {e}")

        # Filter out WAF rules that are pending deletion
        if pending_delete_waf_ids:
            waf_rules_records = [rule for rule in waf_rules_records if rule['id'] not in pending_delete_waf_ids]
            cluster_global_waf_rules = [rule for rule in cluster_global_waf_rules if rule['id'] not in pending_delete_waf_ids]

        # CRITICAL DESIGN CHANGE: DO NOT generate global or defaults sections
        # Agent will preserve existing global and defaults from local haproxy.cfg
        # We ONLY generate: frontends + backends
        # This ensures:
        # 1. Bulk imports never touch global/defaults configuration
        # 2. Entity updates (frontend/backend/SSL) never modify global/defaults
        # 3. Agent maintains control over platform-specific settings (chroot, user, stats socket, etc.)
        logger.info("📝 CONFIG GENERATION: Generating PARTIAL config (frontends + backends only)")
        logger.info("📝 CONFIG GENERATION: Agent will preserve existing global + defaults sections")
        
        config_lines = [
            "# ═══════════════════════════════════════════════════════════════════════",
            "# Generated by HAProxy Open Manager - Partial Configuration",
            "# ═══════════════════════════════════════════════════════════════════════",
            "# This is a PARTIAL configuration containing only:",
            "#   - Frontends (user-defined + stats)",
            "#   - Backends (user-defined)",
            "#",
            "# NOT INCLUDED (preserved from existing haproxy.cfg):",
            "#   - global section",
            "#   - defaults section", 
            "#",
            "# Agent will merge this with existing global/defaults sections",
            "# ═══════════════════════════════════════════════════════════════════════",
            ""
        ]
        
        # CRITICAL: Build backend mode lookup for validation
        backend_modes = {backend['name']: backend['mode'] for backend in backends}
        
        # ENTERPRISE COLLISION PREVENTION: Get DYNAMIC list of conflicting names
        # 1. Query ALL agents in this cluster for their preserved_listen_blocks
        # 2. Build union of all preserved block names
        # 3. Skip entities that would conflict with ANY agent's preserved blocks
        # This prevents "proxy has same name" errors during HAProxy validation
        
        # Static fallback list (used if no agent data available)
        static_reserved_names = {'stats', 'haproxy-stats', 'haproxy_stats', 'monitoring', 'admin', 'health', 'status'}
        
        # Dynamic: Query agents' actual preserved_listen_blocks
        agent_preserved_names = set()
        try:
            agent_blocks = await db_conn.fetch("""
                SELECT a.name as agent_name, a.preserved_listen_blocks
                FROM agents a
                JOIN haproxy_clusters hc ON hc.pool_id = a.pool_id
                WHERE hc.id = $1 AND a.preserved_listen_blocks IS NOT NULL AND a.is_active = TRUE
            """, cluster_id)
            
            for agent in agent_blocks:
                listen_blocks = agent['preserved_listen_blocks'] or []
                if isinstance(listen_blocks, str):
                    try:
                        listen_blocks = json.loads(listen_blocks)
                    except (ValueError, Exception):
                        listen_blocks = []
                
                for block_name in listen_blocks:
                    if isinstance(block_name, str):
                        agent_preserved_names.add(block_name.lower())
                        logger.debug(f"CONFIG GENERATION: Agent '{agent['agent_name']}' preserves listen block '{block_name}'")
            
            if agent_preserved_names:
                logger.info(f"CONFIG GENERATION: Dynamic collision check - {len(agent_preserved_names)} preserved block names from agents: {agent_preserved_names}")
        except Exception as e:
            logger.warning(f"CONFIG GENERATION: Could not query agent preserved blocks (column may not exist): {e}")
        
        # Combine: Use dynamic names if available, otherwise use static fallback
        # IMPORTANT: Only use static fallback if NO agent data available
        # This allows users to create 'stats' frontend if their agents don't preserve it
        if agent_preserved_names:
            conflicting_names = agent_preserved_names
            logger.info(f"CONFIG GENERATION: Using DYNAMIC collision list from agent data")
        else:
            conflicting_names = static_reserved_names
            logger.info(f"CONFIG GENERATION: Using STATIC collision list (no agent preserved_listen_blocks data)")
        
        # Add frontends with comprehensive configuration
        for frontend in frontends:
            # Validate required fields
            if not frontend.get('name'):
                logger.error("Frontend with missing name detected - skipping")
                continue
            if not frontend.get('bind_port') or not frontend.get('bind_address'):
                logger.error(f"Frontend '{frontend['name']}' has invalid bind configuration (address: {frontend.get('bind_address')}, port: {frontend.get('bind_port')}) - skipping")
                continue
            
            # ENTERPRISE COLLISION CHECK: Skip entities that conflict with agent's preserved listen blocks
            # This prevents HAProxy validation errors like "proxy has same name as proxy declared at..."
            if frontend['name'].lower() in conflicting_names:
                logger.warning(f"CONFIG GENERATION: Skipping frontend '{frontend['name']}' - name conflicts with agent's preserved listen block. "
                              f"To use this frontend, remove the corresponding listen block from agent's local haproxy.cfg first.")
                continue
            
            config_lines.append(f"frontend {frontend['name']}")
            
            # BIND DIRECTIVE - Single bind line with conditional SSL
            # SSL Configuration - ENTERPRISE DUAL-MODE SUPPORT
            # NEW WAY (Preferred): ssl_certificate_ids (multiple certs on bind_port)
            # OLD WAY (Deprecated): ssl_certificate_id + ssl_port (separate HTTPS port)
            
            bind_added = False  # Track if bind line was added
            
            if frontend.get('ssl_enabled', False):
                ssl_cert_ids = frontend.get('ssl_certificate_ids')
                
                # CRITICAL: Parse JSONB string from database
                # PostgreSQL returns JSONB as string: '[1, 2, 3]' → need to parse it
                if ssl_cert_ids and isinstance(ssl_cert_ids, str):
                    try:
                        ssl_cert_ids = json.loads(ssl_cert_ids)
                    except (ValueError, Exception):
                        logger.warning(f"Failed to parse ssl_certificate_ids for frontend '{frontend['name']}': {ssl_cert_ids}")
                        ssl_cert_ids = None
                
                # NEW WAY: Multiple SSL certificates on single bind (preferred)
                if ssl_cert_ids and isinstance(ssl_cert_ids, list) and len(ssl_cert_ids) > 0:
                    logger.info(f"🆕 SSL NEW MODE: Processing {len(ssl_cert_ids)} certificate(s) for frontend '{frontend['name']}'")
                    
                    # Get all certificate paths
                    cert_paths = []
                    for cert_id in ssl_cert_ids:
                        # Create temp frontend dict for each cert
                        temp_fe = {'ssl_certificate_id': cert_id, 'name': frontend['name']}
                        cert_path = await _get_ssl_certificate_path(temp_fe, cluster_id, db_conn)
                        if cert_path:
                            cert_paths.append(cert_path)
                    
                    if cert_paths:
                        # Generate single bind with SSL and multiple certificates
                        # Format: bind :443 ssl crt file1.pem crt file2.pem crt file3.pem [alpn h2,http/1.1] [ciphers ...]
                        crt_clause = ' '.join([f"crt {path}" for path in cert_paths])
                        bind_line = f"    bind {frontend['bind_address']}:{frontend['bind_port']} ssl {crt_clause}"
                        
                        # Add SSL advanced options if present
                        if frontend.get('ssl_alpn'):
                            bind_line += f" alpn {frontend['ssl_alpn']}"
                        if frontend.get('ssl_npn'):
                            bind_line += f" npn {frontend['ssl_npn']}"
                        if frontend.get('ssl_ciphers'):
                            bind_line += f" ciphers {frontend['ssl_ciphers']}"
                        if frontend.get('ssl_ciphersuites'):
                            bind_line += f" ciphersuites {frontend['ssl_ciphersuites']}"
                        if frontend.get('ssl_min_ver'):
                            bind_line += f" ssl-min-ver {frontend['ssl_min_ver']}"
                        if frontend.get('ssl_max_ver'):
                            bind_line += f" ssl-max-ver {frontend['ssl_max_ver']}"
                        if frontend.get('ssl_strict_sni'):
                            bind_line += " strict-sni"
                        # R11.A-2 fix (PR-1 hotfix): emit `verify required|optional`
                        # on bind line ONLY when a client-CA bundle is resolvable.
                        # Pre-fix the directive was emitted verbatim, but the
                        # `frontends` schema has no client-CA bundle column yet
                        # — so `bind ... ssl crt <server.pem> verify required`
                        # produced HAProxy fatal ALERT
                        # "verify is enabled but no CA file specified".
                        # Symmetric to the server-side downgrade at line ~840.
                        # Forward path: a future `ssl_client_ca_certificate_id`
                        # column will resolve `client_ca_path`; until then the
                        # directive is silently skipped with an ERROR log so
                        # operator-facing diagnostics surface the cause.
                        bind_line = _apply_bind_ssl_verify(bind_line, frontend, cluster_id)

                        config_lines.append(bind_line)
                        bind_added = True
                        logger.info(f"SSL NEW MODE: Added {len(cert_paths)} certificate(s) on port {frontend['bind_port']}")
                    else:
                        logger.warning(f"SSL enabled but no valid certificates found for frontend '{frontend['name']}'")
                
                # OLD WAY: Single SSL certificate on separate port (backward compatibility)
                elif frontend.get('ssl_certificate_id'):
                    logger.info(f"SSL OLD MODE (DEPRECATED): Single cert for frontend '{frontend['name']}'")
                    ssl_cert_path = await _get_ssl_certificate_path(frontend, cluster_id, db_conn)
                    if ssl_cert_path:
                        # Use explicit SSL port or default to 443
                        https_port = frontend.get('ssl_port') or 443
                        bind_line = f"    bind {frontend['bind_address']}:{https_port} ssl crt {ssl_cert_path}"
                        
                        # Add SSL advanced options if present (OLD MODE support)
                        if frontend.get('ssl_alpn'):
                            bind_line += f" alpn {frontend['ssl_alpn']}"
                        if frontend.get('ssl_npn'):
                            bind_line += f" npn {frontend['ssl_npn']}"
                        if frontend.get('ssl_ciphers'):
                            bind_line += f" ciphers {frontend['ssl_ciphers']}"
                        if frontend.get('ssl_ciphersuites'):
                            bind_line += f" ciphersuites {frontend['ssl_ciphersuites']}"
                        if frontend.get('ssl_min_ver'):
                            bind_line += f" ssl-min-ver {frontend['ssl_min_ver']}"
                        if frontend.get('ssl_max_ver'):
                            bind_line += f" ssl-max-ver {frontend['ssl_max_ver']}"
                        if frontend.get('ssl_strict_sni'):
                            bind_line += " strict-sni"
                        # R11.A-2 fix (PR-1 hotfix): see NEW MODE branch above
                        # for the bind-side ssl_verify safeguard rationale.
                        bind_line = _apply_bind_ssl_verify(bind_line, frontend, cluster_id)

                        config_lines.append(bind_line)
                        bind_added = True
                        logger.info(f"SSL OLD MODE: Separate HTTPS port {https_port} with single cert")
                    else:
                        logger.warning(f"SSL enabled but certificate not found for frontend '{frontend['name']}'")
                else:
                    logger.warning(f"SSL enabled but no certificates configured for frontend '{frontend['name']}'")
            
            # R18c audit fix (round 3 #2 — KRITIK SECURITY): if SSL was
            # ENABLED on this frontend but no certificate could be
            # resolved (cert deleted between INSERT and config gen,
            # or ACME-deferred state where the cert isn't issued
            # yet), the pre-fix branch fell through to a plain
            # `bind addr:port` (no `ssl` keyword) — i.e. it
            # silently downgraded the operator's HTTPS frontend to
            # CLEARTEXT on the same port. Anyone hitting that port
            # over the wire then got plaintext HTTP, leaking
            # cookies and credentials before the operator noticed.
            #
            # The correct behaviour is to OMIT the bind entirely
            # so HAProxy's reload either (a) keeps the previous
            # SSL bind from the running config, or (b) the apply
            # surfaces an empty/incomplete frontend that fails
            # validation rather than degrading to cleartext.
            if not bind_added:
                if frontend.get('ssl_enabled', False):
                    logger.error(
                        f"SSL BIND OMITTED: frontend '{frontend['name']}' "
                        "has ssl_enabled=true but no certificate path could "
                        "be resolved — refusing to emit a cleartext fallback "
                        "bind on the SSL port (would silently downgrade "
                        "HTTPS to plaintext). Resolve the cert binding "
                        "before applying."
                    )
                else:
                    config_lines.append(
                        f"    bind {frontend['bind_address']}:{frontend['bind_port']}"
                    )
            
            config_lines.append(f"    mode {frontend['mode']}")

            # ─────────────────────────────────────────────────────────────────
            # R2.3 / R3.3 (PR-1 hotfix): emit ordering buckets.
            # All directives between `bind/mode` and the closing blank line
            # are routed into per-category buckets and flushed at the
            # end of this frontend block in canonical HAProxy order:
            #
            #   prelude (option/timeout/maxconn/monitor-uri/compression/log)
            #   stick   (stick-table/track-sc0)              — DEDUP'ed
            #   tcp_req (tcp-request *)
            #   acl     (acl *)
            #   http_req (http-request *)
            #   http_resp (http-response *)
            #   redirect (redirect *)
            #   use_be  (use_backend *)
            #   default_be (default_backend)
            #
            # Pre-fix the `http-request` / `tcp-request` / `use_backend`
            # rules emitted in source-code order produced HAProxy
            # warnings of the form
            #   "a 'http-request' rule placed after a 'use_backend' rule
            #    will still be processed before"
            # for every WAF, ACL and rate-limit directive in user
            # configurations. The user's reported bug shows ~30 such
            # warnings on a real config. Buckets eliminate that.
            # `_stick_emitted` tracks whether the global rate-limit
            # `stick-table` line has already been written so subsequent
            # WAF `rate_limit` rules don't redeclare it (HAProxy fatal
            # "stick-table already declared").
            # ─────────────────────────────────────────────────────────────────
            _fe_buckets: Dict[str, List[str]] = {
                "prelude": [], "stick": [], "tcp_req": [],
                "acl": [], "http_req": [], "http_resp": [],
                "redirect": [], "use_be": [], "default_be": [],
            }
            _stick_table_emitted = False
            # Phase K Phase D follow-up (Bulgu #13) — same dedup
            # contract for `http-request track-sc<N> <fetch>` lines.
            # HAProxy only NEEDS one tracking call per
            # (counter, fetch) tuple per frontend; the subsequent
            # rate-limit / WAF rules can all consume the already-
            # tracked counter via `sc_http_req_rate(N)`. Pre-fix
            # every WAF rate_limit rule emitted its own
            # `track-sc0 src` line, producing N-1 redundant
            # directives per frontend (each one a state-table
            # operation per request).
            #
            # We dedup on the FULL `track-sc<N> <fetch>` signature so
            # the (rare) operator who uses both `track-sc0 src` AND
            # `track-sc0 dst` (different sample fetches → different
            # counter keys) keeps both lines — only IDENTICAL
            # signatures collapse.
            _track_sc_signatures: set = set()

            def _emit_fe(line: str) -> None:
                """Route a single rendered HAProxy directive line into the
                correct frontend-block bucket. Idempotent for stick-table
                lines (R3.3 dedup) AND http-request track-sc<N> lines
                (Bulgu #13 dedup)."""
                nonlocal _stick_table_emitted
                cat = _categorize_haproxy_directive(line)
                stripped = line.strip()
                if cat == "stick":
                    if _stick_table_emitted and stripped.startswith("stick-table"):
                        logger.debug(
                            f"STICK-TABLE DEDUP: skipping duplicate "
                            f"declaration in frontend '{frontend['name']}': "
                            f"{stripped}"
                        )
                        return
                    if stripped.startswith("stick-table"):
                        _stick_table_emitted = True
                # Bulgu #13 dedup (round 2) — categorisation routes
                # `http-request track-sc<N>` to the `http_req` bucket
                # (it IS an http-request rule). Build a stable
                # signature from the directive + counter + fetch so
                # multiple counters / fetches don't collide.
                if stripped.startswith("http-request track-sc"):
                    parts = stripped.split()
                    # parts looks like ['http-request', 'track-sc0', 'src', ...]
                    # The (track-scN, fetch) tuple uniquely identifies
                    # the tracker. Anything after that (e.g. `table foo`)
                    # is part of the SAME tracker and shouldn't change
                    # the signature.
                    if len(parts) >= 3:
                        sig = (parts[1], parts[2])
                        if sig in _track_sc_signatures:
                            logger.debug(
                                f"TRACK-SC DEDUP: skipping duplicate "
                                f"`{stripped}` in frontend "
                                f"'{frontend['name']}' — same "
                                f"(counter, fetch) signature already "
                                f"emitted; subsequent rate-limit "
                                f"rules consume the same counter."
                            )
                            return
                        _track_sc_signatures.add(sig)
                _fe_buckets[cat].append(line)

            # ACME HTTP-01 Challenge routing (auto-managed)
            if frontend['mode'] == 'http' and cluster_info.get('acme_enabled', False):
                _emit_fe("    acl is_acme_challenge path_beg /.well-known/acme-challenge/")
                _emit_fe("    http-request allow if is_acme_challenge")
                _emit_fe("    use_backend _acme_challenge_backend if is_acme_challenge")

            # Frontend Options (option httplog, option forwardfor, etc.)
            # Place options early as per HAProxy best practice
            if frontend.get('options'):
                for line in frontend['options'].split('\n'):
                    line_stripped = line.strip()
                    if line_stripped and line_stripped not in ('[]', '{}', 'null', 'None'):
                        _emit_fe(f"    {line_stripped}")

            # CRITICAL: Validate frontend-backend mode compatibility
            if frontend.get('default_backend'):
                default_backend_name = frontend['default_backend'].strip() if frontend['default_backend'] else ''
                if default_backend_name and default_backend_name not in ('[]', '{}', 'null', 'None'):
                    backend_mode = backend_modes.get(default_backend_name)

                    if backend_mode and backend_mode != frontend['mode']:
                        logger.error(f"CONFIG ERROR: Frontend '{frontend['name']}' mode '{frontend['mode']}' does not match backend '{default_backend_name}' mode '{backend_mode}'")
                        # FIX-10 marker: 'BACKEND-MODE-WARNING' keyword in
                        # the comment body routes it to the 'default_be'
                        # bucket via _categorize_haproxy_directive, so the
                        # warning emits next to the actual default_backend
                        # directive instead of at the top of the block.
                        _emit_fe(f"    # BACKEND-MODE-WARNING: Backend '{default_backend_name}' has mode '{backend_mode}' but frontend has mode '{frontend['mode']}'")
                        _emit_fe(f"    # BACKEND-MODE-WARNING: HAProxy will reject this configuration! Please fix the mode mismatch in UI.")

                    _emit_fe(f"    default_backend {default_backend_name}")
                else:
                    logger.warning(f"CONFIG WARNING: Frontend '{frontend['name']}' has invalid default_backend: '{frontend.get('default_backend')}' - skipping")

            # Timeouts - CRITICAL FIX: Append 'ms' suffix
            if frontend.get('timeout_client'):
                _emit_fe(f"    timeout client {frontend['timeout_client']}ms")
            if frontend.get('timeout_http_request'):
                _emit_fe(f"    timeout http-request {frontend['timeout_http_request']}ms")

            # Max connections
            if frontend.get('maxconn'):
                _emit_fe(f"    maxconn {frontend['maxconn']}")

            # Rate limiting (frontend.rate_limit)
            # R3.3: only the FIRST stick-table line is kept; subsequent
            # WAF rate_limit rules track-sc0 against the same table.
            if frontend.get('rate_limit'):
                _emit_fe(f"    stick-table type ip size 100k expire 30s store http_req_rate(10s)")
                _emit_fe(f"    http-request track-sc0 src")
                _emit_fe(f"    http-request deny if {{ sc_http_req_rate(0) gt {frontend['rate_limit']} }}")

            # Compression
            if frontend.get('compression', False):
                _emit_fe("    compression algo gzip")
                _emit_fe("    compression type text/html text/plain text/css text/javascript application/javascript")

            # Monitor URI
            if frontend.get('monitor_uri'):
                monitor_uri = frontend['monitor_uri'].strip() if frontend['monitor_uri'] else ''
                if monitor_uri and monitor_uri not in ('[]', '{}', 'null', 'None'):
                    _emit_fe(f"    monitor-uri {monitor_uri}")
            
            # ACL Rules — categorized into 'acl' bucket; the buffer
            # ordering already guarantees they are emitted before any
            # http-request / use_backend that references them.
            if frontend.get('acl_rules'):
                acl_rules = frontend['acl_rules']
                logger.info(f"ACL_RULES DEBUG: Frontend '{frontend['name']}' acl_rules type: {type(acl_rules)}, repr: {repr(acl_rules)}")

                if isinstance(acl_rules, str):
                    try:
                        acl_rules = json.loads(acl_rules)
                        logger.info(f"ACL_RULES DEBUG: Parsed as JSON list with {len(acl_rules) if isinstance(acl_rules, list) else 'N/A'} items")
                    except (ValueError, json.JSONDecodeError):
                        logger.warning(f"ACL_RULES DEBUG: JSON parse failed, setting to empty list")
                        acl_rules = []

                if isinstance(acl_rules, list):
                    for idx, acl in enumerate(acl_rules):
                        if acl and isinstance(acl, str) and acl.strip():
                            acl_text = acl.strip().strip('[]"\'').strip()
                            logger.info(f"ACL_RULES DEBUG: Rule {idx}: original={repr(acl)}, cleaned={repr(acl_text)}")
                            if acl_text and acl_text not in ('[]', '{}', 'null', 'None'):
                                if not acl_text.startswith('acl '):
                                    acl_text = f"acl {acl_text}"
                                _emit_fe(f"    {acl_text}")

            # HTTP Request Headers — categorized into 'http_req'.
            if frontend.get('request_headers'):
                for line in frontend['request_headers'].split('\n'):
                    line_stripped = line.strip()
                    if line_stripped and line_stripped not in ('[]', '{}', 'null', 'None'):
                        _emit_fe(f"    {line_stripped}")

            # HTTP Response Headers — categorized into 'http_resp'.
            if frontend.get('response_headers'):
                for line in frontend['response_headers'].split('\n'):
                    line_stripped = line.strip()
                    if line_stripped and line_stripped not in ('[]', '{}', 'null', 'None'):
                        _emit_fe(f"    {line_stripped}")

            # TCP Request Rules — categorized into 'tcp_req' bucket so
            # they always emit BEFORE any 'http-request' directive (HAProxy
            # warns "tcp-request placed after http-request will still be
            # processed before" — pre-fix that warning fired on every
            # TCP-mode frontend with later WAF rules).
            if frontend.get('tcp_request_rules'):
                for line in frontend['tcp_request_rules'].split('\n'):
                    line_stripped = line.strip()
                    if line_stripped and line_stripped not in ('[]', '{}', 'null', 'None'):
                        _emit_fe(f"    {line_stripped}")

            # Redirect Rules — categorized into 'redirect' bucket.
            # R11.A-1 (PR-1 hotfix): use _format_redirect_rule helper which
            # safely renders dict payloads (the wizard's `_build_redirect_rules`
            # emits dicts) into proper HAProxy `redirect <type> ...` syntax.
            if frontend.get('redirect_rules'):
                redirect_rules = frontend['redirect_rules']
                if isinstance(redirect_rules, str):
                    try:
                        redirect_rules = json.loads(redirect_rules)
                    except (ValueError, json.JSONDecodeError):
                        redirect_rules = [r.strip() for r in redirect_rules.split('\n') if r.strip()]

                if isinstance(redirect_rules, list):
                    for redirect in redirect_rules:
                        line = _format_redirect_rule(redirect)
                        if line:
                            _emit_fe(line)
            
            # Use Backend Rules — categorized into 'use_be' bucket so they
            # always emit AFTER http-request rules (HAProxy parser
            # warning fix) and BEFORE default_backend.
            if frontend.get('use_backend_rules'):
                use_backend_rules = frontend['use_backend_rules']

                logger.info(f"USE_BACKEND DEBUG: Frontend '{frontend['name']}' use_backend_rules type: {type(use_backend_rules)}, repr: {repr(use_backend_rules)}")

                rules_list = None

                if isinstance(use_backend_rules, str):
                    try:
                        parsed = json.loads(use_backend_rules)
                        if isinstance(parsed, list):
                            rules_list = parsed
                            logger.info(f"USE_BACKEND DEBUG: Parsed as JSON list with {len(rules_list)} items")
                        else:
                            logger.warning(f"Frontend '{frontend['name']}' use_backend_rules parsed to non-list: {type(parsed)}")
                    except json.JSONDecodeError as e:
                        logger.info(f"USE_BACKEND DEBUG: JSON parse failed ({e}), trying newline split")
                        rules_list = [r.strip() for r in use_backend_rules.split('\n') if r.strip()]

                elif isinstance(use_backend_rules, (list, tuple)):
                    rules_list = list(use_backend_rules)
                    logger.info(f"USE_BACKEND DEBUG: Already a list with {len(rules_list)} items")

                else:
                    logger.error(f"Frontend '{frontend['name']}' use_backend_rules has unexpected type {type(use_backend_rules)}: {use_backend_rules}")
                    try:
                        rules_str = str(use_backend_rules)
                        if rules_str.startswith('[') and rules_str.endswith(']'):
                            rules_list = json.loads(rules_str)
                    except Exception as e:
                        logger.error(f"Failed to parse use_backend_rules: {e}")
                        rules_list = None

                if rules_list:
                    for idx, rule in enumerate(rules_list):
                        if rule and isinstance(rule, str):
                            rule_text = rule.strip().strip('[]"\'').strip()
                            logger.info(f"USE_BACKEND DEBUG: Rule {idx}: original={repr(rule)}, cleaned={repr(rule_text)}")
                            if rule_text and rule_text not in ('[]', '{}', 'null', 'None', '""', "''"):
                                if not rule_text.startswith('use_backend '):
                                    rule_text = f"use_backend {rule_text}"
                                _emit_fe(f"    {rule_text}")
                                logger.debug(f"Added use_backend rule: {rule_text}")
                        else:
                            logger.warning(f"Skipping invalid rule (type: {type(rule)}): {rule}")

            # Separate logging
            if frontend.get('log_separate', False):
                _emit_fe(f"    log 127.0.0.1:514 local0 info")

            # Add WAF rules for this frontend
            assigned_waf_rules = [rule for rule in waf_rules_records if frontend['id'] in rule['frontend_ids']]
            effective_waf_rules = list(assigned_waf_rules) + list(cluster_global_waf_rules)
            try:
                effective_waf_rules.sort(key=lambda r: (r.get('priority', 100), r.get('name', '')))
            except Exception:
                pass

            for waf_rule in effective_waf_rules:
                merged_rule = dict(waf_rule)
                cfg = waf_rule.get('config')
                if cfg:
                    try:
                        if isinstance(cfg, str):
                            cfg = json.loads(cfg)
                    except Exception as e:
                        logger.warning(f"Config Generation: Failed to parse WAF rule {waf_rule['id']} config: {e}")
                        cfg = {}
                    if isinstance(cfg, dict):
                        merged_rule.update(cfg)

                waf_config_lines = _generate_waf_config_lines(merged_rule)
                if waf_config_lines:
                    logger.debug(f"Config Generation: Added {len(waf_config_lines)} lines for WAF rule '{waf_rule['name']}' (ID: {waf_rule['id']}, Status: {waf_rule.get('last_config_status', 'N/A')})")
                    # R3.3: each WAF line is routed individually so the
                    # buckets keep ordering correct AND so duplicate
                    # `stick-table` declarations from multiple
                    # rate_limit rules are deduped at the buffer.
                    for waf_line in waf_config_lines:
                        _emit_fe(waf_line)
                else:
                    logger.warning(f"Config Generation: No config lines generated for WAF rule '{waf_rule['name']}' (ID: {waf_rule['id']}, Type: {waf_rule['rule_type']})")

            # ─────────────────────────────────────────────────────────────
            # Flush the per-frontend buckets in canonical HAProxy order.
            # The order below is the single source of truth for emit
            # ordering in this generator. See `_categorize_haproxy_directive`
            # for the per-prefix routing rules.
            # ─────────────────────────────────────────────────────────────
            for _bucket_key in (
                "prelude",
                "stick",
                "tcp_req",
                "acl",
                "http_req",
                "http_resp",
                "redirect",
                "use_be",
                "default_be",
            ):
                if _fe_buckets[_bucket_key]:
                    config_lines.extend(_fe_buckets[_bucket_key])

            config_lines.append("")
        
        # Add backends
        for backend in backends:
            # Validate required fields
            if not backend.get('name'):
                logger.error("Backend with missing name detected - skipping")
                continue
            
            # ENTERPRISE COLLISION CHECK: Skip backends that conflict with agent's preserved listen blocks
            if backend['name'].lower() in conflicting_names:
                logger.warning(f"CONFIG GENERATION: Skipping backend '{backend['name']}' - name conflicts with agent's preserved listen block. "
                              f"To use this backend, remove the corresponding listen block from agent's local haproxy.cfg first.")
                continue
            
            # CRITICAL PRE-CHECK: Get servers BEFORE starting backend config
            # This allows us to skip backends with no servers before writing anything
            # CRITICAL FIX: Handle servers with NULL cluster_id (legacy data)
            # CRITICAL: Select ssl_certificate_id for SSL ca-file path generation
            servers_precheck = await db_conn.fetch("""
                SELECT id FROM backend_servers 
                WHERE backend_name = $1 AND (cluster_id = $2 OR cluster_id IS NULL) AND is_active = TRUE
            """, backend["name"], cluster_id)
            
            if not servers_precheck or len(servers_precheck) == 0:
                logger.info(f"CONFIG GENERATION: Backend '{backend['name']}' has NO ACTIVE SERVERS. Writing backend block (will show as DOWN until servers added).")
            
            config_lines.append(f"backend {backend['name']}")
            
            # --- HAProxy Configuration Best Practice Order ---
            # 1. Mode and balance method
            if backend.get('balance_method'):
                config_lines.append(f"    balance {backend['balance_method']}")
            if backend.get('mode'):
                config_lines.append(f"    mode {backend['mode']}")
            
            # 2. Backend Options (option http-keep-alive, option forwardfor, etc.)
            # Place options early as per HAProxy best practice
            if backend.get('options'):
                for line in backend['options'].split('\n'):
                    line_stripped = line.strip()
                    # Skip empty strings, "[]", or invalid rules
                    if line_stripped and line_stripped not in ('[]', '{}', 'null', 'None'):
                        # Lines are complete HAProxy option directives
                        # Examples: "option http-keep-alive", "option forwardfor"
                        config_lines.append(f"    {line_stripped}")
            
            # 3. Health check configuration
            if backend.get('health_check_uri'):
                health_check_uri = backend['health_check_uri'].strip() if backend['health_check_uri'] else ''
                # Skip empty strings, "[]", or invalid values
                if health_check_uri and health_check_uri not in ('[]', '{}', 'null', 'None'):
                    config_lines.append(f"    option httpchk GET {health_check_uri}")
            
            # HTTP Check Expect Status (new field) - ONLY for HTTP mode!
            # TCP backends cannot use http-check directives
            if backend.get('health_check_expected_status') and backend.get('mode') == 'http':
                config_lines.append(f"    http-check expect status {backend['health_check_expected_status']}")

            # 4. Timeouts
            if backend.get('timeout_connect'):
                config_lines.append(f"    timeout connect {backend.get('timeout_connect')}ms")
            if backend.get('timeout_server'):
                config_lines.append(f"    timeout server {backend.get('timeout_server')}ms")
            if backend.get('timeout_queue'):
                config_lines.append(f"    timeout queue {backend.get('timeout_queue')}ms")
            
            # 5. Cookie Persistence
            if backend.get('cookie_name'):
                cookie_name = backend['cookie_name'].strip() if backend['cookie_name'] else ''
                # Skip empty strings, "[]", or invalid values
                if cookie_name and cookie_name not in ('[]', '{}', 'null', 'None'):
                    cookie_line = f"    cookie {cookie_name}"
                    cookie_opts = backend.get('cookie_options', '').strip()
                    # Skip empty strings, "[]", or invalid values
                    if cookie_opts and cookie_opts not in ('[]', '{}', 'null', 'None'):
                        cookie_line += f" {cookie_opts}"
                    config_lines.append(cookie_line)
            
            # 6. Full Connections
            if backend.get('fullconn'):
                config_lines.append(f"    fullconn {backend['fullconn']}")
            
            # 7. Default Server Options
            if backend.get('default_server_inter') or backend.get('default_server_fall') or backend.get('default_server_rise'):
                default_server_line = "    default-server"
                if backend.get('default_server_inter'):
                    default_server_line += f" inter {backend['default_server_inter']}ms"
                if backend.get('default_server_fall'):
                    default_server_line += f" fall {backend['default_server_fall']}"
                if backend.get('default_server_rise'):
                    default_server_line += f" rise {backend['default_server_rise']}"
                config_lines.append(default_server_line)
            
            # 8. HTTP Request Headers
            if backend.get('request_headers'):
                for line in backend['request_headers'].split('\n'):
                    line_stripped = line.strip()
                    # Skip empty strings, "[]", or invalid rules
                    if line_stripped and line_stripped not in ('[]', '{}', 'null', 'None'):
                        # Lines are already complete directives (e.g., "http-request set-header X-Backend test")
                        config_lines.append(f"    {line_stripped}")
            
            # 9. HTTP Response Headers
            if backend.get('response_headers'):
                for line in backend['response_headers'].split('\n'):
                    line_stripped = line.strip()
                    # Skip empty strings, "[]", or invalid rules
                    if line_stripped and line_stripped not in ('[]', '{}', 'null', 'None'):
                        # Lines are already complete directives (e.g., "http-response add-header X-Powered-By Backend")
                        config_lines.append(f"    {line_stripped}")

            # Get all servers for this backend (including inactive ones for commenting)
            # CRITICAL FIX: Handle servers with NULL cluster_id (legacy data)
            # Some servers might not have cluster_id set, so we also check for NULL cluster_id
            # CRITICAL: Select ssl_certificate_id for SSL ca-file path generation
            servers = await db_conn.fetch("""
                SELECT id, backend_name, server_name, server_address, server_port, weight, maxconn,
                       check_enabled, check_port, backup_server, ssl_enabled, ssl_verify, ssl_certificate_id,
                       ssl_sni, ssl_min_ver, ssl_max_ver, ssl_ciphers,
                       cookie_value, inter, fall, rise, is_active, cluster_id, last_config_status
                FROM backend_servers 
                WHERE backend_name = $1 AND (cluster_id = $2 OR cluster_id IS NULL)
                ORDER BY COALESCE(server_name, 'server_' || id), id
            """, backend["name"], cluster_id)
            
            logger.info(f"CONFIG DEBUG: Found {len(servers)} servers for backend '{backend['name']}' in cluster {cluster_id}")
            for i, server in enumerate(servers):
                logger.info(f"CONFIG DEBUG: Server {i+1}: id={server.get('id')}, name={server.get('server_name')}, address={server.get('server_address')}:{server.get('server_port')}")
            
            for server in servers:
                # CRITICAL FIX: Handle NULL server_name by using a fallback or skipping
                server_name = server.get('server_name', '').strip() if server.get('server_name') else ''
                # Skip invalid server names
                if not server_name or server_name in ('[]', '{}', 'null', 'None'):
                    server_name = f"server_{server['id']}"
                
                # Validate server address (critical - server without address is invalid)
                server_address = server.get('server_address', '').strip() if server.get('server_address') else ''
                if not server_address or server_address in ('[]', '{}', 'null', 'None'):
                    logger.error(f"Server '{server_name}' in backend '{backend['name']}' has no address - skipping")
                    continue
                
                logger.info(f"CONFIG DEBUG: Processing server {server_name} - address={server_address}:{server.get('server_port')}, weight={server.get('weight')}, active={server.get('is_active')}")
                
                # CRITICAL FIX: Port 0 means no port specified (use backend default)
                # In HAProxy, "server name addr" without port uses backend's default port
                server_port = server.get('server_port')
                if server_port and server_port != 0:
                    server_line = f"    server {server_name} {server_address}:{server_port}"
                else:
                    # No port specified - HAProxy will use backend's default port based on mode
                    server_line = f"    server {server_name} {server_address}"
                
                server_line += f" weight {server['weight']}"
                
                if server.get('max_connections'):
                    server_line += f" maxconn {server['max_connections']}"
                
                # SSL Configuration (new field: ssl_verify and ssl_certificate_id)
                if server.get('ssl_enabled', False):
                    server_line += " ssl"
                    ssl_verify = server.get('ssl_verify', '').strip() if server.get('ssl_verify') else ''
                    has_ca_file = False
                    
                    # Add ca-file path if SSL certificate is selected
                    if server.get('ssl_certificate_id'):
                        ssl_cert_id = server['ssl_certificate_id']
                        # Get SSL certificate name to generate path
                        ssl_cert = await db_conn.fetchrow("""
                            SELECT name FROM ssl_certificates 
                            WHERE id = $1 AND is_active = TRUE
                        """, ssl_cert_id)
                        
                        if ssl_cert:
                            cert_filename = f"{ssl_cert['name']}.pem"
                            cert_path = f"/etc/ssl/haproxy/{cert_filename}"
                            server_line += f" ca-file {cert_path}"
                            has_ca_file = True
                            logger.info(f"🔒 CONFIG SSL: Added ca-file for server {server_name}: {cert_path}")
                    
                    # Handle ssl_verify option.
                    # Skip empty strings, "[]", or invalid values.
                    if ssl_verify and ssl_verify not in ('[]', '{}', 'null', 'None'):
                        # R18c audit fix (round 3 #3 — KRITIK config
                        # validity): refuse to emit `verify required`
                        # (or `verify optional`) when no `ca-file`
                        # could be resolved for this server. Pre-fix
                        # the operator's `ssl_verify=required` was
                        # emitted verbatim even after a referenced
                        # SSL cert was deleted / soft-deactivated,
                        # producing a config that HAProxy reload
                        # SOMETIMES rejected and SOMETIMES accepted
                        # (depending on whether
                        # `ssl-default-server-ca-file` was set in
                        # the global block). The result was either a
                        # hard reload failure or — worse — silent
                        # acceptance with default system trust,
                        # leading to upstream connections that
                        # bypassed the operator's expected CA pin.
                        # Downgrade to `verify none` with an ERROR
                        # log so the operator sees the cause in
                        # apply-changes diagnostics and can re-bind
                        # the cert.
                        verify_lower = ssl_verify.strip().lower()
                        if verify_lower in ('required', 'optional') and not has_ca_file:
                            server_line += " verify none"
                            logger.error(
                                f"CONFIG SSL DOWNGRADE: server {server_name} "
                                f"requested verify={verify_lower} but no "
                                "ca-file could be resolved (ssl_certificate_id "
                                "missing or pointing at an inactive cert). "
                                "Emitting 'verify none' to prevent reload "
                                "failure / accidental system-trust validation. "
                                "Re-bind the CA cert before applying."
                            )
                        else:
                            server_line += f" verify {ssl_verify}"
                    elif not has_ca_file:
                        # CRITICAL: If SSL is enabled but no CA file and no explicit verify option,
                        # HAProxy 2.8+ defaults to 'verify required' which will fail without CA.
                        # Default to 'verify none' to prevent validation errors.
                        server_line += " verify none"
                        logger.warning(f"⚠️ CONFIG SSL: Server {server_name} has SSL enabled but no CA file - defaulting to 'verify none'")
                    
                    # Add SSL advanced options if present
                    if server.get('ssl_sni'):
                        server_line += f" sni {server['ssl_sni']}"
                    if server.get('ssl_min_ver'):
                        server_line += f" ssl-min-ver {server['ssl_min_ver']}"
                    if server.get('ssl_max_ver'):
                        server_line += f" ssl-max-ver {server['ssl_max_ver']}"
                    if server.get('ssl_ciphers'):
                        server_line += f" ciphers {server['ssl_ciphers']}"
                
                # Health Check (with new field: check_port)
                if server.get('check_enabled', True):
                    server_line += " check"
                    if server.get('check_port'):
                        server_line += f" port {server['check_port']}"
                
                # Health Check Timings (new fields: inter, fall, rise)
                if server.get('inter'):
                    server_line += f" inter {server['inter']}ms"
                if server.get('fall'):
                    server_line += f" fall {server['fall']}"
                if server.get('rise'):
                    server_line += f" rise {server['rise']}"
                
                # Cookie Value (new field)
                # Phase K Phase D follow-up (Bulgu #13) — only emit
                # the per-server `cookie <value>` attribute when the
                # PARENT backend actually has cookie-based session
                # persistence enabled (`cookie SERVERID insert
                # indirect nocache` directive). Without that, the
                # per-server cookie is just metadata HAProxy stores
                # but never inserts / reads → silently broken
                # stickiness. Pre-fix the wizard let the operator
                # set `cookie srv1` on a server while leaving the
                # backend's cookie_name empty, producing a confusing
                # half-configured stickiness.
                cookie_val = server.get('cookie_value', '').strip() if server.get('cookie_value') else ''
                parent_backend_has_cookie = bool(
                    (backend.get('cookie_name') or '').strip()
                    and backend['cookie_name'].strip() not in ('[]', '{}', 'null', 'None')
                )
                # Skip empty strings, "[]", or invalid values
                if cookie_val and cookie_val not in ('[]', '{}', 'null', 'None'):
                    if parent_backend_has_cookie:
                        server_line += f" cookie {cookie_val}"
                    else:
                        logger.warning(
                            f"CONFIG COOKIE INCONSISTENT: server "
                            f"{server_name} in backend "
                            f"'{backend.get('name', '<unnamed>')}' has "
                            f"cookie_value='{cookie_val}' but the "
                            f"backend itself has no cookie persistence "
                            f"directive (cookie_name is empty). The "
                            f"per-server cookie is being SKIPPED in the "
                            f"rendered config to prevent silently broken "
                            f"stickiness. Enable backend-level cookie "
                            f"persistence first, or clear the per-server "
                            f"cookie_value."
                        )
                
                # Backup Server
                if server.get('backup_server', False):
                    server_line += " backup"
                
                # Skip servers marked for deletion (last_config_status = 'DELETION')
                if server.get('last_config_status') == 'DELETION':
                    # Server is marked for deletion - skip it completely
                    logger.debug(f"Config Generation: Skipping server {server_name} marked for deletion")
                    continue
                
                # If server is disabled (but not deleted), comment it out
                if not server.get('is_active', True):
                    server_line = f"    # DISABLED: {server_line.strip()}"
                    logger.info(f"CONFIG DEBUG: Server {server_name} marked as DISABLED")
                else:
                    logger.info(f"CONFIG DEBUG: Server {server_name} is ACTIVE - adding to config")
                
                config_lines.append(server_line)
                logger.info(f"CONFIG DEBUG: Added server line: {server_line}")
            
            config_lines.append("")
        
        # ACME challenge backend section
        if cluster_info.get('acme_enabled', False):
            # Issue #11: guard against duplicate `backend _acme_challenge_backend`.
            # If the user-defined backends list already contains an entry with this
            # reserved name (synced from agent or imported), skip auto-append to
            # prevent HAProxy "Duplicate Name" validation failure on Apply.
            already_rendered = any(
                b.get('name') == '_acme_challenge_backend' for b in backends
            )
            # Commit 6a: skip auto-append if cluster has no HTTP-mode frontends.
            # The acme-challenge backend is only useful when there's an HTTP frontend
            # routing /.well-known/acme-challenge/* to it. On a TCP-only cluster the
            # appended backend is dead config that pollutes the file (no use_backend
            # ACL targets it), but it's harmless to HAProxy validation.
            has_http_frontend = any(
                (f.get('mode') or 'http').lower() == 'http' for f in frontends
            )
            if already_rendered:
                logger.warning(
                    "ACME auto-append skipped: '_acme_challenge_backend' already present "
                    "in active backends list (likely synced from agent or restored)."
                )
            elif not has_http_frontend:
                logger.info(
                    f"ACME auto-append skipped for cluster {cluster_id}: no HTTP-mode "
                    f"frontend found (would create orphan backend section)."
                )
            else:
                acme_url = cluster_info.get('acme_backend_url') or ''
                if not acme_url:
                    try:
                        acme_settings = await db_conn.fetchrow(
                            "SELECT value FROM system_settings WHERE key = 'acme.challenge_backend_url'"
                        )
                        if acme_settings and acme_settings['value']:
                            val = acme_settings['value']
                            if isinstance(val, str):
                                try:
                                    val = json.loads(val)
                                except (json.JSONDecodeError, TypeError):
                                    pass
                            if val:
                                acme_url = str(val)
                    except Exception:
                        pass
                if not acme_url:
                    from config import MANAGEMENT_BASE_URL
                    acme_url = MANAGEMENT_BASE_URL

                parsed = urllib.parse.urlparse(acme_url)
                host = parsed.hostname or 'localhost'
                port = parsed.port or (443 if parsed.scheme == 'https' else 8080)
                ssl_flag = ' ssl verify none' if parsed.scheme == 'https' else ''

                config_lines.append("# ACME Challenge Backend (auto-managed by HAProxy OpenManager)")
                config_lines.append("backend _acme_challenge_backend")
                config_lines.append("    mode http")
                config_lines.append(f"    server _acme_mgmt {host}:{port}{ssl_flag}")
                config_lines.append("")

        # Only close the connection if it was created within this function
        if not conn:
            await close_database_connection(db_conn)
        
        # Join all lines
        config_content = "\n".join(config_lines)
        
        # Log summary for debugging
        excluded_count = len(pending_delete_waf_ids) if 'pending_delete_waf_ids' in locals() and pending_delete_waf_ids else 0
        logger.info(f"Config Generation: Generated {len(config_lines)} lines for cluster {cluster_id} with {len(frontends)} frontends, {len(backends)} backends, {len(waf_rules_records)} assigned WAF rules, {len(cluster_global_waf_rules)} global WAF rules (excluded {excluded_count} pending-delete WAF rules)")
        
        return config_content
        
    except Exception as e:
        logger.error(f"Failed to generate HAProxy config for cluster {cluster_id}: {e}")
        # Ensure connection is closed on error if it was created here
        if not conn and db_conn:
            await close_database_connection(db_conn)
        return f"# Error generating configuration: {str(e)}"

def _is_valid_haproxy_condition(condition: str) -> bool:
    """Basic validation for HAProxy condition syntax"""
    if not condition or not condition.strip():
        return False
    
    condition = condition.strip()
    
    # Allow complete HAProxy directives
    if condition.startswith(('http-request', 'http-response', 'acl')):
        return True
    
    # Basic ACL condition validation - should contain braces for HAProxy expressions
    # Valid examples: { req.hdr(user-agent) -m sub bot }, { src -f /path/file }
    if '{' in condition and '}' in condition:
        return True
    
    # Allow simple conditions that will be wrapped in braces
    # Valid examples: req.hdr(user-agent) -m sub bot, src -f /path/file
    if any(keyword in condition for keyword in ['req.', 'res.', 'src', 'dst', '-m', '-f', '-i']):
        return True
    
    # Reject obviously invalid conditions (single words, numbers, etc.)
    if len(condition.split()) < 2:
        return False
    
    return False

def _generate_waf_config_lines(waf_rule: Dict[str, Any]) -> List[str]:
    """Generate HAProxy configuration lines for a WAF rule"""
    lines = []
    rule_name = waf_rule['name'].replace(' ', '_').lower()
    
    # Add comment header with rule info for debugging
    priority = waf_rule.get('priority', 100)
    action = waf_rule.get('action', 'block')
    lines.append(f"    # WAF Rule: {waf_rule['name']} (Priority: {priority}, Action: {action})")
    
    if waf_rule['rule_type'] == 'ip_filter' and waf_rule.get('ip_addresses'):
        acl_name = f"waf_{rule_name}_ips"
        ip_list = ' '.join(waf_rule['ip_addresses'])
        lines.append(f"    acl {acl_name} src {ip_list}")
        
        # Use ip_action if available, otherwise fall back to general action
        action_type = waf_rule.get('ip_action', action)
        if action_type in ['blacklist', 'block']:
            lines.append(f"    http-request deny if {acl_name}")
        elif action_type in ['whitelist', 'allow']:
            lines.append(f"    http-request allow if {acl_name}")
        
        # Handle Custom Log Message and Custom HAProxy Condition for IP Filter
        log_msg = waf_rule.get('log_message') or waf_rule.get('custom_log_message')
        if log_msg:
            lines.append(f"    # IP Filter Log: {log_msg}")
        
        custom_condition = waf_rule.get('custom_condition') or waf_rule.get('custom_haproxy_condition')
        if custom_condition:
            custom_condition = custom_condition.strip()
            # Skip empty strings, "[]", or invalid values
            if custom_condition and custom_condition not in ('[]', '{}', 'null', 'None'):
                lines.append(f"    # Custom IP Filter Condition for {waf_rule['name']}")
                if not custom_condition.startswith(('http-request', 'http-response', 'acl')):
                    custom_condition = f"http-request deny if {custom_condition}"
                lines.append(f"    {custom_condition}")
    
    elif waf_rule['rule_type'] == 'rate_limit' and waf_rule.get('rate_limit_requests'):
        lines.append(f"    stick-table type ip size 100k expire {waf_rule.get('rate_limit_window', 60)}s store http_req_rate(10s)")
        lines.append(f"    http-request track-sc0 src")
        # Apply action for rate limit violations
        if action == 'block':
            lines.append(f"    http-request deny if {{ sc_http_req_rate(0) gt {waf_rule['rate_limit_requests']} }}")
        elif action == 'log':
            lines.append(f"    http-request capture req.hdr(User-Agent) len 64 if {{ sc_http_req_rate(0) gt {waf_rule['rate_limit_requests']} }}")
        
        # Handle Custom Log Message and Custom HAProxy Condition for Rate Limit
        log_msg = waf_rule.get('log_message') or waf_rule.get('custom_log_message')
        if log_msg:
            lines.append(f"    # Rate Limit Log: {log_msg}")
        
        custom_condition = waf_rule.get('custom_condition') or waf_rule.get('custom_haproxy_condition')
        if custom_condition:
            custom_condition = custom_condition.strip()
            # Skip empty strings, "[]", or invalid values
            if custom_condition and custom_condition not in ('[]', '{}', 'null', 'None'):
                lines.append(f"    # Custom Rate Limit Condition for {waf_rule['name']}")
                
                if not _is_valid_haproxy_condition(custom_condition):
                    lines.append(f"    # WARNING: Invalid HAProxy condition syntax: {custom_condition}")
                else:
                    if not custom_condition.startswith(('http-request', 'http-response', 'acl')):
                        custom_condition = f"http-request deny if {custom_condition}"
                    lines.append(f"    {custom_condition}")
    
    elif waf_rule['rule_type'] == 'header_filter' and waf_rule.get('header_name'):
        header_name = waf_rule.get('header_name', '').strip()
        header_value = waf_rule.get('header_value', '').strip()
        # Skip if header_name or header_value are invalid
        if not header_name or header_name in ('[]', '{}', 'null', 'None'):
            lines.append(f"    # WARNING: Invalid header_name for WAF rule '{waf_rule['name']}' - skipped")
        elif not header_value or header_value in ('[]', '{}', 'null', 'None'):
            lines.append(f"    # WARNING: Invalid header_value for WAF rule '{waf_rule['name']}' - skipped")
        else:
            acl_name = f"waf_{rule_name}_header"
            header_condition = waf_rule.get('header_condition', 'equals')
            
            if header_condition == 'equals':
                lines.append(f"    acl {acl_name} hdr({header_name}) {header_value}")
            elif header_condition == 'contains':
                lines.append(f"    acl {acl_name} hdr_sub({header_name}) {header_value}")
            elif header_condition == 'regex':
                lines.append(f"    acl {acl_name} hdr_reg({header_name}) {header_value}")
        
        # Apply action based on rule configuration
        if action == 'block':
            lines.append(f"    http-request deny if {acl_name}")
        elif action == 'allow':
            lines.append(f"    http-request allow if {acl_name}")
        elif action == 'log':
            lines.append(f"    http-request capture req.hdr({waf_rule['header_name']}) len 64 if {acl_name}")
        
        # Handle Custom Log Message and Custom HAProxy Condition for Header Filter
        log_msg = waf_rule.get('log_message') or waf_rule.get('custom_log_message')
        if log_msg:
            lines.append(f"    # Header Filter Log: {log_msg}")
        
        custom_condition = waf_rule.get('custom_condition') or waf_rule.get('custom_haproxy_condition')
        if custom_condition:
            custom_condition = custom_condition.strip()
            # Skip empty strings, "[]", or invalid values
            if custom_condition and custom_condition not in ('[]', '{}', 'null', 'None'):
                lines.append(f"    # Custom Header Filter Condition for {waf_rule['name']}")
                if not custom_condition.startswith(('http-request', 'http-response', 'acl')):
                    custom_condition = f"http-request deny if {custom_condition}"
                lines.append(f"    {custom_condition}")
    
    elif waf_rule['rule_type'] == 'request_filter' and (waf_rule.get('path_pattern') or waf_rule.get('http_method')):
        # Handle path pattern filtering
        acl_conditions = []
        if waf_rule.get('path_pattern'):
            path_pattern = waf_rule.get('path_pattern', '').strip()
            # Skip if path_pattern is invalid
            if path_pattern and path_pattern not in ('[]', '{}', 'null', 'None'):
                acl_name_path = f"waf_{rule_name}_path"
                lines.append(f"    acl {acl_name_path} path_reg {path_pattern}")
                acl_conditions.append(acl_name_path)
            else:
                lines.append(f"    # WARNING: Invalid path_pattern for WAF rule '{waf_rule['name']}' - skipped")
        
        # Handle HTTP method filtering
        if waf_rule.get('http_method') and waf_rule['http_method'] != '':
            http_method = waf_rule.get('http_method', '').strip()
            # Skip if http_method is invalid
            if http_method and http_method not in ('[]', '{}', 'null', 'None'):
                acl_name_method = f"waf_{rule_name}_method"
                lines.append(f"    acl {acl_name_method} method {http_method}")
                acl_conditions.append(acl_name_method)
            else:
                lines.append(f"    # WARNING: Invalid http_method for WAF rule '{waf_rule['name']}' - skipped")
        
        # Combine ACL conditions
        if acl_conditions:
            combined_acl = ' '.join(acl_conditions)
            
            # Apply action based on rule configuration
            if action == 'block':
                lines.append(f"    http-request deny if {combined_acl}")
            elif action == 'allow':
                lines.append(f"    http-request allow if {combined_acl}")
            elif action == 'redirect':
                redirect_url = waf_rule.get('redirect_url', '').strip() if waf_rule.get('redirect_url') else ''
                # Skip empty strings, "[]", or invalid values
                if redirect_url and redirect_url not in ('[]', '{}', 'null', 'None'):
                    lines.append(f"    http-request redirect location {redirect_url} if {combined_acl}")
        
        # Handle Custom Log Message and Custom HAProxy Condition for Request Filter
        log_msg = waf_rule.get('log_message') or waf_rule.get('custom_log_message')
        if log_msg:
            lines.append(f"    # Request Filter Log: {log_msg}")
        
        custom_condition = waf_rule.get('custom_condition') or waf_rule.get('custom_haproxy_condition')
        if custom_condition:
            custom_condition = custom_condition.strip()
            # Skip empty strings, "[]", or invalid values
            if custom_condition and custom_condition not in ('[]', '{}', 'null', 'None'):
                lines.append(f"    # Custom Request Filter Condition for {waf_rule['name']}")
                if not custom_condition.startswith(('http-request', 'http-response', 'acl')):
                    custom_condition = f"http-request deny if {custom_condition}"
                lines.append(f"    {custom_condition}")
    
    # Legacy path_filter support (for backward compatibility)
    elif waf_rule['rule_type'] == 'path_filter' and waf_rule.get('path_pattern'):
        path_pattern = waf_rule.get('path_pattern', '').strip()
        # Skip if path_pattern is invalid
        if not path_pattern or path_pattern in ('[]', '{}', 'null', 'None'):
            lines.append(f"    # WARNING: Invalid path_pattern for WAF rule '{waf_rule['name']}' - skipped")
        else:
            acl_name = f"waf_{rule_name}_path"
            lines.append(f"    acl {acl_name} path_reg {path_pattern}")
        
        # Apply action based on rule configuration
        if action == 'block':
            lines.append(f"    http-request deny if {acl_name}")
        elif action == 'allow':
            lines.append(f"    http-request allow if {acl_name}")
        elif action == 'redirect':
            redirect_url = waf_rule.get('redirect_url', '').strip() if waf_rule.get('redirect_url') else ''
            # Skip empty strings, "[]", or invalid values
            if redirect_url and redirect_url not in ('[]', '{}', 'null', 'None'):
                lines.append(f"    http-request redirect location {redirect_url} if {acl_name}")
    
    elif waf_rule['rule_type'] == 'size_limit':
        # Handle Max Request Size limit
        if waf_rule.get('max_request_size'):
            if action == 'block':
                lines.append(f"    http-request deny if {{ req.body_size gt {waf_rule['max_request_size']} }}")
            elif action == 'log':
                log_msg = waf_rule.get('log_message') or waf_rule.get('custom_log_message', 'Request size limit exceeded')
                lines.append(f"    http-request capture req.hdr(Content-Length) len 16 if {{ req.body_size gt {waf_rule['max_request_size']} }}")
                lines.append(f"    # Log Message: {log_msg}")
        
        # Handle Max Header Size limit
        if waf_rule.get('max_header_size'):
            if action == 'block':
                lines.append(f"    http-request deny if {{ req.hdr_cnt() gt 50 }} || {{ req.hdr_val(content-length) gt {waf_rule['max_header_size']} }}")
            elif action == 'log':
                log_msg = waf_rule.get('log_message') or waf_rule.get('custom_log_message', 'Header size limit exceeded')
                lines.append(f"    http-request capture req.hdr(User-Agent) len 32 if {{ req.hdr_cnt() gt 50 }}")
                lines.append(f"    # Log Message: {log_msg}")
        
        # Handle Custom HAProxy Condition if provided
        custom_condition = waf_rule.get('custom_condition') or waf_rule.get('custom_haproxy_condition')
        if custom_condition:
            custom_condition = custom_condition.strip()
            # Skip empty strings, "[]", or invalid values
            if custom_condition and custom_condition not in ('[]', '{}', 'null', 'None'):
                lines.append(f"    # Custom Condition for {waf_rule['name']}")
                
                # Basic validation for HAProxy condition syntax
                if not _is_valid_haproxy_condition(custom_condition):
                    lines.append(f"    # WARNING: Invalid HAProxy condition syntax: {custom_condition}")
                    lines.append(f"    # Example valid conditions: {{ req.hdr(user-agent) -m sub bot }}, {{ src -f /etc/haproxy/whitelist.lst }}")
                else:
                    # Ensure condition starts with proper HAProxy directive
                    if not custom_condition.startswith(('http-request', 'http-response', 'acl')):
                        custom_condition = f"http-request deny if {custom_condition}"
                    lines.append(f"    {custom_condition}")
            
            log_msg = waf_rule.get('log_message') or waf_rule.get('custom_log_message')
            if log_msg:
                lines.append(f"    # Custom Log: {log_msg}")
    
    elif waf_rule['rule_type'] == 'geo_block' and waf_rule.get('countries'):
        # Handle Geo Block filtering
        countries = waf_rule['countries']
        if isinstance(countries, str):
            countries_list = [c.strip().upper() for c in countries.split(',') if c.strip()]
        else:
            countries_list = countries
        
        if countries_list:
            acl_name = f"waf_{rule_name}_geo"
            # Note: This requires HAProxy with GeoIP support or external GeoIP database
            # For basic implementation, we'll use a comment-based approach
            lines.append(f"    # GeoIP filtering for countries: {', '.join(countries_list)}")
            lines.append(f"    # Note: Requires HAProxy with GeoIP support")
            
            geo_action = waf_rule.get('geo_action', 'block')
            if geo_action == 'block':
                lines.append(f"    # http-request deny if {{ src,map_ip(/etc/haproxy/geoip.map,unknown) -m str {' '.join(countries_list)} }}")
                lines.append(f"    # Alternative: Use external GeoIP service or MaxMind database")
            elif geo_action == 'allow':
                lines.append(f"    # http-request allow if {{ src,map_ip(/etc/haproxy/geoip.map,unknown) -m str {' '.join(countries_list)} }}")
                lines.append(f"    # http-request deny # deny all others")
            
            # Handle Custom Log Message and Custom HAProxy Condition for Geo Block
            log_msg = waf_rule.get('log_message') or waf_rule.get('custom_log_message')
            if log_msg:
                lines.append(f"    # Geo Block Log: {log_msg}")
            
            custom_condition = waf_rule.get('custom_condition') or waf_rule.get('custom_haproxy_condition')
            if custom_condition:
                custom_condition = custom_condition.strip()
                # Skip empty strings, "[]", or invalid values
                if custom_condition and custom_condition not in ('[]', '{}', 'null', 'None'):
                    lines.append(f"    # Custom Geo Block Condition for {waf_rule['name']}")
                    if not custom_condition.startswith(('http-request', 'http-response', 'acl')):
                        custom_condition = f"http-request deny if {custom_condition}"
                    lines.append(f"    {custom_condition}")
    
    # Handle custom rule type or unsupported config
    elif waf_rule['rule_type'] == 'custom' and waf_rule.get('custom_condition'):
        lines.append(f"    # Custom WAF rule: {waf_rule['name']}")
        lines.append(f"    {waf_rule['custom_condition']}")
    
    return lines

async def create_config_version(
    cluster_id: int, 
    version_name: str, 
    description: Optional[str] = None,
    user_id: Optional[int] = None,
    status: str = 'PENDING'
) -> int:
    """Create a new configuration version"""
    try:
        conn = await get_database_connection()
        
        # Generate config content
        config_content = await generate_haproxy_config_for_cluster(cluster_id)
        
        # Create checksum
        config_hash = hashlib.sha256(config_content.encode()).hexdigest()
        
        # Insert new version
        version_id = await conn.fetchval("""
            INSERT INTO config_versions 
            (cluster_id, version_name, description, config_content, checksum, created_by, is_active, status)
            VALUES ($1, $2, $3, $4, $5, $6, FALSE, $7)
            RETURNING id
        """, cluster_id, version_name, description, config_content, config_hash, user_id, status)
        
        await close_database_connection(conn)
        return version_id
        
    except Exception as e:
        logger.error(f"Failed to create config version: {e}")
        raise

async def create_pending_config_version(
    cluster_id: int,
    change_description: str,
    user_id: Optional[int] = None,
    entity_type: Optional[str] = None,
    entity_id: Optional[int] = None
) -> Dict[str, Any]:
    """Create a pending configuration version for Apply Changes workflow"""
    try:
        # Generate version name with timestamp and entity info
        timestamp = int(time.time())
        if entity_type and entity_id:
            version_name = f"{entity_type}-{entity_id}-delete-{timestamp}"
        else:
            version_name = f"pending-{timestamp}"
        
        # Create the config version
        version_id = await create_config_version(
            cluster_id=cluster_id,
            version_name=version_name,
            description=change_description,
            user_id=user_id,
            status='PENDING'
        )
        
        logger.info(f"✅ CONFIG VERSION: Created pending version {version_name} (ID: {version_id}) for cluster {cluster_id}")
        
        return {
            'version_id': version_id,
            'version': version_name,
            'status': 'PENDING',
            'description': change_description
        }
        
    except Exception as e:
        logger.error(f"❌ CONFIG VERSION: Failed to create pending version for cluster {cluster_id}: {e}")
        raise 