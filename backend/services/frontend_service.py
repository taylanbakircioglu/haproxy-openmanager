"""
frontend_service: extracted helper for INSERT-row creation of frontends.

Used by:
- routers/site_wizard.py (atomic transaction wizard)
- routers/letsencrypt.py _complete_certificate post_completion_actions

Design (Section 4.2 of v1.5.0 plan):
- M13: writes BOTH ssl_certificate_id (INT col) AND ssl_certificate_ids (JSONB col).
- mark_pending=True triggers post-INSERT UPDATE last_config_status='PENDING'
  (matches existing frontend.py:526 pattern).
- Schema accuracy R38: bind_address / bind_port (NOT port); redirect_rules / acl_rules /
  use_backend_rules are JSONB columns.
"""

import json
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


async def create_frontend_row(
    conn,
    payload: Any,
    cluster_id: int,
    *,
    ssl_certificate_id: Optional[int] = None,
    ssl_enabled: Optional[bool] = None,
    bind_port_override: Optional[int] = None,
    name_override: Optional[str] = None,
    mark_pending: bool = True,
) -> int:
    """Insert a row into frontends; return new id.

    Mirrors POST /api/frontends INSERT (frontend.py:481-499) field-for-field.

    M13: writes ssl_certificate_id AND ssl_certificate_ids consistently. If
    ssl_certificate_id resolved (param OR payload.ssl_certificate_id),
    ssl_certificate_ids = json.dumps([id]); else json.dumps([]).
    """
    cert_id = ssl_certificate_id if ssl_certificate_id is not None else getattr(payload, "ssl_certificate_id", None)
    cert_ids_list = [cert_id] if cert_id else []
    ssl_cert_ids_json = json.dumps(cert_ids_list)

    fe_name = name_override if name_override is not None else payload.name
    fe_ssl_enabled = ssl_enabled if ssl_enabled is not None else getattr(payload, "ssl_enabled", False)
    fe_bind_port = bind_port_override if bind_port_override is not None else payload.bind_port

    frontend_id = await conn.fetchval(
        """
        INSERT INTO frontends (
            name, bind_address, bind_port, default_backend, mode,
            ssl_enabled, ssl_certificate_id, ssl_certificate_ids, ssl_port, ssl_cert_path, ssl_cert, ssl_verify,
            ssl_alpn, ssl_npn, ssl_ciphers, ssl_ciphersuites, ssl_min_ver, ssl_max_ver, ssl_strict_sni,
            acl_rules, redirect_rules, use_backend_rules,
            request_headers, response_headers, options, tcp_request_rules, timeout_client, timeout_http_request,
            rate_limit, compression, log_separate, monitor_uri,
            cluster_id, maxconn, updated_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
            $13, $14, $15, $16, $17, $18, $19,
            $20, $21, $22,
            $23, $24, $25, $26, $27, $28,
            $29, $30, $31, $32,
            $33, $34, CURRENT_TIMESTAMP
        )
        RETURNING id
        """,
        fe_name,
        getattr(payload, "bind_address", "*"),
        fe_bind_port,
        getattr(payload, "default_backend", None),
        getattr(payload, "mode", "http"),
        fe_ssl_enabled,
        cert_id,
        ssl_cert_ids_json,
        getattr(payload, "ssl_port", None),
        getattr(payload, "ssl_cert_path", None),
        getattr(payload, "ssl_cert", None),
        getattr(payload, "ssl_verify", None),
        getattr(payload, "ssl_alpn", None),
        getattr(payload, "ssl_npn", None),
        getattr(payload, "ssl_ciphers", None),
        getattr(payload, "ssl_ciphersuites", None),
        getattr(payload, "ssl_min_ver", None),
        getattr(payload, "ssl_max_ver", None),
        getattr(payload, "ssl_strict_sni", None),
        json.dumps(getattr(payload, "acl_rules", None) or []),
        json.dumps(getattr(payload, "redirect_rules", None) or []),
        json.dumps(getattr(payload, "use_backend_rules", None) or []),
        getattr(payload, "request_headers", None),
        getattr(payload, "response_headers", None),
        getattr(payload, "options", None),
        getattr(payload, "tcp_request_rules", None),
        getattr(payload, "timeout_client", None),
        getattr(payload, "timeout_http_request", None),
        getattr(payload, "rate_limit", None),
        getattr(payload, "compression", None),
        getattr(payload, "log_separate", None),
        getattr(payload, "monitor_uri", None),
        cluster_id,
        getattr(payload, "maxconn", None),
    )

    if mark_pending:
        await conn.execute(
            "UPDATE frontends SET last_config_status='PENDING' WHERE id=$1",
            frontend_id,
        )

    return frontend_id


async def check_bind_port_collision(
    conn,
    cluster_id: int,
    bind_address: str,
    bind_port: int,
    *,
    exclude_frontend_id: Optional[int] = None,
) -> Optional[int]:
    """Return id of an existing frontend that conflicts with bind_address+bind_port,
    or None if no conflict.

    Used by:
    - wizard pre-create (Section 6.2 step before INSERT)
    - _complete_certificate post-action HTTPS frontend create (M21/R35)
    """
    if exclude_frontend_id is not None:
        return await conn.fetchval(
            """
            SELECT id FROM frontends
            WHERE cluster_id=$1 AND bind_address=$2 AND bind_port=$3
              AND is_active=TRUE AND id <> $4
            """,
            cluster_id,
            bind_address,
            bind_port,
            exclude_frontend_id,
        )
    return await conn.fetchval(
        """
        SELECT id FROM frontends
        WHERE cluster_id=$1 AND bind_address=$2 AND bind_port=$3 AND is_active=TRUE
        """,
        cluster_id,
        bind_address,
        bind_port,
    )
