"""
backend_service: extracted helpers for INSERT-row creation of backends + backend_servers.

Used by:
- routers/site_wizard.py (atomic transaction wizard)
- routers/backend.py (delegate)

Design (Section 4.1 of v1.5.0 plan):
- Helpers accept an existing asyncpg connection (caller controls transaction boundary).
- Schema accuracy R38: server_address / server_port / server_name (NOT host/ip/port).
- M13 helper extension: when mark_pending=True, helper performs follow-up
  UPDATE backends/backend_servers SET last_config_status='PENDING' to match the
  existing endpoint pattern (backend.py:646) — otherwise apply pipeline pre-step
  (`WHERE last_config_status='APPLIED'`) may overlook the new entity.
"""

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


def _filter_httpchk_from_options(options: Optional[str]) -> Optional[str]:
    """Strip 'option httpchk' from raw options field (matches backend.py logic)."""
    if not options:
        return options
    out_lines = []
    for line in options.split("\n"):
        if line.strip().lower().startswith("option httpchk"):
            continue
        out_lines.append(line)
    return "\n".join(out_lines).strip() or None


async def create_backend_row(
    conn,
    payload: Any,
    cluster_id: int,
    *,
    mark_pending: bool = True,
) -> int:
    """Insert a row into backends; return new id.

    Mirrors POST /api/backends INSERT (backend.py:591-603) field-for-field.
    Caller must already have validated name uniqueness within cluster.
    """
    options_filtered = _filter_httpchk_from_options(getattr(payload, "options", None))

    backend_id = await conn.fetchval(
        """
        INSERT INTO backends (
            name, balance_method, mode, health_check_uri, health_check_interval,
            health_check_expected_status, fullconn, cookie_name, cookie_options,
            default_server_inter, default_server_fall, default_server_rise,
            request_headers, response_headers, options,
            timeout_connect, timeout_server, timeout_queue, cluster_id
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
            $13, $14, $15, $16, $17, $18, $19
        ) RETURNING id
        """,
        payload.name,
        getattr(payload, "balance_method", "roundrobin"),
        getattr(payload, "mode", "http"),
        getattr(payload, "health_check_uri", None),
        getattr(payload, "health_check_interval", None),
        getattr(payload, "health_check_expected_status", None),
        getattr(payload, "fullconn", None),
        getattr(payload, "cookie_name", None),
        getattr(payload, "cookie_options", None),
        getattr(payload, "default_server_inter", None),
        getattr(payload, "default_server_fall", None),
        getattr(payload, "default_server_rise", None),
        getattr(payload, "request_headers", None),
        getattr(payload, "response_headers", None),
        options_filtered,
        getattr(payload, "timeout_connect", None),
        getattr(payload, "timeout_server", None),
        getattr(payload, "timeout_queue", None),
        cluster_id,
    )

    if mark_pending:
        await conn.execute(
            "UPDATE backends SET last_config_status='PENDING' WHERE id=$1",
            backend_id,
        )

    return backend_id


async def create_server_row(
    conn,
    backend_id: int,
    backend_name: str,
    cluster_id: int,
    server: Any,
    *,
    mark_pending: bool = True,
) -> int:
    """Insert a row into backend_servers; return new id.

    Mirrors POST /api/backends/{id}/servers INSERT (backend.py:725-737).
    """
    server_id = await conn.fetchval(
        """
        INSERT INTO backend_servers (
            backend_id, backend_name, server_name, server_address, server_port, weight,
            maxconn, check_enabled, check_port, backup_server,
            ssl_enabled, ssl_verify, ssl_certificate_id,
            ssl_sni, ssl_min_ver, ssl_max_ver, ssl_ciphers,
            cookie_value, inter, fall, rise, cluster_id
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
            $14, $15, $16, $17, $18, $19, $20, $21, $22
        ) RETURNING id
        """,
        backend_id,
        backend_name,
        server.server_name,
        server.server_address,
        server.server_port,
        getattr(server, "weight", 100),
        getattr(server, "max_connections", None),
        getattr(server, "check_enabled", True),
        getattr(server, "check_port", None),
        getattr(server, "backup_server", False),
        getattr(server, "ssl_enabled", False),
        getattr(server, "ssl_verify", "none"),
        getattr(server, "ssl_certificate_id", None),
        getattr(server, "ssl_sni", None),
        getattr(server, "ssl_min_ver", None),
        getattr(server, "ssl_max_ver", None),
        getattr(server, "ssl_ciphers", None),
        getattr(server, "cookie_value", None),
        getattr(server, "inter", None),
        getattr(server, "fall", None),
        getattr(server, "rise", None),
        cluster_id,
    )

    if mark_pending:
        await conn.execute(
            "UPDATE backend_servers SET last_config_status='PENDING' WHERE id=$1",
            server_id,
        )

    return server_id
