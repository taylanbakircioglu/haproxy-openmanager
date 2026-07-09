from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
import json
import os
import redis
import asyncio
from datetime import datetime, timedelta

# Single source of truth: backend/version.json, which sits next to this module and is baked into
# every image by `COPY . .` (build context ./backend) — no pipeline staging needed. The literal
# below is only a last-resort "file missing" marker; it is deliberately NOT a real version so it can
# never silently drift out of sync (this exact drift showed a stale version after v1.8.5/v1.8.6).
# Keep the canonical version ONLY in backend/version.json — test_version_consistency.py enforces it.
_version_info = {"version": "unknown", "releaseName": "unknown", "releaseDate": ""}
for _vpath in [os.path.join(os.path.dirname(__file__), "version.json"), "/app/version.json"]:
    try:
        with open(_vpath) as _vf:
            _version_info = json.load(_vf)
        break
    except (FileNotFoundError, json.JSONDecodeError):
        continue

# Version: 2026-05-06 - ACME Stability & Enterprise Audit v1.4.0 (Issues #10, #11, #12)
# Version: 2026-04-02 - Dark Mode + UI Improvements v1.2.0
# Version: 2026-04-01 - ACME Auto SSL v1.1.0
# Version: 2025-10-20 - Agent script fixes deployed

# Import configurations and database

from config import CORS_ORIGINS, REDIS_URL, LOG_LEVEL
from database.connection import redis_client, get_database_connection, close_database_connection, init_database_pool, close_database_pool
from database.migrations import run_all_migrations

# Import routers
from routers import frontend_router, backend_router, cluster_router, dashboard_router, agent_router, waf_router, ssl_router, auth_router, user_router
from routers.health import router as health_router
from routers.config import router as config_router
from routers.security import router as security_router
from routers.configuration import router as configuration_router
from routers.maintenance import router as maintenance_router
from routers.dashboard_stats import router as dashboard_stats_router
from routers.settings import router as settings_router
from routers.letsencrypt import router as letsencrypt_router
from routers.acme_diagnostics import router as acme_diagnostics_router
from routers.site_wizard import router as site_wizard_router
from routers.mfa import router as mfa_router
from routers.vip import router as vip_router  # Issue #27 — HA/VIP (Keepalived) management

# Production logging configuration
from utils.logging_config import setup_production_logging
from middleware.error_handler import (
    RequestLoggingMiddleware, PerformanceMonitoringMiddleware, 
    GlobalExceptionHandler, get_error_statistics
)
from middleware.activity_logger import log_activity_middleware

# Setup structured logging
logger = setup_production_logging(LOG_LEVEL)

# Initialize FastAPI app with detailed API documentation
app = FastAPI(
    title="HAProxy Open Manager API", 
    version=_version_info["version"],
    description="""
# HAProxy Open Manager - Enterprise Multi-Cluster Management API

🚀 **Production-ready HAProxy management system** with agent-pull architecture for managing multiple HAProxy clusters remotely.

## Architecture Overview

This system uses an **agent-pull architecture**:
- Changes are NOT pushed from backend to agents
- Agent services periodically poll the backend for tasks
- Agents execute tasks on their local HAProxy servers
- Agents report status and sync configuration back to backend

## Getting Started

### Authentication
All API endpoints (except `/api/auth/login` and agent endpoints) require JWT authentication:

```bash
# 1. Login to get access token
curl -X POST "{BASE_URL}/api/auth/login" \\
  -H "Content-Type: application/json" \\
  -d '{"username": "admin", "password": "admin123"}'

# Response: {"access_token": "eyJ...", "token_type": "bearer"}

# 2. Use token in subsequent requests
curl -X GET "{BASE_URL}/api/clusters" \\
  -H "Authorization: Bearer eyJ..."
```

**Note:** Replace `{BASE_URL}` with your actual deployment URL (e.g., `https://haproxy-manager.company.com`)

## Workflow

### Initial Setup (From Scratch)

1. **Create Agent Pool**
   - Pools group agents logically
   - POST `/api/clusters/pools` - Create a new pool

2. **Create HAProxy Cluster**
   - Select the pool created above
   - POST `/api/clusters` - Create cluster associated with pool

3. **Generate Agent Installation Script**
   - Select pool when creating agent
   - POST `/api/agents` - Generate platform-specific installation script
   - Agent automatically gets associated with cluster via pool

4. **Install Agent on Remote HAProxy Server**
   - Download and run the generated script on target server
   - Agent service starts and begins polling backend
   - Agent logs written to `/var/log/haproxy-agent/agent.log`

5. **Configure HAProxy via UI**
   - Define backends, frontends, WAF rules, SSL certificates
   - Changes are stored in backend database
   - Agents periodically pull changes and apply to local haproxy.cfg
   - HAProxy service is automatically reloaded

### Multi-Cluster Management

Most operations are **cluster-scoped**:
- Select cluster in UI (top bar cluster selector)
- All operations apply to selected cluster only
- Exception: SSL Management can work across all clusters

### Agent Version Management

- Agent versions stored in backend database
- Agents check for updates on each poll cycle
- If new version available, agent downloads and self-updates
- Update agent scripts via UI: `Agent Management > Update Script`

## Key Features

- ✅ Multi-cluster management
- ✅ Agent-pull architecture (no push from backend)
- ✅ Backend & Frontend management
- ✅ WAF rule management
- ✅ SSL certificate management
- ✅ Bulk configuration import
- ✅ Real-time agent health monitoring
- ✅ Configuration version history
- ✅ Role-based access control (RBAC)
- ✅ Audit logging

## Deployment

- Platform: OpenShift
- CI/CD: Azure DevOps Pipeline
- Architecture: Agent-Pull based distributed management
""",
    contact={
        "name": "HAProxy Open Manager Team",
        "email": "support@example.com",
    },
    license_info={
        "name": "Enterprise License",
    },
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    openapi_tags=[
        {
            "name": "Authentication",
            "description": "User authentication and JWT token management. All protected endpoints require a valid JWT token obtained from `/api/auth/login`."
        },
        {
            "name": "Users",
            "description": "User management operations including CRUD operations, role assignments, and user activity tracking."
        },
        {
            "name": "clusters",
            "description": "HAProxy cluster management. Clusters represent groups of HAProxy instances that share configuration. Each cluster is associated with an agent pool."
        },
        {
            "name": "pools",
            "description": "Agent pool management. Pools are logical groups that connect agents to clusters. Create pools first, then create clusters referencing them."
        },
        {
            "name": "agents",
            "description": "Agent management and monitoring. Agents run on HAProxy servers and pull configuration from backend. Includes installation script generation, version management, and health monitoring."
        },
        {
            "name": "frontends",
            "description": "HAProxy frontend management. Frontends define how HAProxy receives incoming traffic (bind addresses, ports, SSL/TLS configuration)."
        },
        {
            "name": "backends",
            "description": "HAProxy backend and server management. Backends define pools of servers that handle requests, including load balancing algorithms and health checks."
        },
        {
            "name": "waf",
            "description": "Web Application Firewall (WAF) rule management. Define security rules to protect web applications from common attacks."
        },
        {
            "name": "ssl",
            "description": "SSL/TLS certificate management. Upload, manage, and deploy SSL certificates across clusters. Supports per-cluster and all-cluster deployment."
        },
        {
            "name": "configuration",
            "description": "Configuration management including bulk import, version history, and configuration preview. Import existing HAProxy configs or view generated configurations."
        },
        {
            "name": "dashboard",
            "description": "Real-time statistics and monitoring dashboard. View cluster health, agent status, traffic metrics, and system overview."
        },
        {
            "name": "security",
            "description": "Security and audit features including activity logs, access control, and system security settings."
        },
        {
            "name": "maintenance",
            "description": "System maintenance operations including database cleanup, soft-delete recovery, and system health checks."
        },
        {
            "name": "health",
            "description": "Health check endpoints for monitoring system status, database connectivity, and Redis status."
        }
    ]
)

# Background task for agent status monitoring
async def monitor_agent_status():
    """Background task to monitor agent status and mark offline agents"""
    while True:
        try:
            conn = await get_database_connection()
            
            # Mark agents as offline if they haven't sent heartbeat in last 120 seconds (2 minutes)
            threshold_time = datetime.utcnow() - timedelta(seconds=120)
            
            result = await conn.execute("""
                UPDATE agents 
                SET status = 'offline', updated_at = CURRENT_TIMESTAMP
                WHERE status = 'online' 
                AND (last_seen IS NULL OR last_seen < $1)
            """, threshold_time)
            
            await close_database_connection(conn)
            
            # Log if any agents were marked offline
            if result and hasattr(result, 'split') and len(result.split()) > 1:
                count = result.split()[1]
                if int(count) > 0:
                    logger.info(f"Marked {count} agents as offline due to missing heartbeats")
            
        except Exception as e:
            logger.error(f"Error in agent status monitoring: {e}")
        
        # Wait 30 seconds before next check
        await asyncio.sleep(30)

# Background task for ACME certificate auto-renewal
async def complete_pending_acme_orders():
    """
    Issue #12 fix: Auto-complete CA-validated ACME orders independent of
    `acme.auto_renew_enabled` flag.
    
    Runs every 60s. Polls in-progress orders (pending/processing/ready, plus
    valid-without-cert) and drives them through finalize -> download -> save
    certificate. Without this task, orders that reach `valid` state at the CA
    but have not yet been downloaded remain "stuck" and require manual
    intervention via the UI.
    
    Multi-replica safety: uses PostgreSQL `FOR UPDATE SKIP LOCKED` atomic claim
    plus updated_at timestamp filter to avoid two replicas working the same order.
    """
    await asyncio.sleep(60)
    while True:
        try:
            conn_check = await get_database_connection()
            try:
                table_exists = await conn_check.fetchval("""
                    SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'letsencrypt_orders')
                """)
            finally:
                await close_database_connection(conn_check)
            if not table_exists:
                await asyncio.sleep(60)
                continue

            # v1.5.0 (M30): daily-watermarked TTL prune for acme_order_events
            # (90d) and wizard_drafts (30d). Best-effort, never raises.
            try:
                from utils.activity_log import prune_acme_events_and_drafts_if_due
                await prune_acme_events_and_drafts_if_due()
            except Exception as prune_err:
                logger.debug(f"v1.5.0 daily prune skipped: {prune_err}")

            from routers.letsencrypt import _complete_certificate
            from services.acme_service import acme_service as acme_svc
            
            # Atomic claim of orders for completion (multi-replica safe).
            # Limit batch to 50 to avoid one replica monopolizing CA rate-limit budget.
            claimed_ids = []
            conn_claim = await get_database_connection()
            try:
                async with conn_claim.transaction():
                    rows = await conn_claim.fetch("""
                        SELECT id FROM letsencrypt_orders
                        WHERE (
                            status IN ('pending', 'processing', 'ready')
                            OR (status = 'valid' AND ssl_certificate_id IS NULL)
                            -- Issue #35: bounded DNS-01 retry. ONLY dns-01 invalids with remaining
                            -- budget + elapsed backoff are claimed; http-01 invalids are NEVER matched
                            -- (their existing skip-and-log is preserved).
                            OR (
                                status = 'invalid' AND challenge_type = 'dns-01'
                                AND ssl_certificate_id IS NULL
                                AND COALESCE(dns01_retry_claimed, FALSE) = FALSE
                                AND COALESCE(dns01_attempts, 0) < 3
                                AND (
                                    dns01_last_attempt_at IS NULL
                                    OR dns01_last_attempt_at < NOW() - (
                                        (CASE COALESCE(dns01_attempts, 0) WHEN 0 THEN 15 WHEN 1 THEN 30 ELSE 60 END)
                                        || ' minutes')::INTERVAL
                                )
                            )
                        )
                        AND created_at > NOW() - INTERVAL '7 days'
                        AND (updated_at IS NULL OR updated_at < NOW() - INTERVAL '30 seconds')
                        ORDER BY created_at
                        LIMIT 50
                        FOR UPDATE SKIP LOCKED
                    """)
                    if rows:
                        claimed_ids = [r['id'] for r in rows]
                        # Bump updated_at to mark claim (other replicas skip these for >=30s)
                        await conn_claim.execute(
                            "UPDATE letsencrypt_orders SET updated_at = NOW() WHERE id = ANY($1::int[])",
                            claimed_ids
                        )
            finally:
                await close_database_connection(conn_claim)
            
            # v1.5.0 (Bulgu #2 fix): wizard_staged orders MUST be processed
            # even when no pending/processing orders exist — otherwise a freshly
            # created wizard order (no concurrent ACME activity) would never
            # leave wizard_staged status and never reach the LE API call.
            # Run the wizard pipeline FIRST so the early-continue below cannot
            # starve it.
            try:
                await _process_wizard_staged_orders(acme_svc)
            except Exception as ws_err:
                logger.error(f"[ACME-WIZARD] Wizard-staged processing failed: {ws_err}")

            if not claimed_ids:
                await asyncio.sleep(60)
                continue

            logger.info(f"[ACME-COMPLETE] Claimed {len(claimed_ids)} order(s) for completion: {claimed_ids}")

            from services.dns01_orchestrator import (
                advance_dns01_order, retry_invalid_dns01, reconcile_dns01_cleanup,
            )

            for oid in claimed_ids:
                try:
                    # Issue #35: advance the DNS-01 publish->confirm->respond state machine for
                    # pending dns-01 orders (no-op for http-01 or non-pending orders).
                    await advance_dns01_order(oid)

                    status_info = await acme_svc.check_order_status(oid)
                    current_status = status_info.get('status')

                    if current_status == 'ready':
                        await acme_svc.finalize_order(oid)
                        status_info = await acme_svc.check_order_status(oid)
                        current_status = status_info.get('status')

                    if current_status == 'valid' and status_info.get('certificate_url'):
                        result = await _complete_certificate(oid)
                        logger.info(f"[ACME-COMPLETE] Order {oid} completed - {result.get('message', '')}")
                    elif current_status == 'invalid':
                        # Issue #35: bounded DNS-01 fresh-order retry (no-op for http-01).
                        await retry_invalid_dns01(oid)
                        logger.warning(f"[ACME-COMPLETE] Order {oid} is invalid")
                    elif current_status in ('pending', 'processing'):
                        logger.info(f"[ACME-COMPLETE] Order {oid} still {current_status}, will retry next cycle")
                except Exception as poll_err:
                    logger.error(f"[ACME-COMPLETE] Failed to complete order {oid}: {poll_err}")

            # Issue #35: best-effort cleanup of TXT records left published on terminal orders
            # (covers a failed cleanup or the kill-switch being flipped off). NOT gated by the switch.
            try:
                await reconcile_dns01_cleanup()
            except Exception as rec_err:
                logger.debug(f"[ACME-COMPLETE] DNS-01 reconcile skipped: {rec_err}")

            # NOTE: v1.5.0 wizard-staged processing now runs BEFORE the
            # claimed_ids early-continue above (Bulgu #2 fix), so it executes
            # every cycle regardless of pending/processing volume.

        except Exception as e:
            logger.error(f"[ACME-COMPLETE] Error in completion task: {e}")
        await asyncio.sleep(60)


async def _process_wizard_staged_orders(acme_svc):
    """v1.5.0 Feature B (Issue #14): drive wizard_staged ACME orders forward.

    Round 11 fix: NO `created_at > NOW() - INTERVAL` filter — that would prevent
    older staged orders from ever reaching the in-loop 24h timeout check. We
    instead enforce the 24h timeout explicitly via wizard_staged_until.
    """
    from utils.activity_log import record_event
    from services.letsencrypt_service import (
        create_order_via_api,
        promote_staged_order_to_pending,
    )

    conn = await get_database_connection()
    try:
        async with conn.transaction():
            rows = await conn.fetch(
                """
                SELECT id, account_id, domains, cluster_ids,
                       pending_apply_version_name, wizard_staged_until, order_url
                FROM letsencrypt_orders
                WHERE status = 'wizard_staged'
                  AND (updated_at IS NULL OR updated_at < NOW() - INTERVAL '30 seconds')
                ORDER BY created_at
                LIMIT 50
                FOR UPDATE SKIP LOCKED
                """
            )
            if not rows:
                return
            await conn.execute(
                "UPDATE letsencrypt_orders SET updated_at = NOW() WHERE id = ANY($1::int[])",
                [r["id"] for r in rows],
            )
    finally:
        await close_database_connection(conn)

    for row in rows:
        order_id = row["id"]
        account_id = row["account_id"]
        version_name = row["pending_apply_version_name"]

        # Parse JSONB payloads defensively (asyncpg may return list or str)
        try:
            domains = (
                row["domains"] if isinstance(row["domains"], list)
                else __import__("json").loads(row["domains"] or "[]")
            )
        except Exception:
            domains = []
        try:
            cluster_ids = (
                row["cluster_ids"] if isinstance(row["cluster_ids"], list)
                else __import__("json").loads(row["cluster_ids"] or "[]")
            )
        except Exception:
            cluster_ids = []

        try:
            # 1) 24h timeout abandonment (M25)
            if row["wizard_staged_until"] is not None:
                # PostgreSQL returns timezone-aware datetime; compare via NOW() in SQL
                conn = await get_database_connection()
                try:
                    expired = await conn.fetchval(
                        "SELECT $1 < NOW()", row["wizard_staged_until"]
                    )
                    if expired:
                        await conn.execute(
                            """
                            UPDATE letsencrypt_orders
                            SET status='invalid',
                                error_detail = 'wizard staged timeout (>24h with no agent confirm)',
                                updated_at = NOW()
                            WHERE id = $1
                            """,
                            order_id,
                        )
                        await record_event(
                            order_id,
                            "wizard_staged_timeout",
                            severity="ERROR",
                            message="Wizard-staged ACME order abandoned after 24h",
                            conn=conn,
                        )
                        logger.warning(
                            f"[ACME-WIZARD] Order {order_id} abandoned (wizard_staged_until elapsed)"
                        )
                        continue
                finally:
                    await close_database_connection(conn)

            # 2) Agent-confirm gating: at least one agent in any of the
            #    target clusters must have applied_config_version equal to the
            #    gating version name. Skip+retry next cycle if not yet.
            if not version_name or not cluster_ids:
                logger.debug(
                    f"[ACME-WIZARD] Order {order_id} missing version_name/cluster_ids, skipping"
                )
                continue

            conn = await get_database_connection()
            try:
                confirmed_count = await conn.fetchval(
                    """
                    SELECT COUNT(*)
                    FROM agents a
                    JOIN haproxy_clusters hc ON hc.pool_id = a.pool_id
                    WHERE hc.id = ANY($1::int[])
                      AND a.applied_config_version = $2
                    """,
                    cluster_ids,
                    version_name,
                )
            finally:
                await close_database_connection(conn)

            if not confirmed_count:
                logger.info(
                    f"[ACME-WIZARD] Order {order_id} waiting on agent confirm (version={version_name})"
                )
                continue

            # 3) R58/M37 idempotency: if order_url is already set we somehow
            #    succeeded the LE call but failed status update — re-try
            #    completion later via the normal pending/processing pipeline.
            if row["order_url"]:
                conn = await get_database_connection()
                try:
                    await conn.execute(
                        "UPDATE letsencrypt_orders SET status='pending', updated_at=NOW() WHERE id=$1",
                        order_id,
                    )
                finally:
                    await close_database_connection(conn)
                continue

            # 4) Promote: call the LE API for real
            try:
                api_result = await create_order_via_api(
                    acme_svc,
                    account_id=account_id,
                    domains=domains,
                    cluster_ids=cluster_ids,
                )
            except Exception as api_err:
                # Failure -> stay wizard_staged, will retry next pass
                logger.warning(
                    f"[ACME-WIZARD] Order {order_id} LE API call failed (will retry): {api_err}"
                )
                conn = await get_database_connection()
                try:
                    await record_event(
                        order_id,
                        "wizard_le_api_retry",
                        severity="WARN",
                        message=str(api_err)[:500],
                        conn=conn,
                    )
                finally:
                    await close_database_connection(conn)
                continue

            # The thin wrapper currently delegates to AcmeService.create_order
            # which INSERTs a NEW row. We translate that into an UPDATE of the
            # staged row by copying the new row's order_url + finalize_url
            # then deleting the duplicate.
            new_order_id = api_result.get("id")
            order_url = api_result.get("order_url")
            conn = await get_database_connection()
            try:
                async with conn.transaction():
                    if new_order_id and new_order_id != order_id:
                        new_row = await conn.fetchrow(
                            """
                            SELECT order_url, finalize_url, status, expires_at
                            FROM letsencrypt_orders WHERE id = $1
                            """,
                            new_order_id,
                        )
                        if new_row:
                            await promote_staged_order_to_pending(
                                conn,
                                order_id=order_id,
                                order_url=new_row["order_url"] or "",
                                finalize_url=new_row["finalize_url"] or "",
                                status=new_row["status"] or "pending",
                                expires_at=new_row["expires_at"],
                            )
                            # Move challenges from the duplicate to the staged row
                            await conn.execute(
                                "UPDATE acme_challenges SET order_id = $1 WHERE order_id = $2",
                                order_id,
                                new_order_id,
                            )
                            await conn.execute(
                                "DELETE FROM letsencrypt_orders WHERE id = $1",
                                new_order_id,
                            )
                    elif order_url:
                        await promote_staged_order_to_pending(
                            conn,
                            order_id=order_id,
                            order_url=order_url,
                            finalize_url=api_result.get("finalize_url") or "",
                            status="pending",
                            expires_at=None,
                        )
                await record_event(
                    order_id,
                    "wizard_promoted",
                    severity="INFO",
                    message=f"Wizard-staged order promoted to pending after agent confirm",
                    details={"version_name": version_name},
                    conn=conn,
                )
                logger.info(
                    f"[ACME-WIZARD] Order {order_id} promoted to pending (LE order created)"
                )
            finally:
                await close_database_connection(conn)
        except Exception as outer:
            logger.error(f"[ACME-WIZARD] Order {order_id} processing error: {outer}")


async def check_letsencrypt_renewals():
    """
    Background task to auto-renew expiring ACME certificates.
    
    Runs every 60 minutes. Two-phase:
    1. Create new orders for certificates expiring within `acme.renew_before_days`
       (default 30). Gated by `acme.auto_renew_enabled` setting.
    2. Warn about stuck orders (>24h in pending/processing state).
    
    Order completion (download cert + save to DB) is handled by the separate
    `complete_pending_acme_orders` task running every 60s, so renewal pickup
    is fast even if this hourly task is throttled.
    """
    await asyncio.sleep(120)
    while True:
        conn = None
        try:
            conn = await get_database_connection()
            table_exists = await conn.fetchval("""
                SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'letsencrypt_orders')
            """)
            if not table_exists:
                await close_database_connection(conn)
                conn = None
                await asyncio.sleep(3600)
                continue

            auto_renew_setting = await conn.fetchval(
                "SELECT value FROM system_settings WHERE key = 'acme.auto_renew_enabled'"
            )
            auto_renew_enabled = False
            if auto_renew_setting:
                try:
                    val = json.loads(auto_renew_setting) if isinstance(auto_renew_setting, str) else auto_renew_setting
                    auto_renew_enabled = val in (True, 'true', 'True')
                except (json.JSONDecodeError, TypeError):
                    pass

            if not auto_renew_enabled:
                await close_database_connection(conn)
                conn = None
                await asyncio.sleep(3600)
                continue

            renew_days_raw = await conn.fetchval(
                "SELECT value FROM system_settings WHERE key = 'acme.renew_before_days'"
            )
            renew_days = 30
            if renew_days_raw:
                try:
                    renew_days = int(json.loads(renew_days_raw) if isinstance(renew_days_raw, str) else renew_days_raw)
                except (ValueError, TypeError, json.JSONDecodeError):
                    pass

            expiring_certs = await conn.fetch("""
                SELECT id, name, primary_domain, letsencrypt_order_id
                FROM ssl_certificates
                WHERE source = 'letsencrypt' AND auto_renew = TRUE AND is_active = TRUE
                AND expiry_date IS NOT NULL
                AND expiry_date <= (CURRENT_DATE + ($1 || ' days')::INTERVAL)
            """, str(renew_days))

            await close_database_connection(conn)
            conn = None

            from services.acme_service import acme_service as acme_svc

            # Phase 1: Create new orders for expiring certificates
            for cert in expiring_certs:
                try:
                    order_id = cert['letsencrypt_order_id']
                    if not order_id:
                        continue

                    conn2 = await get_database_connection()
                    order = None
                    domains = None
                    cluster_ids = None
                    skip = False
                    try:
                        order = await conn2.fetchrow(
                            "SELECT o.account_id, o.domains, o.cluster_ids, o.challenge_type, a.dns_provider "
                            "FROM letsencrypt_orders o JOIN letsencrypt_accounts a ON o.account_id = a.id "
                            "WHERE o.id = $1",
                            order_id
                        )
                        if order:
                            domains = json.loads(order['domains']) if isinstance(order['domains'], str) else order['domains']
                            cluster_ids = json.loads(order['cluster_ids']) if isinstance(order['cluster_ids'], str) else order['cluster_ids']
                            existing = await conn2.fetchrow("""
                                SELECT id FROM letsencrypt_orders
                                WHERE domains::text = $1::text
                                AND status NOT IN ('valid', 'invalid', 'cancelled')
                                AND created_at > NOW() - INTERVAL '48 hours'
                                LIMIT 1
                            """, json.dumps(domains))
                            if existing:
                                logger.info(f"[ACME-RENEWAL] Skipping cert {cert['id']} - order {existing['id']} already in progress")
                                skip = True
                            elif (order['challenge_type'] == 'dns-01'):
                                # Issue #35: manual DNS-01 cannot auto-renew unattended; and for an
                                # automated provider, don't re-mint hourly if a recent retry chain already
                                # exhausted its budget (avoids tripping the CA new-order rate limit).
                                if (order['dns_provider'] or 'manual') == 'manual':
                                    logger.warning(f"[ACME-RENEWAL] cert {cert['id']} uses manual DNS-01; cannot auto-renew unattended (publish the TXT and renew manually)")
                                    skip = True
                                else:
                                    exhausted = await conn2.fetchrow("""
                                        SELECT id FROM letsencrypt_orders
                                        WHERE domains::text = $1::text AND challenge_type = 'dns-01'
                                        AND status = 'invalid' AND COALESCE(dns01_attempts, 0) >= 3
                                        AND created_at > NOW() - INTERVAL '24 hours'
                                        LIMIT 1
                                    """, json.dumps(domains))
                                    if exhausted:
                                        logger.warning(f"[ACME-RENEWAL] cert {cert['id']} DNS-01 renewal recently failed (check DNS); skipping re-mint for 24h")
                                        skip = True
                    finally:
                        await close_database_connection(conn2)

                    if not order or skip:
                        continue

                    challenge_type = order['challenge_type'] or 'http-01'
                    new_order = await acme_svc.create_order(order['account_id'], domains, cluster_ids, challenge_type=challenge_type)
                    # http-01 responds immediately (token served continuously); dns-01 is driven by the
                    # orchestrator AFTER the TXT is published (never respond before publish).
                    if challenge_type != 'dns-01':
                        await acme_svc.respond_to_challenges(new_order['order_id'])
                    logger.info(f"[ACME-RENEWAL] Initiated renewal order {new_order['order_id']} ({challenge_type}) for cert {cert['id']} ({cert['name']})")
                except Exception as cert_err:
                    logger.error(f"[ACME-RENEWAL] Failed to initiate renewal for cert {cert['id']}: {cert_err}")

            # Phase 2: Warn about stuck orders (completion handled by complete_pending_acme_orders)
            conn3 = await get_database_connection()
            try:
                stuck_orders = await conn3.fetch("""
                    SELECT id, status, domains, created_at FROM letsencrypt_orders
                    WHERE status IN ('pending', 'processing')
                    AND created_at < NOW() - INTERVAL '24 hours'
                    AND created_at > NOW() - INTERVAL '7 days'
                """)
            finally:
                await close_database_connection(conn3)
            if stuck_orders:
                stuck_ids = [str(o['id']) for o in stuck_orders]
                logger.warning(f"[ACME-RENEWAL] {len(stuck_orders)} order(s) stuck > 24h: IDs=[{', '.join(stuck_ids)}]")

        except Exception as e:
            logger.error(f"[ACME-RENEWAL] Error in renewal check: {e}")
            if conn:
                try:
                    await close_database_connection(conn)
                except Exception:
                    pass
        await asyncio.sleep(3600)


# Background task for agent upgrade timeout cleanup
async def cleanup_stuck_agent_upgrades():
    """Background task to reset agents stuck in 'upgrading' status
    
    Agents stuck in 'upgrading' for more than 5 minutes are automatically reset.
    This prevents UI issues where delete button is hidden due to stuck upgrade status.
    """
    while True:
        try:
            conn = await get_database_connection()
            
            # MIGRATION SAFETY: Check if upgrade_status column exists before using it
            # This prevents errors during initial deployment before migration runs
            upgrade_column_exists = await conn.fetchval("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name = 'agents' AND column_name = 'upgrade_status'
                )
            """)
            
            if not upgrade_column_exists:
                await close_database_connection(conn)
                logger.debug("Agent upgrade columns not yet created - skipping cleanup (migration pending)")
                await asyncio.sleep(120)
                continue
            
            # Reset stuck upgrades older than 5 minutes
            # upgraded_at tracks the last upgrade status change
            threshold_time = datetime.utcnow() - timedelta(minutes=5)
            
            result = await conn.execute("""
                UPDATE agents 
                SET upgrade_status = NULL, 
                    upgrade_target_version = NULL,
                    status = 'online',
                    updated_at = CURRENT_TIMESTAMP
                WHERE upgrade_status = 'upgrading' 
                AND (upgraded_at IS NULL OR upgraded_at < $1)
            """, threshold_time)
            
            await close_database_connection(conn)
            
            # Log if any stuck upgrades were reset
            if result and hasattr(result, 'split') and len(result.split()) > 1:
                count = result.split()[1]
                if int(count) > 0:
                    logger.warning(f"Reset {count} stuck agent upgrade(s) - timeout after 5 minutes")
            
        except Exception as e:
            logger.error(f"Error in agent upgrade cleanup: {e}")
        
        # Wait 120 seconds (2 minutes) before next check
        await asyncio.sleep(120)

# Production middleware stack (order matters!)
app.add_middleware(PerformanceMonitoringMiddleware, slow_request_threshold_ms=1000)
app.add_middleware(RequestLoggingMiddleware, exclude_paths=["/api/health/", "/docs", "/redoc"])

# Activity logging middleware - must be before CORS
app.middleware("http")(log_activity_middleware)

# CORS middleware  
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global exception handlers
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return await GlobalExceptionHandler.handle_http_exception(request, exc)

@app.exception_handler(StarletteHTTPException)
async def starlette_http_exception_handler(request: Request, exc: StarletteHTTPException):
    return await GlobalExceptionHandler.handle_http_exception(request, HTTPException(status_code=exc.status_code, detail=str(exc.detail)))

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return await GlobalExceptionHandler.handle_validation_error(request, exc)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return await GlobalExceptionHandler.handle_generic_exception(request, exc)

# Include routers
app.include_router(health_router)  # Health checks first for monitoring
app.include_router(config_router)  # Configuration management
app.include_router(maintenance_router, prefix="/api", tags=["maintenance"])  # Database cleanup & maintenance
app.include_router(auth_router)
app.include_router(user_router)
app.include_router(mfa_router)
app.include_router(frontend_router)
app.include_router(backend_router)
app.include_router(cluster_router)
app.include_router(dashboard_router)
app.include_router(dashboard_stats_router)  # HAProxy stats dashboard
app.include_router(agent_router)
app.include_router(waf_router)
app.include_router(ssl_router)
app.include_router(security_router)
app.include_router(configuration_router)
app.include_router(settings_router)
app.include_router(letsencrypt_router)
app.include_router(acme_diagnostics_router)  # v1.5.0 Issue #13: ACME Diagnostic Panel
app.include_router(site_wizard_router)  # v1.5.0 Issue #14: New Site Setup Wizard
app.include_router(vip_router)  # v1.7.0 Issue #27: HA/VIP (Keepalived) management


# Legacy URL alias: /api/proxied-hosts/* → 308 redirect to /api/sites/*.
# The Site Wizard endpoints were renamed from `/api/proxied-hosts/...`
# to `/api/sites/...` in this release. The 308 (Permanent Redirect)
# preserves the original method + body — POST/PUT/DELETE all continue
# to work — so any external integrator still pointing at the old slug
# keeps working through the redirect during the transition window.
# `include_in_schema=False` keeps the legacy paths out of OpenAPI so
# new consumers only see the canonical `/api/sites/*` URLs.
from fastapi import Request as _LegacyAliasRequest
from fastapi.responses import RedirectResponse as _LegacyAliasRedirect


@app.api_route(
    "/api/proxied-hosts",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    include_in_schema=False,
    name="legacy_proxied_hosts_root_alias",
)
async def _legacy_proxied_hosts_root_alias(request: _LegacyAliasRequest):
    qs = request.url.query
    target = "/api/sites" + (("?" + qs) if qs else "")
    return _LegacyAliasRedirect(url=target, status_code=308)


@app.api_route(
    "/api/proxied-hosts/{rest:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    include_in_schema=False,
    name="legacy_proxied_hosts_subpath_alias",
)
async def _legacy_proxied_hosts_subpath_alias(rest: str, request: _LegacyAliasRequest):
    qs = request.url.query
    target = f"/api/sites/{rest}" + (("?" + qs) if qs else "")
    return _LegacyAliasRedirect(url=target, status_code=308)


@app.on_event("startup")
async def startup_event():
    """Initialize the application on startup"""
    logger.info("HAProxy OpenManager API starting up...")
    
    try:
        # Initialize database connection pool FIRST (before any DB operations)
        logger.info("Initializing database connection pool...")
        await init_database_pool()
        logger.info("✅ Database connection pool initialized successfully")
        
        # Run database migrations
        logger.info("Forcing re-check of database schema...")
        await run_all_migrations()
        logger.info("Database migrations completed successfully")
        
        # Initialize agent scripts in database ONLY if empty (first deployment)
        # User edits are preserved, only Reset to Default overwrites from files
        try:
            import os
            
            conn = await get_database_connection()
            
            # Check if agent_script_templates table has any active scripts
            script_count = await conn.fetchval("""
                SELECT COUNT(*) FROM agent_script_templates WHERE is_active = true
            """)
            
            if script_count == 0:
                logger.info("🆕 INITIAL SETUP: No agent scripts in database, loading from files...")
                
                script_files = {
                    'linux': 'linux_install.sh',
                    'macos': 'macos_install.sh'
                }
                
                for platform_key, filename in script_files.items():
                    script_path = os.path.join(os.path.dirname(__file__), 'utils', 'agent_scripts', filename)
                    
                    if os.path.exists(script_path):
                        with open(script_path, 'r') as f:
                            file_content = f.read()
                        
                        # Create initial version 1.0.0
                        await conn.execute("""
                            INSERT INTO agent_script_templates (platform, version, script_content, is_active)
                            VALUES ($1, '1.0.0', $2, true)
                            ON CONFLICT (platform, version) DO NOTHING
                        """, platform_key, file_content)
                        
                        # Also create version entry
                        await conn.execute("""
                            INSERT INTO agent_versions (platform, version, is_active)
                            VALUES ($1, '1.0.0', true)
                            ON CONFLICT (platform, version) DO NOTHING
                        """, platform_key)
                        
                        logger.info(f"✅ INITIAL SETUP: {platform_key} script loaded (version 1.0.0)")
                
                logger.info("✅ INITIAL SETUP: Agent scripts initialized from files")
            else:
                logger.info(f"ℹ️  Agent scripts already exist in database ({script_count} active), preserving user edits")
            
            await close_database_connection(conn)
            
        except Exception as init_error:
            logger.warning(f"Agent script initialization check failed (non-critical): {init_error}")
        
        # Test Redis connection (graceful if unavailable)
        try:
            redis_client.ping()
            logger.info("Redis connection established")
        except Exception as redis_error:
            logger.warning(f"Redis is unavailable, continuing in degraded mode: {redis_error}")
        
        # Start background agent status monitoring task
        asyncio.create_task(monitor_agent_status())
        logger.info("Agent status monitoring task started")
        
        # Start background agent upgrade cleanup task
        asyncio.create_task(cleanup_stuck_agent_upgrades())
        logger.info("Agent upgrade timeout cleanup task started (5 minute timeout)")
        
        # Start ACME certificate auto-renewal task
        asyncio.create_task(check_letsencrypt_renewals())
        logger.info("ACME certificate auto-renewal task started (hourly checks)")

        # Issue #12: Independent task for completing CA-validated orders.
        # Runs every 60s with atomic claim (FOR UPDATE SKIP LOCKED) — multi-replica safe.
        # Decoupled from auto_renew_enabled flag so user-initiated orders also complete.
        asyncio.create_task(complete_pending_acme_orders())
        logger.info("ACME order auto-completion task started (60s checks, replica-safe)")
        
        # Create test activity log entry to verify system is working
        try:
            from utils.activity_log import log_user_activity
            await log_user_activity(
                user_id=1,  # Admin user
                action='system_startup',
                resource_type='system',
                resource_id='main',
                details={'event': 'HAProxy OpenManager system started', 'version': _version_info["version"]},
                ip_address='127.0.0.1',
                user_agent='HAProxy-OpenManager-System'
            )
            logger.info("✅ Test activity log created successfully")
        except Exception as log_error:
            logger.error(f"❌ Failed to create test activity log: {log_error}")
        
        logger.info("HAProxy OpenManager API startup completed successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize application: {e}")
        raise

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("HAProxy OpenManager API shutting down...")

    # R18c audit fix (round 3 #5): drain pending fire-and-forget
    # background tasks BEFORE closing the DB pool. The audit
    # logger middleware (`activity_logger.py`) and the wizard
    # router (`site_wizard.py`, R18b round 7) both use
    # `asyncio.create_task(...)` to write `user_activity_logs`
    # rows without blocking the response. Pre-fix the shutdown
    # event closed the DB pool immediately, so any in-flight
    # background task that was about to fetchval/execute hit
    # "pool is closed" and the audit row was lost — the operator
    # later opened the activity table and could not see why the
    # cluster's last action happened. Wait up to 5 seconds for
    # pending tasks scheduled on this loop to finish before
    # tearing the pool down. Bounded so a stuck task can't block
    # graceful shutdown indefinitely.
    try:
        loop = asyncio.get_event_loop()
        # All non-current tasks (FastAPI's request-handler tasks
        # are already done by the time on_shutdown fires; what's
        # left are the create_task background workers).
        pending = [t for t in asyncio.all_tasks(loop) if t is not asyncio.current_task() and not t.done()]
        if pending:
            logger.info(f"Draining {len(pending)} pending background task(s) before pool close...")
            await asyncio.wait(pending, timeout=5.0)
            still_pending = [t for t in pending if not t.done()]
            if still_pending:
                logger.warning(
                    f"{len(still_pending)} background task(s) did not "
                    "complete within 5s — proceeding with pool close. "
                    "These rows may not be persisted."
                )
    except Exception as drain_err:
        logger.warning(f"Background-task drain skipped: {drain_err}")

    # Close database connection pool gracefully
    try:
        logger.info("Closing database connection pool...")
        await close_database_pool()
        logger.info("✅ Database connection pool closed successfully")
    except Exception as e:
        logger.error(f"❌ Error closing database connection pool: {e}")

@app.get("/")
async def root():
    """Root endpoint"""
    return {"message": "HAProxy Management UI API", "version": _version_info["version"]}

@app.get("/api/version")
async def get_version():
    """Return application version information"""
    return _version_info

@app.get("/.well-known/acme-challenge/{token}")
async def serve_acme_challenge(token: str):
    """Serve ACME HTTP-01 challenge token. Public endpoint, no auth required."""
    logger.info(f"ACME-CHALLENGE: Incoming request for token={token[:32]}...")
    conn = None
    try:
        conn = await get_database_connection()
        row = await conn.fetchrow(
            "SELECT key_authorization FROM acme_challenges WHERE token = $1 AND (status IN ('pending', 'processing') OR status IS NULL) AND (challenge_type = 'http-01' OR challenge_type IS NULL) LIMIT 1",
            token
        )
        if row:
            logger.info(f"ACME-CHALLENGE: Token found, serving key_authorization ({len(row['key_authorization'])} chars)")
            from fastapi.responses import PlainTextResponse
            return PlainTextResponse(row['key_authorization'])
        logger.warning(f"ACME-CHALLENGE: Token NOT found in DB - no matching record with status pending/processing/null")
        raise HTTPException(status_code=404, detail="Challenge not found")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"ACME-CHALLENGE: Error serving token {token[:32]}...: {e}")
        raise HTTPException(status_code=404, detail="Challenge not found")
    finally:
        if conn:
            await close_database_connection(conn)

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Check Redis connection
        try:
            redis_client.ping()
            redis_status = "connected"
        except Exception:
            redis_status = "disconnected"
        
        # Check database connection (basic check)
        conn = await get_database_connection()
        await close_database_connection(conn)
        
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "services": {
                "redis": redis_status,
                "database": "connected"
            }
        }
    except Exception as e:
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
        ) 