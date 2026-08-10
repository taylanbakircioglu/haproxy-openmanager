"""Issue #27 — HA/VIP (Keepalived) management API (v1.7.0).

Isolated router: it owns vip_instances / vip_members only. It NEVER imports or calls
the global HAProxy apply flow (cluster.py::apply_pending_changes) or the haproxy.cfg
generator — VIP "Apply" is a standalone verb that renders per-node keepalived.conf
snapshots into vip_members and flips the VIP to APPLIED.

For Apply-Management consistency it ALSO stages a standard `config_versions` row per
change (version_name `vip-{id}-{action}`, status PENDING, is_active=FALSE — exactly like
ssl-* versions) so VIP changes appear in the right-panel Pending Versions list with the
product's standard "View Change" diff. is_active stays FALSE so a VIP version can never
be served to an agent as haproxy.cfg (the agent config query requires is_active=TRUE);
cluster.py keeps vip-* versions out of the generic haproxy apply/reject (NOT LIKE 'vip-%').

Every DB access is wrapped so a (pathological) missing vip_* relation degrades to an
empty/None result instead of a 500 (B-7) — preserving the fleet-wide no-op guarantee.
"""
import hashlib
import json
import logging
import re
import time
import uuid
from typing import List, Optional

from fastapi import APIRouter, Header, HTTPException, Request

from auth_middleware import check_user_permission, get_current_user_from_token
from database.connection import close_database_connection, get_database_connection
from models.vip import VIPCreate, VIPUpdate
from services.keepalived_config import (
    build_haproxy_check_script,
    decrypt_vrrp_secret,
    encrypt_vrrp_secret,
    render_keepalived_conf,
)
from utils.activity_log import log_user_activity

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/vip", tags=["HA / VIP"])


def _client_ip(request: Optional[Request]) -> Optional[str]:
    try:
        return request.client.host if request and request.client else None
    except Exception:  # noqa: BLE001
        return None


def _user_agent(request: Optional[Request]) -> Optional[str]:
    try:
        return request.headers.get("user-agent") if request else None
    except Exception:  # noqa: BLE001
        return None


async def _require(authorization: Optional[str], action: str):
    """Authenticate + enforce vip.<action>; returns current_user or raises 401/403."""
    current_user = await get_current_user_from_token(authorization)
    ok = await check_user_permission(current_user["id"], "vip", action, current_user=current_user)
    if not ok:
        raise HTTPException(status_code=403, detail=f"vip.{action} permission required")
    return current_user


async def _alloc_free_vrid(conn, pool_id: int, requested: Optional[int]) -> int:
    """Use the requested VRID if free in the pool, else the lowest free 1..255."""
    used = {r["virtual_router_id"] for r in await conn.fetch(
        "SELECT virtual_router_id FROM vip_instances WHERE pool_id=$1 AND is_active=TRUE", pool_id)}
    if requested is not None:
        if requested in used:
            raise HTTPException(status_code=409, detail=f"VRID {requested} already used in this pool")
        return requested
    for cand in range(1, 256):
        if cand not in used:
            return cand
    raise HTTPException(status_code=409, detail="No free VRID (1-255) left in this pool")


def _md5(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


# The VRRP secret is rendered into keepalived.conf as `auth_pass <value>`. The "secret
# never leaves the server in cleartext" rule means any config we hand back to the UI
# (e.g. the version diff) must mask it — only the at-rest Fernet token and the
# agent-delivery endpoint ever see the real value. Mask the WHOLE remainder of the line
# (not just up to the first space) so a secret containing whitespace can't partially leak.
_AUTH_PASS_RE = re.compile(r"(auth_pass\s+).*")


def _redact_secret(conf: Optional[str]) -> str:
    return _AUTH_PASS_RE.sub(r"\1********", conf or "")


def _derive_deploy_status(last_config_status: str, members, pending_delete: bool = False,
                          is_active: bool = True) -> tuple:
    """Display status that reflects ACTUAL agent convergence, not just the staging flag.

    Other entities only read APPLIED once their agents acknowledge the new config; the
    VIP now mirrors that so the table never claims a VIP is live before its member nodes
    have deployed keepalived and acked the current config hash (issue #27 follow-up).

        PENDING_DELETE — a deletion is STAGED and awaiting approval in Apply Management; the
                     VIP keeps running until approved (nothing is torn down)
        DELETING   — deletion APPROVED; member nodes are tearing keepalived down (not yet acked)
        PENDING    — staged (created/edited); apply from Apply Management
        SYNCING    — applied; an ONLINE member is still converging (deploying/acking)
        AWAITING   — applied, but the un-converged members' agents are all OFFLINE, so
                     nothing can deploy yet (bring the node's agent online) — not a hang
        ACTIVE     — applied AND every member deployed & acked the current config hash
        ERROR      — a member reported a deploy error
        ATTENTION  — a member found a hand-managed keepalived (externally_managed)

    Returns (status, synced_count, total_count).
    """
    # Approval-gated delete: staged (still running) vs approved (tearing down).
    if pending_delete:
        return "PENDING_DELETE", 0, len(members)
    if not is_active:
        total = len(members)
        torn = sum(1 for m in members if m["last_deploy_state"] == "disabled")
        return ("DELETED" if total and torn == total else "DELETING"), torn, total
    if last_config_status == "PENDING":
        return "PENDING", 0, len(members)
    total = len(members)
    if total == 0:
        return "APPLIED", 0, 0

    def _in_sync(m) -> bool:
        return (m["last_deploy_state"] == "enabled"
                and m["applied_config_hash"] is not None
                and m["last_deploy_hash"] == m["applied_config_hash"])

    synced = sum(1 for m in members if _in_sync(m))
    if any(m["last_deploy_state"] == "error" for m in members):
        return "ERROR", synced, total
    if any(m["last_deploy_state"] == "externally_managed" for m in members):
        return "ATTENTION", synced, total
    if synced == total:
        return "ACTIVE", synced, total
    # Not fully converged: distinguish "actively converging" (an online agent will deploy
    # on its next poll) from "waiting on offline agents" (nothing will happen until the
    # operator brings the node's agent online) — the latter must NOT read as a live spinner.
    not_synced = [m for m in members if not _in_sync(m)]
    if not_synced and all((m["agent_status"] or "offline") != "online" for m in not_synced):
        return "AWAITING", synced, total
    return "SYNCING", synced, total


async def render_vip_config_masked(conn, vip_id: int):
    """Render the keepalived.conf each member node would deploy, as ONE masked text block
    (VRRP secret never in cleartext). Used by the standard config-version diff for vip-*
    versions (cluster.py) and to populate the staged version's config_content — so VIP
    changes show the product's standard "View Change" instead of a bespoke screen.

    Returns (text, {"name": ...}) or (None, None) if the VIP is gone. Best-effort: a
    per-node render error becomes an inline comment rather than raising.
    """
    v = await conn.fetchrow("SELECT * FROM vip_instances WHERE id=$1", vip_id)
    if not v:
        return None, None
    members = await conn.fetch("""
        SELECT m.agent_id, m.network_interface, m.role, m.priority,
               a.name AS agent_name, a.ip_address
        FROM vip_members m LEFT JOIN agents a ON a.id = m.agent_id
        WHERE m.vip_id=$1 ORDER BY m.priority DESC
    """, vip_id)
    auth_plain = decrypt_vrrp_secret(v["auth_pass_encrypted"]) if v["auth_pass_encrypted"] else None
    vip_dict = {"id": v["id"], "name": v["name"], "virtual_ip": v["virtual_ip"],
                "prefix_length": v["prefix_length"], "virtual_router_id": v["virtual_router_id"],
                "advert_int": v["advert_int"], "use_unicast": v["use_unicast"],
                "track_haproxy": v["track_haproxy"]}
    member_dicts = [{"role": m["role"], "priority": m["priority"],
                     "network_interface": m["network_interface"], "agent_id": m["agent_id"],
                     "ip_address": str(m["ip_address"]) if m["ip_address"] else ""} for m in members]
    blocks = []
    for m in members:
        this_agent = next(d for d in member_dicts if d["agent_id"] == m["agent_id"])
        peer_ips = [d["ip_address"] for d in member_dicts
                    if d["agent_id"] != m["agent_id"] and d["ip_address"]]
        try:
            conf = render_keepalived_conf(vip=vip_dict, members=member_dicts,
                                          this_agent=this_agent, peer_ips=peer_ips,
                                          auth_pass_plain=auth_plain)
        except Exception as exc:  # noqa: BLE001 — best-effort preview
            conf = f"# cannot render this node yet: {exc}\n"
        header = (f"# ===== node: {m['agent_name'] or m['agent_id']} "
                  f"({m['ip_address'] or 'no IP'}) — {m['role']} priority {m['priority']} =====")
        blocks.append(header + "\n" + _redact_secret(conf))
    text = "\n\n".join(blocks) if blocks else "# (no participating nodes selected yet)\n"
    return text, {"name": v["name"]}


async def _stage_vip_version(conn, vip_id: int, action: str, created_by: Optional[int]):
    """Stage a standard PENDING config_versions row for a VIP change so it shows in Apply
    Management exactly like other entities. One row per cluster in the VIP's pool;
    is_active=FALSE so it is NEVER delivered as haproxy.cfg. Best-effort — a staging
    failure never fails the VIP operation (logged); the VIP still applies via its own flow.
    """
    try:
        cluster_ids = [r["id"] for r in await conn.fetch(
            "SELECT id FROM haproxy_clusters WHERE pool_id = "
            "(SELECT pool_id FROM vip_instances WHERE id=$1)", vip_id)]
        if not cluster_ids:
            return
        content, _meta = await render_vip_config_masked(conn, vip_id)
        content = content or f"# VIP {vip_id} ({action})\n"
        checksum = _md5(content)
        # uuid suffix makes the name collision-proof even for sub-second same-action re-edits
        # (UNIQUE(cluster_id, version_name) would otherwise reject a same-second retry; review LOW-1).
        version_name = f"vip-{vip_id}-{action}-{int(time.time())}-{uuid.uuid4().hex[:6]}"
        # Capture this change's PENDING state so undo-reject can faithfully re-stage it
        # (restore the VIP — reactivating it if a rejected create soft-deleted it).
        pending_state = await _capture_vip_pending_state(conn, vip_id)
        metadata = json.dumps({"pending_state": pending_state}) if pending_state else None
        for cid in cluster_ids:
            # Collapse repeated pre-apply edits to a single PENDING row per VIP+cluster.
            await conn.execute(
                "DELETE FROM config_versions WHERE cluster_id=$1 AND status='PENDING' "
                "AND version_name LIKE $2", cid, f"vip-{vip_id}-%")
            await conn.execute("""
                INSERT INTO config_versions
                    (cluster_id, version_name, config_content, checksum, created_by, is_active, status, metadata)
                VALUES ($1,$2,$3,$4,$5,FALSE,'PENDING',$6::jsonb)
            """, cid, version_name, content, checksum, created_by, metadata)
    except Exception as e:  # noqa: BLE001 — versioning is a UI convenience, never block the op
        logger.warning(f"_stage_vip_version({vip_id},{action}) failed: {e}")


async def _capture_vip_pending_state(conn, vip_id: int):
    """Snapshot a VIP's current (pending) field + member state for undo-reject. The VRRP
    secret travels only as its encrypted token (never plaintext)."""
    v = await conn.fetchrow("SELECT * FROM vip_instances WHERE id=$1", vip_id)
    if not v:
        return None
    members = await conn.fetch(
        "SELECT agent_id, network_interface, role, priority FROM vip_members WHERE vip_id=$1", vip_id)
    return {
        "vip": {"name": v["name"], "description": v["description"], "virtual_ip": v["virtual_ip"],
                "prefix_length": v["prefix_length"], "virtual_router_id": v["virtual_router_id"],
                "advert_int": v["advert_int"], "use_unicast": v["use_unicast"],
                "track_haproxy": v["track_haproxy"], "auth_pass_encrypted": v["auth_pass_encrypted"]},
        "members": [{"agent_id": m["agent_id"], "network_interface": m["network_interface"],
                     "role": m["role"], "priority": m["priority"]} for m in members],
    }


async def restore_vip_from_rejected_version(conn, version_id: int):
    """Undo-reject for a vip-* version: re-stage the rejected change as PENDING from the
    version's captured `pending_state`. Reactivates the VIP if a rejected create soft-deleted
    it, or re-applies a rejected edit's members — preserving each remaining member's
    last-applied snapshot so a running VIP is never torn down (T-1). Returns None on success
    or a human-readable error string (e.g. the name/address/VRID was reused since reject).
    """
    row = await conn.fetchrow("SELECT version_name, metadata FROM config_versions WHERE id=$1", version_id)
    if not row:
        return "version not found"
    m = re.match(r"vip-(\d+)-", row["version_name"] or "")
    if not m:
        return "not a VIP version"
    vip_id = int(m.group(1))
    # Undo the reject of a DELETE request → re-arm the staged deletion (the VIP keeps running
    # until re-approved; nothing on the node changes). Requires the VIP to still be active.
    if "-delete-" in (row["version_name"] or ""):
        if not await conn.fetchrow("SELECT 1 FROM vip_instances WHERE id=$1 AND is_active=TRUE", vip_id):
            return "the VIP is no longer active — nothing to re-stage for deletion"
        await conn.execute(
            "UPDATE vip_instances SET pending_delete=TRUE, last_config_status='PENDING', "
            "updated_at=CURRENT_TIMESTAMP WHERE id=$1", vip_id)
        await conn.execute(
            "UPDATE config_versions SET status='PENDING', is_active=FALSE, updated_at=CURRENT_TIMESTAMP "
            "WHERE version_name=$1 AND status='REJECTED'", row["version_name"])
        return None
    meta = row["metadata"]
    meta = json.loads(meta) if isinstance(meta, str) else meta
    ps = (meta or {}).get("pending_state")
    if not ps:
        return ("this VIP change predates undo support — re-create or re-edit the VIP "
                "from the HA/VIP page")
    if not await conn.fetchrow("SELECT 1 FROM vip_instances WHERE id=$1", vip_id):
        return "the VIP no longer exists — re-create it from the HA/VIP page"
    sv, sm = ps["vip"], ps.get("members", [])
    # One-VIP-per-agent must STILL hold after reactivation: if a member was meanwhile added
    # to another active VIP (while this one was rejected/soft-deleted), undoing here would
    # create a double-membership — and since the delivery endpoint serves one VIP per agent,
    # reactivating this (never-applied → not_configured) VIP would tear down the other live
    # VIP on that node. Block it with a clear message (review round-3 FINDING 2).
    member_ids = [m["agent_id"] for m in sm]
    if member_ids:
        dup = await conn.fetchrow(
            "SELECT a.name AS agent_name, v.name AS vip_name FROM vip_members vm "
            "JOIN vip_instances v ON v.id = vm.vip_id JOIN agents a ON a.id = vm.agent_id "
            "WHERE vm.agent_id = ANY($1) AND v.is_active = TRUE AND v.id <> $2 LIMIT 1",
            member_ids, vip_id)
        if dup:
            return (f"node '{dup['agent_name']}' now belongs to active VIP '{dup['vip_name']}' — "
                    f"remove it there first, then undo")
    # Preserve the running (applied) snapshot for members that remain, so undo of an edit
    # never momentarily flips a live node to not_configured (T-1).
    prev = {r["agent_id"]: r for r in await conn.fetch(
        "SELECT agent_id, applied_config_content, applied_config_hash, last_deploy_state, "
        "last_deploy_message, last_deploy_hash, last_deploy_at FROM vip_members WHERE vip_id=$1", vip_id)}
    try:
        async with conn.transaction():
            await conn.execute("""
                UPDATE vip_instances SET name=$2, description=$3, virtual_ip=$4, prefix_length=$5,
                    virtual_router_id=$6, advert_int=$7, use_unicast=$8, track_haproxy=$9,
                    auth_pass_encrypted=$10, is_active=TRUE, last_config_status='PENDING',
                    updated_at=CURRENT_TIMESTAMP
                WHERE id=$1
            """, vip_id, sv["name"], sv.get("description"), sv["virtual_ip"], sv["prefix_length"],
                sv["virtual_router_id"], sv["advert_int"], sv["use_unicast"], sv["track_haproxy"],
                sv.get("auth_pass_encrypted"))
            await conn.execute("DELETE FROM vip_members WHERE vip_id=$1", vip_id)
            for mm in sm:
                o = prev.get(mm["agent_id"])
                await conn.execute("""
                    INSERT INTO vip_members (vip_id, agent_id, network_interface, role, priority,
                        applied_config_content, applied_config_hash,
                        last_deploy_state, last_deploy_message, last_deploy_hash, last_deploy_at)
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                """, vip_id, mm["agent_id"], mm["network_interface"], mm["role"], mm["priority"],
                    o["applied_config_content"] if o else None, o["applied_config_hash"] if o else None,
                    o["last_deploy_state"] if o else None, o["last_deploy_message"] if o else None,
                    o["last_deploy_hash"] if o else None, o["last_deploy_at"] if o else None)
            # A multi-cluster pool stages one row per cluster under the SAME version_name;
            # flip them all back to PENDING so every affected cluster's Apply Management shows
            # the restored change (mirrors the SSL auto-undo). is_active stays FALSE (review MED-2).
            await conn.execute(
                "UPDATE config_versions SET status='PENDING', is_active=FALSE, "
                "updated_at=CURRENT_TIMESTAMP WHERE version_name=$1 AND status='REJECTED'",
                row["version_name"])
    except Exception as e:  # noqa: BLE001
        if "unique" in str(e).lower() or "duplicate" in str(e).lower():
            return "the VIP's name, address or VRID was reused after it was rejected"
        raise
    return None


async def _transition_vip_versions(conn, vip_id: int, new_status: str):
    """Move this VIP's PENDING config_versions to APPLIED/REJECTED (is_active stays FALSE).
    Called by the VIP apply/reject endpoints so the right-panel version tracks the VIP."""
    try:
        await conn.execute(
            "UPDATE config_versions SET status=$2, is_active=FALSE, updated_at=CURRENT_TIMESTAMP "
            "WHERE status='PENDING' AND version_name LIKE $1", f"vip-{vip_id}-%", new_status)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"_transition_vip_versions({vip_id},{new_status}) failed: {e}")


def _jsonb_list(v):
    """agents.capabilities/network_interfaces are JSONB; asyncpg returns them as a raw
    JSON string (no codec). Normalize to a Python list."""
    if isinstance(v, list):
        return v
    if isinstance(v, str):
        try:
            parsed = json.loads(v)
            return parsed if isinstance(parsed, list) else []
        except Exception:  # noqa: BLE001
            return []
    return []


def _capable(capabilities) -> bool:
    return "keepalived_management" in _jsonb_list(capabilities)


# ---------------------------------------------------------------------------
# List / read
# ---------------------------------------------------------------------------
@router.get("")
async def list_vips(cluster_id: Optional[int] = None, authorization: str = Header(None)):
    """List VIPs with their members + live MASTER/BACKUP state (never the secret).

    Optional cluster_id scopes to VIPs in that cluster's pool — used by the Apply
    Management page (which is cluster-scoped) to surface pending VIP changes.
    """
    await _require(authorization, "read")
    conn = await get_database_connection()
    try:
        # Show active VIPs PLUS approved-but-still-tearing-down ones (is_active=FALSE with a
        # member that hasn't acked 'disabled' yet) so the operator can TRACK a deletion through
        # to completion; a VIP drops off only once every member has torn keepalived down.
        # The teardown-tracking clause is gated on last_config_status='APPLIED' so it ONLY shows
        # deletions APPROVED via the new flow — a VIP soft-deleted under the old immediate-delete
        # (pre-1.7.2: is_active=FALSE, last_config_status='PENDING') is NOT resurfaced (backward
        # compat). Rejected never-applied creates (also PENDING) are likewise excluded.
        _visible = ("(v.is_active = TRUE OR (v.last_config_status = 'APPLIED' AND EXISTS ("
                    "SELECT 1 FROM vip_members mm WHERE mm.vip_id = v.id "
                    "AND mm.applied_config_hash IS NOT NULL "
                    "AND mm.last_deploy_state IS DISTINCT FROM 'disabled')))")
        if cluster_id is not None:
            vips = await conn.fetch(f"""
                SELECT v.id, v.name, v.description, v.pool_id, v.virtual_ip, v.prefix_length,
                       v.virtual_router_id, v.advert_int, v.use_unicast, v.track_haproxy,
                       v.is_active, v.last_config_status, v.pending_delete,
                       (v.auth_pass_encrypted IS NOT NULL) AS auth_pass_set,
                       v.created_at, v.updated_at, p.name AS pool_name
                FROM vip_instances v
                LEFT JOIN haproxy_cluster_pools p ON p.id = v.pool_id
                WHERE {_visible}
                  AND v.pool_id = (SELECT pool_id FROM haproxy_clusters WHERE id = $1)
                ORDER BY v.name
            """, cluster_id)
        else:
            vips = await conn.fetch(f"""
                SELECT v.id, v.name, v.description, v.pool_id, v.virtual_ip, v.prefix_length,
                       v.virtual_router_id, v.advert_int, v.use_unicast, v.track_haproxy,
                       v.is_active, v.last_config_status, v.pending_delete,
                       (v.auth_pass_encrypted IS NOT NULL) AS auth_pass_set,
                       v.created_at, v.updated_at, p.name AS pool_name
                FROM vip_instances v
                LEFT JOIN haproxy_cluster_pools p ON p.id = v.pool_id
                WHERE {_visible}
                ORDER BY v.name
            """)
        result = []
        for v in vips:
            members = await conn.fetch("""
                SELECT m.id, m.agent_id, m.network_interface, m.role, m.priority,
                       m.applied_config_hash, m.last_deploy_state, m.last_deploy_hash, m.last_deploy_at,
                       a.name AS agent_name, a.status AS agent_status,
                       a.keepalive_state, a.keepalive_ip, a.capabilities,
                       a.ip_address
                FROM vip_members m
                LEFT JOIN agents a ON a.id = m.agent_id
                WHERE m.vip_id = $1
                ORDER BY m.priority DESC
            """, v["id"])
            deploy_status, deploy_synced, deploy_total = _derive_deploy_status(
                v["last_config_status"], members, v["pending_delete"], v["is_active"])
            result.append({
                **dict(v),
                # Convergence-aware status for the table (issue #27 follow-up); the raw
                # last_config_status is kept above for the PENDING gate / Apply button.
                "deploy_status": deploy_status,
                "deploy_synced": deploy_synced,
                "deploy_total": deploy_total,
                "members": [{
                    "id": m["id"], "agent_id": m["agent_id"], "agent_name": m["agent_name"],
                    "network_interface": m["network_interface"], "role": m["role"],
                    "priority": m["priority"], "agent_status": m["agent_status"],
                    "keepalive_state": m["keepalive_state"], "keepalive_ip": m["keepalive_ip"],
                    "ip_address": str(m["ip_address"]) if m["ip_address"] else None,
                    "keepalived_capable": _capable(m["capabilities"]),
                    "last_deploy_state": m["last_deploy_state"],
                    "last_deploy_at": m["last_deploy_at"].isoformat() if m["last_deploy_at"] else None,
                } for m in members],
            })
        return {"vips": result}
    except Exception as e:  # noqa: BLE001 — degrade to empty rather than 500 (B-7)
        logger.error(f"list_vips failed: {e}")
        return {"vips": []}
    finally:
        await close_database_connection(conn)


@router.get("/{vip_id}")
async def get_vip(vip_id: int, authorization: str = Header(None)):
    await _require(authorization, "read")
    conn = await get_database_connection()
    try:
        v = await conn.fetchrow("""
            SELECT v.id, v.name, v.description, v.pool_id, v.virtual_ip, v.prefix_length,
                   v.virtual_router_id, v.advert_int, v.use_unicast, v.track_haproxy,
                   v.is_active, v.last_config_status,
                   (v.auth_pass_encrypted IS NOT NULL) AS auth_pass_set,
                   v.created_at, v.updated_at
            FROM vip_instances v WHERE v.id = $1 AND v.is_active = TRUE
        """, vip_id)
        if not v:
            raise HTTPException(status_code=404, detail="VIP not found")
        members = await conn.fetch("""
            SELECT m.agent_id, m.network_interface, m.role, m.priority,
                   m.last_deploy_state, m.last_deploy_at,
                   a.name AS agent_name, a.keepalive_state, a.keepalive_ip
            FROM vip_members m LEFT JOIN agents a ON a.id = m.agent_id
            WHERE m.vip_id = $1 ORDER BY m.priority DESC
        """, vip_id)
        return {**dict(v), "members": [dict(m) for m in members]}
    finally:
        await close_database_connection(conn)


# ---------------------------------------------------------------------------
# Create / update / delete
# ---------------------------------------------------------------------------
async def _validate_members_against_pool(conn, pool_id: int, members: List, vip_virtual_ip: str,
                                         exclude_vip_id: Optional[int] = None):
    """Members must belong to the VIP's pool; VIP must not collide with an agent IP
    or another live VIP (T-4/SQL-1)."""
    # pool membership
    for m in members:
        row = await conn.fetchrow("SELECT pool_id FROM agents WHERE id=$1", m.agent_id)
        if not row:
            raise HTTPException(status_code=400, detail=f"agent {m.agent_id} not found")
        if row["pool_id"] != pool_id:
            raise HTTPException(status_code=400,
                                detail=f"agent {m.agent_id} is not in pool {pool_id}")
    # One active VIP per agent (v1): a node deploys a single keepalived.conf, and the
    # delivery endpoint serves one VIP per agent — a second active membership would never
    # converge (stuck SYNCING) instead of erroring. Reject it up front (review MED-2).
    agent_ids = [m.agent_id for m in members]
    if agent_ids:
        dq = ("SELECT a.name AS agent_name, v.name AS vip_name "
              "FROM vip_members vm JOIN vip_instances v ON v.id = vm.vip_id "
              "JOIN agents a ON a.id = vm.agent_id "
              "WHERE vm.agent_id = ANY($1) AND v.is_active = TRUE")
        dparams = [agent_ids]
        if exclude_vip_id is not None:
            dq += " AND v.id <> $2"
            dparams.append(exclude_vip_id)
        dup = await conn.fetchrow(dq + " LIMIT 1", *dparams)
        if dup:
            raise HTTPException(status_code=409,
                                detail=f"node '{dup['agent_name']}' is already a member of VIP "
                                       f"'{dup['vip_name']}' — a node can belong to only one VIP")
    # VIP must not be an existing agent's primary IP (INET cast, SQL-1)
    clash = await conn.fetchval("SELECT 1 FROM agents WHERE ip_address = $1::inet LIMIT 1", vip_virtual_ip)
    if clash:
        raise HTTPException(status_code=409, detail=f"{vip_virtual_ip} is already a node's IP")
    # …or another live VIP's address
    q = "SELECT 1 FROM vip_instances WHERE virtual_ip=$1 AND is_active=TRUE"
    params = [vip_virtual_ip]
    if exclude_vip_id is not None:
        q += " AND id <> $2"
        params.append(exclude_vip_id)
    if await conn.fetchval(q, *params):
        raise HTTPException(status_code=409, detail=f"{vip_virtual_ip} is already used by another VIP")


@router.post("")
async def create_vip(payload: VIPCreate, request: Request, authorization: str = Header(None)):
    current_user = await _require(authorization, "create")
    conn = await get_database_connection()
    try:
        pool = await conn.fetchrow("SELECT id FROM haproxy_cluster_pools WHERE id=$1", payload.pool_id)
        if not pool:
            raise HTTPException(status_code=400, detail=f"pool {payload.pool_id} not found")
        await _validate_members_against_pool(conn, payload.pool_id, payload.members, payload.virtual_ip)

        enc = encrypt_vrrp_secret(payload.auth_pass) if payload.auth_pass else None
        # Allocate VRID + insert, retrying once on a unique-violation race (B-1).
        last_err = None
        for _attempt in range(2):
            vrid = await _alloc_free_vrid(conn, payload.pool_id, payload.virtual_router_id)
            try:
                async with conn.transaction():
                    vip_id = await conn.fetchval("""
                        INSERT INTO vip_instances
                          (name, description, pool_id, virtual_ip, prefix_length, virtual_router_id,
                           advert_int, auth_pass_encrypted, use_unicast, track_haproxy,
                           is_active, last_config_status, created_by)
                        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,TRUE,'PENDING',$11)
                        RETURNING id
                    """, payload.name, payload.description, payload.pool_id, payload.virtual_ip,
                        payload.prefix_length, vrid, payload.advert_int, enc,
                        payload.use_unicast, payload.track_haproxy, current_user["id"])
                    for m in payload.members:
                        await conn.execute("""
                            INSERT INTO vip_members (vip_id, agent_id, network_interface, role, priority)
                            VALUES ($1,$2,$3,$4,$5)
                        """, vip_id, m.agent_id, m.network_interface, m.role, m.priority)
                last_err = None
                break
            except Exception as ie:  # noqa: BLE001
                if "unique" in str(ie).lower() or "duplicate" in str(ie).lower():
                    last_err = ie
                    if payload.virtual_router_id is not None:
                        raise HTTPException(status_code=409, detail="VIP name/address/VRID already in use")
                    continue  # auto-VRID race → retry allocation
                raise
        if last_err is not None:
            raise HTTPException(status_code=409, detail="VIP create conflict (name/address/VRID)")

        # Stage a standard PENDING config_version so the change shows in Apply Management.
        await _stage_vip_version(conn, vip_id, "create", current_user["id"])
        await log_user_activity(
            user_id=current_user["id"], action="create", resource_type="vip",
            resource_id=str(vip_id),
            details={"name": payload.name, "virtual_ip": payload.virtual_ip,
                     "pool_id": payload.pool_id, "vrid": vrid, "members": len(payload.members)},
            ip_address=_client_ip(request), user_agent=_user_agent(request))
        return {"id": vip_id, "message": "VIP created (PENDING — apply from Apply Management)"}
    finally:
        await close_database_connection(conn)


@router.put("/{vip_id}")
async def update_vip(vip_id: int, payload: VIPUpdate, request: Request, authorization: str = Header(None)):
    current_user = await _require(authorization, "update")
    conn = await get_database_connection()
    try:
        v = await conn.fetchrow("SELECT * FROM vip_instances WHERE id=$1 AND is_active=TRUE", vip_id)
        if not v:
            raise HTTPException(status_code=404, detail="VIP not found")
        new_ip = payload.virtual_ip or v["virtual_ip"]
        members = payload.members if payload.members is not None else None
        if members is not None:
            await _validate_members_against_pool(conn, v["pool_id"], members, new_ip, exclude_vip_id=vip_id)
        elif payload.virtual_ip:
            # Address-only change: re-check the VIP isn't a node IP or another live VIP.
            clash = await conn.fetchval("SELECT 1 FROM agents WHERE ip_address=$1::inet LIMIT 1", new_ip)
            if clash:
                raise HTTPException(status_code=409, detail=f"{new_ip} is already a node's IP")
            dup = await conn.fetchval(
                "SELECT 1 FROM vip_instances WHERE virtual_ip=$1 AND is_active=TRUE AND id<>$2", new_ip, vip_id)
            if dup:
                raise HTTPException(status_code=409, detail=f"{new_ip} is already used by another VIP")

        enc_set = payload.auth_pass is not None and payload.auth_pass != ""
        try:
            async with conn.transaction():
                await conn.execute("""
                    UPDATE vip_instances SET
                        name = COALESCE($2, name),
                        description = COALESCE($3, description),
                        virtual_ip = COALESCE($4, virtual_ip),
                        prefix_length = COALESCE($5, prefix_length),
                        virtual_router_id = COALESCE($6, virtual_router_id),
                        advert_int = COALESCE($7, advert_int),
                        use_unicast = COALESCE($8, use_unicast),
                        track_haproxy = COALESCE($9, track_haproxy),
                        auth_pass_encrypted = CASE WHEN $10 THEN $11 ELSE auth_pass_encrypted END,
                        last_config_status = 'PENDING',
                        -- Editing a VIP means you are KEEPING and changing it, so it cancels any
                        -- staged deletion (otherwise a later Apply would delete instead of applying
                        -- the edit). The edit then becomes the pending change to approve.
                        pending_delete = FALSE,
                        purge_on_teardown = FALSE,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = $1
                """, vip_id, payload.name, payload.description, payload.virtual_ip,
                    payload.prefix_length, payload.virtual_router_id, payload.advert_int,
                    payload.use_unicast, payload.track_haproxy,
                    enc_set, encrypt_vrrp_secret(payload.auth_pass) if enc_set else None)
                if members is not None:
                    # T-1: preserve the APPLIED snapshot + deploy ack for members that REMAIN,
                    # so a pending member edit never momentarily flips a running node to
                    # not_configured (which would self-heal-teardown a live VIP). The new
                    # config only goes live on the next Apply. A REMOVED member loses its row
                    # → delivery returns not_configured → marker self-heal teardown (correct:
                    # it's no longer part of the VIP). A NEW member starts with a NULL snapshot.
                    prev = {r["agent_id"]: r for r in await conn.fetch(
                        "SELECT agent_id, applied_config_content, applied_config_hash, "
                        "last_deploy_state, last_deploy_message, last_deploy_hash, last_deploy_at "
                        "FROM vip_members WHERE vip_id=$1", vip_id)}
                    await conn.execute("DELETE FROM vip_members WHERE vip_id=$1", vip_id)
                    for m in members:
                        o = prev.get(m.agent_id)
                        await conn.execute("""
                            INSERT INTO vip_members (vip_id, agent_id, network_interface, role, priority,
                                applied_config_content, applied_config_hash,
                                last_deploy_state, last_deploy_message, last_deploy_hash, last_deploy_at)
                            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                        """, vip_id, m.agent_id, m.network_interface, m.role, m.priority,
                            o["applied_config_content"] if o else None,
                            o["applied_config_hash"] if o else None,
                            o["last_deploy_state"] if o else None,
                            o["last_deploy_message"] if o else None,
                            o["last_deploy_hash"] if o else None,
                            o["last_deploy_at"] if o else None)
        except HTTPException:
            raise
        except Exception as ie:  # noqa: BLE001
            if "unique" in str(ie).lower() or "duplicate" in str(ie).lower():
                raise HTTPException(status_code=409, detail="VIP name/address/VRID already in use")
            raise
        # Re-stage the standard PENDING config_version reflecting the edited config.
        await _stage_vip_version(conn, vip_id, "update", current_user["id"])
        await log_user_activity(
            user_id=current_user["id"], action="update", resource_type="vip",
            resource_id=str(vip_id), details={"vip_id": vip_id},
            ip_address=_client_ip(request), user_agent=_user_agent(request))
        return {"message": "VIP updated (PENDING — apply from Apply Management)"}
    finally:
        await close_database_connection(conn)


@router.delete("/{vip_id}")
async def delete_vip(vip_id: int, request: Request, purge_package: bool = False,
                     authorization: str = Header(None)):
    """Request VIP deletion — APPROVAL-GATED for safety.

    Deleting a *running* (already-applied) VIP does NOT take effect immediately: it is STAGED
    for Apply Management (pending_delete=TRUE + a vip-*-delete version) and the VIP keeps
    running — is_active stays TRUE, agents keep serving it, NOTHING is torn down — until the
    operator APPROVES the deletion. Rejecting it leaves the VIP running, untouched. Only the
    approval flips is_active=FALSE and lets the agents tear keepalived down. So a misclick can
    never tear down a production VIP, and an agent never deletes without an explicit approval.

    A VIP that was NEVER applied (not deployed to any node) is removed immediately — there is
    nothing running to tear down. purge_package opts into uninstalling the keepalived package
    on teardown (default keeps it) and is honoured only once the deletion is approved, and only
    on nodes where WE installed it (the agent's install marker), never an admin's package.
    """
    current_user = await _require(authorization, "delete")
    conn = await get_database_connection()
    try:
        v = await conn.fetchrow(
            "SELECT id, name, applied_snapshot FROM vip_instances WHERE id=$1 AND is_active=TRUE", vip_id)
        if not v:
            raise HTTPException(status_code=404, detail="VIP not found")

        if v["applied_snapshot"] is None:
            # Never deployed to any node — removing it affects nothing, so do it at once.
            await conn.execute(
                "UPDATE vip_instances SET is_active=FALSE, last_config_status='PENDING', "
                "pending_delete=FALSE, purge_on_teardown=$2, updated_at=CURRENT_TIMESTAMP WHERE id=$1",
                vip_id, bool(purge_package))
            await conn.execute(
                "DELETE FROM config_versions WHERE status='PENDING' AND version_name LIKE $1",
                f"vip-{vip_id}-%")
            await log_user_activity(
                user_id=current_user["id"], action="delete", resource_type="vip",
                resource_id=str(vip_id), details={"name": v["name"], "never_applied": True},
                ip_address=_client_ip(request), user_agent=_user_agent(request))
            return {"message": "VIP removed — it was never applied, so no node was affected.",
                    "staged": False}

        # Running VIP → STAGE the deletion for approval. is_active stays TRUE (no teardown yet);
        # the agent keeps serving the VIP until the operator approves in Apply Management.
        await conn.execute(
            "UPDATE vip_instances SET pending_delete=TRUE, purge_on_teardown=$2, "
            "last_config_status='PENDING', updated_at=CURRENT_TIMESTAMP WHERE id=$1",
            vip_id, bool(purge_package))
        await _stage_vip_version(conn, vip_id, "delete", current_user["id"])
        await log_user_activity(
            user_id=current_user["id"], action="delete-requested", resource_type="vip",
            resource_id=str(vip_id), details={"name": v["name"], "purge_package": bool(purge_package)},
            ip_address=_client_ip(request), user_agent=_user_agent(request))
        return {"message": ("Deletion staged for approval — the VIP keeps running until you APPROVE it "
                            "in Apply Management; reject to keep it. Nothing changes on the node until "
                            "you approve."),
                "staged": True, "purge_package": bool(purge_package)}
    finally:
        await close_database_connection(conn)


# ---------------------------------------------------------------------------
# Apply (isolated) + status
# ---------------------------------------------------------------------------
@router.post("/{vip_id}/apply")
async def apply_vip(vip_id: int, request: Request, authorization: str = Header(None)):
    current_user = await _require(authorization, "apply")
    conn = await get_database_connection()
    try:
        v = await conn.fetchrow("SELECT * FROM vip_instances WHERE id=$1 AND is_active=TRUE", vip_id)
        if not v:
            raise HTTPException(status_code=404, detail="VIP not found")
        # APPROVED DELETION: if a deletion was staged for this VIP, approving it here performs the
        # actual delete — flip is_active=FALSE so the agents tear keepalived down on their next
        # poll (honouring purge_on_teardown). Until this moment the VIP kept running untouched, so
        # the teardown happens ONLY after this explicit human approval.
        if v["pending_delete"]:
            async with conn.transaction():
                await conn.execute(
                    "UPDATE vip_instances SET is_active=FALSE, pending_delete=FALSE, "
                    "last_config_status='APPLIED', updated_at=CURRENT_TIMESTAMP WHERE id=$1", vip_id)
            await _transition_vip_versions(conn, vip_id, "APPLIED")
            await log_user_activity(
                user_id=current_user["id"], action="delete", resource_type="vip", resource_id=str(vip_id),
                details={"name": v["name"], "approved_delete": True,
                         "purge_package": bool(v["purge_on_teardown"])},
                ip_address=_client_ip(request), user_agent=_user_agent(request))
            msg = "VIP deletion approved — member nodes will stop keepalived and release the VIP on their next poll"
            if v["purge_on_teardown"]:
                msg += "; the keepalived package will be uninstalled on nodes where we installed it"
            return {"message": msg, "deleted": True}
        members = await conn.fetch("""
            SELECT m.id, m.agent_id, m.network_interface, m.role, m.priority, a.ip_address
            FROM vip_members m LEFT JOIN agents a ON a.id = m.agent_id
            WHERE m.vip_id = $1
        """, vip_id)
        if len(members) < 1:
            raise HTTPException(status_code=400, detail="VIP needs at least 1 member")
        masters = [m for m in members if m["role"] == "MASTER"]
        if len(masters) != 1:
            raise HTTPException(status_code=400, detail="exactly one member must be MASTER")
        if any(m["ip_address"] is None for m in members):
            raise HTTPException(status_code=400,
                                detail="every member must have a reported IP before apply (unicast peers)")
        master_prio = masters[0]["priority"]
        if any(m["role"] == "BACKUP" and m["priority"] >= master_prio for m in members):
            raise HTTPException(status_code=400, detail="MASTER priority must exceed every BACKUP")

        auth_plain = decrypt_vrrp_secret(v["auth_pass_encrypted"]) if v["auth_pass_encrypted"] else None
        # If a secret is set but can't be decrypted (SECRET_KEY/VIP_ENCRYPTION_KEY rotated or
        # drifted between pods), FAIL the apply rather than silently rendering a config with NO
        # VRRP authentication — that would be a silent security downgrade and a guaranteed
        # MASTER/BACKUP auth mismatch with any node still holding the old config (review MED-1).
        if v["auth_pass_encrypted"] and not auth_plain:
            raise HTTPException(status_code=409,
                                detail="VRRP secret could not be decrypted (encryption key changed?) — "
                                       "re-enter the VRRP secret on the VIP, then apply again")
        check_script = build_haproxy_check_script() if v["track_haproxy"] else ""
        member_dicts = [{"role": m["role"], "priority": m["priority"],
                         "network_interface": m["network_interface"],
                         "agent_id": m["agent_id"],
                         "ip_address": str(m["ip_address"])} for m in members]
        vip_dict = {"id": v["id"], "name": v["name"], "virtual_ip": v["virtual_ip"],
                    "prefix_length": v["prefix_length"], "virtual_router_id": v["virtual_router_id"],
                    "advert_int": v["advert_int"], "use_unicast": v["use_unicast"],
                    "track_haproxy": v["track_haproxy"]}

        snapshot_members = []
        async with conn.transaction():
            for m in members:
                this_agent = next(d for d in member_dicts if d["agent_id"] == m["agent_id"])
                peer_ips = [d["ip_address"] for d in member_dicts if d["agent_id"] != m["agent_id"]]
                conf = render_keepalived_conf(vip=vip_dict, members=member_dicts,
                                              this_agent=this_agent, peer_ips=peer_ips,
                                              auth_pass_plain=auth_plain)
                chash = _md5(conf)
                await conn.execute("""
                    UPDATE vip_members
                    SET applied_config_content=$2, applied_config_hash=$3, updated_at=CURRENT_TIMESTAMP
                    WHERE id=$1
                """, m["id"], conf, chash)
                snapshot_members.append({
                    "agent_id": m["agent_id"], "network_interface": m["network_interface"],
                    "role": m["role"], "priority": m["priority"],
                    "applied_config_content": conf, "applied_config_hash": chash})
            # Capture the field-level applied state so a later pending edit can be REJECTED
            # and fully reverted to exactly this state (auth secret stored encrypted, never plain).
            applied_snapshot = {
                "vip": {"name": v["name"], "description": v["description"], "virtual_ip": v["virtual_ip"],
                        "prefix_length": v["prefix_length"], "virtual_router_id": v["virtual_router_id"],
                        "advert_int": v["advert_int"], "use_unicast": v["use_unicast"],
                        "track_haproxy": v["track_haproxy"], "auth_pass_encrypted": v["auth_pass_encrypted"]},
                "members": snapshot_members}
            await conn.execute(
                "UPDATE vip_instances SET last_config_status='APPLIED', "
                "applied_snapshot=$2::jsonb, updated_at=CURRENT_TIMESTAMP WHERE id=$1",
                vip_id, json.dumps(applied_snapshot))

        # Move the standard config_version PENDING → APPLIED (stays is_active=FALSE so it is
        # never served as haproxy.cfg). Keeps the right-panel version in lockstep with the VIP.
        await _transition_vip_versions(conn, vip_id, "APPLIED")
        await log_user_activity(
            user_id=current_user["id"], action="apply", resource_type="vip",
            resource_id=str(vip_id),
            details={"name": v["name"], "virtual_ip": v["virtual_ip"], "members": len(members)},
            ip_address=_client_ip(request), user_agent=_user_agent(request))
        # check_script is rendered but not stored on the vip row; the agent gets it via
        # the delivery endpoint (which rebuilds it). Returned here only for visibility.
        return {"message": "VIP applied — agents will converge on next poll",
                "members_rendered": len(members), "tracks_haproxy": bool(check_script)}
    finally:
        await close_database_connection(conn)


@router.post("/{vip_id}/reject")
async def reject_vip(vip_id: int, request: Request, authorization: str = Header(None)):
    """Discard a VIP's PENDING changes and fully restore the last-APPLIED state — the
    isolated equivalent of the product's reject -> restore-to-previous. Restores both the
    vip_instances fields and the exact member set (with their delivered config snapshots)
    from `applied_snapshot`, so the agents keep running what they already have (no churn).
    A never-applied PENDING VIP (no snapshot) is SOFT-deleted (is_active=FALSE) and its
    staged version marked REJECTED — so the change is reversible from the Rejected tab
    (undo-reject reactivates it). Never touches the global haproxy.cfg apply flow.
    """
    current_user = await _require(authorization, "update")
    conn = await get_database_connection()
    try:
        v = await conn.fetchrow("SELECT * FROM vip_instances WHERE id=$1 AND is_active=TRUE", vip_id)
        if not v:
            raise HTTPException(status_code=404, detail="VIP not found")
        # REJECT A STAGED DELETION: cancel it — the VIP keeps running exactly as before (it was
        # never touched; is_active was never flipped). Clear the delete + purge intent and mark
        # the staged version REJECTED. This is the "nothing happened" path the operator expects.
        if v["pending_delete"]:
            await conn.execute(
                "UPDATE vip_instances SET pending_delete=FALSE, purge_on_teardown=FALSE, "
                "last_config_status='APPLIED', updated_at=CURRENT_TIMESTAMP WHERE id=$1", vip_id)
            await _transition_vip_versions(conn, vip_id, "REJECTED")
            await log_user_activity(
                user_id=current_user["id"], action="reject", resource_type="vip", resource_id=str(vip_id),
                details={"name": v["name"], "delete_cancelled": True},
                ip_address=_client_ip(request), user_agent=_user_agent(request))
            return {"message": "Deletion rejected — the VIP keeps running unchanged."}
        if v["last_config_status"] != "PENDING":
            return {"message": "Nothing to reject — no pending changes"}

        snap_raw = v["applied_snapshot"]
        snap = json.loads(snap_raw) if isinstance(snap_raw, str) else snap_raw
        if not snap:
            # Created but never applied -> reject SOFT-deletes the VIP (is_active=FALSE) and
            # marks its staged version REJECTED. The row + members are kept so undo-reject can
            # reactivate the exact VIP (no orphan). The partial unique indexes free its
            # name/address/VRID for reuse while it's inactive.
            await _transition_vip_versions(conn, vip_id, "REJECTED")
            await conn.execute(
                "UPDATE vip_instances SET is_active=FALSE, last_config_status='PENDING', "
                "updated_at=CURRENT_TIMESTAMP WHERE id=$1", vip_id)
            await log_user_activity(
                user_id=current_user["id"], action="reject", resource_type="vip", resource_id=str(vip_id),
                details={"name": v["name"], "discarded": True},
                ip_address=_client_ip(request), user_agent=_user_agent(request))
            return {"message": "Pending VIP rejected (undo from the Rejected tab to restore it)"}

        sv = snap["vip"]
        sm = snap.get("members", [])
        try:
            async with conn.transaction():
                await conn.execute("""
                    UPDATE vip_instances SET
                        name=$2, description=$3, virtual_ip=$4, prefix_length=$5, virtual_router_id=$6,
                        advert_int=$7, use_unicast=$8, track_haproxy=$9, auth_pass_encrypted=$10,
                        last_config_status='APPLIED', updated_at=CURRENT_TIMESTAMP
                    WHERE id=$1
                """, vip_id, sv["name"], sv.get("description"), sv["virtual_ip"], sv["prefix_length"],
                    sv["virtual_router_id"], sv["advert_int"], sv["use_unicast"], sv["track_haproxy"],
                    sv.get("auth_pass_encrypted"))
                await conn.execute("DELETE FROM vip_members WHERE vip_id=$1", vip_id)
                for m in sm:
                    await conn.execute("""
                        INSERT INTO vip_members (vip_id, agent_id, network_interface, role, priority,
                            applied_config_content, applied_config_hash)
                        VALUES ($1,$2,$3,$4,$5,$6,$7)
                    """, vip_id, m["agent_id"], m["network_interface"], m["role"], m["priority"],
                        m.get("applied_config_content"), m.get("applied_config_hash"))
        except HTTPException:
            raise
        except Exception as ie:  # noqa: BLE001
            if "unique" in str(ie).lower() or "duplicate" in str(ie).lower():
                raise HTTPException(status_code=409,
                                    detail="Cannot restore — the previous address/VRID was taken in the meantime")
            raise
        # Mark the standard config_version REJECTED (history); the VIP is back to APPLIED.
        await _transition_vip_versions(conn, vip_id, "REJECTED")
        await log_user_activity(
            user_id=current_user["id"], action="reject", resource_type="vip", resource_id=str(vip_id),
            details={"name": v["name"], "restored": True},
            ip_address=_client_ip(request), user_agent=_user_agent(request))
        return {"message": "Pending changes rejected — VIP restored to its last applied state"}
    finally:
        await close_database_connection(conn)


@router.get("/{vip_id}/status")
async def vip_status(vip_id: int, authorization: str = Header(None)):
    await _require(authorization, "read")
    conn = await get_database_connection()
    try:
        v = await conn.fetchrow("SELECT id, name, is_active, last_config_status FROM vip_instances WHERE id=$1", vip_id)
        if not v:
            raise HTTPException(status_code=404, detail="VIP not found")
        members = await conn.fetch("""
            SELECT m.agent_id, m.role, m.priority, m.network_interface,
                   m.last_deploy_state, m.last_deploy_message, m.last_deploy_at, m.applied_config_hash,
                   a.name AS agent_name, a.keepalive_state, a.keepalive_ip, a.status AS agent_status,
                   a.capabilities
            FROM vip_members m LEFT JOIN agents a ON a.id = m.agent_id
            WHERE m.vip_id=$1 ORDER BY m.priority DESC
        """, vip_id)
        out = []
        for m in members:
            applied = m["applied_config_hash"]
            deploy = m["last_deploy_state"]
            capable = _capable(m["capabilities"])
            if applied and not deploy:
                converge = "awaiting agent (upgrade may be required)" if not capable else "converging"
            else:
                converge = deploy or "pending"
            out.append({
                "agent_name": m["agent_name"], "role": m["role"], "priority": m["priority"],
                "network_interface": m["network_interface"],
                "agent_status": m["agent_status"], "keepalive_state": m["keepalive_state"],
                "keepalive_ip": m["keepalive_ip"], "keepalived_capable": capable,
                "deploy_state": deploy, "deploy_message": m["last_deploy_message"],
                "deploy_at": m["last_deploy_at"].isoformat() if m["last_deploy_at"] else None,
                "convergence": converge,
            })
        return {"id": v["id"], "name": v["name"], "is_active": v["is_active"],
                "last_config_status": v["last_config_status"], "members": out}
    finally:
        await close_database_connection(conn)


# NOTE: the keepalived config preview/diff is served by the STANDARD config-version diff
# endpoint (cluster.py get_config_version_diff, vip-* branch) via render_vip_config_masked
# above — there is no bespoke VIP preview endpoint, so VIP changes use the product's
# standard "View Change" like every other entity (issue #27 follow-up).


# ---------------------------------------------------------------------------
# v1.10.4 — Adoption of a keepalived setup that already exists on the nodes
# ---------------------------------------------------------------------------
# The HA/VIP page starts empty on a fleet that already runs keepalived, because the flow is
# one-way: VIPs are declared here and pushed to the node, and nothing read what was already
# there. The agent now reports the keepalived.conf it found (read-only) into vip_discoveries;
# these two endpoints list those findings and turn one into a managed VIP.
#
# Adoption REPLACES the operator's file with our render, so it is gated hard: the parser
# reports every directive we cannot reproduce and every value we cannot know, and adoption
# refuses while any remain. See services/keepalived_parser.py for the reasoning.


def _discovery_row_to_api(row) -> dict:
    """Shape a vip_discoveries row for the UI. Never includes the VRRP password: the stored
    config copy is masked and the analysis has the secret replaced by a boolean."""
    analysis = row["analysis"]
    if isinstance(analysis, str):
        try:
            analysis = json.loads(analysis)
        except (json.JSONDecodeError, TypeError):
            analysis = None
    return {
        "agent_id": row["agent_id"],
        "agent_name": row["agent_name"],
        "pool_id": row["pool_id"],
        "pool_name": row["pool_name"],
        "config_path": row["config_path"],
        "config_hash": row["config_hash"],
        "is_managed": row["is_managed"],
        "parse_error": row["parse_error"],
        "adopted_vip_id": row["adopted_vip_id"],
        "reported_at": row["reported_at"].isoformat() if row["reported_at"] else None,
        "config_preview": row["raw_config_masked"],
        "analysis": analysis,
    }


@router.get("/discoveries")
async def list_vip_discoveries(authorization: str = Header(None)):
    """Unmanaged keepalived configs the agents found on their nodes.

    Read-only and safe to poll: this is what the HA/VIP page shows so an existing VIP is
    visible before anyone adopts it.
    """
    await _require(authorization, "read")
    conn = await get_database_connection()
    try:
        try:
            rows = await conn.fetch("""
                SELECT d.*, a.name AS agent_name, a.pool_id, p.name AS pool_name
                FROM vip_discoveries d
                JOIN agents a ON a.id = d.agent_id
                LEFT JOIN haproxy_cluster_pools p ON p.id = a.pool_id
                ORDER BY d.reported_at DESC, d.id DESC
            """)
        except Exception as exc:  # noqa: BLE001 — a missing relation degrades to empty (B-7)
            logger.debug(f"vip_discoveries unavailable: {exc}")
            return {"discoveries": []}
        return {"discoveries": [_discovery_row_to_api(r) for r in rows]}
    finally:
        await close_database_connection(conn)


def _find_candidate(analysis: Optional[dict], instance_name: str) -> Optional[dict]:
    for cand in ((analysis or {}).get("candidates") or []):
        if cand.get("instance_name") == instance_name:
            return cand
    return None


@router.post("/adopt")
async def adopt_vip(payload: dict, request: Request, authorization: str = Header(None)):
    """Turn one discovered vrrp_instance into a managed VIP.

    Body: agent_id, instance_name, name, [description], [prefix_length], [accept_data_loss].

    Refuses while the parser reports blockers. Two of them are resolvable by the operator
    rather than fatal:
      * a missing prefix length can be supplied as `prefix_length` (we never guess a netmask
        for a live VIP);
      * "we would delete this directive" can be accepted with `accept_data_loss: true`, which
        is an explicit choice to lose e.g. a notify hook. Everything else — an unknown VRID, a
        fractional advert_int, an unsupported auth_type — is not a loss but an impossibility,
        and no flag overrides it.

    The VIP is created PENDING like any other, so nothing reaches the node until the operator
    applies it from Apply Management.
    """
    current_user = await _require(authorization, "create")
    agent_id = payload.get("agent_id")
    instance_name = (payload.get("instance_name") or "").strip()
    name = (payload.get("name") or "").strip()
    if not agent_id or not instance_name or not name:
        raise HTTPException(status_code=400, detail="agent_id, instance_name and name are required")

    conn = await get_database_connection()
    try:
        disc = await conn.fetchrow("""
            SELECT d.*, a.name AS agent_name, a.pool_id
            FROM vip_discoveries d JOIN agents a ON a.id = d.agent_id
            WHERE d.agent_id = $1
        """, int(agent_id))
        if not disc:
            raise HTTPException(status_code=404, detail="No discovered keepalived config for that agent")
        if disc["adopted_vip_id"]:
            raise HTTPException(status_code=409, detail="This discovery has already been adopted")
        if not disc["pool_id"]:
            raise HTTPException(status_code=400, detail="The agent is not in a pool; assign it first")
        if disc["parse_error"]:
            raise HTTPException(status_code=422,
                                detail=f"Config could not be parsed: {disc['parse_error']}")

        analysis = disc["analysis"]
        if isinstance(analysis, str):
            analysis = json.loads(analysis)
        cand = _find_candidate(analysis, instance_name)
        if not cand:
            raise HTTPException(status_code=404,
                                detail=f"No vrrp_instance '{instance_name}' in the report")

        vip_fields = dict(cand.get("vip") or {})
        member = dict(cand.get("member") or {})

        # The operator may supply the one value we refuse to guess.
        supplied_prefix = payload.get("prefix_length")
        if vip_fields.get("prefix_length") is None and supplied_prefix is not None:
            try:
                vip_fields["prefix_length"] = int(supplied_prefix)
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail="prefix_length must be an integer")

        # One source of truth for which blockers an operator may resolve (see the docstring on
        # remaining_blockers): a supplied prefix, and an explicit acceptance of directives our
        # renderer would delete. Nothing else is waivable.
        from services.keepalived_parser import remaining_blockers
        blockers = remaining_blockers(
            list(cand.get("blockers") or []),
            prefix_supplied=vip_fields.get("prefix_length") is not None,
            accept_data_loss=bool(payload.get("accept_data_loss")),
        )
        if blockers:
            raise HTTPException(status_code=422, detail={
                "message": "This keepalived config cannot be adopted as-is",
                "blockers": blockers,
            })

        vrid = vip_fields.get("virtual_router_id")
        virtual_ip = vip_fields.get("virtual_ip")
        if vrid is None or not virtual_ip or not member.get("network_interface"):
            raise HTTPException(status_code=422,
                                detail="Incomplete candidate (vrid/address/interface)")

        # Adoption must keep the VRRP identity it found. A different VRID would create a second
        # VRRP domain on the wire, so a collision inside the pool is a hard conflict, never an
        # auto-reallocation the way create_vip does it.
        clash = await conn.fetchrow("""
            SELECT id, name FROM vip_instances
            WHERE pool_id = $1 AND is_active = TRUE AND virtual_router_id = $2
        """, disc["pool_id"], int(vrid))
        if clash:
            raise HTTPException(status_code=409, detail=(
                f"VRID {vrid} is already used by VIP '{clash['name']}' in this pool; the adopted "
                f"config must keep its VRID, so resolve the collision first"))

        async with conn.transaction():
            vip_id = await conn.fetchval("""
                INSERT INTO vip_instances
                  (name, description, pool_id, virtual_ip, prefix_length, virtual_router_id,
                   advert_int, auth_pass_encrypted, use_unicast, track_haproxy,
                   is_active, last_config_status, adopted_at, created_by)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,TRUE,'PENDING',CURRENT_TIMESTAMP,$11)
                RETURNING id
            """, name, payload.get("description") or f"Adopted from {disc['agent_name']}",
                disc["pool_id"], virtual_ip, int(vip_fields["prefix_length"]), int(vrid),
                int(vip_fields.get("advert_int") or 1),
                disc["auth_pass_encrypted"],           # already Fernet-encrypted at ingest
                bool(vip_fields.get("use_unicast")), bool(vip_fields.get("track_haproxy")),
                current_user["id"])
            # The reporting node becomes a member with the role/priority its own file declares,
            # and carries the one-shot takeover authorisation pinned to the hash we analysed.
            await conn.execute("""
                INSERT INTO vip_members
                    (vip_id, agent_id, network_interface, role, priority, takeover_expected_hash)
                VALUES ($1,$2,$3,$4,$5,$6)
            """, vip_id, int(agent_id), member["network_interface"],
                member.get("role") or "BACKUP", int(member.get("priority") or 100),
                disc["config_hash"])
            await conn.execute(
                "UPDATE vip_discoveries SET adopted_vip_id = $2 WHERE agent_id = $1",
                int(agent_id), vip_id)

        await _stage_vip_version(conn, vip_id, "adopt", current_user["id"])
        await log_user_activity(
            user_id=current_user["id"], action="adopt", resource_type="vip",
            resource_id=str(vip_id),
            details={"name": name, "virtual_ip": virtual_ip, "vrid": vrid,
                     "adopted_from_agent": disc["agent_name"],
                     "accepted_data_loss": bool(payload.get("accept_data_loss"))},
            ip_address=_client_ip(request), user_agent=_user_agent(request))

        peers = list(cand.get("peers") or [])
        return {
            "id": vip_id,
            "message": ("VIP adopted (PENDING — review it in Apply Management, then apply to hand "
                        "the node's keepalived.conf over to OpenManager)"),
            # Adoption covers the node that reported. Its peers hold their own keepalived.conf,
            # so they must be added as members (or adopted from their own report) before the VIP
            # renders a complete unicast group.
            "peers_to_add": peers,
        }
    finally:
        await close_database_connection(conn)
