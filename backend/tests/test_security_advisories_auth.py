"""Regression tests for the 2026-07 security advisories.

Covers:
- GHSA-7rhv-c5pc-69r8 (CRITICAL RCE): agent script-template management must
  require the agents.version permission, not merely authentication.
- GHSA-3p5c-m5m4-mjpx (missing auth): agent data-plane endpoints must require a
  valid X-API-Key, and operator/UI endpoints must require a JWT. An anonymous
  caller must never get a 200 with sensitive data.

These are behavioral assertions via FastAPI's TestClient. The auth checks were
deliberately moved ahead of any DB access, so an unauthenticated request is
rejected without needing a database — the same approach as the existing
test_ssl_list_endpoint_auth.py. Accepted rejection statuses are 401/403/422
(never 200-with-data).
"""
import re
import os
import pytest

REJECT = (401, 403, 422)


# --------------------------------------------------------------------------
# GHSA-3p5c: agent data-plane endpoints must reject a missing X-API-Key
# --------------------------------------------------------------------------

def test_agent_config_requires_api_key(client):
    """GET /api/agents/{name}/config leaked the full haproxy.cfg without a key."""
    res = client.get("/api/agents/prod-haproxy-1/config")
    assert res.status_code in REJECT, (
        f"GHSA-3p5c regression: agent config served without X-API-Key ({res.status_code})"
    )


def test_agent_ssl_certificates_requires_api_key(client):
    """GET /api/agents/{name}/ssl-certificates leaked SSL private keys without a key."""
    res = client.get("/api/agents/prod-haproxy-1/ssl-certificates")
    assert res.status_code in REJECT, (
        f"GHSA-3p5c regression: SSL certs (private keys!) served without X-API-Key ({res.status_code})"
    )
    if res.status_code == 200:
        assert "private_key_content" not in res.text


def test_agent_upgrade_status_requires_api_key(client):
    res = client.get("/api/agents/prod-haproxy-1/upgrade-status")
    assert res.status_code in REJECT


def test_agent_pending_requests_requires_api_key(client):
    res = client.get("/api/configuration/agents/prod-haproxy-1/pending-requests")
    assert res.status_code in REJECT


def test_agent_heartbeat_by_name_requires_api_key(client):
    res = client.post("/api/agents/heartbeat", json={"name": "rogue-poc"})
    assert res.status_code in REJECT, (
        f"GHSA-3p5c regression: keyless heartbeat/auto-register accepted ({res.status_code})"
    )


def test_agent_heartbeat_by_id_requires_api_key(client):
    res = client.post("/api/agents/1/heartbeat", json={"name": "spoofed"})
    assert res.status_code in REJECT, (
        f"GHSA-3p5c regression: keyless by-id heartbeat state-spoof accepted ({res.status_code})"
    )


# --------------------------------------------------------------------------
# GHSA-3p5c: operator/UI endpoints must reject a missing JWT
# --------------------------------------------------------------------------

def test_agents_inventory_requires_jwt(client):
    """GET /api/agents (RCE read-back channel) was served without a JWT."""
    res = client.get("/api/agents")
    assert res.status_code in REJECT


@pytest.mark.parametrize("path", ["/api/health/deep", "/api/health/agents", "/api/health/clusters"])
def test_detailed_health_requires_jwt(client, path):
    res = client.get(path)
    assert res.status_code in REJECT, f"{path} served without a JWT ({res.status_code})"


def test_simple_health_stays_public(client):
    """The liveness probe endpoint (/api/health) must remain UNAUTHENTICATED.

    It reports 200 when healthy and 503 when the DB is unreachable (as in this
    no-DB test env); what matters for the k8s probe is that it is never gated
    behind auth (401/403). We only added auth to /api/health/{deep,agents,clusters}.
    """
    res = client.get("/api/health")
    assert res.status_code not in (401, 403), (
        f"Regression: /api/health liveness probe now requires auth ({res.status_code}) — "
        f"this breaks k8s liveness/readiness"
    )


def test_dashboard_stats_requires_jwt(client):
    res = client.get("/api/dashboard-stats/stats?cluster_id=1")
    assert res.status_code in REJECT


def test_ssl_config_versions_requires_jwt(client):
    res = client.get("/api/ssl/certificates/1/config-versions")
    assert res.status_code in REJECT


# --------------------------------------------------------------------------
# GHSA-7rhv (CRITICAL RCE): script-template management
# --------------------------------------------------------------------------

def test_script_template_write_requires_auth(client):
    """Anonymous POST must be rejected outright."""
    res = client.post("/api/agents/script-templates/linux",
                      json={"script_content": "#!/bin/bash\nid", "version": "9.9.9"})
    assert res.status_code in REJECT


def test_script_template_read_requires_auth(client):
    res = client.get("/api/agents/script-templates/linux")
    assert res.status_code in REJECT


def test_script_template_write_enforces_agents_version_permission():
    """Static guarantee: the write handler checks agents.version (not just authN).

    A behavioral 403-for-viewer test would need a seeded DB + a minted viewer JWT;
    instead we assert the permission gate is present in source, mirroring the
    existing audit-style source tests. This is the core RCE fix (GHSA-7rhv).
    """
    src_path = os.path.join(os.path.dirname(__file__), "..", "routers", "agent.py")
    with open(src_path, "r") as f:
        src = f.read()
    # Isolate the save_agent_script_template handler body.
    m = re.search(r"async def save_agent_script_template\(.*?\n(.*?)\n@router\.", src, re.DOTALL)
    assert m, "save_agent_script_template handler not found"
    body = m.group(1)
    assert 'check_user_permission' in body and '"agents", "version"' in body, (
        "GHSA-7rhv regression: script-template WRITE no longer enforces the "
        "agents.version permission — any JWT holder could poison the root install script"
    )
