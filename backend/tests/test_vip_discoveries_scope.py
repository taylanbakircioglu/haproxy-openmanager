"""
v1.10.6 — GET /api/vip/discoveries resolves to its own handler and honours cluster_id.

Two defects, one endpoint, found in that order on a live fleet:

1. The route was declared after `GET /{vip_id}`, so FastAPI matched it there and answered
   422 ("discoveries" is not an int) before the handler ran. The static declaration-order
   guard lives in test_router_path_shadowing.py; this file pins the observable behaviour,
   because a 422 is what the browser actually saw.

2. Once reachable, it returned every discovery in the fleet regardless of the cluster
   selected in the header, so a multi-cluster install saw one undifferentiated list. The
   endpoint now takes the same optional `cluster_id` the VIP list takes.

The auth tests here deliberately assert `!= 422`: the repo's generic endpoint-auth tests
accept 401/403/422 together, which is precisely why defect 1 slipped through them.
"""
import pathlib
import re

import pytest

VIP_ROUTER = pathlib.Path(__file__).resolve().parents[1] / "routers" / "vip.py"


# ----------------------------------------------------------------------------
# 1. The route reaches its own handler (defect 1)
# ----------------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/api/vip/discoveries",
    "/api/vip/discoveries?cluster_id=7",
])
def test_discoveries_route_is_not_captured_by_the_vip_id_route(client, path):
    res = client.get(path)
    assert res.status_code != 422, (
        f"GET {path} returned 422 — the request was routed into the get-one-VIP handler, "
        f"which parses the path segment as an int. Declaration order regressed. "
        f"Body: {res.text[:200]}"
    )
    assert res.status_code in (401, 403), (
        f"GET {path} without a token should be refused by the vip.read gate, got "
        f"{res.status_code}. Body: {res.text[:200]}"
    )


def test_get_one_vip_still_parses_a_numeric_id(client):
    """Moving /discoveries above /{vip_id} must not shadow the numeric route itself."""
    res = client.get("/api/vip/12")
    assert res.status_code in (401, 403), res.text[:200]


# ----------------------------------------------------------------------------
# 2. cluster_id is accepted and actually scopes the query (defect 2)
# ----------------------------------------------------------------------------

def test_handler_accepts_cluster_id():
    from routers.vip import list_vip_discoveries
    import inspect

    params = inspect.signature(list_vip_discoveries).parameters
    assert "cluster_id" in params, (
        "list_vip_discoveries no longer takes cluster_id; the HA/VIP page would show every "
        "cluster's nodes at once again"
    )
    assert params["cluster_id"].default is None, (
        "cluster_id must stay optional — omitting it returns the whole fleet, which is what "
        "a caller that predates the parameter expects"
    )


def test_discovery_query_scopes_by_the_cluster_pool():
    """The filter must resolve cluster -> pool the same way the VIP list does, and must be a
    no-op when the parameter is absent."""
    source = VIP_ROUTER.read_text()
    start = source.index("async def list_vip_discoveries")
    end = source.index("def _find_candidate", start)
    body = source[start:end]

    assert "FROM vip_discoveries" in body, "the discovery query moved; re-point this test"
    assert re.search(r"a\.pool_id\s*=\s*\(\s*SELECT\s+pool_id\s+FROM\s+haproxy_clusters", body), (
        "the cluster filter must map cluster -> pool via haproxy_clusters, matching list_vips"
    )
    assert "IS NULL" in body, (
        "the filter must short-circuit when cluster_id is absent, so an unscoped call still "
        "returns the whole fleet"
    )
