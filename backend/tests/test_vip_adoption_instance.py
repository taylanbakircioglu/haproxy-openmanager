"""
v1.10.8 — the four adoption defects found while testing v1.10.4 on a live HA pair.

B1  The Apply Management "View Change" diff did not recognise the `adopt` action, so the
    version fell through to the generic HAProxy diff and rendered the cluster's whole
    haproxy.cfg as removed.

B2  `vip_discoveries.adopted_vip_id` is write-once and nothing clears it, while a VIP is only
    ever SOFT-deleted — so `ON DELETE SET NULL` never fires. Rejecting an adoption therefore
    hid the node from the panel permanently: the VIP was gone from the VIP list too, and the
    agent does not re-report a file whose hash has not changed. Adoptability is now derived
    from whether the linked VIP is still active.

B3  Adoption took only the node that was clicked. On a two-node pair that meant: adopting the
    BACKUP produced a VIP whose apply fails ("exactly one member must be MASTER"), adopting the
    MASTER left the peer unmanaged, and adopting the peer afterwards hit the VRID-collision
    guard with 409. The pair could never be completed from the panel.

B4  Worst of the four. `render_keepalived_conf` emits the unicast block only when it has peer
    addresses, so a single-member adoption of a UNICAST instance silently dropped it and
    keepalived fell back to multicast on that node while its peer stayed unicast — they stop
    seeing each other and BOTH claim the VIP.

B3 and B4 share one root and one fix: adoption now resolves the whole VRRP instance, keyed on
(virtual_router_id, virtual address) exactly as keepalived groups nodes.

These are source-level and unit tests: the adoption endpoint needs a live database, so the
behaviour that can be exercised without one is pinned here, and the SQL/flow invariants are
pinned by reading the module.
"""
import pathlib
import re

import pytest

BACKEND = pathlib.Path(__file__).resolve().parents[1]
VIP_ROUTER = (BACKEND / "routers" / "vip.py").read_text()
CLUSTER_ROUTER = (BACKEND / "routers" / "cluster.py").read_text()
RENDERER = (BACKEND / "services" / "keepalived_config.py").read_text()


def _adopt_body() -> str:
    start = VIP_ROUTER.index("async def adopt_vip")
    return VIP_ROUTER[start:]


# ----------------------------------------------------------------------------
# B1 — the diff must recognise `adopt`
# ----------------------------------------------------------------------------

def test_view_change_diff_recognises_the_adopt_action():
    match = re.search(r"vip_match = re\.search\(r'vip-\(\\d\+\)-\(([^)]+)\)'", CLUSTER_ROUTER)
    assert match, "the vip version regex moved; re-point this test"
    actions = set(match.group(1).split("|"))
    assert actions == {"create", "update", "delete", "adopt"}, (
        f"the View Change diff recognises {sorted(actions)}. An action missing here does not "
        f"degrade gracefully: the version falls through to the generic HAProxy diff and shows "
        f"the cluster's whole haproxy.cfg as removed."
    )


def test_every_staged_vip_action_is_covered_by_the_diff_regex():
    """Whatever _stage_vip_version can be called with must be in that alternation."""
    staged = set(re.findall(r'_stage_vip_version\(conn, vip_id, "(\w+)"', VIP_ROUTER))
    match = re.search(r"vip_match = re\.search\(r'vip-\(\\d\+\)-\(([^)]+)\)'", CLUSTER_ROUTER)
    recognised = set(match.group(1).split("|"))
    assert staged, "no _stage_vip_version call sites found; re-point this test"
    assert staged <= recognised, (
        f"staged action(s) {sorted(staged - recognised)} are not recognised by the View Change "
        f"diff regex {sorted(recognised)}"
    )


# ----------------------------------------------------------------------------
# B2 — adoptability follows the VIP's liveness, not the bare link
# ----------------------------------------------------------------------------

def test_discovery_api_exposes_whether_the_adopted_vip_still_stands():
    assert "adopted_vip_active" in VIP_ROUTER, (
        "the discovery payload no longer reports whether the adopted VIP is still active; the "
        "UI would go back to hiding a rejected adoption forever"
    )
    assert re.search(r"LEFT JOIN vip_instances av ON av\.id = d\.adopted_vip_id", VIP_ROUTER), (
        "the discovery query must join the linked VIP to report its is_active"
    )


def test_adopt_refuses_only_while_the_previous_adoption_still_stands():
    body = _adopt_body()
    assert re.search(r'if disc\["adopted_vip_id"\] and disc\["adopted_vip_active"\]', body), (
        "adopt must refuse only when the linked VIP is still ACTIVE — refusing on the bare link "
        "makes a rejected adoption impossible to retry, because nothing ever clears the column"
    )


def test_nothing_clears_adopted_vip_id_so_the_derivation_is_load_bearing():
    """If a future change starts clearing the column, this test should be revisited rather than
    silently left in place — the derived flag is what makes reject recoverable today."""
    writes = re.findall(r"UPDATE vip_discoveries SET adopted_vip_id = (\S+)", VIP_ROUTER)
    assert writes, "no adopted_vip_id write found; re-point this test"
    assert all(w != "NULL" for w in writes), (
        "adopted_vip_id is now cleared somewhere — re-check that the adopted_vip_active "
        "derivation and this test still describe reality"
    )


# ----------------------------------------------------------------------------
# B3 — the whole VRRP instance is adopted, not one node
# ----------------------------------------------------------------------------

def test_participants_are_resolved_by_vrid_and_address():
    assert "async def _collect_instance_participants" in VIP_ROUTER
    start = VIP_ROUTER.index("async def _collect_instance_participants")
    end = VIP_ROUTER.index("@router.post(\"/adopt\")", start)
    body = VIP_ROUTER[start:end]
    assert 'v.get("virtual_router_id") == vrid' in body and 'v.get("virtual_ip") == virtual_ip' in body, (
        "instance identity must be (VRID, address) — the same key keepalived uses to decide two "
        "nodes are one VRRP group"
    )
    assert 'if r["parse_error"]' in body, "a node whose config failed to parse must not become a member"
    assert 'r["adopted_vip_id"] and r["adopted_vip_active"]' in body, (
        "a node already held by a STANDING VIP must not be pulled into a second one"
    )


def test_adopt_inserts_one_member_per_participant():
    body = _adopt_body()
    insert = body.index("INSERT INTO vip_members")
    preceding = body[:insert]
    assert "for p in participants:" in preceding, (
        "members must be inserted in a loop over the resolved participants; a single insert is "
        "the half-adoption bug"
    )
    assert 'p["config_hash"]' in body[insert:insert + 800], (
        "each member must carry ITS OWN takeover hash — the one-shot takeover guard is per node"
    )


def test_adopt_requires_exactly_one_master_across_the_instance():
    body = _adopt_body()
    assert 'roles.count("MASTER") != 1' in body, (
        "adoption must reject an instance that does not have exactly one MASTER, instead of "
        "letting apply fail later with 'exactly one member must be MASTER'"
    )


def test_adopt_enforces_one_active_vip_per_agent():
    body = _adopt_body()
    assert "already a member of VIP" in body, (
        "adoption must enforce the one-active-VIP-per-agent rule that create/update enforce via "
        "_validate_members_against_pool; a second membership never converges"
    )


# ----------------------------------------------------------------------------
# B4 — a unicast instance can never be half-adopted
# ----------------------------------------------------------------------------

def test_renderer_only_emits_unicast_when_it_has_peers():
    """The property that makes B4 dangerous. Pinned so the guard below keeps its reason."""
    assert re.search(r"if use_unicast and peer_ips:", RENDERER), (
        "the renderer no longer gates the unicast block on having peers; re-derive whether the "
        "adoption guard is still needed"
    )


def test_adopt_refuses_a_unicast_peer_that_is_not_being_adopted():
    body = _adopt_body()
    assert "declared_peers" in body and "member_ips" in body, (
        "adoption must verify every declared unicast peer is among the nodes being adopted"
    )
    assert "fall back to multicast" in body, (
        "the refusal must explain the consequence — silently dropping a peer puts both nodes in "
        "MASTER state on the same address"
    )


def test_adopt_requires_reported_ips_before_trusting_the_peer_check():
    body = _adopt_body()
    assert "have not reported an IP address yet" in body, (
        "the unicast peer check compares against member IPs, so a member without a reported IP "
        "must block the check rather than silently pass it"
    )


# ----------------------------------------------------------------------------
# Backward compatibility
# ----------------------------------------------------------------------------

@pytest.mark.parametrize("guard", [
    "version_name NOT LIKE 'vip-%'",     # bulk apply/reject still skip VIP versions
])
def test_vip_versions_stay_excluded_from_the_haproxy_apply_flow(guard):
    assert guard in CLUSTER_ROUTER, (
        "vip-* versions must stay out of the HAProxy apply/reject sweep; they are owned by the "
        "VIP endpoints and are never served as haproxy.cfg"
    )


def test_vip_version_transition_matches_any_action():
    """_transition_vip_versions must key on the VIP id alone, or a new action's PENDING row
    would be stranded in Apply Management after apply/reject."""
    assert 'f"vip-{vip_id}-%"' in VIP_ROUTER, (
        "the PENDING -> APPLIED/REJECTED transition must match every action for the VIP"
    )
