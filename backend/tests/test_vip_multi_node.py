"""Issue #73 (v1.12.0) — several VIPs on one node, several addresses on one VIP.

Pure tests for the merge of a node's applied single-VIP files, the extra-address rendering
and validation, plus source-level guards for the delivery / ack / adoption / migration
invariants that need a live database to exercise end to end.
"""
from __future__ import annotations

import hashlib
import os
import pathlib
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.vip import MAX_ADDITIONAL_IPS, VIPCreate, VIPUpdate  # noqa: E402
from services import keepalived_config as kc  # noqa: E402
from services.keepalived_parser import (  # noqa: E402
    ANALYSIS_VERSION, analyse_keepalived_conf, parse_keepalived_conf,
)

BACKEND = pathlib.Path(__file__).resolve().parents[1]
AGENT_ROUTER = (BACKEND / "routers" / "agent.py").read_text()
VIP_ROUTER = (BACKEND / "routers" / "vip.py").read_text()
MIGRATIONS = (BACKEND / "database" / "migrations.py").read_text()

NODE = {"role": "MASTER", "priority": 150, "network_interface": "eth0",
        "agent_id": 1, "ip_address": "10.0.0.11"}
PEER = {"role": "BACKUP", "priority": 100, "network_interface": "eth0",
        "agent_id": 2, "ip_address": "10.0.0.12"}


def _vip(vid, ip, vrid, **over):
    base = {"id": vid, "name": f"vip-{vid}", "virtual_ip": ip, "prefix_length": 24,
            "virtual_router_id": vrid, "advert_int": 1, "use_unicast": True,
            "track_haproxy": True}
    base.update(over)
    return base


def _applied(vip, auth="s3cr3t", this=NODE, members=(NODE, PEER)):
    peers = [m["ip_address"] for m in members if m["agent_id"] != this["agent_id"]]
    return kc.render_keepalived_conf(vip=vip, members=list(members), this_agent=this,
                                     peer_ips=peers, auth_pass_plain=auth)


A = _vip(3, "10.0.0.100", 51)
B = _vip(7, "10.0.0.200", 52, track_haproxy=False)


class TestCompose:
    def test_single_vip_is_served_byte_identical(self):
        conf = _applied(A)
        assert kc.compose_node_keepalived_conf([(3, conf)]) == conf

    def test_two_vips_merge_into_one_valid_file(self):
        out = kc.compose_node_keepalived_conf([(3, _applied(A)), (7, _applied(B))])
        assert out.count("global_defs {") == 1
        assert out.startswith(kc.OWNERSHIP_MARKER)
        assert "vrrp_script chk_haproxy_3 {" in out
        assert "vrrp_script chk_haproxy {" not in out
        assert "vrrp_instance VI_3 {" in out and "vrrp_instance VI_7 {" in out
        assert out.index("VI_3") < out.index("VI_7")
        assert "        chk_haproxy_3\n" in out
        parsed = parse_keepalived_conf(out)
        assert [i["instance_name"] for i in parsed["instances"]] == ["VI_3", "VI_7"]
        assert [i["track_scripts"] for i in parsed["instances"]] == [["chk_haproxy_3"], []]

    def test_order_follows_vip_id_not_input_order(self):
        a, b = (3, _applied(A)), (7, _applied(B))
        assert kc.compose_node_keepalived_conf([b, a]) == kc.compose_node_keepalived_conf([a, b])

    def test_each_instance_keeps_its_own_failover_weight(self):
        a2 = _vip(9, "10.0.0.150", 53)
        low_peer = {**PEER, "priority": 50}
        out = kc.compose_node_keepalived_conf([
            (3, _applied(A)), (9, _applied(a2, members=(NODE, low_peer)))])
        assert "weight -51" in out and "weight -101" in out

    def test_braces_in_the_secret_do_not_break_the_merge(self):
        out = kc.compose_node_keepalived_conf([(3, _applied(A, auth="a}b{")),
                                               (7, _applied(B, auth="}x"))])
        assert "auth_pass a}b{" in out and "auth_pass }x" in out
        assert out.count("vrrp_instance") == 2

    @pytest.mark.parametrize("bad", [
        "",
        "global_defs {\n}\n",
        "vrrp_instance VI_3 {\n    state MASTER\n",
        "something else\n",
    ])
    def test_unexpected_snapshot_fails_closed(self, bad):
        with pytest.raises(kc.KeepalivedComposeError):
            kc.compose_node_keepalived_conf([(3, _applied(A)), (7, bad)])

    def test_foreign_block_fails_closed(self):
        tampered = _applied(B) + "virtual_server 10.0.0.1 80 {\n}\n"
        with pytest.raises(kc.KeepalivedComposeError):
            kc.compose_node_keepalived_conf([(3, _applied(A)), (7, tampered)])

    def test_snapshot_of_another_vip_id_fails_closed(self):
        with pytest.raises(kc.KeepalivedComposeError):
            kc.compose_node_keepalived_conf([(3, _applied(A)), (8, _applied(B))])

    def test_nothing_to_compose_raises(self):
        with pytest.raises(kc.KeepalivedComposeError):
            kc.compose_node_keepalived_conf([])


class TestAdditionalAddresses:
    def test_empty_list_renders_byte_identical(self):
        assert _applied({**A, "additional_ips": []}) == _applied(A)

    def test_extras_follow_the_primary_on_the_same_interface(self):
        conf = _applied({**A, "additional_ips": [
            {"address": "10.0.0.101", "prefix_length": 24},
            {"address": "192.168.5.9", "prefix_length": 32}]})
        lines = [l.strip() for l in conf.splitlines()]
        i = lines.index("10.0.0.100/24 dev eth0")
        assert lines[i + 1:i + 3] == ["10.0.0.101/24 dev eth0", "192.168.5.9/32 dev eth0"]

    def test_rendered_extras_are_adopted_back_unchanged(self):
        extras = [{"address": "10.0.0.101", "prefix_length": 25}]
        conf = _applied({**A, "additional_ips": extras})
        cand = analyse_keepalived_conf(conf)["candidates"][0]
        assert cand["adoptable"] is True, cand["blockers"]
        assert cand["vip"]["additional_ips"] == extras


def _members():
    return [{"agent_id": 1, "network_interface": "eth0", "role": "MASTER", "priority": 150}]


class TestModels:
    def test_default_is_empty(self):
        v = VIPCreate(name="v", pool_id=1, virtual_ip="10.0.0.100", members=_members())
        assert v.additional_ips == []

    def test_address_is_normalised_and_prefix_defaults(self):
        v = VIPCreate(name="v", pool_id=1, virtual_ip="10.0.0.100", members=_members(),
                      additional_ips=[{"address": " 10.0.0.101 "}])
        assert v.additional_ips[0].model_dump() == {"address": "10.0.0.101", "prefix_length": 24}

    @pytest.mark.parametrize("extras", [
        [{"address": "10.0.0.100"}],
        [{"address": "10.0.0.101"}, {"address": "10.0.0.101"}],
        [{"address": "fd00::1"}],
        [{"address": "nope"}],
        [{"address": "10.0.0.101", "prefix_length": 33}],
        [{"address": f"10.0.1.{i}"} for i in range(1, MAX_ADDITIONAL_IPS + 2)],
    ])
    def test_invalid_extras_are_rejected(self, extras):
        with pytest.raises(ValueError):
            VIPCreate(name="v", pool_id=1, virtual_ip="10.0.0.100", members=_members(),
                      additional_ips=extras)

    def test_update_omitted_keeps_and_empty_clears(self):
        assert VIPUpdate().additional_ips is None
        assert VIPUpdate(additional_ips=[]).additional_ips == []


class TestDeliveryAndAckGuards:
    def test_failures_answer_with_statuses_the_agent_ignores(self):
        assert '"status": "compose_error"' in AGENT_ROUTER
        generic = AGENT_ROUTER.split("keepalived-config delivery failed", 1)[1][:600]
        assert '"status": "unavailable"' in generic
        assert "not_configured" not in generic.split("return", 1)[1].split("}", 1)[0]

    def test_merged_delivery_hash_is_md5_of_the_composed_text(self):
        assert 'hashlib.md5(composed.encode("utf-8")).hexdigest()' in AGENT_ROUTER
        out = kc.compose_node_keepalived_conf([(3, _applied(A)), (7, _applied(B))])
        assert len(hashlib.md5(out.encode("utf-8")).hexdigest()) == 32

    def test_only_applied_snapshots_are_merged(self):
        q = AGENT_ROUTER.split("async def _node_applied_vips", 1)[1].split("async def ", 1)[0]
        assert "v.is_active = TRUE" in q
        assert "m.applied_config_content IS NOT NULL" in q

    def test_ack_failure_to_merge_is_not_a_500(self):
        ack = AGENT_ROUTER.split("acks the merged file once", 1)[1][:1200]
        assert "except Exception" in ack and "composed_hash = None" in ack

    def test_discovery_known_asks_old_analyses_to_be_reported_again(self):
        assert "vd.analysis_version >= $2" in AGENT_ROUTER
        assert ANALYSIS_VERSION >= 1
        assert analyse_keepalived_conf(_applied(A))["analysis_version"] == ANALYSIS_VERSION


class TestAdoptionGuards:
    def test_apply_refuses_an_inflight_adoption_of_a_multi_instance_file(self):
        apply = VIP_ROUTER.split("async def apply_vip", 1)[1].split("\nasync def ", 1)[0]
        assert "d.config_hash = m.takeover_expected_hash" in apply
        assert "(d.analysis->>'instance_count')::int, 0) > 1" in apply
        assert "status_code=409" in apply

    def test_old_analyses_get_the_blocker_in_the_list_and_on_adopt(self):
        assert VIP_ROUTER.count("multi_instance_blocker(") >= 2
        row_api = VIP_ROUTER.split("def _discovery_row_to_api", 1)[1].split("\ndef ", 1)[0]
        assert 'cand["adoptable"] = False' in row_api

    def test_address_writes_take_the_address_lock(self):
        for fn in ("create_vip", "update_vip", "adopt_vip"):
            body = VIP_ROUTER.split(f"async def {fn}", 1)[1].split("\nasync def ", 1)[0]
            assert "_lock_and_check_addresses(" in body, fn


class TestDeltaMigration:
    def test_versions(self):
        assert "SCHEMA_VERSION = 13" in MIGRATIONS
        assert "_DELTA_BASE_VERSION = 12" in MIGRATIONS
        assert "return [(13, ensure_vip_multi_address_columns)]" in MIGRATIONS

    def test_full_sequence_also_creates_the_columns(self):
        inner = MIGRATIONS.split("async def _run_all_migrations_inner", 1)[1].split("\nasync def ", 1)[0]
        assert inner.index("await ensure_vip_tables()") < inner.index(
            "await ensure_vip_multi_address_columns()")

    def test_delta_path_does_not_reseed_roles(self):
        run = MIGRATIONS.split("async def run_all_migrations", 1)[1].split("\nasync def ", 1)[0]
        delta = run.split("applied_version >= _DELTA_BASE_VERSION", 1)[1].split("else:", 1)[0]
        assert "_delta_steps()" in delta
        assert "_run_all_migrations_inner" not in delta
        assert "update_system_roles" not in delta

    def test_columns_are_additive_with_safe_defaults(self):
        body = MIGRATIONS.split("async def ensure_vip_multi_address_columns", 1)[1].split(
            "\nasync def ", 1)[0].replace('"\n            "', "")
        assert "ADD COLUMN IF NOT EXISTS additional_ips JSONB NOT NULL DEFAULT '[]'::jsonb" in body
        assert "ADD COLUMN IF NOT EXISTS analysis_version SMALLINT NOT NULL DEFAULT 0" in body
