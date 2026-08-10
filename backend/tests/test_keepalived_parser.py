"""Issue #27 follow-up (v1.10.4) — unit tests for parsing an EXISTING keepalived.conf so a
hand-maintained VIP can be adopted.

Pure-function tests; no DB, no network. The parser exists because the heartbeat carries only
the VIP address and a best-effort MASTER/BACKUP, while rendering a node's config needs eleven
fields — and because adoption REPLACES the operator's file, so anything our renderer cannot
reproduce has to be reported as a blocker rather than silently dropped.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-keepalived-parser-tests")

from services import keepalived_config as kc  # noqa: E402
from services.keepalived_parser import (  # noqa: E402
    KeepalivedParseError, analyse_keepalived_conf, build_adoption_candidate,
    parse_keepalived_conf,
)


# A realistic hand-maintained config: two nodes, unicast VRRP, password auth, HAProxy check.
HANDWRITTEN = """\
! Configuration File for keepalived
global_defs {
    enable_script_security
    script_user root
}

vrrp_script chk_haproxy {
    script "/etc/keepalived/check_haproxy.sh"
    interval 2
    weight -21
}

vrrp_instance VI_1 {
    state MASTER
    interface eth0        # public leg
    virtual_router_id 51
    priority 150
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass s3cr3t
    }
    unicast_src_ip 10.0.0.11
    unicast_peer {
        10.0.0.12
    }
    virtual_ipaddress {
        10.0.0.100/24 dev eth0
    }
    track_script {
        chk_haproxy
    }
}
"""


def _only_candidate(text):
    parsed = parse_keepalived_conf(text)
    assert len(parsed["instances"]) == 1
    return build_adoption_candidate(parsed, parsed["instances"][0])


def test_parses_a_handwritten_config_into_model_fields():
    cand = _only_candidate(HANDWRITTEN)
    assert cand["adoptable"] is True, cand["blockers"]
    assert cand["blockers"] == []
    assert cand["vip"] == {
        "virtual_ip": "10.0.0.100",
        "prefix_length": 24,
        "virtual_router_id": 51,
        "advert_int": 1,
        "use_unicast": True,
        "track_haproxy": True,
        "auth_pass": "s3cr3t",
    }
    assert cand["member"] == {"network_interface": "eth0", "role": "MASTER", "priority": 150}
    assert cand["peers"] == ["10.0.0.12"] and cand["unicast_src_ip"] == "10.0.0.11"
    assert cand["defaulted"] == []          # every value came from the file, nothing assumed


def test_comment_and_layout_variants():
    # `!` and `#` both start comments; a block may open and close on one line; a quoted
    # script path keeps its spaces. None of this may change the parse.
    text = """\
#!/not/a/shebang — this whole line is a comment
vrrp_script chk { script "/opt/my scripts/chk.sh" }
vrrp_instance VI_1 { state BACKUP
    interface eth1   ! trailing bang comment
    virtual_router_id 7
    priority 90
    virtual_ipaddress { 192.168.5.9/32 dev eth1 }
}
"""
    parsed = parse_keepalived_conf(text)
    assert parsed["scripts"]["chk"]["script"] == "/opt/my scripts/chk.sh"
    inst = parsed["instances"][0]
    assert inst["state"] == "BACKUP" and inst["interface"] == "eth1"
    assert inst["virtual_router_id"] == 7 and inst["priority"] == 90
    assert inst["virtual_ips"] == [
        {"address": "192.168.5.9", "prefix_length": 32, "dev": "eth1", "extra": []}
    ]


def test_documented_defaults_are_applied_and_flagged():
    # keepalived's own defaults for absent directives. Applying them re-renders the same
    # behaviour, so they are allowed — but the UI must be able to say they were assumed.
    text = """\
vrrp_instance VI_1 {
    interface eth0
    virtual_router_id 12
    virtual_ipaddress { 10.1.1.5/24 dev eth0 }
}
"""
    cand = _only_candidate(text)
    assert cand["adoptable"] is True, cand["blockers"]
    assert cand["member"]["role"] == "BACKUP" and cand["member"]["priority"] == 100
    assert cand["vip"]["advert_int"] == 1
    assert sorted(cand["defaulted"]) == ["advert_int", "priority", "state"]
    # No authentication block and no track_script — both legal, both faithfully represented.
    assert cand["vip"]["auth_pass"] is None and cand["vip"]["track_haproxy"] is False
    assert cand["vip"]["use_unicast"] is False


def _blockers_for(text):
    return " | ".join(_only_candidate(text)["blockers"])


def test_directives_we_cannot_render_block_adoption():
    # THE central safety property: adoption overwrites the file, so a failover hook we do not
    # render would be destroyed. It must stop the flow, not warn.
    text = HANDWRITTEN.replace(
        "    track_script {", '    notify_master "/usr/local/bin/promote.sh"\n    track_script {')
    blockers = _blockers_for(text)
    assert "notify_master" in blockers and "would delete it" in blockers
    assert _only_candidate(text)["adoptable"] is False


def test_multiple_addresses_in_one_instance_block_adoption():
    text = HANDWRITTEN.replace("        10.0.0.100/24 dev eth0",
                               "        10.0.0.100/24 dev eth0\n        10.0.0.101/24 dev eth0")
    blockers = _blockers_for(text)
    assert "2 addresses" in blockers and "10.0.0.101" in blockers


def test_missing_vrid_blocks_adoption_with_the_split_brain_reason():
    text = HANDWRITTEN.replace("    virtual_router_id 51\n", "")
    blockers = _blockers_for(text)
    assert "no virtual_router_id" in blockers and "separate VRRP domains" in blockers


def test_missing_prefix_blocks_adoption():
    # Our renderer always writes an explicit prefix; guessing one would change the netmask of a
    # live VIP, so the operator has to state it.
    text = HANDWRITTEN.replace("10.0.0.100/24 dev eth0", "10.0.0.100 dev eth0")
    blockers = _blockers_for(text)
    assert "no explicit prefix length" in blockers


def test_address_on_a_different_dev_blocks_adoption():
    text = HANDWRITTEN.replace("10.0.0.100/24 dev eth0", "10.0.0.100/24 dev eth1")
    blockers = _blockers_for(text)
    assert "dev eth1" in blockers and "interface eth0" in blockers


def test_foreign_track_script_blocks_adoption():
    text = HANDWRITTEN.replace("        chk_haproxy", "        chk_custom")
    blockers = _blockers_for(text)
    assert "chk_custom" in blockers and "replaced by OpenManager" in blockers


def test_unsupported_auth_type_blocks_adoption():
    text = HANDWRITTEN.replace("auth_type PASS", "auth_type AH")
    assert "auth_type AH" in _blockers_for(text)


def test_fractional_advert_int_blocks_adoption():
    # Rounding 0.5s to 1s changes VRRP timing, so adopt-and-alter is not acceptable.
    text = HANDWRITTEN.replace("advert_int 1", "advert_int 0.5")
    blockers = _blockers_for(text)
    assert "advert_int 0.5" in blockers and "fractional" in blockers


def test_half_configured_unicast_blocks_adoption():
    text = HANDWRITTEN.replace("    unicast_peer {\n        10.0.0.12\n    }\n", "")
    assert "unicast_src_ip without unicast_peer" in _blockers_for(text)


def test_sync_group_and_lvs_sections_block_adoption():
    text = HANDWRITTEN + """
vrrp_sync_group VG1 {
    group {
        VI_1
    }
}
virtual_server 10.0.0.100 80 {
    lb_algo rr
}
"""
    parsed = parse_keepalived_conf(text)
    assert [g["name"] for g in parsed["sync_groups"]] == ["VG1"]
    directives = " ".join(d["directive"] for d in parsed["unsupported"])
    assert "vrrp_sync_group VG1" in directives and "virtual_server" in directives
    # Both are top-level, so EVERY candidate in the file is blocked — a sync group changes
    # failover semantics for the instances it groups.
    cand = build_adoption_candidate(parsed, parsed["instances"][0])
    assert cand["adoptable"] is False


def test_extra_global_defs_are_reported_as_losses():
    text = HANDWRITTEN.replace("    script_user root",
                               "    script_user root\n    router_id LVS_DEVEL")
    parsed = parse_keepalived_conf(text)
    directives = " ".join(d["directive"] for d in parsed["unsupported"])
    assert "global_defs/router_id LVS_DEVEL" in directives
    assert parsed["global_defs"]["router_id"] == "LVS_DEVEL"


def test_multiple_instances_yield_one_candidate_each():
    text = HANDWRITTEN + """
vrrp_instance VI_2 {
    state BACKUP
    interface eth0
    virtual_router_id 52
    priority 100
    advert_int 1
    virtual_ipaddress { 10.0.0.200/24 dev eth0 }
}
"""
    analysed = analyse_keepalived_conf(text)
    assert analysed["instance_count"] == 2
    names = [c["instance_name"] for c in analysed["candidates"]]
    assert names == ["VI_1", "VI_2"]
    assert [c["vip"]["virtual_ip"] for c in analysed["candidates"]] == ["10.0.0.100", "10.0.0.200"]
    assert all(c["adoptable"] for c in analysed["candidates"])


def test_unbalanced_braces_raise():
    for bad in ("vrrp_instance VI_1 {\n    state MASTER\n", "}\n"):
        raised = False
        try:
            parse_keepalived_conf(bad)
        except KeepalivedParseError:
            raised = True
        assert raised, f"should have raised for {bad!r}"


def test_our_own_render_round_trips_with_zero_blockers():
    """The invariant that keeps the parser honest: a config WE generated must parse back into
    the same model with nothing unsupported. If a future change to render_keepalived_conf emits
    a directive the parser does not know, this fails — instead of adoption silently reporting
    that OpenManager's own output is unadoptable."""
    vip = {"id": 3, "name": "web-vip", "virtual_ip": "10.0.0.100", "prefix_length": 24,
           "virtual_router_id": 51, "advert_int": 1, "use_unicast": True, "track_haproxy": True}
    members = [{"role": "MASTER", "priority": 150, "network_interface": "eth0",
                "agent_id": 1, "ip_address": "10.0.0.11"},
               {"role": "BACKUP", "priority": 100, "network_interface": "eth0",
                "agent_id": 2, "ip_address": "10.0.0.12"}]
    rendered = kc.render_keepalived_conf(
        vip=vip, members=members, this_agent=members[0],
        peer_ips=["10.0.0.12"], auth_pass_plain="s3cr3t")

    cand = _only_candidate(rendered)
    assert cand["adoptable"] is True, cand["blockers"]
    assert cand["vip"]["virtual_ip"] == vip["virtual_ip"]
    assert cand["vip"]["prefix_length"] == vip["prefix_length"]
    assert cand["vip"]["virtual_router_id"] == vip["virtual_router_id"]
    assert cand["vip"]["track_haproxy"] is True and cand["vip"]["use_unicast"] is True
    assert cand["member"] == {"network_interface": "eth0", "role": "MASTER", "priority": 150}
    assert cand["vip"]["auth_pass"] == "s3cr3t"

    # And the same for the no-auth / multicast / untracked shape, which renders fewer blocks.
    plain = kc.render_keepalived_conf(
        vip={**vip, "use_unicast": False, "track_haproxy": False},
        members=members, this_agent=members[1], peer_ips=[], auth_pass_plain=None)
    cand2 = _only_candidate(plain)
    assert cand2["adoptable"] is True, cand2["blockers"]
    assert cand2["vip"]["use_unicast"] is False and cand2["vip"]["track_haproxy"] is False
    assert cand2["vip"]["auth_pass"] is None


# --- v1.10.4 adoption gate: which blockers an operator may resolve --------------------------


def test_only_prefix_and_data_loss_are_waivable():
    from services.keepalived_parser import remaining_blockers

    loss = "line 9: `notify_master \"/x.sh\"` — OpenManager's renderer cannot reproduce this, so adopting would delete it"
    prefix = "`10.0.0.5` has no explicit prefix length; state it during adoption so the netmask cannot change on takeover"
    hard_vrid = "no virtual_router_id — it cannot be guessed: a wrong VRID puts the nodes in separate VRRP domains"
    hard_auth = "auth_type AH is not supported (only PASS is rendered)"
    all_four = [loss, prefix, hard_vrid, hard_auth]

    # Nothing waived: everything survives.
    assert remaining_blockers(all_four) == all_four
    # A supplied prefix resolves ONLY the prefix blocker.
    assert remaining_blockers(all_four, prefix_supplied=True) == [loss, hard_vrid, hard_auth]
    # Accepting data loss resolves ONLY the loss blocker.
    assert remaining_blockers(all_four, accept_data_loss=True) == [prefix, hard_vrid, hard_auth]
    # Both together still cannot wave through an impossibility — this is the property that stops
    # a UI flag from destroying a VIP whose VRID or auth_type we could not reproduce.
    assert remaining_blockers(all_four, prefix_supplied=True, accept_data_loss=True) == \
        [hard_vrid, hard_auth]
    # And an adoptable candidate stays adoptable.
    assert remaining_blockers([]) == []


def test_waiver_markers_match_the_messages_the_parser_actually_emits():
    # The gate matches on substrings of the blocker prose, so a reworded message would silently
    # stop being waivable. Pin both directions against real parser output.
    from services.keepalived_parser import remaining_blockers

    no_prefix = HANDWRITTEN.replace("10.0.0.100/24 dev eth0", "10.0.0.100 dev eth0")
    blockers = _only_candidate(no_prefix)["blockers"]
    assert blockers, "expected a prefix blocker"
    assert remaining_blockers(blockers, prefix_supplied=True) == []

    with_hook = HANDWRITTEN.replace(
        "    track_script {", '    notify_master "/usr/local/bin/promote.sh"\n    track_script {')
    blockers = _only_candidate(with_hook)["blockers"]
    assert blockers, "expected a data-loss blocker"
    assert remaining_blockers(blockers, accept_data_loss=True) == []


def test_auth_pass_masking_leaves_no_trace_of_the_secret():
    # The discovered config is stored and served to the UI, so the ingest endpoint masks the VRRP
    # password. Reuse the router's own regex so the test breaks if it is loosened.
    from routers.agent import _AUTH_PASS_MASK_RE

    secret = "s3cr3t with spaces"
    text = HANDWRITTEN.replace("auth_pass s3cr3t", f"auth_pass {secret}")
    masked = _AUTH_PASS_MASK_RE.sub(r"\1********", text)
    assert secret not in masked and "s3cr3t" not in masked
    assert "auth_pass ********" in masked
    # Everything else survives, so the preview is still useful.
    assert "virtual_router_id 51" in masked and "10.0.0.100/24 dev eth0" in masked
