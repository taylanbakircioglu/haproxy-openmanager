"""Issue #31 — agent heartbeat JSON sanitizer.

A self-hosted agent builds its heartbeat JSON as text in bash. When a collected value is empty,
the payload can contain a structurally-invalid comma that broke the heartbeat with
`HTTP 400 Invalid JSON: Expecting property name enclosed in double quotes`. The backend now
repairs that pattern in `_sanitize_agent_json` so an already-deployed agent recovers without a
re-install. These tests pin that behaviour and prove the repair never corrupts a healthy payload.
"""
import json

from routers.agent import _sanitize_agent_json


def _assert_parses(raw: str) -> dict:
    out, _ = _sanitize_agent_json(raw)
    return json.loads(out)  # raises if the repair did not produce valid JSON


def test_reporter_empty_system_info_bare_comma():
    # The exact shape the reporter hit: an empty $system_info collapses '    $system_info,' to a
    # bare comma between two members -> '"version": "x",\n    ,\n    "haproxy_status": ...'.
    raw = (
        '{\n'
        '    "name": "test",\n'
        '    "hostname": "h",\n'
        '    "status": "online",\n'
        '    "version": "2.0.0",\n'
        '    ,\n'
        '    "haproxy_status": "running",\n'
        '    "cluster_id": 1\n'
        '}'
    )
    parsed = _assert_parses(raw)
    assert parsed["name"] == "test"
    assert parsed["status"] == "online"
    assert parsed["haproxy_status"] == "running"


def test_empty_numeric_subfield_before_comma():
    # An empty unquoted numeric ("memory_total": ,) — covered by the pre-existing Fix 1.
    raw = '{ "name": "t", "cpu_count": , "memory_total": , "status": "online" }'
    parsed = _assert_parses(raw)
    assert parsed["cpu_count"] is None and parsed["memory_total"] is None
    assert parsed["status"] == "online"


def test_empty_value_before_closing_brace():
    raw = '{ "name": "t", "status": "online", "applied_config_version": }'
    parsed = _assert_parses(raw)
    assert parsed["applied_config_version"] is None


def test_leading_comma_first_member():
    # Empty $system_info as the FIRST member -> '{ , "name": ... }'.
    raw = '{\n    ,\n    "name": "t",\n    "status": "online"\n}'
    parsed = _assert_parses(raw)
    assert parsed["name"] == "t"


def test_comma_run_two_empty_fields():
    # Two empties in a row (odd-length comma run) must still collapse to valid JSON.
    raw = '{ "a": 1,\n    ,\n    ,\n    "b": 2 }'
    parsed = _assert_parses(raw)
    assert parsed["a"] == 1 and parsed["b"] == 2


def test_trailing_comma_regression():
    # Pre-existing Fix 3 must still hold after the new fixes were added.
    raw = '{ "name": "t", "status": "online", }'
    parsed = _assert_parses(raw)
    assert parsed["name"] == "t"


def test_healthy_payload_is_untouched():
    # A well-formed agent payload must pass through unchanged (sanitized=False) and its values —
    # including the base64 stats CSV and the nested server_statuses — must be byte-identical.
    payload = {
        "name": "agent-1",
        "status": "online",
        "cluster_id": 1,
        "server_statuses": {"be_app": {"s1": "UP", "s2": "DOWN"}},
        "network_interfaces": ["eth0", "eth1"],
        "haproxy_stats_csv": "IyBwdmJjLGJhY2tlbmQsZnJvbnRlbmQs",  # base64: contains commas only inside a quoted string is impossible (base64 has none)
        "applied_config_version": "cluster-1-v42",
    }
    raw = json.dumps(payload)
    out, changed = _sanitize_agent_json(raw)
    assert changed is False
    assert out == raw  # byte-identical
    assert json.loads(out) == payload


def test_idempotent_on_already_clean_minimal():
    raw = '{"name": "t", "status": "online"}'
    out, changed = _sanitize_agent_json(raw)
    assert changed is False
    assert out == raw
