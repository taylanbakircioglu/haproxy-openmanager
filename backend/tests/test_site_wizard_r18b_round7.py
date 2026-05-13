"""v1.5.0 R18b round 7 audit fixes — final convergence polish.

Findings discovered during R18b round 7 (final convergence):

  R18b-#18 (check_port80 rollup branching): when every probe target
    was skipped because the SSRF guard refused to probe a non-
    public IP, the rollup message read "Egress to port 80 appears
    blocked" — operators chased corporate firewall logs while the
    real cause was an internal-only DNS A record. Now the rollup
    branches on whether skips were SSRF or egress, and a default
    is provided so the message never reads "(None)".

  R18b-#19 (Audit log fire-and-forget): the wizard create endpoint
    awaited the `log_user_activity` call before returning. The
    secondary INSERT added wizard tail-latency. The activity-log
    helper already swallows its own exceptions and never raises;
    spawning the call as a fire-and-forget task lets the wizard
    return as soon as the main transaction is committed.
"""
import asyncio
import socket
from pathlib import Path

import pytest

from services.acme_diagnostics import _is_public_ip, check_port80


_REPO = Path(__file__).resolve().parent.parent


# ----------------- R18b-#18: rollup message branching -----------------


@pytest.mark.asyncio
async def test_check_port80_rollup_says_ssrf_skip_not_egress(monkeypatch):
    """When every target is SSRF-skipped, rollup must NOT say
    'egress blocked'."""
    def fake_gethostbyname_ex(domain):
        return (domain, [], ["10.0.0.1"])
    monkeypatch.setattr(socket, "gethostbyname_ex", fake_gethostbyname_ex)
    out = await check_port80(["a.example.com", "b.example.com"])
    assert out["status"] == "warn"
    msg = out["message"].lower()
    assert "non-public" in msg, (
        f"R18b-#18 regression: SSRF-skip rollup no longer mentions "
        f"non-public IP. Got: {out['message']!r}"
    )
    assert "egress" not in msg, (
        f"R18b-#18 regression: SSRF-skip rollup still says 'egress' — "
        f"misleads operators chasing firewall logs. Got: {out['message']!r}"
    )


@pytest.mark.asyncio
async def test_check_port80_rollup_message_no_none_default(monkeypatch):
    """The skip_reason fallback string must never let the message
    read '(None)' — pre-fix that happened when no IPs resolved."""
    def fake_gethostbyname_ex(domain):
        # Empty IP list — _all_ips_public returns (False, [])
        return (domain, [], [])
    monkeypatch.setattr(socket, "gethostbyname_ex", fake_gethostbyname_ex)
    out = await check_port80(["a.example.com"])
    assert "(None)" not in out["message"], (
        f"R18b-#18 regression: rollup message contains '(None)' — "
        f"got: {out['message']!r}"
    )


# ----------------- R18b-#19: audit log fire-and-forget -----------------


def test_wizard_audit_log_emit_is_fire_and_forget():
    src = (_REPO / "routers" / "site_wizard.py").read_text()
    # Locate the audit-log emit block.
    audit_block = src[src.find("R18b audit fix (round 6 #15)"):]
    audit_block = audit_block[: audit_block.find("return {")]
    # Must use create_task (fire-and-forget), not bare await.
    assert "create_task" in audit_block, (
        "R18b-#19 regression: wizard audit-log emit no longer uses "
        "asyncio.create_task — adds tail latency to wizard response"
    )
    # The bare `await _log_user_activity(` pattern must be gone from
    # the audit block.
    assert "await _log_user_activity(" not in audit_block, (
        "R18b-#19 regression: wizard audit-log emit still awaits the "
        "log helper — the secondary INSERT adds tail latency"
    )
