"""
v1.5.0 Feature B — _execute_post_completion_actions unit tests.

Coverage targets the high-risk gates that survived the multi-round audit:
  * idempotency (M2/M3): an action with executed_at must be skipped silently
  * port-collision pre-check (M21/R35): pre-INSERT collision check rejects
    cleanly without writing
  * non-dict / unknown-type actions are skipped (defensive parsing)
  * renewal of a cert whose order has post_completion_actions DOES NOT
    re-execute them (handled in _complete_certificate's caller path: the
    is_renewal flag gates the call; we cover that contract here)
"""
import json
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ----------------------------------------------------------------------------
# Test helpers
# ----------------------------------------------------------------------------


@asynccontextmanager
async def _fake_tx():
    """Stand-in for conn.transaction() async context manager."""
    yield


def _make_conn():
    conn = AsyncMock()
    conn.transaction = MagicMock(side_effect=lambda: _fake_tx())
    return conn


# ----------------------------------------------------------------------------
# Idempotency
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_already_executed_action_is_skipped():
    from routers.letsencrypt import _execute_post_completion_actions
    conn = _make_conn()

    actions = [{
        "type": "create_frontend",
        "executed_at": "2026-05-01T00:00:00Z",   # already done
        "frontend_config": {"cluster_id": 1, "name": "fe-https"},
    }]

    outcomes = await _execute_post_completion_actions(
        conn, order_id=1, actions=actions, cert_id=42,
    )
    assert len(outcomes) == 1
    assert outcomes[0]["status"] == "skipped"
    assert "already executed" in outcomes[0]["reason"]


@pytest.mark.asyncio
async def test_non_dict_action_is_skipped():
    from routers.letsencrypt import _execute_post_completion_actions
    conn = _make_conn()

    outcomes = await _execute_post_completion_actions(
        conn, order_id=1, actions=["not a dict", 42, None], cert_id=42,
    )
    assert len(outcomes) == 3
    assert all(o["status"] == "skipped" for o in outcomes)


# ----------------------------------------------------------------------------
# Port-collision pre-check (M21/R35)
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_port_collision_skips_create_and_records_event():
    """If the bind port is taken at the moment of post-completion, we must
    NEVER attempt the INSERT — that would orphan the cert.
    """
    from routers.letsencrypt import _execute_post_completion_actions
    conn = _make_conn()

    actions = [{
        "type": "create_frontend",
        "frontend_config": {
            "cluster_id": 1,
            "bind_address": "*",
            "bind_port": 443,
            "name": "fe-https",
        },
    }]

    record_event_mock = AsyncMock()

    with patch(
        "services.frontend_service.check_bind_port_collision",
        AsyncMock(return_value=99),  # collision: existing frontend id 99
    ), patch(
        "services.frontend_service.create_frontend_row",
        AsyncMock(),
    ) as create_fe, patch(
        "utils.activity_log.record_event",
        record_event_mock,
    ):
        outcomes = await _execute_post_completion_actions(
            conn, order_id=1, actions=actions, cert_id=42,
        )

    create_fe.assert_not_called()
    assert outcomes[0]["status"] == "error"
    assert outcomes[0]["reason"] == "port_collision"

    # An event was recorded for the skip
    record_event_mock.assert_awaited()
    awaited_args = record_event_mock.await_args.args
    awaited_kwargs = record_event_mock.await_args.kwargs
    # First positional is order_id, second is event_type
    assert awaited_args[0] == 1
    assert "skipped" in awaited_args[1]


# ----------------------------------------------------------------------------
# Unknown action type does not crash the loop
# ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unknown_action_type_does_not_raise():
    from routers.letsencrypt import _execute_post_completion_actions
    conn = _make_conn()

    # Action with no recognized type — must not crash; outcome flagged.
    actions = [{"type": "redact_secrets"}]
    outcomes = await _execute_post_completion_actions(
        conn, order_id=1, actions=actions, cert_id=42,
    )
    assert len(outcomes) == 1
    # Defensive parsing: at minimum a status is returned per action.
    assert "status" in outcomes[0]


# ----------------------------------------------------------------------------
# Contract: renewal does NOT execute post-completion actions
# (the gate lives in _complete_certificate; we assert via grep that
# `is_renewal` guards the actions call)
# ----------------------------------------------------------------------------


def test_complete_certificate_renewal_gate_exists_in_source():
    """The renewal of a cert (where the order is being re-issued via the
    auto-renew daemon) MUST NOT trigger post_completion_actions a second
    time. The gate is `if not is_renewal:` inside _complete_certificate.

    This is a static assertion against the source — refactor that drops the
    gate would silently re-create the wizard's HTTPS frontend on every
    renewal.
    """
    from pathlib import Path
    src = Path(__file__).resolve().parent.parent / "routers" / "letsencrypt.py"
    text = src.read_text()
    assert "is_renewal" in text
    # Specifically inside _complete_certificate, post_completion_actions
    # is invoked under the `if not is_renewal:` guard.
    idx = text.find("_execute_post_completion_actions")
    assert idx != -1, "post-completion call must exist in _complete_certificate"
    # Look back a few hundred chars for the renewal guard.
    window_start = max(0, idx - 800)
    surrounding = text[window_start:idx]
    assert ("is_renewal" in surrounding or "not is_renewal" in surrounding), (
        "_execute_post_completion_actions must be gated by 'is_renewal' to "
        "prevent re-running wizard actions on renewal."
    )


def test_wizard_order_bypasses_existing_cert_match():
    """Bulgu #4: a wizard-staged order with non-empty post_completion_actions
    must NOT be merged into a manually-issued cert that happens to share
    the same primary_domain. The is_wizard_order short-circuit forces
    existing_cert=None so a fresh cert row is INSERTed and the deferred
    HTTPS frontend creation actually fires.

    Static source assertion — a refactor that drops `is_wizard_order` would
    silently regress wizard host creation when an old manual cert exists.
    """
    from pathlib import Path
    src = Path(__file__).resolve().parent.parent / "routers" / "letsencrypt.py"
    text = src.read_text()
    assert "is_wizard_order" in text, (
        "_complete_certificate must short-circuit existing_cert lookup "
        "when post_completion_actions is non-empty (Bulgu #4)"
    )


def test_wizard_uses_consolidated_version_for_acme_gating():
    """Bulgu #30: the staged ACME order's pending_apply_version_name must be
    the CONSOLIDATED version name returned by apply_cluster_pending
    (`apply-consolidated-{ts}`), NOT the original PENDING version name
    (`bulk-proxied-host-create-{ts}`). Agents only ever report the
    consolidated name back via /config-applied, so gating on the bulk
    name would block wizard order promotion forever.
    """
    from pathlib import Path
    src = Path(__file__).resolve().parent.parent / "routers" / "site_wizard.py"
    text = src.read_text()
    assert "gating_version_name" in text, (
        "create_proxied_host must derive a gating version name from "
        "apply_result.latest_version (Bulgu #30)"
    )
    # The staged order must be created with gating_version_name, not
    # the literal `version_name` (which is the PENDING bulk name).
    idx = text.find("create_order_staged(")
    assert idx != -1
    # Look forward 1000 chars for the pending_apply_version_name= kwarg.
    snippet = text[idx:idx + 1500]
    assert "pending_apply_version_name=gating_version_name" in snippet, (
        "create_order_staged must be called with pending_apply_version_name="
        "gating_version_name (Bulgu #30)"
    )


def test_main_processes_wizard_staged_orders_unconditionally():
    """Bulgu #2: _process_wizard_staged_orders must run every cycle of
    complete_pending_acme_orders, even when no claimed_ids exist. Otherwise
    a freshly created wizard order on an idle system would never leave
    wizard_staged status.

    Static source assertion against main.py: the call to
    _process_wizard_staged_orders should NOT sit after the
    `if not claimed_ids: continue` early-out.
    """
    from pathlib import Path
    src = Path(__file__).resolve().parent.parent / "main.py"
    text = src.read_text()
    process_call_idx = text.find("_process_wizard_staged_orders(acme_svc)")
    assert process_call_idx != -1, (
        "_process_wizard_staged_orders must be invoked from "
        "complete_pending_acme_orders"
    )
    early_continue_idx = text.find("if not claimed_ids:")
    assert early_continue_idx != -1
    # The wizard processing call must come BEFORE the early-out so the
    # idle-system path still drives wizard_staged orders forward.
    assert process_call_idx < early_continue_idx, (
        "_process_wizard_staged_orders must run BEFORE 'if not claimed_ids: continue' "
        "(Bulgu #2: otherwise wizard orders are starved on idle systems)"
    )
