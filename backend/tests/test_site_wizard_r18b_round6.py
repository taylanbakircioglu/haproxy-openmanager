"""v1.5.0 R18b round 6 audit fixes — convergence regression tests.

Findings discovered during R18b round 6:

  R18b-#16 (DELETE drafts idempotency): the DELETE /drafts/{id}
    endpoint relied on `result.endswith("0")` to decide whether to
    return 404. That is fragile under asyncpg upgrades (the status
    string format is undocumented stable surface). Replaced with
    `DELETE ... RETURNING id` + explicit None check.

  R18b-#17 (Wizard audit-trail fidelity): the activity-logger
    middleware only records 2xx HTTP responses with the bare status
    code. The wizard create endpoint can return HTTP 200 while the
    body's `status` field is `created_pending_apply_failed` or
    `applied_acme_staging_failed` — the audit trail claimed "wizard
    succeeded" while downstream apply or ACME staging actually
    failed. Now the wizard explicitly emits a `user_activity_logs`
    row capturing the wizard outcome so the audit trail reflects
    reality regardless of HTTP status interpretation.
"""
from pathlib import Path

import pytest


_REPO = Path(__file__).resolve().parent.parent


# ----------------- R18b-#16: DELETE drafts RETURNING -----------------


def test_drafts_delete_uses_returning_for_idempotency():
    src = (_REPO / "routers" / "site_wizard.py").read_text()
    # Locate the DELETE endpoint body.
    delete_marker = '@router.delete("/drafts/{draft_id}")'
    assert delete_marker in src, "draft DELETE endpoint missing"
    body = src[src.find(delete_marker):]
    # Just inspect the next ~80 lines of code.
    body = body[: body.find("@router", 1) if body.find("@router", 1) > 0 else 4000]

    assert "RETURNING id" in body, (
        "R18b-#16 regression: drafts DELETE no longer uses RETURNING "
        "to detect 0-rows-affected — relies on fragile string parsing"
    )
    assert "deleted_id is None" in body, (
        "R18b-#16 regression: drafts DELETE no longer guards against "
        "the 0-rows case via explicit None check"
    )
    # The pre-R18b fragile pattern must be gone — but allow it in
    # comments (the R18b fix comment intentionally cites the legacy
    # pattern as documentation). Strip line comments before the
    # check.
    code_only = "\n".join(
        ln for ln in body.splitlines() if not ln.lstrip().startswith("#")
    )
    assert 'result.endswith("0")' not in code_only, (
        "R18b-#16 regression: drafts DELETE still parses the asyncpg "
        "status string via `result.endswith(\"0\")` — this breaks "
        "silently if asyncpg ever changes the status format"
    )


# ----------------- R18b-#17: Wizard audit-trail fidelity -----------------


def test_wizard_create_logs_outcome_to_user_activity_logs():
    src = (_REPO / "routers" / "site_wizard.py").read_text()
    # The wizard create response builder must emit log_user_activity.
    assert "log_user_activity" in src or "_log_user_activity" in src, (
        "R18b-#17 regression: wizard create endpoint no longer emits "
        "an explicit user_activity_logs row — middleware-only logging "
        "misses degraded 200-status outcomes"
    )
    assert 'action="wizard_create_site"' in src, (
        "R18b-#17 regression: wizard activity-log action name missing "
        "or not migrated to the post-Phase-D `wizard_create_site` value"
    )
    # The details dict must include enough context to reconstruct
    # what actually happened on a degraded outcome.
    detail_keys = [
        '"wizard_status"',
        '"cluster_id"',
        '"ssl_mode"',
        '"acme_staging_error"',
        '"apply_error"',
    ]
    for k in detail_keys:
        assert k in src, (
            f"R18b-#17 regression: wizard activity-log details no "
            f"longer include {k} — auditor cannot reconstruct degraded "
            "outcomes"
        )


def test_wizard_audit_log_failure_does_not_break_response():
    """The audit-log emit path is wrapped in try/except so a logging
    failure never breaks the main wizard response."""
    src = (_REPO / "routers" / "site_wizard.py").read_text()
    # The block must include a try around the log_user_activity call.
    audit_block = src[src.find("R18b audit fix (round 6 #15)"):]
    assert "try:" in audit_block[:1500], (
        "R18b-#17 regression: wizard audit-log emit no longer wrapped "
        "in try/except — a logging failure can now break the response"
    )
    assert "except Exception" in audit_block[:2500], (
        "R18b-#17 regression: wizard audit-log emit no longer guards "
        "all exception types"
    )
    # And the failure handler must not re-raise.
    handler = audit_block[audit_block.find("except Exception"):][:200]
    assert "raise" not in handler, (
        "R18b-#17 regression: wizard audit-log handler now re-raises "
        "— a logging failure can break the wizard response"
    )
