"""
Phase 2 (R11-audit follow-up, PR-5 scope): pre-persist HAProxy
config validator gate on the Site Wizard create endpoint.

The wizard now runs the rendered config through
``HAProxyConfigValidator`` BEFORE writing the ``config_versions``
PENDING row, and aborts the transaction (HTTP 422) if any
ERROR-level diagnostic fires. This is a defence-in-depth layer
on top of:

  * Pydantic Literal/coerce validation on the request body.
  * DB UNIQUE / FOREIGN KEY / partial-index constraints.
  * Generator-side safeguards (``_apply_bind_ssl_verify``,
    ``_format_redirect_rule``, bucket-ordered emit, stick-table
    dedup).

The user-stated rule is: "the UI must not allow any operation
that would fail HAProxy validation". This test suite pins the
gate's source-level structure so a future refactor cannot remove
it silently.
"""
from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_ROUTER = _ROOT / "routers" / "site_wizard.py"


def _src() -> str:
    return _ROUTER.read_text()


def test_pre_persist_validator_gate_imports_validator():
    """The wizard create endpoint must import the validator INSIDE
    the transaction (lazy import) so a missing module never breaks
    cold-start, and call its `validate_config` on the generated
    string."""
    src = _src()
    assert "HAProxyConfigValidator" in src, (
        "Phase 2 regression: HAProxyConfigValidator import is gone "
        "from the wizard router — the pre-persist gate is missing."
    )
    assert "ValidationLevel" in src, (
        "Phase 2 regression: ValidationLevel import is gone — gate "
        "cannot distinguish ERROR from WARNING/SUGGESTION."
    )


def test_pre_persist_gate_runs_inside_transaction():
    """The validator call must live INSIDE the
    `async with conn.transaction():` block so that a 422 raises
    BEFORE the `INSERT INTO config_versions ...` and the transaction
    rolls back, leaving the database clean (no orphan
    backend / server / frontend rows for an invalid wizard run)."""
    src = _src()
    # Find the transaction block start
    tx_idx = src.find("async with conn.transaction():")
    assert tx_idx > 0, "transaction block not found in wizard router"
    # The validator call must appear after the transaction start
    val_idx = src.find("HAProxyConfigValidator()", tx_idx)
    assert val_idx > tx_idx, (
        "Phase 2 regression: HAProxyConfigValidator call must be "
        "INSIDE the wizard's `async with conn.transaction():` "
        "block so a 422 rolls back the freshly-inserted entities."
    )
    # The config_versions INSERT must come AFTER the validator gate
    insert_idx = src.find("INSERT INTO config_versions", val_idx)
    assert insert_idx > val_idx, (
        "Phase 2 regression: validator gate is AFTER the "
        "`INSERT INTO config_versions` — gate is structurally "
        "ineffective (the PENDING row is already persisted)."
    )


def test_pre_persist_gate_blocks_on_error_level_only():
    """The gate must filter for ERROR-level results — a WARNING
    (e.g. an unknown but harmless directive) must NOT block create.
    Only fatal-equivalent diagnostics abort the transaction."""
    src = _src()
    # The list comprehension that filters validator results must
    # reference ValidationLevel.ERROR explicitly.
    filter_pattern = re.compile(
        r"if r\.level == ValidationLevel\.ERROR",
        re.MULTILINE,
    )
    assert filter_pattern.search(src), (
        "Phase 2 regression: validator gate must filter "
        "`r.level == ValidationLevel.ERROR` — without the filter "
        "the gate would block on harmless WARNING-level findings."
    )


def test_pre_persist_gate_raises_422_with_structured_error_payload():
    """When the gate fires it must raise HTTP 422 (Unprocessable
    Entity) with a structured `errors` array so the frontend can
    render the issues as a list, not a giant dump."""
    src = _src()
    # 422 status code
    assert "status_code=422" in src, (
        "Phase 2 regression: validator gate must use HTTP 422, "
        "not a generic 400 — 422 is the correct status for a "
        "syntactically-valid request that fails business / "
        "validation rules."
    )
    # Structured error tag
    assert '"haproxy_validation_failed"' in src, (
        "Phase 2 regression: validator gate must surface the "
        "`haproxy_validation_failed` error tag so the frontend "
        "can route the response into the dedicated banner."
    )
    # Structured `errors` field with line/message
    assert '"line": e.line_number' in src and '"message": e.message' in src, (
        "Phase 2 regression: validator gate response must include "
        "per-error `line` + `message` so the operator can locate "
        "the offending rule."
    )


def test_pre_persist_gate_caps_error_payload():
    """Defence: a misconfigured cluster could produce hundreds of
    validator findings. The response payload caps to the first 20
    so we don't blow up the wire / UI table with 500+ rows."""
    src = _src()
    # The slice [:20] must be present on the validator-error list
    assert "_val_errors[:20]" in src, (
        "Phase 2 regression: validator gate response should cap "
        "the error array (first 20 items) — uncapped payloads can "
        "blow up the response size for misconfigured clusters."
    )


def test_pre_persist_gate_validator_crash_is_non_fatal():
    """If the validator itself crashes (NEW directive it doesn't
    recognise, edge case in our static rules) the wizard create
    must NOT block — the apply-time `haproxy -c` on the agent is
    the ultimate authority. We log a WARNING and proceed."""
    src = _src()
    # The validator's own try/except must catch the broad Exception
    # AFTER re-raising HTTPException so 422s still escape.
    assert "except HTTPException:" in src, (
        "Phase 2 regression: validator gate must let HTTPException "
        "bubble up (transaction rollback path) but swallow other "
        "exceptions to keep validator bugs from blocking creation."
    )
    assert "non-fatal" in src.lower() or "validator crashed" in src.lower(), (
        "Phase 2 regression: validator gate's broad-except branch "
        "must log a clear 'non-fatal / validator crashed' message "
        "so operators can tell a validator bug from an actual "
        "config problem in the logs."
    )


def test_pre_persist_gate_only_runs_on_non_empty_config():
    """If the upstream config-generation step itself raised, the
    string is empty and we already logged ERROR. Skipping the
    validator on an empty string avoids a misleading 'config has
    no `frontend` section' warning when the real cause was the
    generator crash above.

    Phase K Phase C: site_wizard.py now also calls
    `HAProxyConfigValidator()` from inside `preview_create` on the
    dry-run path (gated by `if validate_haproxy_config:`). The
    create-time gate stays guarded by `if config_content:` — the
    pin walks past the preview-side call so it lands on the
    create_site validator call, which is the path this test
    actually pins.
    """
    src = _src()
    # Pin the create_site path's validator call. There are two
    # validator references after Phase K: one in `preview_create`
    # (gated by `if validate_haproxy_config:`) and one in
    # `create_site` (gated by `if config_content:`). We want the
    # latter — the create-time gate where empty config_content can
    # surface from a generator crash.
    create_idx = src.find("async def create_site(")
    assert create_idx > 0, "create_site function not found"
    val_idx = src.find("HAProxyConfigValidator()", create_idx)
    assert val_idx > 0, "HAProxyConfigValidator() call not found inside create_site"
    # Phase K Phase D follow-up (Bulgu #12 round 3): the explanatory
    # comment block above the validator call grew when we forwarded
    # `partial_fragment=True` to suppress false-positive global-section
    # warnings. Widen the lookback window so the pin keeps catching the
    # guard while accommodating the larger inline docs.
    pre_window = src[max(0, val_idx - 1500) : val_idx]
    assert "if config_content:" in pre_window, (
        "Phase 2 regression: validator gate must be guarded by "
        "`if config_content:` — running the validator on an empty "
        "string surfaces misleading 'no frontend section' findings "
        "when the real failure was upstream config generation."
    )
