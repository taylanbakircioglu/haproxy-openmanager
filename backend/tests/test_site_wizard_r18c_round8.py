"""v1.5.0 R18c round 8 audit fixes — JSONB → API serialization contract.

Bulgu A (KRITIK regression — observed in production):
  asyncpg has no JSONB codec registered on our connection pool, so
  every column declared as JSONB in PostgreSQL comes back to Python as
  a raw JSON string, not a parsed dict. Several router endpoints were
  forwarding this raw string verbatim into their JSON response, which
  meant the React renderer received `payload` (or `details`) as a
  string and ended up trying to access `.domains` / `.cluster_id` on
  a plain string — silently undefined.

  Concrete failure observed in screenshot:
    * Site Drafts page shows empty Domains and "—" Cluster columns
      and "No SSL" SSL/TLS even when the user actually saved a fully
      populated draft.
    * Resume from a draft does NOT hydrate the wizard form: backend
      returned a JSON string, the drafts page then JSON.stringify'd
      it (re-quoting), the wizard JSON.parse'd it back to a plain
      string, the `typeof parsed === 'object'` guard failed, hydrate
      bailed.

  Fix:
    * Backend: list_drafts.payload is now ALWAYS a dict (parsed via
      json.loads when asyncpg hands us a string).
    * Backend: acme_diagnostics event_log .details is normalized to
      a dict (JSONB columns) instead of forwarding the raw string.
    * Frontend: SiteDrafts normalizes payload on ingest via
      a single normalizePayload helper; handleResume / handlePreview
      use that helper too.
    * Frontend: SiteWizard hydrate effect defensively re-parses
      up to 3 times if it receives a stringified-JSON-as-string (so a
      pre-fix sessionStorage entry from an old tab still hydrates).

  Why this slipped past R12-R18c rounds 1-7:
    * Pre-existing live deployments may have had a JSONB codec set up
      via a different code path that our new routers didn't pick up,
      OR the shape was tolerated because the column renders were
      accidentally null-safe (Array.isArray returned false → empty
      array → no crash, but ALSO no data shown). The defect was
      cosmetically silent until a user actually compared what they
      typed to what the table rendered.
"""
import json
import re
from pathlib import Path

import pytest


_REPO = Path(__file__).resolve().parent.parent
_FRONT = _REPO.parent / "frontend" / "src"
_DRAFTS_PATH = _FRONT / "components" / "SiteDrafts.js"
_WIZARD_PATH = _FRONT / "components" / "SiteWizard.js"

_FRONTEND_AVAILABLE = _DRAFTS_PATH.exists() and _WIZARD_PATH.exists()


def _read(p: Path) -> str:
    return p.read_text()


_skip_no_frontend = pytest.mark.skipif(
    not _FRONTEND_AVAILABLE,
    reason="frontend/src not present (backend-only test container) — "
           "JS source-level assertions skipped",
)


# =====================================================================
# Backend: list_drafts payload contract
# =====================================================================


def test_list_drafts_payload_is_normalized_to_dict():
    """The response builder must coerce r['payload'] to a dict before
    handing it to FastAPI. Otherwise asyncpg's raw JSONB string leaks
    into the API contract and the FE can't access nested fields."""
    src = _read(_REPO / "routers" / "site_wizard.py")
    # Find the list_drafts function body.
    idx = src.find("async def list_drafts(")
    assert idx != -1, "list_drafts not found"
    next_idx = src.find("\nasync def ", idx + 1)
    block = src[idx:next_idx if next_idx != -1 else idx + 6000]

    # The payload field in the response dict must use the parsed dict
    # (the function-local variable `p` populated by `_payload(r)`),
    # NOT the raw asyncpg row value.
    assert '"payload": p if isinstance(p, dict) else {}' in block, (
        "R18c-#30 (Bulgu A) regression: list_drafts is forwarding the "
        "raw r['payload'] (a JSON string when asyncpg has no JSONB "
        "codec) instead of the parsed dict. Frontend cannot read "
        "`payload.domains` or `payload.cluster_id` from a string."
    )
    # Also verify the helper that does the parse exists and handles the
    # str-vs-dict cases defensively.
    assert "if isinstance(p, str):" in block and "json.loads(p)" in block, (
        "R18c-#30 regression: _payload() helper no longer parses str "
        "JSON payloads."
    )


# =====================================================================
# Backend: acme_diagnostics event_log details contract
# =====================================================================


def test_acme_event_log_details_is_normalized_to_dict():
    src = _read(_REPO / "routers" / "acme_diagnostics.py")
    # Look for the new defensive parse in the acme_order_event branch.
    assert "isinstance(_det, str)" in src and "json.loads(_det)" in src, (
        "R18c-#30 regression: acme_diagnostics event_log no longer "
        "parses asyncpg's raw JSONB string for the `details` field. "
        "Frontend ends up trying to access dict keys on a plain string."
    )


# =====================================================================
# Frontend: SiteDrafts normalizePayload helper
# =====================================================================


@_skip_no_frontend
def test_drafts_defines_normalizePayload_helper():
    src = _read(_DRAFTS_PATH)
    assert "const normalizePayload" in src, (
        "R18c-#30 regression: SiteDrafts.js no longer exposes "
        "a normalizePayload helper — the FE has no last-line-of-defense "
        "if the backend ever regresses to returning str payloads."
    )
    assert "JSON.parse(p)" in src, (
        "R18c-#30 regression: normalizePayload no longer attempts to "
        "JSON.parse a string payload."
    )


@_skip_no_frontend
def test_drafts_normalizes_payload_on_ingest():
    """Drafts must be normalized once on fetch so every render and the
    Resume / Preview handlers see a dict."""
    src = _read(_DRAFTS_PATH)
    assert "raw.map(normalizeDraft)" in src, (
        "R18c-#30 regression: drafts list no longer normalizes payloads "
        "via map(normalizeDraft) on ingest."
    )


@_skip_no_frontend
def test_drafts_resume_uses_normalized_payload():
    """handleResume must stringify a NORMALIZED dict, not the raw
    server response, so the wizard's hydrate effect always lands on
    a dict after JSON.parse."""
    src = _read(_DRAFTS_PATH)
    idx = src.find("const handleResume")
    assert idx != -1
    next_idx = src.find("const handle", idx + 1)
    block = src[idx:next_idx if next_idx != -1 else idx + 1000]
    assert "normalizePayload(draft" in block, (
        "R18c-#30 regression: handleResume no longer normalizes the "
        "payload before stuffing it into sessionStorage. A pre-fix "
        "string would be JSON.stringify-quoted and never hydrated."
    )


@_skip_no_frontend
def test_drafts_preview_uses_normalized_payload():
    src = _read(_DRAFTS_PATH)
    idx = src.find("const handlePreview")
    assert idx != -1
    next_idx = src.find("const handle", idx + 1)
    block = src[idx:next_idx if next_idx != -1 else idx + 1500]
    assert "normalizePayload(draft" in block, (
        "R18c-#30 regression: handlePreview no longer normalizes the "
        "payload before POSTing to /preview."
    )


# =====================================================================
# Frontend: SiteWizard defensive parse on hydrate
# =====================================================================


@_skip_no_frontend
def test_wizard_hydrate_handles_doubly_encoded_payload():
    """Belt-and-suspenders guard for any pre-fix sessionStorage entry
    that was double-encoded by the old drafts page."""
    src = _read(_WIZARD_PATH)
    # The hydrate effect should attempt to re-parse if the result of
    # JSON.parse(raw) is still a string (i.e. the raw was a quoted
    # string of a JSON string).
    assert "while (typeof parsed === 'string'" in src, (
        "R18c-#30 regression: wizard hydrate effect no longer guards "
        "against double-encoded payloads. A user who has an old draft "
        "page open in another tab would still get an empty wizard."
    )
    # Final check guards against the result still not being a usable
    # dict (must be `object && !Array.isArray`).
    assert "!Array.isArray(parsed)" in src, (
        "R18c-#30 regression: wizard hydrate no longer rejects array-"
        "shaped parsed values; an array would silently bypass the "
        "object guard and break setFieldsValue."
    )


# =====================================================================
# Sanity: round 8 didn't break round 7 wiring
# =====================================================================


@_skip_no_frontend
def test_round8_preserves_round7_setStep_to_review():
    src = _read(_WIZARD_PATH)
    assert "setStep(WIZARD_LAST_STEP)" in src, (
        "R18c-#27 regression after round 8: hydrate effect no longer "
        "jumps to Review & Apply on resume."
    )
