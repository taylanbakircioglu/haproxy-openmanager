"""v1.5.0 R18b round 3 audit fixes — regression tests.

Findings discovered during R18b round 3 (production hazards):

  R18b-#7 (UniqueViolationError mapping): two operators racing the
    same wizard host name, OR an active-only pre-flight check that
    misses a soft-deleted (is_active=FALSE) row, hit the UNIQUE
    (name, cluster_id) constraint inside the create transaction.
    Pre-fix that bubbled up as 500 Internal Server Error with no
    operator-actionable detail. Now we map asyncpg
    UniqueViolationError to 409 with a precise hint.

  R18b-#8 (Resume with deleted cert): wizard hydration from a
    sessionStorage draft can carry an `ssl.ssl_certificate_id` (or
    per-server `ssl_certificate_id`) pointing at a cert that was
    deleted via SSL Management since the draft was saved. Pre-fix
    the Select rendered the orphan id as an empty option and the
    operator had no signal — submit then 400'd at FK validation.
    Now we surface a single warning toast and clear the dangling
    field whenever existingCerts refresh.

  R18b-#9 (Drafts corrupt payload guard): a malformed payload (e.g.
    `payload.domains` not an array, or `payload.cluster_id` a list)
    threw inside an Ant Design Table column render, blanking the
    entire drafts page. Now each render is defensive against
    non-conforming JSONB.
"""
import re
from pathlib import Path

import pytest


_REPO = Path(__file__).resolve().parent.parent
_FRONT = _REPO.parent / "frontend" / "src"


# ----------------- R18b-#7: UniqueViolationError → 409 -----------------


def test_site_wizard_create_imports_unique_violation_error():
    src = (_REPO / "routers" / "site_wizard.py").read_text()
    # The import block may evolve to include other asyncpg exceptions
    # (R18b round 4 added ForeignKeyViolationError). Match the symbol
    # rather than a fixed-shape import line.
    assert "UniqueViolationError" in src and "asyncpg.exceptions" in src, (
        "R18b-#7 regression: proxied_host router no longer imports "
        "UniqueViolationError — TOCTOU name conflicts will fall "
        "through to a generic 500"
    )


def test_site_wizard_create_maps_unique_violation_to_409():
    src = (_REPO / "routers" / "site_wizard.py").read_text()
    # Look for the catch + raise pattern.
    assert "except UniqueViolationError" in src, (
        "R18b-#7 regression: create endpoint no longer catches "
        "UniqueViolationError"
    )
    # The detail must mention a concrete next step.
    assert (
        "already exists" in src
        and "Pick a different" in src
    ), (
        "R18b-#7 regression: 409 detail copy no longer guides the "
        "operator to a concrete remedy"
    )
    # Verify it's actually raising HTTPException(409).
    catch_block = src[src.find("except UniqueViolationError"):]
    catch_block = catch_block[:catch_block.find("except Exception as e:")]
    assert "status_code=409" in catch_block, (
        "R18b-#7 regression: UniqueViolationError handler no longer "
        "raises HTTP 409"
    )


def test_site_wizard_create_distinguishes_backend_vs_frontend_unique_violation():
    """The UNIQUE(name, cluster_id) constraint can fire on either the
    `backends` or the `frontends` table. The 409 detail should tell
    the operator which entity is in conflict so they know which name
    to change. Pre-R18b the message was undifferentiated."""
    src = (_REPO / "routers" / "site_wizard.py").read_text()
    catch_block = src[src.find("except UniqueViolationError"):]
    catch_block = catch_block[:catch_block.find("except Exception as e:")]
    assert "backends_name_cluster_id_key" in catch_block, (
        "R18b-#7 regression: handler no longer special-cases the "
        "backends UNIQUE constraint name"
    )
    assert "frontends_name_cluster_id_key" in catch_block, (
        "R18b-#7 regression: handler no longer special-cases the "
        "frontends UNIQUE constraint name"
    )


# ----------------- R18b-#8: deleted-cert hydration warning -----------------


def test_wizard_warns_and_clears_orphan_ssl_certificate_id():
    src = (_FRONT / "components" / "SiteWizard.js")
    if not src.exists():
        pytest.skip("frontend tree not mounted")
    body = src.read_text()
    # The orphan-detect effect must exist.
    assert "orphanWarnedRef" in body, (
        "R18b-#8 regression: wizard no longer tracks orphan-cert warnings"
    )
    # It must check both the HTTPS frontend and per-server slots.
    assert "cur.ssl.ssl_certificate_id" in body or "ssl?.ssl_certificate_id" in body, (
        "R18b-#8 regression: wizard no longer checks HTTPS frontend "
        "ssl_certificate_id for orphan state"
    )
    assert "s.ssl_certificate_id" in body, (
        "R18b-#8 regression: wizard no longer checks per-server "
        "ssl_certificate_id for orphan state"
    )
    # And clears the dangling fields.
    assert "form.setFieldsValue(updates)" in body, (
        "R18b-#8 regression: wizard no longer clears orphan cert IDs "
        "from the form"
    )


# ----------------- R18b-#9: drafts table defensive render -----------------


def test_drafts_table_guards_non_array_domains():
    src = (_FRONT / "components" / "SiteDrafts.js")
    if not src.exists():
        pytest.skip("frontend tree not mounted")
    body = src.read_text()
    assert "Array.isArray(raw) ? raw : []" in body, (
        "R18b-#9 regression: drafts table 'Domains' column no longer "
        "guards against a non-array payload — corrupt JSONB will "
        "blank the whole page"
    )
    # The bare `r.payload?.domains || []` pattern was the pre-fix
    # form. It looks safe at a glance but `[].slice` only exists on
    # an Array; a string `"a,b"` would silently slice to `"a,b"`.
    bad_pattern = re.compile(r"r\.payload\?\.domains\s*\|\|\s*\[\]")
    assert not bad_pattern.search(body), (
        "R18b-#9 regression: drafts table still uses the unsafe "
        "`r.payload?.domains || []` fallback that admits string "
        "payloads and silently slices them"
    )
