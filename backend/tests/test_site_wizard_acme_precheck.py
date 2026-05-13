"""v1.5.0 R12 — ACME mode must pre-check HTTPS frontend collisions.

Bulgu #f10: previously the create_proxied_host pre-flight only checked
the HTTPS frontend's name and bind port for upload/existing modes —
ACME deferred the entire HTTPS frontend creation to
_execute_post_completion_actions. That meant a bind-443 collision
(e.g. another wizard run already grabbed it) was only detected AFTER
Let's Encrypt issued the cert, costing the tenant an LE rate-limit
quota on a doomed order.

Fix: pre-check for ALL https-creating modes (upload, existing, acme).
ACME's deferred path keeps its own collision check too (defense in
depth) — but the user gets a clear 400 up front instead of a confusing
post-completion error long after they hit Submit.

These are static source-level assertions.
"""
from pathlib import Path


SOURCE = (
    Path(__file__).resolve().parent.parent
    / "routers"
    / "site_wizard.py"
).read_text()


def test_create_proxied_host_acme_precheck_https_collision():
    """create_proxied_host's pre-flight gate must include 'acme' in the
    https-creating mode set."""
    # Look for the literal tuple membership check.
    assert 'body.ssl.mode in ("upload", "existing", "acme")' in SOURCE, (
        "Bulgu #f10 regression: create_proxied_host's HTTPS frontend "
        "pre-check must run for ACME mode too — otherwise users only "
        "discover the collision after burning an LE rate-limit quota."
    )


def test_preview_acme_precheck_https_collision_warning():
    """The same gate must apply on /preview to surface the warning before
    the user clicks Submit."""
    # Either the literal tuple appears twice (once each in
    # create_proxied_host and preview_create) OR a unified helper. The
    # current implementation duplicates the literal — pin it.
    occurrences = SOURCE.count('body.ssl.mode in ("upload", "existing", "acme")')
    assert occurrences >= 2, (
        "Bulgu #f10 regression: both POST / and POST /preview must include "
        "'acme' in the HTTPS frontend collision pre-check / warning gate."
    )
