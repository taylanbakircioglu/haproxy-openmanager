"""v1.5.0 R18 audit ROUND 4 — behavioral test for the SSL list endpoint
authentication fix.

Round 2 added an auth guard to GET /api/ssl/certificates. That fix had
only static-source coverage. Round 4 adds a behavioral assertion via
FastAPI's TestClient: an HTTP request without an Authorization header
must NOT receive 200 — it must be rejected with 401 (or whatever the
shared auth_middleware produces) to prevent anonymous enumeration.

We use the existing `client` fixture from conftest. The exact status
may be 401 (Unauthorized) or 403 (Forbidden) depending on the
auth_middleware policy; either is acceptable as long as the response
is NOT a 200 with cert data.
"""
import pytest


def test_ssl_list_unauthenticated_request_rejected(client):
    """No Authorization header → endpoint must refuse the request."""
    res = client.get("/api/ssl/certificates")
    # Anything in the auth-failure family is fine; what we forbid is
    # 200-with-data (which was the pre-R18 leak).
    assert res.status_code in (401, 403, 422), (
        f"R18 audit (round 4) regression: GET /api/ssl/certificates "
        f"without Authorization returned {res.status_code} — anonymous "
        f"enumeration of SSL certificate metadata is possible again. "
        f"Body: {res.text[:200]}"
    )
    # Defensive check: even if some misconfiguration returned 200,
    # the body must not be a list of certs.
    if res.status_code == 200:
        data = res.json()
        assert not isinstance(data, list) or len(data) == 0, (
            "R18 audit regression: SSL list returned data without auth"
        )


def test_ssl_list_with_invalid_token_rejected(client):
    """Garbage token → endpoint must refuse the request."""
    res = client.get(
        "/api/ssl/certificates",
        headers={"Authorization": "Bearer not-a-valid-jwt"},
    )
    assert res.status_code in (401, 403, 422), (
        f"R18 audit (round 4) regression: GET /api/ssl/certificates "
        f"with an invalid token returned {res.status_code}"
    )
