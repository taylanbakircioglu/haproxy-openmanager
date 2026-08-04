"""
v1.9.0 CSR creation — behavioral auth tests for /api/ssl/csrs endpoints
(pattern: test_ssl_list_endpoint_auth.py).

Every CSR endpoint must refuse unauthenticated / garbage-token requests.
The CSR detail route additionally must never 200 without auth because it
returns the CSR PEM; no endpoint ever returns the private key, but auth is
the first line regardless.
"""
import pytest

_VALID_CREATE_BODY = {
    "name": "auth-test-csr",
    "common_name": "www.example.com",
}

_VALID_IMPORT_BODY = {
    "certificate_content": (
        "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----"
    ),
    "is_global": True,
}

_ENDPOINTS = [
    ("get", "/api/ssl/csrs", None),
    ("get", "/api/ssl/csrs/1", None),
    ("post", "/api/ssl/csrs", _VALID_CREATE_BODY),
    ("post", "/api/ssl/csrs/1/import", _VALID_IMPORT_BODY),
    ("delete", "/api/ssl/csrs/1", None),
]


@pytest.mark.parametrize("method,path,body", _ENDPOINTS)
def test_csr_endpoint_unauthenticated_rejected(client, method, path, body):
    """No Authorization header → endpoint must refuse the request."""
    res = getattr(client, method)(path, json=body) if body is not None else getattr(client, method)(path)
    assert res.status_code in (401, 403, 422), (
        f"{method.upper()} {path} without Authorization returned "
        f"{res.status_code} — anonymous access to CSR data must not be "
        f"possible. Body: {res.text[:200]}"
    )
    if res.status_code == 200:  # defensive, mirrors the R18 test style
        data = res.json()
        assert not data, "CSR endpoint returned data without auth"


@pytest.mark.parametrize("method,path,body", _ENDPOINTS)
def test_csr_endpoint_invalid_token_rejected(client, method, path, body):
    """Garbage token → endpoint must refuse the request."""
    headers = {"Authorization": "Bearer not-a-valid-jwt"}
    if body is not None:
        res = getattr(client, method)(path, json=body, headers=headers)
    else:
        res = getattr(client, method)(path, headers=headers)
    assert res.status_code in (401, 403, 422), (
        f"{method.upper()} {path} with an invalid token returned {res.status_code}"
    )


def test_csr_routes_are_registered(client):
    """The router must actually be mounted — a 404 would make the auth tests
    above pass vacuously."""
    res = client.get("/api/ssl/csrs")
    assert res.status_code != 404, (
        "GET /api/ssl/csrs returned 404 — csr_router is not registered in main.py"
    )
