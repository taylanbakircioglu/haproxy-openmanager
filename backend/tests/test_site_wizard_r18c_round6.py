"""v1.5.0 R18c round 6 audit fixes — anonymous-read endpoints.

Findings discovered during R18c round 6 (final convergence sweep):

  R18c-#22 (`GET /api/frontends` accepted anonymous GETs — KRITIK
    info leak): pre-fix the listener catalog was readable without a
    JWT, exposing bind addresses, SSL cert IDs, ACL/redirect rules,
    and ssl_verify configuration for every cluster. With wizard-
    created rows now part of the catalog, an unauthenticated
    reader could enumerate the platform's complete frontend
    inventory. Now requires an authenticated caller; the React UI
    already attaches the JWT via axios defaults so the change is
    non-breaking.

  R18c-#23 (`GET /api/backends` accepted anonymous GETs — KRITIK
    info leak): same shape as #22 for backend topology — server
    addresses, ports, ca-file paths, weights — including any rows
    the wizard wired up.

  R18c-#24 (`GET /api/clusters` accepted anonymous GETs — KRITIK
    info leak): clusters are the backbone of cluster-scoped RBAC
    elsewhere; pre-fix the endpoint leaked cluster topology
    (stats socket, config paths, ACME flags, agent counts) without
    any JWT. Now requires authentication so cluster-scoped
    enumeration cannot be done as a passer-by.
"""
from pathlib import Path

import pytest


_REPO = Path(__file__).resolve().parent.parent


def _read(p):
    return p.read_text()


def _function_block(src: str, name: str, *, tail: int = 2500) -> str:
    idx = src.find(f"async def {name}")
    assert idx != -1, f"function {name} not found"
    return src[idx:idx + tail]


# ----------------- R18c-#22: GET /api/frontends auth -----------------


def test_get_frontends_requires_authorization():
    src = _read(_REPO / "routers" / "frontend.py")
    block = _function_block(src, "get_frontends")
    assert "authorization: str = Header" in block, (
        "R18c-#22 KRITIK info leak regression: GET /api/frontends "
        "no longer accepts the Authorization header parameter — "
        "guard removed?"
    )
    assert "get_current_user_from_token(authorization)" in block, (
        "R18c-#22 KRITIK info leak regression: GET /api/frontends "
        "no longer authenticates the caller — full listener "
        "catalog leaks anonymously"
    )


# ----------------- R18c-#23: GET /api/backends auth -----------------


def test_get_backends_requires_authorization():
    src = _read(_REPO / "routers" / "backend.py")
    # The backends function body is very long (extensive docstring +
    # branching), so widen the read window to cover the auth guard.
    block = _function_block(src, "get_backends", tail=4500)
    assert "authorization: str = Header" in block, (
        "R18c-#23 KRITIK info leak regression: GET /api/backends "
        "no longer accepts the Authorization header parameter"
    )
    assert "get_current_user_from_token(authorization)" in block, (
        "R18c-#23 KRITIK info leak regression: GET /api/backends "
        "no longer authenticates the caller — backend server "
        "addresses leak anonymously"
    )


# ----------------- R18c-#24: GET /api/clusters auth -----------------


def test_get_clusters_requires_authorization():
    src = _read(_REPO / "routers" / "cluster.py")
    block = _function_block(src, "get_clusters", tail=4000)
    assert "authorization: str = Header" in block, (
        "R18c-#24 KRITIK info leak regression: GET /api/clusters "
        "no longer accepts the Authorization header parameter"
    )
    assert "get_current_user_from_token(authorization)" in block, (
        "R18c-#24 KRITIK info leak regression: GET /api/clusters "
        "no longer authenticates the caller — cluster topology "
        "(stats socket, config paths) leaks anonymously"
    )


def test_get_cluster_by_id_requires_authorization():
    """R18c convergence: anonymous GET /api/clusters/{id} bypassed
    the round 6 list guard by iterating IDs. Locked down for parity
    with the list endpoint so the attack surface is symmetric."""
    src = _read(_REPO / "routers" / "cluster.py")
    block = _function_block(src, "get_cluster", tail=2500)
    assert "authorization: str = Header" in block, (
        "R18c convergence regression: GET /api/clusters/{id} no "
        "longer accepts the Authorization header — anonymous "
        "ID-iterate enumeration possible despite list endpoint guard"
    )
    assert "get_current_user_from_token(authorization)" in block, (
        "R18c convergence regression: GET /api/clusters/{id} no "
        "longer authenticates the caller"
    )
