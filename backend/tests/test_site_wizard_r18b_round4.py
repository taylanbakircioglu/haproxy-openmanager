"""v1.5.0 R18b round 4 audit fixes — security & data integrity tests.

Findings discovered during R18b round 4:

  R18b-#10 (SSRF guard): ACME diagnostics check_port80 issued an
    outbound HTTP HEAD against operator-supplied domains. If the
    domain resolved to private/loopback/link-local/cloud-metadata
    IP space, the API host became a request-forwarding primitive.
    Pre-fix any authenticated operator could fingerprint internal
    services or hit AWS/GCP metadata IPs. Now we check `ipaddress`
    classification before issuing the HTTP request and skip non-
    public IPs with a "warn" target row.

  R18b-#11 (Cert RBAC bypass): `select_existing_cert` only checked
    `is_active=TRUE`. Pre-fix an operator with cluster-B access
    could reference a cluster-A-only cert id; the helper would
    silently bind the cert to cluster B via `ensure_cluster_junction`,
    granting visibility the listing endpoint forbids. The helper
    now mirrors the listing eligibility rule: the cert must be
    global (no cluster junction rows) OR already bound to the
    target cluster.

  R18b-#11.1 (Server CA bundle scoping): per-server `ssl_certificate_id`
    (HAProxy `ca-file` for upstream verification) had NO cluster
    eligibility check pre-fix — only DB FK integrity. A new helper
    `validate_server_ca_bundle_eligibility` is now called inside the
    wizard transaction.

  R18b-#12 (FK violation → 409): cert/cluster/backend deleted mid-
    create produced a generic 500 from the create endpoint.
    `ForeignKeyViolationError` now maps to 409 with a "retry with
    fresh state" hint.

  R18b-#13 (HSTS max_age cap): `hsts_max_age` accepted unbounded
    ints. An operator could emit `Strict-Transport-Security:
    max-age=10**18` and pin the host to HTTPS forever in every
    browser that observed the response. Now capped at 2 years
    (63072000s), matching the HSTS preload list maximum.
"""
import re
from pathlib import Path

import pytest

from pydantic import ValidationError


_REPO = Path(__file__).resolve().parent.parent
_FRONT = _REPO.parent / "frontend" / "src"


# ----------------- R18b-#10: SSRF guard -----------------


def test_acme_diagnostics_imports_ipaddress():
    src = (_REPO / "services" / "acme_diagnostics.py").read_text()
    assert "import ipaddress" in src, (
        "R18b-#10 regression: acme_diagnostics no longer imports "
        "ipaddress for SSRF guard"
    )


def test_acme_diagnostics_is_public_ip_helper_present():
    """The SSRF guard depends on `_is_public_ip` correctly classifying
    each IP. Verify the helper returns False for the most common
    private/metadata addresses and True for a public address."""
    from services.acme_diagnostics import _is_public_ip
    # Loopback
    assert not _is_public_ip("127.0.0.1")
    # RFC1918
    assert not _is_public_ip("10.0.0.1")
    assert not _is_public_ip("192.168.1.1")
    assert not _is_public_ip("172.20.5.5")
    # Link-local incl. AWS / GCP metadata IP
    assert not _is_public_ip("169.254.169.254")
    # IPv6 loopback / ULA / link-local
    assert not _is_public_ip("::1")
    assert not _is_public_ip("fc00::1")
    # R18b audit fix (round 7 hardening): IPv6 link-local fe80::/10
    # falls under is_link_local in the stdlib; explicit coverage
    # because Python's classification is the only line of defence.
    assert not _is_public_ip("fe80::1")
    assert not _is_public_ip("fe80::dead:beef")
    # Multicast
    assert not _is_public_ip("224.0.0.1")
    # Public addresses
    assert _is_public_ip("8.8.8.8")
    assert _is_public_ip("1.1.1.1")
    assert _is_public_ip("2606:4700:4700::1111")
    # Garbage
    assert not _is_public_ip("not-an-ip")
    assert not _is_public_ip("")
    assert not _is_public_ip(None)  # type: ignore[arg-type]


def test_acme_diagnostics_check_port80_calls_ssrf_guard():
    src = (_REPO / "services" / "acme_diagnostics.py").read_text()
    # The guard helper must be invoked before session.head.
    assert "_all_ips_public" in src, (
        "R18b-#10 regression: check_port80 no longer references the "
        "SSRF guard helper"
    )
    # Non-public IPs must be marked skipped/warned and continue (no probe).
    assert "non-public IP" in src, (
        "R18b-#10 regression: check_port80 no longer emits a non-public "
        "IP skip row"
    )


# ----------------- R18b-#11: select_existing_cert eligibility -----------------


def test_select_existing_cert_filters_by_cluster_eligibility():
    src = (_REPO / "services" / "ssl_service.py").read_text()
    # The query must reference ssl_certificate_clusters with the
    # "global OR already bound" predicate.
    assert "NOT EXISTS" in src and "ssl_certificate_clusters" in src, (
        "R18b-#11 regression: select_existing_cert no longer filters "
        "by cluster eligibility — cross-tenant cert binding is open"
    )
    # The naive pre-R18b query must be gone.
    naive = re.compile(
        r"SELECT id FROM ssl_certificates WHERE id\s*=\s*\$1\s+AND\s+is_active\s*=\s*TRUE\b",
        re.IGNORECASE,
    )
    assert not naive.search(src), (
        "R18b-#11 regression: select_existing_cert still uses the "
        "naive id+is_active query that bypasses cluster scoping"
    )


def test_validate_server_ca_bundle_eligibility_helper_exists():
    src = (_REPO / "services" / "ssl_service.py").read_text()
    assert "async def validate_server_ca_bundle_eligibility" in src, (
        "R18b-#11.1 regression: per-server CA-bundle eligibility "
        "validator is missing from ssl_service"
    )
    # And it must use the same eligibility predicate.
    assert (
        "ssl_certificate_clusters" in src
        and "NOT EXISTS" in src
    ), (
        "R18b-#11.1 regression: validate_server_ca_bundle_eligibility "
        "no longer enforces the cluster eligibility predicate"
    )


def test_site_wizard_router_calls_server_ca_bundle_validator():
    src = (_REPO / "routers" / "site_wizard.py").read_text()
    assert "validate_server_ca_bundle_eligibility" in src, (
        "R18b-#11.1 regression: wizard router no longer calls the "
        "per-server CA-bundle eligibility validator"
    )
    # And the failure path must be a 400, not silent acceptance.
    assert (
        "is not visible to cluster" in src
    ), (
        "R18b-#11.1 regression: server CA-bundle eligibility failure "
        "no longer surfaces a clear error to the operator"
    )


# ----------------- R18b-#12: FK violation → 409 -----------------


def test_site_wizard_create_imports_fk_violation():
    src = (_REPO / "routers" / "site_wizard.py").read_text()
    assert "ForeignKeyViolationError" in src, (
        "R18b-#12 regression: proxied_host router no longer imports "
        "ForeignKeyViolationError"
    )
    assert "except ForeignKeyViolationError" in src, (
        "R18b-#12 regression: create endpoint no longer catches FK "
        "violations — they bubble to a generic 500"
    )
    catch_block = src[src.find("except ForeignKeyViolationError"):]
    catch_block = catch_block[:catch_block.find("except UniqueViolationError")]
    assert "status_code=409" in catch_block, (
        "R18b-#12 regression: FK violation handler no longer raises 409"
    )


# ----------------- R18b-#13: hsts_max_age cap -----------------


def test_hsts_max_age_capped_at_two_years():
    from models.site_wizard import SSLChoice
    # Default OK
    SSLChoice(mode="none", hsts_enabled=True, hsts_max_age=31536000)
    # 2 year cap is the boundary
    SSLChoice(mode="none", hsts_enabled=True, hsts_max_age=63072000)
    # Above the cap must reject
    with pytest.raises(ValidationError):
        SSLChoice(mode="none", hsts_enabled=True, hsts_max_age=63072001)
    with pytest.raises(ValidationError):
        SSLChoice(mode="none", hsts_enabled=True, hsts_max_age=10**18)
    # Negative still rejected by ge=0
    with pytest.raises(ValidationError):
        SSLChoice(mode="none", hsts_enabled=True, hsts_max_age=-1)
