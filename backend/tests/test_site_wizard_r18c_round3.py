"""v1.5.0 R18c round 3 audit fixes — API contract / config / SSRF tests.

Findings discovered during R18c round 3 (concurrency, SSRF,
graceful shutdown, HAProxy config validity, weak TLS):

  R18c-#10 (Frontends bind UNIQUE — KRITIK concurrency): pre-fix
    `check_bind_port_collision` ran a plain SELECT outside the
    wizard transaction with no FOR UPDATE, and the schema had NO
    uniqueness on (cluster_id, bind_address, bind_port). Two
    concurrent wizards could both pass the check and both INSERT,
    producing two active frontends bound to the same port —
    HAProxy refused to reload and the cluster was wedged. Migration
    `ensure_frontends_bind_unique_constraint` adds a partial
    UNIQUE index that serializes the race; the wizard router's
    UniqueViolationError handler (R18b round 3) maps duplicates
    to a clean 409.

  R18c-#11 (HTTPS cleartext fallback — KRITIK SECURITY): pre-fix
    when `ssl_enabled=true` but no certificate path resolved
    (deleted cert, ACME-deferred state) the config generator fell
    through to `bind addr:port` (no `ssl` keyword), silently
    downgrading the operator's HTTPS frontend to CLEARTEXT on the
    same port. The fix omits the bind line entirely and emits an
    ERROR log so the operator notices.

  R18c-#12 (`verify required` without ca-file — KRITIK config
    validity): pre-fix `verify required` was emitted verbatim even
    if the referenced ssl_certificate_id resolved to no PEM,
    producing a config that either failed reload or — worse —
    silently fell through to system trust. The fix downgrades to
    `verify none` with an ERROR log.

  R18c-#13 (SSRF IPv4-mapped IPv6 — KRITIK SECURITY): pre-fix the
    `_is_public_ip` guard tested `is_loopback / is_private` on
    raw IPv6 addresses; an attacker who controlled a domain's
    AAAA record could point it at `::ffff:127.0.0.1` (IPv4-mapped
    loopback) or `::ffff:169.254.169.254` (cloud metadata) and
    bypass the SSRF guard. Now the guard normalizes via
    `.ipv4_mapped` before classification.

  R18c-#14 (Shutdown drain for fire-and-forget audit): pre-fix
    `shutdown_event` immediately closed the DB pool, so any
    in-flight `asyncio.create_task(log_user_activity(...))`
    background task hit "pool is closed" and dropped its row.
    Now the shutdown drains pending tasks for up to 5s before
    closing the pool.

  R18c-#15 (Weak TLS — RFC 8996): pre-fix the wizard accepted
    `TLSv1.0` / `TLSv1.1` for both server and HTTPS frontend
    `ssl_min_ver` / `ssl_max_ver`. Both are formally deprecated.
    The wizard now rejects them with a clear error.
"""
from pathlib import Path
import asyncio

import pytest


_REPO = Path(__file__).resolve().parent.parent


# ----------------- R18c-#10: bind UNIQUE migration -----------------


def test_frontends_bind_unique_migration_present():
    src = (_REPO / "database" / "migrations.py").read_text()
    assert "ensure_frontends_bind_unique_constraint" in src, (
        "R18c-#10 KRITIK regression: bind unique migration "
        "function `ensure_frontends_bind_unique_constraint` "
        "missing — concurrent wizards can race-INSERT duplicate "
        "binds"
    )
    assert "idx_frontends_active_bind_unique" in src, (
        "R18c-#10 KRITIK regression: partial UNIQUE index name "
        "missing — re-creating the index requires the literal "
        "name to remain stable"
    )
    # The migration must be wired into the startup sequence.
    assert "await ensure_frontends_bind_unique_constraint()" in src, (
        "R18c-#10 KRITIK regression: bind unique migration not "
        "called from startup — index will not be created on a "
        "fresh deploy"
    )


# ----------------- R18c-#11: HTTPS cleartext fallback -----------------


def test_haproxy_config_omits_bind_when_ssl_enabled_and_no_cert():
    src = (_REPO / "services" / "haproxy_config.py").read_text()
    # Locate the post-SSL fallback block.
    fallback_idx = src.find("# If no SSL bind was added")
    if fallback_idx == -1:
        # The legacy comment may have been replaced by the new
        # comment block — try a stable anchor on the new code.
        fallback_idx = src.find("if not bind_added:")
    assert fallback_idx != -1, "fallback block anchor missing"
    block = src[fallback_idx:fallback_idx + 1200]
    # The fix MUST have a guard against ssl_enabled=true falling
    # through to a plain bind.
    assert "ssl_enabled" in block, (
        "R18c-#11 KRITIK SECURITY regression: cleartext-fallback "
        "block no longer checks ssl_enabled — HTTPS frontends "
        "with unresolved certs may degrade to plaintext on the "
        "same port"
    )
    assert "SSL BIND OMITTED" in block or "refusing to emit" in block, (
        "R18c-#11 KRITIK SECURITY regression: fallback no longer "
        "OMITS the cleartext bind for ssl_enabled frontends"
    )


# ----------------- R18c-#12: server `verify required` without ca-file -----------------


def test_haproxy_config_downgrades_verify_required_without_ca_file():
    src = (_REPO / "services" / "haproxy_config.py").read_text()
    # The downgrade branch must check has_ca_file.
    assert "verify_lower in ('required', 'optional') and not has_ca_file" in src, (
        "R18c-#12 KRITIK config validity regression: server-line "
        "verify guard no longer downgrades to `verify none` when "
        "the referenced ca-file did not resolve — HAProxy reload "
        "may fail or silently fall through to system trust"
    )
    assert "CONFIG SSL DOWNGRADE" in src, (
        "R18c-#12 regression: downgrade is no longer logged as "
        "ERROR — operator loses the diagnostic trail"
    )


# ----------------- R18c-#13: SSRF IPv4-mapped IPv6 -----------------


def test_is_public_ip_unwraps_ipv4_mapped_ipv6():
    # Import the helper directly and assert behaviour.
    import importlib
    spec = importlib.util.spec_from_file_location(
        "acme_diagnostics_test_import",
        _REPO / "services" / "acme_diagnostics.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    # IPv4-mapped IPv6 loopback / private / link-local must be REJECTED.
    assert mod._is_public_ip("::ffff:127.0.0.1") is False, (
        "R18c-#13 KRITIK SSRF regression: ::ffff:127.0.0.1 "
        "(IPv4-mapped loopback) classified as public — SSRF guard "
        "bypass via crafted AAAA record"
    )
    assert mod._is_public_ip("::ffff:169.254.169.254") is False, (
        "R18c-#13 KRITIK SSRF regression: ::ffff:169.254.169.254 "
        "(cloud metadata IP via IPv4-mapped IPv6) classified as "
        "public"
    )
    assert mod._is_public_ip("::ffff:10.0.0.5") is False, (
        "R18c-#13 regression: IPv4-mapped RFC1918 classified as "
        "public"
    )
    # And the existing public/private classifications must still
    # work for the unwrapped forms.
    assert mod._is_public_ip("127.0.0.1") is False
    assert mod._is_public_ip("10.0.0.5") is False
    assert mod._is_public_ip("8.8.8.8") is True
    assert mod._is_public_ip("2606:4700:4700::1111") is True


# ----------------- R18c-#14: shutdown drains background tasks -----------------


def test_shutdown_drains_background_tasks_before_pool_close():
    src = (_REPO / "main.py").read_text()
    # Locate shutdown_event body.
    sd_idx = src.find("async def shutdown_event")
    assert sd_idx != -1
    body = src[sd_idx:sd_idx + 3000]
    assert "asyncio.all_tasks" in body, (
        "R18c-#14 regression: shutdown_event no longer enumerates "
        "pending background tasks before closing the DB pool — "
        "fire-and-forget audit log writes can be lost"
    )
    assert "asyncio.wait" in body, (
        "R18c-#14 regression: shutdown_event no longer waits for "
        "pending tasks to finish"
    )
    # The drain must happen BEFORE close_database_pool.
    drain_idx = body.find("asyncio.wait")
    pool_close_idx = body.find("close_database_pool()")
    assert 0 < drain_idx < pool_close_idx, (
        "R18c-#14 regression: drain step is no longer ordered "
        "before close_database_pool — closing the pool first "
        "still loses background task writes"
    )


# ----------------- R18c-#15: weak TLS rejection -----------------


def test_wizard_rejects_tls_1_0_and_1_1_on_servers():
    from models.site_wizard import ServerStep
    from pydantic import ValidationError

    base = dict(
        server_name="srv",
        server_address="10.0.0.5",
        server_port=8080,
    )
    for v in ("TLSv1.0", "TLSv1.1"):
        with pytest.raises(ValidationError) as exc:
            ServerStep(**base, ssl_enabled=True, ssl_min_ver=v)
        assert "deprecated" in str(exc.value).lower() or "rfc 8996" in str(exc.value).lower(), (
            f"R18c-#15 regression: server.ssl_min_ver={v} no "
            "longer rejected with the RFC 8996 hint"
        )
        with pytest.raises(ValidationError):
            ServerStep(**base, ssl_enabled=True, ssl_max_ver=v)


def test_wizard_rejects_tls_1_0_and_1_1_on_https_frontend():
    from models.site_wizard import SSLChoice
    from pydantic import ValidationError

    for v in ("TLSv1.0", "TLSv1.1"):
        with pytest.raises(ValidationError):
            SSLChoice(mode="upload", ssl_min_ver=v)
        with pytest.raises(ValidationError):
            SSLChoice(mode="upload", ssl_max_ver=v)


def test_wizard_still_accepts_tls_1_2_and_1_3():
    """Sanity: the rejection is targeted, not blanket."""
    from models.site_wizard import ServerStep, SSLChoice
    base = dict(
        server_name="srv",
        server_address="10.0.0.5",
        server_port=8080,
    )
    for v in ("TLSv1.2", "TLSv1.3"):
        # Should not raise.
        ServerStep(**base, ssl_enabled=True, ssl_min_ver=v)
        ServerStep(**base, ssl_enabled=True, ssl_max_ver=v)
        SSLChoice(mode="upload", ssl_min_ver=v)
        SSLChoice(mode="upload", ssl_max_ver=v)
