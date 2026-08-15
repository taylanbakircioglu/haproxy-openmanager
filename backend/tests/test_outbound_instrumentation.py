"""v1.11.0: every outbound HTTP call is recorded, and instrumentation can never
become the failure.

Two independent risks:

**Secrets.** The outbound calls carry the most sensitive material in the
system: the ACME JWS (a replayable signed capability for the lifetime of its
nonce) and the DNS provider API credentials. Those call sites must opt out of
request-body capture and out of verbatim error text — the tests below assert
that at the call site, not just in the helper.

**Availability.** Both DNS provider funnels end in
`except Exception: raise DnsProviderError("Unexpected ... failure")`, and in
GoDaddy's publish path that reverts `dns_record_published` and stalls the ACME
order. So an exception escaping `outbound_span` would be reported to the
operator as a provider outage. It must never raise — and it must never swallow.
"""
import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dataclasses import replace  # noqa: E402
from unittest.mock import patch  # noqa: E402

from utils import http_instrumentation  # noqa: E402
from utils import request_log_settings  # noqa: E402
from utils.http_instrumentation import (  # noqa: E402
    TARGET_ACME,
    TARGET_DNS_CLOUDFLARE,
    TARGET_DNS_GODADDY,
    outbound_span,
)
from utils.request_log_settings import DEFAULT_CONFIG  # noqa: E402

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(_BACKEND, *parts), encoding="utf-8") as f:
        return f.read()


def _function_body(src, signature):
    start = src.index(signature)
    rest = src[start:]
    # Next def at the same or lower indentation ends the body.
    end = rest.find("\n    async def ", 1)
    alt = rest.find("\n    def ", 1)
    if alt != -1 and (end == -1 or alt < end):
        end = alt
    return rest if end == -1 else rest[:end]


@pytest.fixture
def captured(monkeypatch):
    rows = []
    monkeypatch.setattr(http_instrumentation.request_log_sink, "offer", rows.append)
    monkeypatch.setattr(request_log_settings, "_CACHE", DEFAULT_CONFIG)
    monkeypatch.setattr(http_instrumentation, "get_config", lambda: request_log_settings._CACHE)
    return rows


# --------------------------------------------------------------------------
# outbound_span behaviour
# --------------------------------------------------------------------------

def test_records_a_successful_call(captured):
    async def run():
        async with outbound_span(target=TARGET_ACME, method="POST",
                                 url="https://acme-v02.api.letsencrypt.org/acme/new-order") as span:
            span.set_response(201, {"content-type": "application/json"}, {"status": "pending"})

    asyncio.run(run())

    row = captured[0]
    assert row.direction == "outbound"
    assert row.target == TARGET_ACME
    assert row.method == "POST"
    assert row.status_code == 201
    assert row.status_class == 2
    assert row.response_body_value == {"status": "pending"}


def test_exception_is_recorded_and_reraised_unchanged(captured):
    async def run():
        async with outbound_span(target=TARGET_ACME, method="GET", url="https://example.com/x"):
            raise ValueError("connection reset")

    with pytest.raises(ValueError, match="connection reset"):
        asyncio.run(run())

    row = captured[0]
    assert row.status_code is None
    assert row.status_class == 0, (
        "a call that never got a response must be status_class 0 — the sentinel the "
        "error-retention window keys off"
    )
    assert row.error.startswith("ValueError")


def test_safe_error_only_records_the_type_not_the_message(captured):
    async def run():
        async with outbound_span(target=TARGET_DNS_GODADDY, method="PUT",
                                 url="https://api.godaddy.com/v1/domains/example.com/records/TXT/_acme-challenge",
                                 safe_error_only=True):
            raise RuntimeError("failed talking to https://api.godaddy.com/v1/domains/secret-zone")

    with pytest.raises(RuntimeError):
        asyncio.run(run())

    assert captured[0].error == "RuntimeError"
    assert "secret-zone" not in (captured[0].error or "")


def test_instrumentation_failure_never_becomes_a_provider_failure(captured, monkeypatch):
    """A bug in row construction must not surface to the operator as
    'Unexpected GoDaddy API failure' and stall an ACME order."""
    def explode(row):
        raise RuntimeError("sink is broken")

    monkeypatch.setattr(http_instrumentation.request_log_sink, "offer", explode)

    async def run():
        async with outbound_span(target=TARGET_DNS_CLOUDFLARE, method="GET",
                                 url="https://api.cloudflare.com/client/v4/zones") as span:
            span.set_response(200, {}, {"success": True})
            return "provider-result"

    assert asyncio.run(run()) == "provider-result", (
        "a broken sink propagated out of outbound_span; both DNS funnels would convert "
        "that into DnsProviderError('Unexpected ... failure'), and in GoDaddy's publish "
        "path that reverts dns_record_published and stalls the ACME order"
    )


def test_block_exception_still_propagates_when_the_sink_is_broken(monkeypatch):
    monkeypatch.setattr(http_instrumentation.request_log_sink, "offer",
                        lambda row: (_ for _ in ()).throw(RuntimeError("sink is broken")))

    async def run():
        async with outbound_span(target=TARGET_ACME, method="GET", url="https://example.com"):
            raise KeyError("original")

    with pytest.raises(KeyError, match="original"):
        asyncio.run(run())


def test_capture_body_false_stores_the_summary_not_the_payload(captured):
    async def run():
        async with outbound_span(
            target=TARGET_ACME, method="POST", url="https://acme/new-order",
            request_body={"jws": True, "kid_present": True, "payload_empty": False},
            capture_body=False,
        ) as span:
            span.set_response(200, {}, {"status": "valid"})

    asyncio.run(run())

    row = captured[0]
    assert row.request_body_value == {"jws": True, "kid_present": True, "payload_empty": False}
    assert row.request_body_raw is None
    # The CA's RESPONSE is still captured — that is the half operators need.
    assert row.response_body_value == {"status": "valid"}


def test_urls_are_scrubbed_before_storage(captured):
    async def run():
        async with outbound_span(
            target=TARGET_DNS_CLOUDFLARE, method="GET",
            url="https://user:hunter2@api.cloudflare.com/client/v4/zones?api_key=abc&page=1",
        ) as span:
            span.set_response(200, {}, {})

    asyncio.run(run())

    url = captured[0].url
    assert "hunter2" not in url
    assert "abc" not in url
    assert "page=1" in url


def test_outbound_rows_inherit_the_inbound_request_id(captured):
    from utils.request_log_sink import request_id_context

    async def run():
        token = request_id_context.set("abc123def456")
        try:
            async with outbound_span(target=TARGET_ACME, method="GET", url="https://acme/dir") as span:
                span.set_response(200, {}, {})
        finally:
            request_id_context.reset(token)

    asyncio.run(run())

    assert captured[0].request_id == "abc123def456", (
        "an outbound call must carry the inbound request's id, otherwise the detail view "
        "cannot show which API call triggered which CA/DNS call"
    )


def test_background_calls_get_a_task_scoped_id(captured):
    async def run():
        async with outbound_span(target=TARGET_ACME, method="GET", url="https://acme/dir") as span:
            span.set_response(200, {}, {})

    asyncio.run(run())
    assert captured[0].request_id.startswith("bg:")


def test_disabled_outbound_capture_produces_no_row(captured, monkeypatch):
    monkeypatch.setattr(request_log_settings, "_CACHE",
                        replace(DEFAULT_CONFIG, capture_outbound=False))

    async def run():
        async with outbound_span(target=TARGET_ACME, method="GET", url="https://acme/dir") as span:
            # The call site keeps working — set_response must still be callable.
            span.set_response(200, {}, {})

    asyncio.run(run())
    assert captured == []


def test_set_response_tolerates_a_response_without_headers(captured):
    """Some call sites are driven in tests by minimal fakes exposing only
    `.status`."""
    async def run():
        async with outbound_span(target=TARGET_ACME, method="HEAD", url="https://acme/nonce") as span:
            span.set_response(200, None)

    asyncio.run(run())
    assert captured[0].status_code == 200


# --------------------------------------------------------------------------
# Call-site coverage
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path,target", [
    (("services", "acme_service.py"), "TARGET_ACME"),
    (("services", "acme_diagnostics.py"), "TARGET_ACME_DIAG"),
    (("services", "dns_providers", "cloudflare.py"), "TARGET_DNS_CLOUDFLARE"),
    (("services", "dns_providers", "godaddy.py"), "TARGET_DNS_GODADDY"),
    (("routers", "letsencrypt.py"), "TARGET_LETSENCRYPT_CA"),
    (("routers", "settings.py"), "TARGET_SETTINGS_PROBE"),
    (("haproxy_client.py",), "TARGET_HAPROXY_STATS"),
    (("agent_notifications.py",), "TARGET_AGENT"),
])
def test_every_outbound_module_is_instrumented(path, target):
    src = _read(*path)
    assert "outbound_span(" in src, f"{'/'.join(path)} makes HTTP calls but records nothing"
    assert target in src, f"{'/'.join(path)} does not tag its rows with {target}"


def test_acme_signed_request_never_captures_the_jws_body():
    """The JWS body is {protected, payload, signature}: `protected` carries the
    nonce and account kid, `signature` is made with the account private key. A
    stored (protected, signature) pair is a replayable ACME credential."""
    src = _read("services", "acme_service.py")
    body = _function_body(src, "    async def _signed_request(")

    assert "capture_body=False" in body, (
        "the ACME JWS request body would be written to request_logs verbatim — that is a "
        "replayable signed credential sitting in an audit table"
    )
    assert '"jws": True' in body, "no synthetic summary replaces the suppressed JWS body"


def test_acme_span_is_inside_the_retry_loop():
    """The session is built outside `for attempt in range(3)`; the span must be
    inside it, so a badNonce retry is its own row rather than being folded into
    the successful attempt."""
    src = _read("services", "acme_service.py")
    body = _function_body(src, "    async def _signed_request(")

    loop_at = body.index("for attempt in range(3):")
    span_at = body.index("async with outbound_span(")
    assert loop_at < span_at, (
        "outbound_span wraps the retry loop instead of sitting inside it, so three "
        "attempts collapse into one log row and a nonce retry becomes invisible"
    )


@pytest.mark.parametrize("path", [
    ("services", "dns_providers", "cloudflare.py"),
    ("services", "dns_providers", "godaddy.py"),
])
def test_dns_providers_record_error_types_only(path):
    src = _read(*path)
    body = _function_body(src, "    async def _request(")
    assert "safe_error_only=True" in body, (
        f"{'/'.join(path)} would record the full exception text, which can carry the "
        f"request URL and through it the tenant/zone identifier"
    )


def test_godaddy_narrow_value_error_handling_is_preserved():
    """R-round hardening: only a JSON decode failure may be swallowed. Widening
    it would make a mid-read transport failure look like an empty RRset, and the
    follow-up full-RRset PUT would then destroy coexisting TXT values."""
    src = _read("services", "dns_providers", "godaddy.py")
    body = _function_body(src, "    async def _request(")
    assert "except ValueError:" in body
    assert "except Exception:\n                        body = None" not in body


def test_acme_diagnostics_keeps_its_ipv4_pinned_connector():
    """Duplicates an existing assertion on purpose: instrumenting this module
    must not have refactored the SSRF-guard connector away."""
    src = _read("services", "acme_diagnostics.py")
    assert "TCPConnector(family=socket.AF_INET" in src, (
        "the IPv4 pin was removed from the port-80 probe — that reopens the dual-stack "
        "AAAA bypass the SSRF guard closes"
    )


def test_haproxy_stats_never_logs_basic_auth_or_the_csv():
    """aiohttp.BasicAuth is a NamedTuple whose repr contains the cleartext
    password, and a full stats CSV has no audit value."""
    src = _read("haproxy_client.py")
    body = _function_body(src, "    async def _get_stats_via_http(")
    assert "capture_body=False" in body
    assert "capture_response_body=False" in body
    assert "auth=auth" in body and "request_body=auth" not in body
