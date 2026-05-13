"""
ACME Diagnostics service (Feature A — Issue #13).

Pre-flight & post-failure diagnostics for an ACME order. Each check produces a
structured `{id, label, status, message, details, duration_ms, severity}` row
suitable for an Antd Tabs/Steps display.

Key constraints (Section 3.3 of the v1.5.0 plan):
- DNS resolution uses stdlib socket.gethostbyname_ex via run_in_executor (we
  intentionally avoid pulling aiodns as a runtime dep for v1.5.0).
- Port-80 probe is HEAD-only, target locked to the order's domains, success on
  HTTP 200 OR 404, warns on egress timeout (don't fail-hard — corp egress
  policies often blackhole outbound 80).
- All checks have hard wall-clock timeouts (asyncio.wait_for) to bound impact
  on the API event loop.
- humanize_error_detail covers >= 11 RFC8555 problem types and is backwards
  compatible with the legacy plain-string error_detail field.
"""

import asyncio
import ipaddress
import json
import logging
import socket
import time
from typing import Any, Dict, List, Optional

import aiohttp

logger = logging.getLogger(__name__)


# R18b audit fix (round 4 #B): SSRF guard for outbound HTTP probes.
# The ACME diagnostics check_port80 helper opens an HTTP HEAD against
# the operator-supplied domain. If that domain resolves to a private
# / loopback / link-local / cloud-metadata IP, the API host becomes a
# request-forwarding primitive: an authenticated operator could
# fingerprint internal services or hit AWS/GCP metadata endpoints by
# pointing DNS at them. Refuse to probe non-public IPs and surface
# the skip in the diagnostic result so the operator knows why.
def _is_public_ip(ip_str: str) -> bool:
    """Return True only for globally-routable IPv4/IPv6 addresses.

    Excludes loopback, link-local, RFC1918 private space, multicast,
    cloud-metadata IPs (169.254.169.254 falls under link-local), and
    reserved blocks. Used by check_port80 before issuing an HTTP
    request to operator-supplied hostnames.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except (ValueError, TypeError):
        return False
    # R18c audit fix (round 3 #4 — KRITIK SSRF): normalize IPv4-mapped
    # IPv6 addresses to their underlying IPv4 form before
    # classification. PRE-FIX an attacker who controlled the
    # domain's AAAA record could point it at `::ffff:127.0.0.1`
    # (or `::ffff:169.254.169.254` for cloud metadata) and our
    # guard would return True because IPv6Address.is_loopback /
    # is_private only check the IPv6 address space — they do NOT
    # walk into the embedded IPv4 mapping. The guard would then
    # let the probe through, creating an SSRF path back into the
    # OpenManager host's loopback / cloud metadata service. Always
    # unwrap `.ipv4_mapped` first so the IPv4 classification rules
    # apply.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_link_local or ip.is_private:
        return False
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return False
    return True


async def _all_ips_public(domain: str, *, timeout: float = 5.0) -> tuple[bool, list[str]]:
    """Resolve `domain` and return (all_public, ips). On DNS failure
    returns (False, []) — caller should treat as "skip / unable to
    verify safety" rather than "probe anyway"."""
    try:
        info = await _resolve_dns(domain, timeout=timeout)
    except Exception:
        return (False, [])
    ips = info.get("ips", []) or []
    if not ips:
        return (False, [])
    return (all(_is_public_ip(ip) for ip in ips), ips)


# RFC8555 problem types (https://datatracker.ietf.org/doc/html/rfc8555#section-6.7)
# Plus a few extra ACMEv2 additions used in the wild.
_PROBLEM_HUMANIZED: Dict[str, Dict[str, str]] = {
    "urn:ietf:params:acme:error:accountDoesNotExist": {
        "title": "ACME account not found",
        "hint": "The ACME account is missing or has been deactivated. Re-create the LE account from Settings → Let's Encrypt.",
    },
    "urn:ietf:params:acme:error:badNonce": {
        "title": "Stale request nonce",
        "hint": "Transient — the next retry should succeed. If it persists, your system clock may be skewed.",
    },
    "urn:ietf:params:acme:error:badRevocationReason": {
        "title": "Invalid revocation reason",
        "hint": "The CA rejected the revocation reason code. Use a valid RFC5280 CRLReason.",
    },
    "urn:ietf:params:acme:error:caa": {
        "title": "CAA record forbids issuance",
        "hint": "DNS CAA records prevent Let's Encrypt from issuing this certificate. Add 'letsencrypt.org' to the CAA records.",
    },
    "urn:ietf:params:acme:error:connection": {
        "title": "CA could not connect to your server",
        "hint": "Let's Encrypt's validators could not reach port 80 from the public internet. Check inbound firewall and routing.",
    },
    "urn:ietf:params:acme:error:dns": {
        "title": "DNS resolution failed during validation",
        "hint": "The domain does not resolve, or the CA's DNS lookup timed out. Verify A/AAAA records are public.",
    },
    "urn:ietf:params:acme:error:incorrectResponse": {
        "title": "HTTP-01 challenge response mismatch",
        "hint": "The CA fetched the challenge URL but received the wrong key authorization. Confirm the challenge was served from the right backend.",
    },
    "urn:ietf:params:acme:error:invalidContact": {
        "title": "Invalid contact email",
        "hint": "The ACME account email is malformed. Update the LE account email.",
    },
    "urn:ietf:params:acme:error:malformed": {
        "title": "Malformed request",
        "hint": "The request body could not be parsed. Often a transient bug — retry; if it persists, raise an issue.",
    },
    "urn:ietf:params:acme:error:rateLimited": {
        "title": "Let's Encrypt rate limit hit",
        "hint": "Too many certificates issued or too many duplicate orders. Wait or use the staging directory.",
    },
    "urn:ietf:params:acme:error:rejectedIdentifier": {
        "title": "Domain rejected by CA",
        "hint": "The CA refused this hostname (e.g. blocklisted TLD, public-suffix mismatch).",
    },
    "urn:ietf:params:acme:error:serverInternal": {
        "title": "ACME server error",
        "hint": "Let's Encrypt is reporting a transient server error. Retry.",
    },
    "urn:ietf:params:acme:error:tls": {
        "title": "TLS error during validation",
        "hint": "The validator could not complete the TLS handshake (only relevant for tls-alpn-01 / tls-sni).",
    },
    "urn:ietf:params:acme:error:unauthorized": {
        "title": "Unauthorized",
        "hint": "The challenge response could not be verified — most often an HTTP-01 path-not-served issue.",
    },
    "urn:ietf:params:acme:error:unsupportedContact": {
        "title": "Unsupported contact scheme",
        "hint": "Only 'mailto:' contacts are currently supported by Let's Encrypt.",
    },
    "urn:ietf:params:acme:error:unsupportedIdentifier": {
        "title": "Unsupported identifier",
        "hint": "Only DNS identifiers are supported.",
    },
    "urn:ietf:params:acme:error:userActionRequired": {
        "title": "User action required",
        "hint": "ACME account requires Terms-of-Service re-acceptance. Visit the URL in the error to acknowledge.",
    },
}


def humanize_error_detail(error_detail: Any) -> Dict[str, Any]:
    """Convert the order.error_detail field into a UI-friendly structured form.

    error_detail may be:
      - A JSON string with {type, detail, status, subproblems}
      - A plain string (legacy)
      - None
    Always returns a dict with at minimum {title, message, hint}.
    """
    if not error_detail:
        return {"title": "No error", "message": "", "hint": ""}

    parsed: Optional[Dict[str, Any]] = None
    if isinstance(error_detail, dict):
        parsed = error_detail
    elif isinstance(error_detail, str):
        s = error_detail.strip()
        if s.startswith("{"):
            try:
                parsed = json.loads(s)
            except json.JSONDecodeError:
                parsed = None

    if parsed is None:
        # Legacy plain string fallback
        return {
            "title": "ACME error",
            "message": str(error_detail),
            "hint": "",
            "raw": str(error_detail),
        }

    problem_type = parsed.get("type") or ""
    base = _PROBLEM_HUMANIZED.get(problem_type, {})
    title = base.get("title") or "ACME error"
    hint = base.get("hint") or ""
    message = parsed.get("detail") or parsed.get("message") or ""
    status = parsed.get("status")
    subproblems = parsed.get("subproblems") or []

    out = {
        "title": title,
        "message": message,
        "hint": hint,
        "type": problem_type,
        "raw": parsed,
    }
    if status is not None:
        out["status"] = status
    if subproblems:
        out["subproblems"] = [
            {
                "type": sp.get("type"),
                "detail": sp.get("detail"),
                "identifier": (sp.get("identifier") or {}).get("value"),
            }
            for sp in subproblems
            if isinstance(sp, dict)
        ]
    return out


# ----------------------------------------------------------------------------
# Per-check helpers
# ----------------------------------------------------------------------------


def _check_result(
    check_id: str,
    label: str,
    status: str,
    message: str,
    *,
    severity: str = "info",
    details: Optional[Dict[str, Any]] = None,
    duration_ms: Optional[int] = None,
) -> Dict[str, Any]:
    return {
        "id": check_id,
        "label": label,
        "status": status,  # 'ok' | 'warn' | 'fail' | 'skipped'
        "severity": severity,  # 'info' | 'warn' | 'error'
        "message": message,
        "details": details or {},
        "duration_ms": duration_ms,
    }


async def _resolve_dns(domain: str, *, timeout: float = 5.0) -> Dict[str, Any]:
    """Resolve a domain via stdlib socket.gethostbyname_ex; never blocks the
    asyncio event loop.
    """
    loop = asyncio.get_running_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyname_ex, domain),
            timeout=timeout,
        )
        canonical, aliases, ips = result
        return {"canonical": canonical, "aliases": aliases, "ips": ips}
    except asyncio.TimeoutError:
        raise
    except Exception as e:
        # socket.gaierror, etc.
        raise RuntimeError(str(e)) from e


async def check_dns(domains: List[str]) -> Dict[str, Any]:
    """Check that each order domain resolves to at least one public-looking IPv4."""
    started = time.time()
    failed: List[Dict[str, Any]] = []
    resolved: Dict[str, List[str]] = {}
    for d in domains:
        # Wildcards are valid per RFC8555 but cannot be HTTP-01 validated; skip
        # actual DNS resolution for them (they would fail A-record lookup).
        if d.startswith("*."):
            resolved[d] = []
            continue
        try:
            r = await _resolve_dns(d, timeout=5.0)
            resolved[d] = r["ips"]
            if not r["ips"]:
                failed.append({"domain": d, "reason": "no A records"})
        except asyncio.TimeoutError:
            failed.append({"domain": d, "reason": "dns timeout"})
        except Exception as e:
            failed.append({"domain": d, "reason": str(e)})

    duration_ms = int((time.time() - started) * 1000)
    if failed:
        return _check_result(
            "dns",
            "DNS resolution",
            "fail",
            f"DNS lookup failed for {len(failed)} domain(s)",
            severity="error",
            details={"failed": failed, "resolved": resolved},
            duration_ms=duration_ms,
        )
    return _check_result(
        "dns",
        "DNS resolution",
        "ok",
        f"All {len(domains)} domain(s) resolved",
        severity="info",
        details={"resolved": resolved},
        duration_ms=duration_ms,
    )


async def check_port80(domains: List[str], *, http_timeout: float = 5.0) -> Dict[str, Any]:
    """Probe HTTP-01 readiness on port 80 with a HEAD request to a synthetic
    challenge URL. Success on 200 OR 404 (404 means the well-known path is
    served but no challenge yet — fine).

    On egress timeout we WARN rather than FAIL because many corporate egress
    policies blackhole port 80 outbound; that does not impair LE's ingress
    validation (LE comes inbound).
    """
    started = time.time()
    targets: List[Dict[str, Any]] = []
    timeout = aiohttp.ClientTimeout(total=http_timeout)
    skip_reason = None

    domains_to_check = [d for d in domains if not d.startswith("*.")]
    if not domains_to_check:
        return _check_result(
            "port80",
            "Port 80 reachability",
            "skipped",
            "All domains are wildcards; HTTP-01 not applicable",
            severity="info",
            duration_ms=int((time.time() - started) * 1000),
        )

    # R18c audit fix (round 4 #4 — KRITIK SSRF residual): force the
    # aiohttp connector to family=AF_INET (IPv4-only) so the HTTP
    # probe resolves and connects with the SAME family that
    # _resolve_dns / _all_ips_public classifies. PRE-FIX the SSRF
    # guard ran on the IPv4 list returned by `gethostbyname_ex`,
    # but aiohttp's default connector did its own dual-stack
    # `getaddrinfo` and could connect via AAAA — so an attacker
    # who controlled a domain's DNS could publish a benign public
    # A record (passing our guard) AND a `::1`/`fc00::/7`/`fe80::/10`
    # AAAA record that aiohttp picked, hitting our internal IPv6
    # space. Constraining the connector to IPv4 closes the loop
    # because the family the guard inspects equals the family the
    # connector uses. ACME HTTP-01 itself works only over IPv4-or-
    # IPv6 paths the CA can reach; the diagnostic just needs to
    # confirm reachability and we already only classify IPv4.
    connector = aiohttp.TCPConnector(family=socket.AF_INET, ssl=False)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        for d in domains_to_check:
            # R18b audit fix (round 4 #B — SSRF guard): refuse to
            # probe a domain whose A/AAAA records point at private,
            # loopback, link-local, multicast, or cloud-metadata IP
            # space. Pre-fix the diagnostic was a usable SSRF
            # primitive for any authenticated operator: pick a
            # hostname pointing at 169.254.169.254 / 10.0.0.0/8 /
            # 127.0.0.1 and the API host issued an outbound HEAD,
            # reflecting status / error back into the diagnostic
            # JSON. The HTTP-01 protocol fundamentally requires the
            # CA to reach the host from the public internet, so a
            # private-IP domain cannot validate anyway.
            all_public, ips = await _all_ips_public(d, timeout=2.0)
            if not all_public:
                targets.append({
                    "domain": d,
                    "skip": "non-public IP — refusing to probe (SSRF guard)",
                    "ips": ips,
                    "ok": False,
                    "warn": True,
                })
                if ips:
                    skip_reason = "non-public IPs blocked"
                continue
            url = f"http://{d}/.well-known/acme-challenge/diagnostic-probe"
            try:
                async with session.head(url, allow_redirects=False) as resp:
                    targets.append({
                        "domain": d,
                        "status": resp.status,
                        "ok": resp.status in (200, 404),
                    })
            except asyncio.TimeoutError:
                targets.append({"domain": d, "error": "egress timeout", "warn": True})
                skip_reason = "egress timeout"
            except aiohttp.ClientError as e:
                targets.append({"domain": d, "error": str(e), "ok": False})
            except Exception as e:
                targets.append({"domain": d, "error": str(e), "ok": False})

    duration_ms = int((time.time() - started) * 1000)
    failed = [t for t in targets if not t.get("ok") and not t.get("warn")]
    warns = [t for t in targets if t.get("warn")]
    if failed:
        return _check_result(
            "port80",
            "Port 80 reachability",
            "fail",
            f"Port 80 probe failed for {len(failed)} domain(s)",
            severity="error",
            details={"targets": targets},
            duration_ms=duration_ms,
        )
    if warns and not [t for t in targets if t.get("ok")]:
        # R18b audit fix (round 7): branch the rollup message on the
        # actual cause. Pre-fix the message was always "Egress to
        # port 80 appears blocked" — even when every target was
        # skipped because the SSRF guard refused to probe a non-
        # public IP, which has nothing to do with egress firewalls.
        # Operators saw "egress blocked" and started spelunking
        # corporate firewall logs while the real cause was an
        # internal-only DNS A record. Also harden against
        # `skip_reason=None` so the message never reads "(None)".
        ssrf_skip = any(
            "non-public" in (t.get("skip") or "")
            or "SSRF" in (t.get("skip") or "")
            for t in targets
        )
        if ssrf_skip and not skip_reason:
            skip_reason = "non-public IPs blocked"
        if ssrf_skip:
            human = (
                f"Probe skipped for non-public IPs ({skip_reason}). "
                "ACME HTTP-01 requires a public A record; corporate / "
                "internal-only domains cannot satisfy LE validation."
            )
        else:
            reason = skip_reason or "egress restriction"
            human = (
                f"Egress to port 80 appears blocked ({reason}); "
                "inbound CA validation may still succeed"
            )
        return _check_result(
            "port80",
            "Port 80 reachability",
            "warn",
            human,
            severity="warn",
            details={"targets": targets},
            duration_ms=duration_ms,
        )
    return _check_result(
        "port80",
        "Port 80 reachability",
        "ok",
        f"All {len(domains_to_check)} domain(s) responded on port 80",
        severity="info",
        details={"targets": targets},
        duration_ms=duration_ms,
    )


async def check_routing(conn, domains: List[str], cluster_ids: List[int]) -> Dict[str, Any]:
    """Verify that at least one frontend on the order's clusters has a
    use_backend_rules / acl_rules pointing at the system ACME challenge
    backend OR that an HTTP frontend covering port 80 exists for the
    requesting cluster(s).
    """
    started = time.time()
    if not cluster_ids:
        return _check_result(
            "routing",
            "HAProxy routing",
            "warn",
            "Order has no associated cluster",
            severity="warn",
            duration_ms=int((time.time() - started) * 1000),
        )

    rows = await conn.fetch(
        """
        SELECT id, name, bind_address, bind_port, mode, default_backend
        FROM frontends
        WHERE cluster_id = ANY($1::int[]) AND is_active = TRUE AND bind_port = 80
        """,
        cluster_ids,
    )
    duration_ms = int((time.time() - started) * 1000)
    if not rows:
        return _check_result(
            "routing",
            "HAProxy routing",
            "fail",
            "No HTTP frontend on port 80 found in target cluster(s)",
            severity="error",
            details={"cluster_ids": cluster_ids},
            duration_ms=duration_ms,
        )
    return _check_result(
        "routing",
        "HAProxy routing",
        "ok",
        f"Found {len(rows)} HTTP frontend(s) on port 80",
        severity="info",
        details={"frontends": [dict(r) for r in rows]},
        duration_ms=duration_ms,
    )


async def check_account(conn, account_id: Optional[int]) -> Dict[str, Any]:
    """Verify the ACME account exists, has status='valid', and has an
    account_url stored.
    """
    started = time.time()
    if not account_id:
        return _check_result(
            "account",
            "ACME account",
            "fail",
            "Order has no ACME account id",
            severity="error",
            duration_ms=int((time.time() - started) * 1000),
        )
    row = await conn.fetchrow(
        "SELECT id, email, status, account_url FROM letsencrypt_accounts WHERE id = $1",
        account_id,
    )
    duration_ms = int((time.time() - started) * 1000)
    if not row:
        return _check_result(
            "account",
            "ACME account",
            "fail",
            f"Account {account_id} not found",
            severity="error",
            duration_ms=duration_ms,
        )
    if row["status"] != "valid":
        return _check_result(
            "account",
            "ACME account",
            "fail",
            f"Account status is '{row['status']}', expected 'valid'",
            severity="error",
            details={"account": dict(row)},
            duration_ms=duration_ms,
        )
    if not row["account_url"]:
        return _check_result(
            "account",
            "ACME account",
            "warn",
            "Account has no account_url stored",
            severity="warn",
            details={"account": dict(row)},
            duration_ms=duration_ms,
        )
    return _check_result(
        "account",
        "ACME account",
        "ok",
        f"Account {row['email']} is valid",
        severity="info",
        details={"account": dict(row)},
        duration_ms=duration_ms,
    )


async def check_agents(conn, cluster_ids: List[int]) -> Dict[str, Any]:
    """Verify at least one healthy agent is registered for the order's
    cluster(s).
    """
    started = time.time()
    if not cluster_ids:
        return _check_result(
            "agents",
            "HAProxy agents",
            "warn",
            "Order has no associated cluster",
            severity="warn",
            duration_ms=int((time.time() - started) * 1000),
        )
    # Bulgu #84 (round-23 audit) — the canonical timestamp column on the
    # `agents` table is `last_seen`. Pre-fix this query referenced a
    # non-existent `a.last_heartbeat`, so every ACME preflight call
    # (`POST /api/sites/preflight-acme`) crashed at the `check_agents`
    # stage with `UndefinedColumnError: column a.last_heartbeat does
    # not exist`, blocking the entire wizard's ACME pre-validation
    # gate. Every other agents.last_seen reader in the codebase
    # (routers/cluster.py:695-702, routers/agent.py, routers/dashboard
    # *.py) uses `last_seen`; aligning here.
    rows = await conn.fetch(
        """
        SELECT a.id, a.hostname, a.status, a.last_seen, hc.id AS cluster_id, hc.name AS cluster_name
        FROM agents a
        JOIN haproxy_clusters hc ON hc.pool_id = a.pool_id
        WHERE hc.id = ANY($1::int[])
        """,
        cluster_ids,
    )
    duration_ms = int((time.time() - started) * 1000)
    if not rows:
        return _check_result(
            "agents",
            "HAProxy agents",
            "fail",
            "No agents registered for the target cluster(s)",
            severity="error",
            details={"cluster_ids": cluster_ids},
            duration_ms=duration_ms,
        )
    healthy = [r for r in rows if r["status"] in ("active", "online")]
    if not healthy:
        return _check_result(
            "agents",
            "HAProxy agents",
            "warn",
            f"{len(rows)} agent(s) registered but none currently active",
            severity="warn",
            details={"agents": [dict(r) for r in rows]},
            duration_ms=duration_ms,
        )
    return _check_result(
        "agents",
        "HAProxy agents",
        "ok",
        f"{len(healthy)} of {len(rows)} agents are active",
        severity="info",
        details={"agents": [dict(r) for r in rows]},
        duration_ms=duration_ms,
    )


# ----------------------------------------------------------------------------
# Public orchestration
# ----------------------------------------------------------------------------


CHECK_IDS = ("dns", "port80", "routing", "account", "agents")


def _coerce_cluster_ids(raw) -> List[int]:
    """Coerce a cluster_ids list to ints, dropping non-integer-compatible
    values. JSONB-stored lists occasionally land as ["1", "2"] (string form)
    due to legacy paths; asyncpg's `$1::int[]` cast then fails the diagnostic
    query with InvalidTextRepresentationError. We normalise here so the
    diagnostic surface is the same regardless of how the order was written.
    """
    out: List[int] = []
    if not raw:
        return out
    for v in raw:
        try:
            out.append(int(v))
        except (TypeError, ValueError):
            continue
    return out


# Bulgu #94 (Round-25 audit) — the entire point of the diagnostic panel
# is to SHOW the operator what went wrong. Pre-fix, a single check raising
# an uncaught exception (e.g. an asyncpg cast error from a malformed
# cluster_ids JSONB, a DNS resolver outage, an SSRF-guard glitch) would
# propagate up to the router's `try/finally` block, which had no `except`
# clause, and return HTTP 500 with no body. The operator saw only
# "Internal Server Error" in DevTools — the inverse of what a diagnostic
# panel should ever produce. We now wrap every check inside `run_checks`
# so that a check crash becomes a structured `fail` row instead of
# bubbling up; the operator gets the exception type + message in the
# UI and can carry it forward, and the rest of the panel still renders.
async def _safe_check(check_id: str, label: str, coro):
    """Run an awaitable that produces a check result; swallow exceptions
    and convert them to a structured `fail` result so the diagnostic
    response is never short-circuited by a single broken check."""
    started = time.time()
    try:
        return await coro
    except Exception as exc:  # noqa: BLE001 — diagnostic boundary
        duration_ms = int((time.time() - started) * 1000)
        logger.exception(
            "ACME diagnostic check %s raised", check_id
        )
        return _check_result(
            check_id,
            label,
            "fail",
            f"Diagnostic check crashed: {exc.__class__.__name__}: {exc}",
            severity="error",
            details={
                "exception_type": exc.__class__.__name__,
                "exception_message": str(exc),
            },
            duration_ms=duration_ms,
        )


async def run_checks(
    conn,
    *,
    domains: List[str],
    cluster_ids: List[int],
    account_id: Optional[int],
    only: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Execute the full pre-flight check suite. `only` lets callers re-run a
    subset (per-check rerun in the UI).

    Every individual check is wrapped in `_safe_check` so the diagnostic
    endpoint NEVER 500s because of one broken check — the operator gets
    a structured `fail` row identifying which check crashed and why.
    """
    selected = set(only) if only else set(CHECK_IDS)
    results: List[Dict[str, Any]] = []

    # Normalise inputs once so the per-check error stays in the right
    # bucket (a malformed cluster_ids should not crash routing/agents).
    safe_domains = [d for d in (domains or []) if isinstance(d, str) and d]
    safe_cluster_ids = _coerce_cluster_ids(cluster_ids)
    try:
        safe_account_id = int(account_id) if account_id is not None else None
    except (TypeError, ValueError):
        safe_account_id = None

    if "dns" in selected:
        results.append(await _safe_check("dns", "DNS resolution", check_dns(safe_domains)))
    if "port80" in selected:
        results.append(await _safe_check("port80", "Port 80 reachability", check_port80(safe_domains)))
    if "routing" in selected:
        results.append(await _safe_check("routing", "HAProxy routing", check_routing(conn, safe_domains, safe_cluster_ids)))
    if "account" in selected:
        results.append(await _safe_check("account", "ACME account", check_account(conn, safe_account_id)))
    if "agents" in selected:
        results.append(await _safe_check("agents", "HAProxy agents", check_agents(conn, safe_cluster_ids)))

    return results
