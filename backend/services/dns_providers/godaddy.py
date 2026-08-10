"""GoDaddy DNS provider for ACME DNS-01 (Issue #35 follow-up, v1.10.0).

Uses the GoDaddy Domains API v1 over aiohttp (no new dependency). The base URL is a hardcoded
constant and redirects are not followed (no user-controlled URL — only the already-validated
domain name selects which zone is touched), which is the same reason cloudflare.py is exempt from
utils/ssrf_guard.py. Every failure is wrapped in DnsProviderError with a SANITIZED message: the
API Key and Secret are scrubbed out of any text that could reach a log, an order event, or
letsencrypt_orders.error_detail.

Two GoDaddy-specific hazards drive the shape of this module — neither exists on Cloudflare:

1. NO PER-VALUE WRITE. `PUT /v1/domains/{d}/records/TXT/{name}` REPLACES the entire RRset at that
   type+name; it does not merge. A certificate for `example.com` + `*.example.com` publishes two
   DIFFERENT TXT values at the SAME name `_acme-challenge.example.com` (base.py's additive
   contract), so a naive single-value PUT would silently destroy the sibling and fail the wildcard
   authorization. Every mutation here is therefore read-modify-write: GET the current RRset, merge,
   PUT the whole list back. An EMPTY array is rejected (422 INVALID_BODY, "Records must be
   specified"), so removing the LAST value must use DELETE — never `PUT []`.

2. ZONE-DESTRUCTIVE SIBLING PATHS. `PUT /v1/domains/{d}/records/TXT` (three segments, no name)
   wipes EVERY TXT in the zone — SPF, DKIM, DMARC, Microsoft/Google verification — and
   `PUT /v1/domains/{d}/records` wipes the whole zone (this is dehydrated issue #430 verbatim).
   The record path is built only by _rrset_path(), which refuses an empty zone or relative name so
   a URL can never collapse onto one of those endpoints.

Concurrency: v1 has no ETag, no If-Match and no per-record id, so read-modify-write can lose an
update if two mutations at one name overlap. Today they cannot: orders are advanced sequentially
(`for oid in claimed_ids: await advance_dns01_order(oid)` in main.py) and an order's challenges are
published sequentially (`for ch in challenges: await provider.add_txt_record(...)` in
dns01_orchestrator.py), so the apex+wildcard pair is strictly ordered and the second publish sees
the first. _rrset_lock() makes that safety structural rather than incidental. Across REPLICAS the
window is real but narrow (two orders publishing at the same record name in overlapping cycles) and
self-healing: a lost publish ends `invalid` and the bounded retry chain mints a fresh order, a lost
cleanup is retried by the reconcile sweep, and an orphaned `_acme-challenge` TXT is inert. The real
fix is the v3 API (POST + DELETE by recordId, natively per-value), which is PAT-only and a
follow-up; it is deliberately not used here because v1 + sso-key is what operators can use today.

Credentials: an API Key + Secret pair from https://developer.godaddy.com/keys. It must be a
PRODUCTION key — the first key the dashboard issues is an OTE (test) key and an OTE credential
against api.godaddy.com returns 401. A Personal Access Token also works: paste it as the API Key
and leave the Secret blank, and the Authorization header becomes `Bearer <token>`. That path is not
cosmetic — GoDaddy marks sso-key "deprecated, supported through 2026" and the current v1 OpenAPI
advertises only bearer auth, so the PAT is the migration target, not an alternative.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import aiohttp

from .base import DnsProvider, DnsProviderError

logger = logging.getLogger(__name__)

GODADDY_API_BASE = "https://api.godaddy.com/v1"
_TIMEOUT = aiohttp.ClientTimeout(total=20)

# GoDaddy enforces a 600s (10 min) TTL floor at request time. The published v1 OpenAPI declares no
# minimum, so a smaller value is not caught by the schema — it fails with
# 422 {"code":"INVALID_BODY","fields":[{"message":"must have a minimum value of 600", ...}]}.
# Pin the floor; DNS-01 has no reason to want anything longer.
_TXT_TTL = 600

# Read-modify-write serialization, keyed by the RRset (record name), not the zone — the RRset is the
# actual unit of contention, and keying on it avoids serializing unrelated subdomains of one zone.
# The orchestrator is sequential today (see the module docstring), so this is defence in depth: it
# is what stops a future `asyncio.gather()` over the publish loop from silently breaking every
# wildcard+apex certificate. Bounded in practice by the certificate inventory of one process, so
# there is no eviction; the entries are empty Lock objects.
_RRSET_LOCKS: Dict[str, asyncio.Lock] = {}


def _rrset_lock(record_name: str) -> asyncio.Lock:
    key = (record_name or "").rstrip(".").lower()
    lock = _RRSET_LOCKS.get(key)
    if lock is None:
        # Safe without a guard: a single event loop never preempts between the get and the assign.
        lock = _RRSET_LOCKS[key] = asyncio.Lock()
    return lock


def _scrub(text: str, *secrets: str) -> str:
    """Remove credential substrings from a message before it can reach a log or an order event.

    GoDaddy error bodies do not echo the Authorization header, so this is belt-and-braces — but it
    makes base.py's "never leak a secret" invariant structural instead of a matter of care. Short
    strings are skipped so a 1-2 char credential fragment cannot blank out ordinary prose.
    """
    out = text or ""
    for secret in secrets:
        if secret and len(secret) >= 4:
            out = out.replace(secret, "***")
    return out[:300]


def _relative_name(fqdn: str, zone: str) -> str:
    """Convert an absolute record name to the zone-relative form GoDaddy's API requires.

    GoDaddy record names are RELATIVE to the zone with NO trailing dot, and the zone apex is the
    literal "@" — never an empty string (which would collapse the URL onto the zone-wide TXT
    endpoint) and never the domain name itself.

      ("_acme-challenge.example.com",         "example.com") -> "_acme-challenge"
      ("_acme-challenge.foo.bar.example.com", "example.com") -> "_acme-challenge.foo.bar"
      ("example.com",                         "example.com") -> "@"
    """
    f = (fqdn or "").rstrip(".").lower()
    z = (zone or "").rstrip(".").lower()
    if z and f == z:
        return "@"
    if z and f.endswith("." + z):
        return f[: -(len(z) + 1)]
    # Defensive: callers always pass a zone that _resolve_domain derived from this very name.
    return f or "@"


def _rrset_path(zone: str, rel_name: str) -> str:
    """Build the 4-segment record path `/domains/{zone}/records/TXT/{name}`.

    SAFETY GATE: an empty rel_name would collapse the URL to `/domains/{zone}/records/TXT` — the
    endpoint that replaces EVERY TXT record in the zone (SPF, DKIM, DMARC, domain verifications).
    A "." or ".." segment does the same thing one step later: `quote()` leaves both untouched
    (they are unreserved) and yarl normalizes dot segments away when it builds the URL, so
    ".../records/TXT/.." would resolve to ".../records" — the whole-zone endpoint. Refuse both
    rather than build them. `safe=''` percent-encodes the apex "@" as "%40" (accepted bare too,
    but safer through proxies); "_", "-" and "." are unreserved and pass through unchanged, so a
    multi-label relative name stays one readable path segment.
    """
    if not zone or not rel_name:
        raise DnsProviderError("Internal error: refusing to build a zone-wide GoDaddy TXT record path.")
    if rel_name.strip(".") == "" or any(part in (".", "..") for part in rel_name.split("/")):
        raise DnsProviderError("Internal error: refusing to build a GoDaddy TXT path from a dot segment.")
    return f"/domains/{quote(zone, safe='')}/records/TXT/{quote(rel_name, safe='')}"


def _live_values(records: List[Dict]) -> List[str]:
    """The non-empty `data` values in an RRset read.

    GoDaddy leaves tombstone rows with `"data": ""` behind at a name after some removals. Echoing
    one back in a PUT body is rejected with 422 INVALID_BODY, so every field implementation
    (lego, acme.sh, Posh-ACME) filters them independently — so do we.
    """
    out: List[str] = []
    for rec in records or []:
        data = (rec or {}).get("data") or ""
        if data:
            out.append(data)
    return out


def _merge_add(existing: List[Dict], value: str) -> Optional[List[Dict]]:
    """PUT body that adds `value` while preserving every coexisting sibling value.

    Returns None when `value` is already present — an idempotent no-op, which is where an ACME
    retry cycle lands.
    """
    live = _live_values(existing)
    if value in live:
        return None
    return [{"data": d, "ttl": _TXT_TTL} for d in live] + [{"data": value, "ttl": _TXT_TTL}]


def _merge_remove(existing: List[Dict], value: str) -> Optional[List[Dict]]:
    """PUT body that removes ONLY `value`, keeping every sibling.

    Three-state result, because GoDaddy needs three different calls:
      None -> `value` is not there; already gone, tolerate (base.py's remove contract).
      []   -> it was the last value; the caller must DELETE, since `PUT []` is rejected.
      list -> PUT this body.
    """
    live = _live_values(existing)
    if value not in live:
        return None
    return [{"data": d, "ttl": _TXT_TTL} for d in live if d != value]


def _require_rrset(body: Any) -> List[Dict]:
    """The RRset read, or a refusal.

    FAIL CLOSED. A read that did not come back as a JSON array must never be treated as "the RRset
    is empty" — the very next call is a full-RRset PUT, so coercing an unreadable read to [] would
    replace every coexisting sibling value with just ours. Failing instead is free: the orchestrator
    reverts the publish flag and retries next cycle, while a destructive PUT is unrecoverable.
    """
    if not isinstance(body, list):
        raise DnsProviderError(
            "GoDaddy returned an unreadable TXT record list; refusing to replace the record set."
        )
    return body


def _error_fields(body: Any) -> Tuple[str, str]:
    """The whitelisted (code, message) pair from a GoDaddy error body.

    Only these two string fields are ever read; the raw body is never interpolated into a
    user-facing message.
    """
    if not isinstance(body, dict):
        return "", ""
    code = body.get("code")
    message = body.get("message")
    return (code if isinstance(code, str) else ""), (message if isinstance(message, str) else "")


def _retry_after_seconds(headers, body: Any) -> int:
    """Seconds to wait after a 429.

    The current platform sends `Retry-After` and `ratelimit-reset` headers with no body, while the
    legacy v1 OpenAPI documents an `ErrorLimit` body carrying `retryAfterSec`. All three shapes are
    live in the wild — and so is none of them, hence the 60s default.
    """
    for key in ("Retry-After", "ratelimit-reset"):
        raw = (headers or {}).get(key)
        if raw:
            try:
                return max(1, int(str(raw).strip()))
            except (TypeError, ValueError):
                pass
    if isinstance(body, dict):
        raw = body.get("retryAfterSec")
        if isinstance(raw, int) and raw > 0:
            return raw
    return 60


class _GoDaddyHTTPError(DnsProviderError):
    """A DnsProviderError that also carries the HTTP status and GoDaddy `code`.

    Callers INSIDE this module branch on the status (tolerate a 404 read-back, fall through a
    zone probe), while everything outside — dns01_orchestrator, letsencrypt.py — still sees a
    plain sanitized DnsProviderError and needs no change.
    """

    def __init__(self, message: str, status: int, code: str = ""):
        super().__init__(message)
        self.status = status
        self.code = code


class GoDaddyDNSProvider(DnsProvider):
    name = "godaddy"
    label = "GoDaddy"
    automated = True
    credential_fields: List[Dict] = [
        {
            "key": "api_key",
            "label": "API Key",
            "type": "password",
            "required": True,
            "max_length": 200,
            "help": ("Production API Key from developer.godaddy.com/keys — the first key the dashboard "
                     "issues is an OTE (test) key and will be rejected. A Personal Access Token also "
                     "works: paste it here and leave the Secret blank."),
        },
        {
            "key": "api_secret",
            "label": "API Secret",
            "type": "password",
            "required": False,
            "max_length": 200,
            "help": ("The Secret half of the same API Key pair. Leave blank ONLY if the field above "
                     "holds a Personal Access Token. The account also needs at least one registered "
                     "domain for GoDaddy to allow DNS API access at all."),
        },
    ]

    def __init__(self, credentials: Dict[str, str] | None = None):
        super().__init__(credentials)
        # Normalize, never validate: dns01_orchestrator.py calls get_provider() OUTSIDE any
        # DnsProviderError guard, so a constructor that raised on malformed credentials would escape
        # as an unhandled exception in the 60s background cycle. The UI drops blank fields before
        # submitting, so a left-blank field arrives as a MISSING key rather than "" — `.get() or ""`
        # covers both.
        self._api_key = (self.credentials.get("api_key") or "").strip()
        self._api_secret = (self.credentials.get("api_secret") or "").strip()
        # Per-INSTANCE zone cache. A module-level cache would leak one ACME account's zone visibility
        # into another's; an instance lives for exactly one orchestrator step, which is precisely the
        # scope where caching pays off (apex + wildcard resolve the same zone from the same name).
        self._zone_cache: Dict[str, str] = {}

    def _auth_header(self) -> str:
        """`sso-key <key>:<secret>` when a Secret is present, else `Bearer <token>` for a PAT.

        Literal prefix, one space, a single colon — no base64, no URL-encoding, no quotes. Keeping
        this as one swappable string is what makes GoDaddy's sso-key sunset a credential change
        rather than a code change.
        """
        if self._api_secret:
            return f"sso-key {self._api_key}:{self._api_secret}"
        return f"Bearer {self._api_key}"

    def _headers(self) -> Dict[str, str]:
        # Accept is not optional: these endpoints content-negotiate application/xml and
        # text/javascript. Content-Type is required on every write or GoDaddy answers 400/415.
        return {
            "Authorization": self._auth_header(),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _http_error(self, status: int, code: str, message: str, retry_after: Optional[int]) -> _GoDaddyHTTPError:
        """Map an HTTP status to a sanitized, operator-actionable DnsProviderError.

        These strings land in acme_order_events and letsencrypt_orders.error_detail and are shown
        in the order timeline, so each one names what to fix. GoDaddy's own `code`/`message` is
        appended when present because the two 403 causes — account not eligible for the DNS API vs.
        a PAT missing `domains.dns:update` — are indistinguishable by status alone. Scrubbing
        happens HERE, at the single point where provider-supplied text enters a message, so a new
        caller cannot forget it.
        """
        code = _scrub(code, self._api_key, self._api_secret)
        message = _scrub(message, self._api_key, self._api_secret)
        if status == 401:
            detail = ("GoDaddy rejected the API credentials. Check they are a PRODUCTION Key/Secret pair "
                      "from developer.godaddy.com/keys — the first key the dashboard issues is an OTE "
                      "(test) key and is not valid here.")
        elif status == 403:
            detail = ("GoDaddy denied access to the DNS API. The account needs at least one registered "
                      "domain, and a Personal Access Token needs the domains.domain:read and "
                      "domains.dns:update scopes.")
        elif status == 404:
            detail = ("GoDaddy has no zone for this domain (check it is registered in this account and "
                      "uses GoDaddy nameservers).")
        elif status == 409:
            detail = "GoDaddy reports this domain is not eligible to have its DNS records changed."
        elif status == 422:
            detail = "GoDaddy rejected the record change as invalid (HTTP 422)."
        elif status == 429:
            detail = f"GoDaddy rate limit reached; retry in ~{retry_after or 60}s."
        else:
            detail = f"GoDaddy API error (HTTP {status})."
        if code or message:
            detail += f" (GoDaddy: {code}{': ' + message if message else ''})"
        return _GoDaddyHTTPError(detail, status=status, code=code)

    async def _request(self, session: aiohttp.ClientSession, method: str, path: str, **kwargs) -> Any:
        """One GoDaddy API call. Returns the parsed JSON body, or None for the empty-bodied writes.

        Raises a SANITIZED _GoDaddyHTTPError / DnsProviderError — never the credentials, never the
        request, never a response body verbatim.
        """
        url = f"{GODADDY_API_BASE}{path}"
        # v1.11.0: single funnel for every GoDaddy call. `safe_error_only=True`
        # keeps the recorded error to the exception TYPE, matching the stance the
        # handlers below already take — a raw message can carry the request URL.
        # The `Authorization: sso-key <key>:<secret>` header never reaches the log:
        # the header allowlist reduces it to a presence marker.
        from utils.http_instrumentation import outbound_span, TARGET_DNS_GODADDY

        try:
            async with outbound_span(
                target=TARGET_DNS_GODADDY,
                method=method,
                url=url,
                request_body=kwargs.get("json"),
                safe_error_only=True,
            ) as span:
                async with session.request(
                    method, url, headers=self._headers(), allow_redirects=False, **kwargs
                ) as resp:
                    try:
                        # content_type=None: every GoDaddy write answers 200/204 with an EMPTY body, and
                        # aiohttp would otherwise raise on the missing/other content type before parsing.
                        body = await resp.json(content_type=None)
                    except ValueError:
                        # ONLY a decode failure (JSONDecodeError subclasses ValueError) is swallowed —
                        # an empty write body, or an HTML error page on a >=400. A transport failure
                        # mid-read (ClientPayloadError, TimeoutError) must NOT land here: it would look
                        # identical to "empty body", and a caller that reads an RRset would then see
                        # None and could mistake it for an empty RRset. Those propagate to the handlers
                        # below and become a real DnsProviderError.
                        body = None
                    span.set_response(resp.status, getattr(resp, "headers", None), body)
                    # 2xx only. Redirects are deliberately not followed (aiohttp would forward the
                    # Authorization header), so a 3xx is a failed call — treating `< 400` as success
                    # would report a redirected write as a silent no-op.
                    if 200 <= resp.status < 300:
                        return body
                    code, message = _error_fields(body)
                    retry_after = _retry_after_seconds(resp.headers, body) if resp.status == 429 else None
                    raise self._http_error(resp.status, code, message, retry_after)
        except DnsProviderError:
            raise
        except aiohttp.ClientError as exc:
            # Only the exception TYPE is interpolated: an aiohttp client error's str() can carry the
            # request URL, and the message is persisted to the order timeline.
            raise DnsProviderError(f"Could not reach the GoDaddy API ({type(exc).__name__}).")
        except Exception as exc:  # noqa: BLE001
            raise DnsProviderError(f"Unexpected GoDaddy API failure ({type(exc).__name__}).")

    async def verify_credentials(self) -> Dict:
        if not self._api_key:
            return {"ok": False, "detail": "No GoDaddy API Key provided."}
        try:
            async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
                # Cheapest read-only check: one request, no zone needed. Deliberately NOT
                # GET /v1/domains/{domain} — GoDaddy has rejected that details call for small
                # accounts since 2024-05 while record-level calls keep working, so verifying with it
                # produces false negatives on accounts where DNS-01 would succeed.
                body = await self._request(session, "GET", "/domains?limit=1")
            if not isinstance(body, list):
                return {"ok": False, "detail": "GoDaddy returned an unexpected response to the credential check."}
            if not body:
                # An empty list is NOT a failure: sub-zones delegated to GoDaddy nameservers are
                # manageable via the records API but never appear in the domain listing.
                return {"ok": True, "detail": ("GoDaddy credentials valid, but no domains are visible in this "
                                               "account — the domain you validate must be registered here, or "
                                               "be a zone delegated to GoDaddy nameservers.")}
            return {"ok": True, "detail": "GoDaddy credentials valid."}
        except DnsProviderError as exc:
            detail = str(exc)
            if not self._api_secret:
                # The Bearer path is silent otherwise, and a half-filled form is the likeliest cause.
                detail += (" Note: no API Secret was entered, so the API Key was sent as a Personal Access "
                           "Token (Bearer). If you have a Key + Secret pair, enter both halves.")
            return {"ok": False, "detail": detail}
        except Exception:  # noqa: BLE001 — never leak an internal/transport error verbatim
            return {"ok": False, "detail": "Could not verify the GoDaddy credentials."}

    async def _resolve_domain(self, session: aiohttp.ClientSession, record_name: str) -> str:
        """Find the most-specific (longest-suffix) GoDaddy-managed zone for an absolute record name.

        GoDaddy has no `/zones?name=` equivalent, so this walks suffixes longest-to-shortest and
        probes `GET /v1/domains/{candidate}/records/NS`. That probe (rather than the domain listing
        or the domain-details call) is deliberate: it finds sub-zones delegated to GoDaddy
        nameservers, which never appear in `GET /v1/domains` at all, and it does not depend on the
        details endpoint that small accounts are rejected from.
        """
        cached = self._zone_cache.get(record_name)
        if cached:
            return cached
        labels = record_name.rstrip(".").lower().split(".")
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            if candidate.count(".") < 1:
                break  # a zone needs at least two labels
            try:
                body = await self._request(
                    session, "GET", f"/domains/{quote(candidate, safe='')}/records/NS"
                )
            except _GoDaddyHTTPError as exc:
                if exc.status in (404, 422):
                    continue  # not a zone in this account — keep walking
                # 401/403/409/429/5xx are credential, eligibility or platform failures, not
                # "wrong zone". Continuing would burn the rate-limit budget re-failing on every
                # remaining suffix and would bury the real cause under "no managed domain".
                raise
            if isinstance(body, list) and body:
                self._zone_cache[record_name] = candidate
                return candidate
        raise DnsProviderError(f"No managed GoDaddy domain found for {record_name}.")

    async def add_txt_record(self, name: str, value: str) -> None:
        async with _rrset_lock(name):
            async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
                zone = await self._resolve_domain(session, name)
                path = _rrset_path(zone, _relative_name(name, zone))
                try:
                    existing = await self._request(session, "GET", path)
                except _GoDaddyHTTPError as exc:
                    if exc.status != 404:
                        raise
                    # Some accounts 404 reading back a record set in a zone whose WRITES succeed
                    # (acme.sh #6517). Reachable only when the NS probe resolved the zone but the
                    # TXT read 404s — if the NS probe itself 404s we never get here and the caller
                    # sees "No managed GoDaddy domain found", which is the honest answer. We cannot
                    # merge what we cannot read, and a single-value PUT would destroy any coexisting
                    # sibling, so PATCH is the only correct recovery: it is the one genuinely
                    # ADDITIVE primitive in v1 ("Appends DNS records ... Existing records with the
                    # same type and name are preserved"). It cannot dedupe, but a duplicate
                    # identical TXT is harmless for validation and cleanup removes the whole RRset.
                    await self._request(
                        session, "PATCH", f"/domains/{quote(zone, safe='')}/records",
                        json=[{"type": "TXT", "name": _relative_name(name, zone),
                               "data": value, "ttl": _TXT_TTL}],
                    )
                    return
                body = _merge_add(_require_rrset(existing), value)
                if body is None:
                    return  # already published — idempotent, this is where ACME retries land
                await self._request(session, "PUT", path, json=body)

    async def remove_txt_record(self, name: str, value: str) -> None:
        async with _rrset_lock(name):
            async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
                try:
                    zone = await self._resolve_domain(session, name)
                except _GoDaddyHTTPError as exc:
                    # Raise only what a later sweep could plausibly succeed at. reconcile_dns01_cleanup
                    # swallows the error and leaves dns_record_cleaned FALSE, so the row is re-selected
                    # every cycle — and its query takes a bare LIMIT 50, so rows that can NEVER succeed
                    # (revoked key, account lost DNS-API eligibility) would monopolise the whole
                    # cleanup budget and starve every other account. For those terminal statuses we
                    # give up quietly: the orphaned `_acme-challenge` TXT is inert, and the same
                    # credential failure is already loud on the publish path, where it is actionable.
                    if exc.status == 429 or exc.status >= 500:
                        raise
                    return
                except DnsProviderError:
                    return  # zone genuinely not resolvable — nothing we could clean up
                path = _rrset_path(zone, _relative_name(name, zone))
                try:
                    existing = await self._request(session, "GET", path)
                except _GoDaddyHTTPError as exc:
                    if exc.status == 404:
                        return  # RRset (or the read) is gone — tolerate
                    raise
                body = _merge_remove(_require_rrset(existing), value)
                if body is None:
                    return  # our value is not there — already gone, tolerate
                if not body:
                    # The LAST value at this name. `PUT []` is rejected (422 INVALID_BODY, "Records
                    # must be specified"), so emptying an RRset REQUIRES DELETE. This removes only
                    # TXT at this exact name; other names and other record types are preserved.
                    # Do NOT fall back to the "write an empty string to delete" folklore — that hack
                    # is what creates the tombstone rows _live_values has to filter.
                    try:
                        await self._request(session, "DELETE", path)
                    except _GoDaddyHTTPError as exc:
                        if exc.status == 404:
                            return  # raced with another cleanup — tolerate
                        raise
                    return
                await self._request(session, "PUT", path, json=body)
