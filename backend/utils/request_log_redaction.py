"""v1.11.0 — redaction for the unified request/response log.

Everything that lands in `request_logs.request_body` / `response_body` /
`request_headers` / `response_headers` / `query_params` passes through here
first. The rules, in order of how much they are trusted:

1.  **Headers are an ALLOWLIST.** Anything not explicitly listed is dropped.
    A small set of high-signal headers (`Authorization`, `Cookie`, …) is kept
    as a presence marker with the value replaced, so an operator debugging a
    401 can still see *that* a credential was sent.
2.  **Body keys are matched by a normalized name** (lowercased, punctuation
    stripped), against an exact set for short generic names that would
    over-match as substrings (`key`, `payload`) and a contains set for the
    compound ones (`cert_private_key`, `eab_hmac_key`, …).
3.  **Values are shape-checked too.** A PEM private key or a JWT-shaped string
    is redacted no matter what key it arrived under — this is the net that
    catches a route echoing a secret under a renamed field.

None of these functions raise: a redaction failure must never turn into a
failed request or a failed provider call, so callers get a safe placeholder
instead of an exception.
"""
import json
import logging
import re
import urllib.parse
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("haproxy_openmanager.request_log")

REDACTED = "***REDACTED***"

# Short, generic names. Matched EXACTLY after normalization, because as
# substrings they would swallow innocent fields (`key_suffix`, `monkey`,
# `payload_size`, `keyboard`, `nonce_count`).
REDACT_EXACT = {
    "password", "passwd", "pwd", "secret", "token", "key", "auth",
    "authorization", "cookie", "signature", "protected", "payload",
    "nonce", "credentials", "credential", "otp", "pin", "jwk", "csr",
}

# Compound names. Matched as SUBSTRINGS of the normalized key.
#
# `token` is in here on purpose, not just its compounds. In this domain EVERY
# field whose name contains "token" is a credential — api_token (the Cloudflare
# provider credential), agent_token, access_token, session_token — and the cost
# of over-redacting a hypothetical innocent one is a blanked field, while the
# cost of under-redacting is a live credential sitting in an audit table.
REDACT_CONTAINS = {
    "password", "passwordhash", "secret", "apisecret", "clientsecret",
    "token", "accesstoken", "refreshtoken", "mfatoken", "resettoken",
    "sessiontoken", "apitoken", "agenttoken", "csrftoken",
    "apikey", "xapikey", "privatekey", "publicprivate", "jwkprivatekey",
    "certprivatekey", "csrprivatekey", "keypem", "privkey",
    "hmac", "eabhmackey", "eabkid",
    "credentialsencrypted", "encryptedcredentials", "dnscredentials",
    "authorization", "cookie", "setcookie", "keyauthorization",
    "backupcode", "backupcodes", "totp", "totpcode", "totpsecret",
    "replaynonce", "sessionid", "statspassword", "encryptionkey",
    "bearer", "signature",
}

_NORMALIZE_RE = re.compile(r"[^a-z0-9]")

# Value-shaped guards — these fire regardless of the key name.
_PEM_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}$")

_MAX_DEPTH = 6
_MAX_NODES = 2000
_MAX_STRING = 4096
_MAX_LIST_ITEMS = 200

# Header handling. Allowlist wins; presence-only names are emitted with the
# value replaced so the operator knows the header was there.
HEADER_ALLOWLIST = {
    "content-type", "content-length", "content-encoding", "accept",
    "accept-encoding", "accept-language", "user-agent", "referer", "origin",
    "host", "connection", "cache-control", "pragma", "date", "server",
    "x-correlation-id", "x-request-id", "x-response-time",
    "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-real-ip",
    "location", "retry-after", "ratelimit-reset", "ratelimit-remaining",
    "link", "etag", "vary",
}

HEADER_PRESENCE_ONLY = {
    "authorization", "cookie", "set-cookie", "x-api-key", "api-key",
    "proxy-authorization", "replay-nonce", "www-authenticate",
    "x-auth-token", "x-agent-token", "x-agent-api-key",
}

_MAX_HEADERS = 40


class _NodeBudget:
    """Shared mutable counter so a single body can't blow the CPU budget by
    being wide as well as deep."""

    __slots__ = ("remaining",)

    def __init__(self, remaining: int = _MAX_NODES):
        self.remaining = remaining

    def spend(self) -> int:
        self.remaining -= 1
        return self.remaining


def _normalize_key(key: Any) -> str:
    try:
        return _NORMALIZE_RE.sub("", str(key).lower())
    except Exception:
        return ""


def is_secret_key(key: Any) -> bool:
    """True when a dict key / query param name names a secret."""
    norm = _normalize_key(key)
    if not norm:
        return False
    if norm in REDACT_EXACT:
        return True
    return any(needle in norm for needle in REDACT_CONTAINS)


def _is_secret_value(value: str) -> bool:
    """Shape-based guard for secrets that arrive under an innocent key."""
    if len(value) < 32:
        # Neither a PEM block nor a JWT fits in less than this; skip the
        # regex work on the overwhelmingly common short-string case.
        return False
    if _PEM_RE.search(value):
        return True
    return bool(_JWT_RE.match(value.strip()))


def redact(value: Any, *, depth: int = 0, budget: Optional[_NodeBudget] = None) -> Any:
    """Recursively redact a decoded body.

    Depth- and node-capped so a hostile or merely pathological payload cannot
    burn CPU on the writer task. Never raises.
    """
    if budget is None:
        budget = _NodeBudget()

    try:
        if depth > _MAX_DEPTH:
            return "***DEPTH_LIMIT***"

        if isinstance(value, dict):
            out: Dict[str, Any] = {}
            for k, v in value.items():
                if budget.spend() <= 0:
                    out["_node_limit"] = True
                    break
                if is_secret_key(k):
                    out[str(k)] = REDACTED
                else:
                    out[str(k)] = redact(v, depth=depth + 1, budget=budget)
            return out

        if isinstance(value, (list, tuple)):
            out_list = []
            for item in list(value)[:_MAX_LIST_ITEMS]:
                if budget.spend() <= 0:
                    out_list.append("_node_limit")
                    break
                out_list.append(redact(item, depth=depth + 1, budget=budget))
            if len(value) > _MAX_LIST_ITEMS:
                out_list.append(f"…[{len(value) - _MAX_LIST_ITEMS} more items]")
            return out_list

        if isinstance(value, str):
            if _is_secret_value(value):
                return REDACTED
            if len(value) > _MAX_STRING:
                return value[:_MAX_STRING] + f"…[truncated {len(value) - _MAX_STRING} chars]"
            return value

        return value
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug(f"redact() failed, substituting placeholder: {exc}")
        return "***REDACTION_ERROR***"


def redact_headers(headers: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
    """Allowlist-filter a header mapping.

    Allowlisted headers keep their value, `HEADER_PRESENCE_ONLY` headers keep
    only the fact they were present, everything else is dropped silently.
    """
    if not headers:
        return None
    try:
        out: Dict[str, str] = {}
        for raw_name, raw_value in headers.items():
            name = str(raw_name).lower()
            if name in HEADER_PRESENCE_ONLY:
                out[name] = REDACTED
            elif name in HEADER_ALLOWLIST:
                value = str(raw_value)
                out[name] = value[:1024]
            if len(out) >= _MAX_HEADERS:
                break
        return out or None
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug(f"redact_headers() failed: {exc}")
        return None


def scrub_query_string(query: Optional[str]) -> Tuple[str, Optional[Dict[str, str]]]:
    """Return (scrubbed_query_string, scrubbed_dict) for a raw query string."""
    if not query:
        return "", None
    try:
        pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
        scrubbed = [(k, REDACTED if is_secret_key(k) else v) for k, v in pairs]
        return urllib.parse.urlencode(scrubbed), dict(scrubbed)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug(f"scrub_query_string() failed: {exc}")
        return "", None


def scrub_url(url: str) -> str:
    """Strip userinfo and scrub the query string of an absolute URL.

    `https://user:pass@api.example.com/v1?api_key=x`
      → `https://api.example.com/v1?api_key=***REDACTED***`
    """
    if not url:
        return ""
    try:
        parts = urllib.parse.urlsplit(url)
        netloc = parts.hostname or ""
        if parts.port:
            netloc = f"{netloc}:{parts.port}"
        query, _ = scrub_query_string(parts.query)
        # Fragments are dropped: they never reach a server and can carry tokens.
        return urllib.parse.urlunsplit((parts.scheme, netloc, parts.path, query, ""))
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug(f"scrub_url() failed: {exc}")
        return "***URL_PARSE_ERROR***"


# Content types whose bodies are worth buffering. Anything else (octet-stream,
# images, text/event-stream) is size-counted but never copied, which is what
# keeps streaming and file responses safe.
CAPTURABLE_CONTENT_TYPES = (
    "application/json",
    "application/problem+json",
    "application/jose+json",
    "application/x-www-form-urlencoded",
    "text/plain",
    "text/html",
    "text/xml",
    "application/xml",
)


def is_capturable_content_type(content_type: Optional[str]) -> bool:
    if not content_type:
        # No Content-Type on a body-bearing message is rare; assume JSON-ish
        # rather than dropping the one field the operator wanted to see.
        return True
    ct = content_type.split(";")[0].strip().lower()
    return any(ct.startswith(prefix) for prefix in CAPTURABLE_CONTENT_TYPES)


def decode_body(
    raw: Optional[bytes],
    content_type: Optional[str],
    total_bytes: int = 0,
) -> Tuple[Optional[Any], bool]:
    """Decode + redact a captured body fragment.

    `raw` is what the middleware managed to buffer (already capped);
    `total_bytes` is how large the body actually was on the wire. Returns
    `(jsonb_value, truncated)`. Non-JSON payloads are wrapped as
    `{"_raw": "..."}` so the column stays a uniform JSONB object that the
    detail view and any future `->>` query can rely on.
    """
    if not raw:
        return None, False

    truncated = total_bytes > len(raw)
    ct = (content_type or "").split(";")[0].strip().lower()

    try:
        text = raw.decode("utf-8", "replace")
    except Exception:  # pragma: no cover - decode with 'replace' can't raise
        return {"_raw": "***DECODE_ERROR***"}, truncated

    value: Any
    if ct in ("application/json", "application/problem+json", "application/jose+json") or (
        not ct and text[:1] in ("{", "[")
    ):
        try:
            value = redact(json.loads(text))
        except Exception:
            # A truncated JSON body will not parse — keep the raw prefix so the
            # operator still sees what was sent.
            value = {"_raw": redact(text)}
    elif ct == "application/x-www-form-urlencoded":
        try:
            value = redact(dict(urllib.parse.parse_qsl(text, keep_blank_values=True)))
        except Exception:
            value = {"_raw": redact(text)}
    else:
        value = {"_raw": redact(text)}

    if truncated:
        if isinstance(value, dict):
            value["_truncated"] = True
            value["_original_bytes"] = total_bytes
        else:
            value = {
                "_value": value,
                "_truncated": True,
                "_original_bytes": total_bytes,
            }

    return value, truncated


def safe_error_text(exc: BaseException, *, type_only: bool = False, limit: int = 2000) -> str:
    """Render an exception for the `error` column.

    `type_only=True` is used for the DNS providers, whose own error paths
    deliberately never surface `str(exc)` — it can carry the request URL and,
    through it, tenant/zone identifiers (see services/dns_providers/*.py).
    """
    try:
        name = type(exc).__name__
        if type_only:
            return name
        text = f"{name}: {exc}"
        redacted = redact(text)
        if not isinstance(redacted, str):
            return name
        return redacted[:limit]
    except Exception:  # pragma: no cover - defensive
        return "UnknownError"
