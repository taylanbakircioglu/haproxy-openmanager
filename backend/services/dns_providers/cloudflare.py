"""Cloudflare DNS provider for ACME DNS-01 (Issue #35).

Uses the Cloudflare API v4 over aiohttp (no new dependency). The base URL is a hardcoded
constant and redirects are not followed (no user-controlled URL — only the already-validated
domain name influences which zone is used). Errors are wrapped in DnsProviderError with a
sanitized message so the API token never reaches logs / order events.

Token scope required: Zone:DNS:Edit + Zone:Read.
"""
from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

import aiohttp

from .base import DnsProvider, DnsProviderError

logger = logging.getLogger(__name__)

CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4"
_TIMEOUT = aiohttp.ClientTimeout(total=20)

# Characters NOT valid in an HTTP bearer credential (RFC 6750 token68: A-Za-z0-9-._~+/=).
# Cloudflare API tokens are a strict subset of this set, so removing anything outside it can
# never corrupt a valid token, but it does strip the paste artifacts that make Cloudflare
# reject the Authorization header with HTTP 400 "Invalid request headers" (CF code 6003):
# surrounding/embedded quotes, interior spaces/tabs, zero-width/unicode chars, and CR/LF
# (the latter would otherwise make aiohttp raise client-side before the request is even sent).
_NON_TOKEN68 = re.compile(r"[^A-Za-z0-9._~+/=-]")


def _strip_quotes(s: str) -> str:
    s = (s or "").strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1]
    return s


def _sanitize_token(s: str) -> str:
    """Strip surrounding quotes/whitespace, then drop every character outside the token68 set."""
    return _NON_TOKEN68.sub("", _strip_quotes(s))


class CloudflareDNSProvider(DnsProvider):
    name = "cloudflare"
    label = "Cloudflare"
    automated = True
    credential_fields: List[Dict] = [
        {
            "key": "api_token",
            "label": "API Token",
            "type": "password",
            "required": True,
            "max_length": 200,
            "help": "Scoped API token with Zone:DNS:Edit and Zone:Read permissions.",
        }
    ]

    def __init__(self, credentials: Dict[str, str] | None = None):
        super().__init__(credentials)
        self._raw_token = (self.credentials.get("api_token") or "").strip()
        # Sanitize to the token68 set so a pasted token with quotes/spaces/control/unicode chars
        # cannot produce an invalid Authorization header (CF 6003 "Invalid request headers").
        self._token = _sanitize_token(self._raw_token)

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}

    async def _request(self, session: aiohttp.ClientSession, method: str, path: str, **kwargs) -> dict:
        """One Cloudflare API call. Returns the parsed JSON body. Raises a SANITIZED
        DnsProviderError on transport/HTTP/API error (never echoes the token or raw headers)."""
        url = f"{CLOUDFLARE_API_BASE}{path}"
        try:
            async with session.request(
                method, url, headers=self._headers(), allow_redirects=False, **kwargs
            ) as resp:
                try:
                    body = await resp.json()
                except Exception:  # noqa: BLE001
                    body = {}
                if resp.status in (401, 403):
                    raise DnsProviderError("Cloudflare rejected the API token (check it has Zone:DNS:Edit + Zone:Read).")
                if resp.status >= 400 or not body.get("success", False):
                    # Cloudflare returns {"errors":[{"code":..,"message":..}]} — surface only the
                    # human message text, never the request (which carries the token header).
                    msgs = "; ".join(
                        str(e.get("message")) for e in (body.get("errors") or []) if e.get("message")
                    )
                    raise DnsProviderError(
                        f"Cloudflare API error (HTTP {resp.status}){': ' + msgs if msgs else ''}"
                    )
                return body
        except DnsProviderError:
            raise
        except aiohttp.ClientError as exc:
            # Do NOT include exc verbatim everywhere; aiohttp client errors are URL/transport only
            # (no token), but keep the message generic and stable.
            raise DnsProviderError(f"Could not reach the Cloudflare API ({type(exc).__name__}).")
        except Exception as exc:  # noqa: BLE001
            raise DnsProviderError(f"Unexpected Cloudflare API failure ({type(exc).__name__}).")

    async def verify_credentials(self) -> Dict:
        if not self._token:
            return {"ok": False, "detail": "No Cloudflare API token provided."}
        try:
            async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
                body = await self._request(session, "GET", "/zones?per_page=1")
            total = ((body.get("result_info") or {}).get("total_count"))
            detail = "Cloudflare token valid."
            if isinstance(total, int):
                detail = f"Cloudflare token valid; {total} zone(s) visible."
            return {"ok": True, "detail": detail}
        except DnsProviderError as exc:
            # Always surface the real Cloudflare reason (e.g. token scope). If sanitizing also changed
            # the token, append a hint that stray characters were stripped (never echo the token).
            detail = str(exc)
            if self._raw_token != self._token:
                detail += (" Note: the token contained characters that were stripped; if it still "
                           "fails, re-copy it from Cloudflare without quotes or spaces.")
            return {"ok": False, "detail": detail}
        except Exception:  # noqa: BLE001 — never leak an internal/transport error verbatim
            return {"ok": False, "detail": "Could not verify the Cloudflare token."}

    async def _resolve_zone(self, session: aiohttp.ClientSession, record_name: str) -> Tuple[str, str]:
        """Find the most-specific (longest-suffix) managed zone for a record name.
        Returns (zone_id, zone_name). Raises DnsProviderError if no zone matches."""
        labels = record_name.split(".")
        # Walk suffixes from longest to shortest; a zone needs at least 2 labels.
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            if candidate.count(".") < 1:
                break
            body = await self._request(
                session, "GET", f"/zones?name={quote(candidate)}&status=active&per_page=50"
            )
            results = body.get("result") or []
            if results:
                return results[0]["id"], candidate
        raise DnsProviderError(f"No managed Cloudflare zone found for {record_name}.")

    async def _find_record_id(
        self, session: aiohttp.ClientSession, zone_id: str, name: str, value: str
    ) -> Optional[str]:
        body = await self._request(
            session, "GET", f"/zones/{zone_id}/dns_records?type=TXT&name={quote(name)}&per_page=100"
        )
        for rec in body.get("result") or []:
            if _strip_quotes(rec.get("content", "")) == value:
                return rec.get("id")
        return None

    async def add_txt_record(self, name: str, value: str) -> None:
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            zone_id, _zone_name = await self._resolve_zone(session, name)
            # Idempotent: only create if (name, value) is not already present (preserves coexisting values).
            existing = await self._find_record_id(session, zone_id, name, value)
            if existing:
                return
            await self._request(
                session,
                "POST",
                f"/zones/{zone_id}/dns_records",
                json={"type": "TXT", "name": name, "content": value, "ttl": 120},
            )

    async def remove_txt_record(self, name: str, value: str) -> None:
        async with aiohttp.ClientSession(timeout=_TIMEOUT) as session:
            try:
                zone_id, _zone_name = await self._resolve_zone(session, name)
            except DnsProviderError:
                # Zone gone / not resolvable — nothing we can clean up.
                return
            record_id = await self._find_record_id(session, zone_id, name, value)
            if not record_id:
                return  # already gone — tolerate
            await self._request(session, "DELETE", f"/zones/{zone_id}/dns_records/{record_id}")
