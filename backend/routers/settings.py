from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Dict, Any
import json
import logging
from datetime import datetime

from database.connection import get_database_connection, close_database_connection
from utils.acme_backend_url import AcmeBackendUrlError, validate_acme_backend_url

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/settings", tags=["Settings"])


class SettingsUpdate(BaseModel):
    settings: Dict[str, Any]


async def _get_admin_user(authorization: str):
    from auth_middleware import get_current_user_from_token
    current_user = await get_current_user_from_token(authorization)
    if not current_user.get('is_admin', False):
        raise HTTPException(status_code=403, detail="Admin access required for settings management")
    return current_user


@router.get("/{category}")
async def get_settings_by_category(category: str, authorization: str = Header(None)):
    current_user = await _get_admin_user(authorization)
    conn = await get_database_connection()
    try:
        rows = await conn.fetch(
            "SELECT key, value, description, updated_at FROM system_settings WHERE category = $1 ORDER BY key",
            category
        )
        result = {}
        for row in rows:
            key_suffix = row['key'].split('.', 1)[1] if '.' in row['key'] else row['key']
            result[key_suffix] = {
                "value": row['value'],
                "description": row['description'],
                "updated_at": row['updated_at'].isoformat() if row['updated_at'] else None
            }
        return {"category": category, "settings": result}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching settings for category '{category}': {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch settings")
    finally:
        await close_database_connection(conn)


def _validate_acme_challenge_backend_url(value):
    """Validate `acme.challenge_backend_url` exactly as the config renderer reads it.

    Settings values are stored as jsonb, so the renderer json.loads them before use
    (services/haproxy_config.py). Validating the raw column text instead of the
    decoded string would check the quoting rather than the URL.
    """
    decoded = value
    if isinstance(decoded, str):
        try:
            decoded = json.loads(decoded)
        except (json.JSONDecodeError, TypeError):
            pass
    if decoded is None:
        return
    try:
        validate_acme_backend_url(str(decoded))
    except AcmeBackendUrlError as exc:
        raise HTTPException(
            status_code=422,
            detail=f"acme.challenge_backend_url: {exc}",
        ) from None


# Per-key validators for settings that end up in generated configuration or in
# outbound requests. Everything else is still written through unchecked; this is a
# deliberate allow-list of the keys where a bad value causes silent breakage rather
# than an obvious one.
_SETTING_VALIDATORS = {
    "acme.challenge_backend_url": _validate_acme_challenge_backend_url,
}


@router.put("/{category}")
async def update_settings_by_category(
    category: str,
    body: SettingsUpdate,
    authorization: str = Header(None)
):
    current_user = await _get_admin_user(authorization)
    conn = await get_database_connection()
    try:
        # Validate the whole batch before writing any of it, so a rejected key cannot
        # leave the category half-applied.
        for key_suffix, value in body.settings.items():
            validator = _SETTING_VALIDATORS.get(f"{category}.{key_suffix}")
            if validator is not None:
                validator(value)

        updated = []
        for key_suffix, value in body.settings.items():
            full_key = f"{category}.{key_suffix}"
            result = await conn.execute("""
                INSERT INTO system_settings (key, value, category, updated_at, updated_by)
                VALUES ($1, $2::jsonb, $3, $4, $5)
                ON CONFLICT (key) DO UPDATE SET
                    value = $2::jsonb,
                    updated_at = $4,
                    updated_by = $5
            """, full_key, str(value) if not isinstance(value, str) else value,
                category, datetime.utcnow(), current_user.get('id'))
            updated.append(full_key)

        logger.info(f"Settings updated by user {current_user.get('username')}: {updated}")
        return {"message": f"Updated {len(updated)} settings", "keys": updated}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating settings for category '{category}': {e}")
        raise HTTPException(status_code=500, detail="Failed to update settings")
    finally:
        await close_database_connection(conn)


@router.get("/acme/test-connection")
async def test_acme_connection(authorization: str = Header(None), directory_url: str = None):
    current_user = await _get_admin_user(authorization)

    if not directory_url:
        conn = await get_database_connection()
        try:
            row = await conn.fetchrow(
                "SELECT value FROM system_settings WHERE key = 'acme.directory_url'"
            )
            if not row or not row['value']:
                return {"success": False, "error": "No ACME directory URL configured"}

            import json as _json
            directory_url = _json.loads(row['value']) if isinstance(row['value'], str) else row['value']
            if isinstance(directory_url, dict):
                directory_url = directory_url.get('value', directory_url)
        finally:
            await close_database_connection(conn)

    # SECURITY (GHSA-3vh4-gvxx-wm2p): validate the URL before any outbound request
    # (https-only; block loopback/RFC1918/link-local/cloud-metadata after DNS),
    # pin the connector to IPv4, and never follow redirects. Also do NOT reflect
    # arbitrary upstream JSON keys back to the caller — that was an information-
    # disclosure oracle. Only report presence of the FIXED, known ACME directory
    # field names (never attacker-controlled data).
    from utils.ssrf_guard import assert_public_url, safe_connector, SSRFValidationError

    directory_url = str(directory_url)
    try:
        await assert_public_url(directory_url)
    except SSRFValidationError as e:
        return {"success": False, "error": f"Refused to fetch directory URL: {e}"}

    _KNOWN_ACME_FIELDS = ["newNonce", "newAccount", "newOrder", "newAuthz", "revokeCert", "keyChange"]
    try:
        import aiohttp
        # v1.11.0: this handler returns str(e) to the caller and logs nothing —
        # the span gives the failed probe a durable record.
        from utils.http_instrumentation import outbound_span, TARGET_SETTINGS_PROBE

        async with aiohttp.ClientSession(connector=safe_connector()) as session:
            async with outbound_span(
                target=TARGET_SETTINGS_PROBE, method="GET", url=directory_url
            ) as span:
                async with session.get(
                    directory_url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    allow_redirects=False,
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        span.set_response(resp.status, getattr(resp, "headers", None), data)
                        if not isinstance(data, dict):
                            return {"success": False, "error": "Directory URL did not return a JSON object"}
                        present = [k for k in _KNOWN_ACME_FIELDS if k in data]
                        if not present:
                            return {"success": False, "error": "Response is not a valid ACME directory"}
                        return {
                            "success": True,
                            "directory": directory_url,
                            "endpoints": present,
                        }
                    else:
                        span.set_response(resp.status, getattr(resp, "headers", None))
                        return {"success": False, "error": f"HTTP {resp.status} from directory URL"}
    except HTTPException:
        raise
    except Exception as e:
        return {"success": False, "error": str(e)}
