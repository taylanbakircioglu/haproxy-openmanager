from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Dict, Any
import logging
from datetime import datetime

from database.connection import get_database_connection, close_database_connection

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


@router.put("/{category}")
async def update_settings_by_category(
    category: str,
    body: SettingsUpdate,
    authorization: str = Header(None)
):
    current_user = await _get_admin_user(authorization)
    conn = await get_database_connection()
    try:
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

    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(str(directory_url), timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        "success": True,
                        "directory": str(directory_url),
                        "endpoints": list(data.keys()) if isinstance(data, dict) else []
                    }
                else:
                    return {"success": False, "error": f"HTTP {resp.status} from directory URL"}
    except HTTPException:
        raise
    except Exception as e:
        return {"success": False, "error": str(e)}
