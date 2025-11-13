"""
Entity Snapshot Module for HAProxy OpenManager

Bu modül, entity değişikliklerinin snapshot'ını alır ve reject edildiğinde
geri yüklenmesini sağlar.

Usage:
    # UPDATE için snapshot al
    old_entity = await conn.fetchrow("SELECT * FROM frontends WHERE id = 5")
    snapshot_metadata = await save_entity_snapshot(
        conn=conn,
        entity_type="frontend",
        entity_id=5,
        old_values=old_entity,
        new_values={"bind_port": 443},
        operation="UPDATE"
    )
    
    # Config version'a ekle
    await conn.execute(
        "INSERT INTO config_versions (..., metadata) VALUES (..., $1)",
        json.dumps(snapshot_metadata)
    )
    
    # Reject edildiğinde rollback yap
    await rollback_entity_from_snapshot(conn, snapshot_metadata["entity_snapshot"])

Supported Operations:
    - UPDATE: Var olan entity'nin field'larını eski değerlere döndür
    - CREATE: Yeni oluşturulan entity'yi sil (bulk import için)
    - UPDATE_RESTORE: Restore işlemi sırasında yapılan UPDATE'i geri al

Feature Flag:
    ENTITY_SNAPSHOT_ENABLED=true|false
    Default: false (güvenli başlangıç)

Author: Taylan Bakırcıoğlu
Date: 2025-01-13
Version: 1.0.0
"""

import json
import os
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime

# Setup logger
logger = logging.getLogger(__name__)

# Entity snapshot enabled by default
# Can be disabled with ENTITY_SNAPSHOT_ENABLED=false if needed
ENTITY_SNAPSHOT_ENABLED = os.getenv("ENTITY_SNAPSHOT_ENABLED", "true").lower() == "true"


async def save_entity_snapshot(
    conn,
    entity_type: str,
    entity_id: int,
    old_values: Dict[str, Any],
    new_values: Optional[Dict[str, Any]] = None,
    operation: str = "UPDATE"
) -> Dict[str, Any]:
    """
    Entity snapshot'ı metadata formatında hazırla.
    
    Args:
        conn: Database connection (asyncpg)
        entity_type: Entity tipi ('frontend', 'backend', 'waf_rule', 'ssl_certificate', 'server')
        entity_id: Entity ID
        old_values: Eski değerler (asyncpg Record'dan dict)
        new_values: Yeni değerler (opsiyonel, UPDATE için)
        operation: İşlem tipi ('CREATE', 'UPDATE', 'DELETE', 'UPDATE_RESTORE')
    
    Returns:
        Dict containing entity_snapshot metadata:
        {
            "entity_snapshot": {
                "entity_type": "frontend",
                "entity_id": 5,
                "operation": "UPDATE",
                "timestamp": "2025-01-13T10:30:45Z",
                "old_values": {...},
                "new_values": {...},  # Sadece değişen alanlar (compaction)
                "changed_fields": ["bind_port", "ssl_enabled"]
            }
        }
    
    Example:
        old_frontend = await conn.fetchrow("SELECT * FROM frontends WHERE id = 5")
        metadata = await save_entity_snapshot(
            conn=conn,
            entity_type="frontend",
            entity_id=5,
            old_values=dict(old_frontend),
            new_values={"bind_port": 443, "ssl_enabled": True},
            operation="UPDATE"
        )
    """
    # Feature flag check
    if not ENTITY_SNAPSHOT_ENABLED:
        logger.debug(f"Entity snapshot disabled by feature flag for {entity_type} {entity_id}")
        return {}
    
    try:
        # Convert asyncpg Record to dict if needed
        if hasattr(old_values, '__iter__') and not isinstance(old_values, dict):
            old_values = dict(old_values)
        
        # CRITICAL FIX: Convert non-JSON-serializable types to JSON-safe format
        # Use try-catch for each value to handle asyncpg types, datetime, etc.
        import json as json_test
        serializable_old_values = {}
        
        for key, value in old_values.items():
            try:
                # Test if value is JSON serializable
                json_test.dumps(value)
                # If no exception, use as-is
                serializable_old_values[key] = value
            except (TypeError, ValueError):
                # Value is not JSON serializable, convert it
                if value is None:
                    serializable_old_values[key] = None
                elif hasattr(value, 'isoformat'):
                    # datetime, date, time objects
                    serializable_old_values[key] = str(value)
                else:
                    # Everything else: convert to string
                    serializable_old_values[key] = str(value)
        
        # Calculate changed fields for UPDATE operations
        changed_fields = []
        if operation in ["UPDATE", "UPDATE_RESTORE"] and new_values:
            changed_fields = [
                field for field, new_val in new_values.items()
                if field in old_values and old_values[field] != new_val
            ]
        
        # Build snapshot
        snapshot = {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "operation": operation,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "old_values": serializable_old_values,  # JSON-safe values
            "changed_fields": changed_fields
        }
        
        # For UPDATE: add new_values (compaction - only changed fields)
        if operation in ["UPDATE", "UPDATE_RESTORE"] and new_values:
            # Only store changed fields to save space (compaction)
            snapshot["new_values"] = {
                field: new_values[field]
                for field in changed_fields
            }
        
        logger.info(
            f"SNAPSHOT: Created for {entity_type} {entity_id} "
            f"(operation={operation}, changed_fields={len(changed_fields)})"
        )
        logger.info(f"SNAPSHOT DEBUG: old_values keys={list(serializable_old_values.keys())[:10]}")
        logger.info(f"SNAPSHOT DEBUG: Serializable check - can serialize to JSON: {len(serializable_old_values)} fields")
        
        # Test if snapshot is JSON serializable
        try:
            import json as json_final_test
            json_final_test.dumps(snapshot)
            logger.info(f"SNAPSHOT DEBUG: Final JSON test PASSED for {entity_type} {entity_id}")
        except Exception as json_err:
            logger.error(f"SNAPSHOT DEBUG: Final JSON test FAILED for {entity_type} {entity_id}: {json_err}")
            return {}
        
        return {"entity_snapshot": snapshot}
        
    except Exception as e:
        logger.error(f"SNAPSHOT ERROR: Failed to create snapshot for {entity_type} {entity_id}: {e}")
        # Return empty dict on error (graceful degradation)
        return {}


async def rollback_entity_from_snapshot(
    conn,
    entity_snapshot: Dict[str, Any]
) -> bool:
    """
    Entity'yi snapshot'taki eski değerlerine geri yükle.
    
    Args:
        conn: Database connection (asyncpg)
        entity_snapshot: Snapshot dict (from metadata.entity_snapshot)
    
    Returns:
        True if rollback successful, False otherwise
    
    Example:
        metadata = json.loads(version['metadata'])
        entity_snapshot = metadata.get('entity_snapshot')
        
        if entity_snapshot:
            success = await rollback_entity_from_snapshot(conn, entity_snapshot)
            if success:
                logger.info("Rollback successful")
            else:
                logger.warning("Rollback failed")
    """
    if not ENTITY_SNAPSHOT_ENABLED:
        logger.warning("ROLLBACK DEBUG: Entity snapshot disabled by feature flag, skipping rollback")
        return False
    
    entity_type = entity_snapshot.get("entity_type")
    entity_id = entity_snapshot.get("entity_id")
    operation = entity_snapshot.get("operation")
    old_values = entity_snapshot.get("old_values")
    
    logger.info(f"ROLLBACK DEBUG: entity_type={entity_type}, entity_id={entity_id}, operation={operation}")
    logger.info(f"ROLLBACK DEBUG: old_values exists={old_values is not None}, old_values length={len(old_values) if old_values else 0}")
    
    if not all([entity_type, entity_id, operation, old_values]):
        logger.warning(f"ROLLBACK: Invalid snapshot data, skipping rollback (missing: {[k for k in ['entity_type', 'entity_id', 'operation', 'old_values'] if not entity_snapshot.get(k)]})")
        return False
    
    try:
        if operation in ["UPDATE", "UPDATE_RESTORE"]:
            # Entity'yi eski değerlerine geri yükle
            logger.info(f"ROLLBACK DEBUG: Calling _rollback_update for {entity_type} {entity_id}")
            success = await _rollback_update(conn, entity_type, entity_id, old_values)
            logger.info(f"ROLLBACK DEBUG: _rollback_update returned {success}")
            return success
            
        elif operation == "CREATE":
            # Yeni oluşturulan entity'yi sil
            # ÖNEMLİ: Sadece bulk import ile TAMAMEN YENİ oluşturulan entity'ler için!
            success = await _rollback_create(conn, entity_type, entity_id)
            return success
            
        elif operation == "DELETE":
            # Silinen entity'yi geri yükle
            # NOT: Şu an soft-delete kullanıldığı için kullanılmıyor
            success = await _rollback_delete(conn, entity_type, entity_id, old_values)
            return success
        
        else:
            logger.warning(f"ROLLBACK: Unknown operation '{operation}', skipping")
            return False
            
    except Exception as e:
        logger.error(f"ROLLBACK ERROR: Failed for {entity_type} {entity_id}: {e}")
        return False


async def _rollback_update(
    conn,
    entity_type: str,
    entity_id: int,
    old_values: Dict[str, Any]
) -> bool:
    """
    Entity'yi UPDATE öncesi haline döndür.
    
    ÖNEMLİ: Bu fonksiyon var olan entity'lerin field'larını eski değerlere döndürür.
    Entity'yi KESİNLİKLE silmez!
    
    Args:
        conn: Database connection
        entity_type: Entity tipi
        entity_id: Entity ID
        old_values: Eski değerler (snapshot'tan)
    
    Returns:
        True if successful, False otherwise
    """
    try:
        if entity_type == "frontend":
            # Frontend'i eski değerlerine geri yükle
            logger.info(f"ROLLBACK UPDATE DEBUG: Frontend {entity_id} - restoring bind_port={old_values.get('bind_port')}")
            logger.info(f"ROLLBACK UPDATE DEBUG: old_values sample: name={old_values.get('name')}, bind_port={old_values.get('bind_port')}, ssl_enabled={old_values.get('ssl_enabled')}")
            
            result = await conn.execute("""
                UPDATE frontends SET
                    name = $1, bind_address = $2, bind_port = $3,
                    default_backend = $4, mode = $5, ssl_enabled = $6,
                    ssl_certificate_id = $7, ssl_certificate_ids = $8, ssl_port = $9,
                    ssl_cert_path = $10, ssl_cert = $11, ssl_verify = $12,
                    acl_rules = $13, redirect_rules = $14, use_backend_rules = $15,
                    request_headers = $16, response_headers = $17, options = $18,
                    tcp_request_rules = $19, timeout_client = $20, timeout_http_request = $21,
                    rate_limit = $22, compression = $23, log_separate = $24,
                    monitor_uri = $25, maxconn = $26,
                    last_config_status = $27, updated_at = $28
                WHERE id = $29
            """,
                old_values.get('name'),
                old_values.get('bind_address'),
                old_values.get('bind_port'),
                old_values.get('default_backend'),
                old_values.get('mode'),
                old_values.get('ssl_enabled'),
                old_values.get('ssl_certificate_id'),
                old_values.get('ssl_certificate_ids'),
                old_values.get('ssl_port'),
                old_values.get('ssl_cert_path'),
                old_values.get('ssl_cert'),
                old_values.get('ssl_verify'),
                old_values.get('acl_rules'),
                old_values.get('redirect_rules'),
                old_values.get('use_backend_rules'),
                old_values.get('request_headers'),
                old_values.get('response_headers'),
                old_values.get('options'),
                old_values.get('tcp_request_rules'),
                old_values.get('timeout_client'),
                old_values.get('timeout_http_request'),
                old_values.get('rate_limit'),
                old_values.get('compression'),
                old_values.get('log_separate'),
                old_values.get('monitor_uri'),
                old_values.get('maxconn'),
                old_values.get('last_config_status'),
                old_values.get('updated_at'),
                entity_id
            )
            
            logger.info(f"ROLLBACK UPDATE: Frontend {entity_id} restored to previous state (UPDATE query result={result})")
            
            # Verify rollback
            verify = await conn.fetchrow("SELECT bind_port, last_config_status FROM frontends WHERE id = $1", entity_id)
            logger.info(f"ROLLBACK UPDATE VERIFY: Frontend {entity_id} after rollback - bind_port={verify['bind_port']}, status={verify['last_config_status']}")
            
            return True
            
        elif entity_type == "backend":
            # Backend'i eski değerlerine geri yükle
            # SCHEMA: backends (ALL FIELDS from migrations.py line 1943-1962 + additions 1966-2006)
            await conn.execute("""
                UPDATE backends SET
                    name = $1, balance_method = $2, mode = $3,
                    health_check_uri = $4, health_check_interval = $5,
                    health_check_expected_status = $6, fullconn = $7,
                    timeout_connect = $8, timeout_server = $9, timeout_queue = $10,
                    cluster_id = $11, maxconn = $12, last_config_status = $13,
                    is_active = $14,
                    cookie_name = $15, cookie_options = $16,
                    default_server_inter = $17, default_server_fall = $18,
                    default_server_rise = $19, request_headers = $20,
                    response_headers = $21, options = $22,
                    updated_at = $23
                WHERE id = $24
            """,
                old_values.get('name'),
                old_values.get('balance_method'),
                old_values.get('mode'),
                old_values.get('health_check_uri'),
                old_values.get('health_check_interval'),
                old_values.get('health_check_expected_status'),
                old_values.get('fullconn'),
                old_values.get('timeout_connect'),
                old_values.get('timeout_server'),
                old_values.get('timeout_queue'),
                old_values.get('cluster_id'),
                old_values.get('maxconn'),
                old_values.get('last_config_status'),
                old_values.get('is_active'),
                old_values.get('cookie_name'),
                old_values.get('cookie_options'),
                old_values.get('default_server_inter'),
                old_values.get('default_server_fall'),
                old_values.get('default_server_rise'),
                old_values.get('request_headers'),
                old_values.get('response_headers'),
                old_values.get('options'),
                old_values.get('updated_at'),
                entity_id
            )
            logger.info(f"ROLLBACK UPDATE: Backend {entity_id} restored to previous state")
            return True
            
        elif entity_type == "waf_rule":
            # WAF rule'u eski değerlerine geri yükle
            # SCHEMA: waf_rules (ALL FIELDS from migrations.py line 2144-2160)
            await conn.execute("""
                UPDATE waf_rules SET
                    name = $1, rule_type = $2, config = $3, action = $4,
                    priority = $5, description = $6, enabled = $7,
                    cluster_id = $8, last_config_status = $9, is_active = $10,
                    updated_at = $11
                WHERE id = $12
            """,
                old_values.get('name'),
                old_values.get('rule_type'),
                old_values.get('config'),
                old_values.get('action'),
                old_values.get('priority'),
                old_values.get('description'),
                old_values.get('enabled'),
                old_values.get('cluster_id'),
                old_values.get('last_config_status'),
                old_values.get('is_active'),
                old_values.get('updated_at'),
                entity_id
            )
            logger.info(f"ROLLBACK UPDATE: WAF rule {entity_id} restored to previous state")
            return True
            
        elif entity_type == "ssl_certificate":
            # SSL certificate'i eski değerlerine geri yükle
            # SCHEMA: ssl_certificates (ALL FIELDS from migrations.py line 2120-2140)
            await conn.execute("""
                UPDATE ssl_certificates SET
                    name = $1, primary_domain = $2, certificate_content = $3,
                    private_key_content = $4, chain_content = $5,
                    expiry_date = $6, issuer = $7, status = $8,
                    fingerprint = $9, days_until_expiry = $10, all_domains = $11,
                    cluster_id = $12, last_config_status = $13, usage_type = $14,
                    is_active = $15, updated_at = $16
                WHERE id = $17
            """,
                old_values.get('name'),
                old_values.get('primary_domain'),
                old_values.get('certificate_content'),
                old_values.get('private_key_content'),
                old_values.get('chain_content'),
                old_values.get('expiry_date'),
                old_values.get('issuer'),
                old_values.get('status'),
                old_values.get('fingerprint'),
                old_values.get('days_until_expiry'),
                old_values.get('all_domains'),
                old_values.get('cluster_id'),
                old_values.get('last_config_status'),
                old_values.get('usage_type'),
                old_values.get('is_active'),
                old_values.get('updated_at'),
                entity_id
            )
            logger.info(f"ROLLBACK UPDATE: SSL certificate {entity_id} restored to previous state")
            return True
            
        elif entity_type == "server":
            # Server'ı eski değerlerine geri yükle
            # SCHEMA: backend_servers (ALL FIELDS from migrations.py line 2010-2036)
            await conn.execute("""
                UPDATE backend_servers SET
                    backend_id = $1, backend_name = $2, server_name = $3,
                    server_address = $4, server_port = $5, weight = $6,
                    maxconn = $7, check_enabled = $8, check_port = $9,
                    backup_server = $10, ssl_enabled = $11, ssl_verify = $12,
                    ssl_certificate_id = $13, cookie_value = $14,
                    inter = $15, fall = $16, rise = $17,
                    cluster_id = $18, is_active = $19, last_config_status = $20,
                    haproxy_status = $21, haproxy_status_updated_at = $22,
                    updated_at = $23
                WHERE id = $24
            """,
                old_values.get('backend_id'),
                old_values.get('backend_name'),
                old_values.get('server_name'),
                old_values.get('server_address'),
                old_values.get('server_port'),
                old_values.get('weight'),
                old_values.get('maxconn'),
                old_values.get('check_enabled'),
                old_values.get('check_port'),
                old_values.get('backup_server'),
                old_values.get('ssl_enabled'),
                old_values.get('ssl_verify'),
                old_values.get('ssl_certificate_id'),
                old_values.get('cookie_value'),
                old_values.get('inter'),
                old_values.get('fall'),
                old_values.get('rise'),
                old_values.get('cluster_id'),
                old_values.get('is_active'),
                old_values.get('last_config_status'),
                old_values.get('haproxy_status'),
                old_values.get('haproxy_status_updated_at'),
                old_values.get('updated_at'),
                entity_id
            )
            logger.info(f"ROLLBACK UPDATE: Server {entity_id} restored to previous state")
            return True
            
        else:
            logger.warning(f"ROLLBACK UPDATE: Unsupported entity type '{entity_type}'")
            return False
            
    except Exception as e:
        logger.error(f"ROLLBACK UPDATE ERROR: {entity_type} {entity_id}: {e}", exc_info=True)
        return False


async def _rollback_create(
    conn,
    entity_type: str,
    entity_id: int
) -> bool:
    """
    Yeni oluşturulan entity'yi sil (reject edilen CREATE).
    
    ÖNEMLİ: Bu fonksiyon SADECE bulk import ile TAMAMEN YENİ oluşturulan
    entity'ler için kullanılır. Var olan entity'nin UPDATE'i için
    KESİNLİKLE kullanılmaz!
    
    Kullanım Senaryosu:
        - Bulk import ile 5 yeni backend oluşturuldu
        - Kullanıcı reject yaptı
        - Bu fonksiyon 5 backend'i siler
    
    Args:
        conn: Database connection
        entity_type: Entity tipi
        entity_id: Entity ID (silinecek)
    
    Returns:
        True if successful, False otherwise
    """
    try:
        if entity_type == "frontend":
            await conn.execute("DELETE FROM frontends WHERE id = $1", entity_id)
            logger.info(f"ROLLBACK CREATE: Deleted frontend {entity_id}")
            return True
            
        elif entity_type == "backend":
            # Cascade delete: servers otomatik silinecek (foreign key)
            await conn.execute("DELETE FROM backends WHERE id = $1", entity_id)
            logger.info(f"ROLLBACK CREATE: Deleted backend {entity_id} (+ cascade servers)")
            return True
            
        elif entity_type == "waf_rule":
            await conn.execute("DELETE FROM waf_rules WHERE id = $1", entity_id)
            logger.info(f"ROLLBACK CREATE: Deleted WAF rule {entity_id}")
            return True
            
        elif entity_type == "ssl_certificate":
            await conn.execute("DELETE FROM ssl_certificates WHERE id = $1", entity_id)
            logger.info(f"ROLLBACK CREATE: Deleted SSL certificate {entity_id}")
            return True
            
        elif entity_type == "server":
            await conn.execute("DELETE FROM backend_servers WHERE id = $1", entity_id)
            logger.info(f"ROLLBACK CREATE: Deleted server {entity_id}")
            return True
            
        else:
            logger.warning(f"ROLLBACK CREATE: Unsupported entity type '{entity_type}'")
            return False
            
    except Exception as e:
        logger.error(f"ROLLBACK CREATE ERROR: {entity_type} {entity_id}: {e}", exc_info=True)
        return False


async def _rollback_delete(
    conn,
    entity_type: str,
    entity_id: int,
    old_values: Dict[str, Any]
) -> bool:
    """
    Silinen entity'yi geri yükle (reject edilen DELETE).
    
    NOT: Şu an projede soft-delete kullanıldığı için bu fonksiyon
    aktif olarak kullanılmıyor. Gelecekte hard-delete kullanılırsa
    bu fonksiyon implement edilecek.
    
    Future Implementation:
        - Entity'yi INSERT ile geri yükle
        - Foreign key'leri geri yükle
        - Related entity'leri geri yükle
    
    Args:
        conn: Database connection
        entity_type: Entity tipi
        entity_id: Entity ID
        old_values: Eski değerler (snapshot'tan)
    
    Returns:
        True if successful, False otherwise
    """
    logger.warning(
        f"ROLLBACK DELETE: Not implemented yet for {entity_type} {entity_id}. "
        "Currently using soft-delete (is_active=false). Hard-delete rollback is a future feature."
    )
    return False

