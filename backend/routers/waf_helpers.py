
import json
import hashlib
import time
import logging
from services.haproxy_config import generate_haproxy_config_for_cluster
from utils.activity_log import log_user_activity

logger = logging.getLogger(__name__)

async def assign_frontends_and_get_clusters(conn, rule_id, frontend_ids, waf_cluster_id=None):
    """Assign WAF rule to frontends and return assignments and affected cluster IDs."""
    frontend_assignments = []
    cluster_ids = set()
    
    # If WAF rule has a direct cluster_id, use that as primary cluster
    if waf_cluster_id:
        cluster_ids.add(waf_cluster_id)
    
    if frontend_ids:
        for frontend_id in frontend_ids:
            frontend = await conn.fetchrow(
                "SELECT id, name, cluster_id FROM frontends WHERE id = $1", frontend_id
            )
            if frontend:
                await conn.execute(
                    "INSERT INTO frontend_waf_rules (frontend_id, waf_rule_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                    frontend_id, rule_id
                )
                frontend_assignments.append({'id': frontend['id'], 'name': frontend['name']})
                if frontend['cluster_id']:
                    cluster_ids.add(frontend['cluster_id'])
    
    return frontend_assignments, cluster_ids

async def create_pending_configs_for_clusters(conn, cluster_ids, action, rule_id):
    """Generate HAProxy config and create PENDING config versions for affected clusters."""
    sync_results = []
    admin_user_id = await conn.fetchval("SELECT id FROM users WHERE username = 'admin' LIMIT 1") or 1
    
    for cluster_id in cluster_ids:
        try:
            # CRITICAL FIX: The config generation MUST happen *after* the database state is updated
            # and within the same transaction. We pass the connection object 'conn'.
            config_content = await generate_haproxy_config_for_cluster(cluster_id, conn=conn)
            config_hash = hashlib.sha256(config_content.encode()).hexdigest()
            version_name = f"waf-{rule_id}-{action}-{int(time.time())}"
            
            await conn.fetchval("""
                INSERT INTO config_versions 
                (cluster_id, version_name, config_content, checksum, created_by, is_active, status, file_size)
                VALUES ($1, $2, $3, $4, $5, FALSE, 'PENDING', $6)
                RETURNING id
            """, cluster_id, version_name, config_content, config_hash, admin_user_id, len(config_content))
            
            logger.info(f"APPLY WORKFLOW: Created PENDING config version {version_name} for cluster {cluster_id}")
            sync_results.append({
                'cluster_id': cluster_id, 'success': True, 'status': 'PENDING',
                'message': f'WAF rule {action} changes created. Click Apply to activate.'
            })
        except Exception as e:
            logger.error(f"Cluster config update failed for WAF rule {rule_id} on cluster {cluster_id}: {e}", exc_info=True)
            sync_results.append({'cluster_id': cluster_id, 'success': False, 'error': str(e)})
            
    # Mark entity as PENDING for UI
    # PENDING status is now set *before* this function is called, so this is redundant

    return sync_results

async def log_activity(current_user, action, rule_id, waf_rule, assignments, clusters, sync, request):
    """Log user activity for WAF rule changes."""
    await log_user_activity(
        user_id=current_user['id'],
        action=action,
        resource_type='waf_rule',
        resource_id=str(rule_id),
        details={
            'waf_rule_name': waf_rule.name,
            'rule_type': waf_rule.rule_type,
            'action': waf_rule.action,
            'config': waf_rule.config,
            'frontend_assignments': assignments,
            'affected_clusters': list(clusters),
            'sync_results': len(sync)
        },
        ip_address=str(request.client.host) if request.client else None,
        user_agent=request.headers.get('user-agent')
    )

