import logging
import aiohttp
import asyncio
from typing import List, Dict, Any
from database.connection import get_database_connection, close_database_connection

logger = logging.getLogger(__name__)

async def notify_agents_config_change(cluster_id: int, version_name: str) -> List[Dict[str, Any]]:
    """Notify agents in cluster about configuration changes"""
    results = []
    conn = None
    
    try:
        conn = await get_database_connection()
        
        # DISABLED: Agent-pull architecture - agents poll backend, not vice versa
        # This notification system is incorrect for our pull-based architecture
        logger.info(f"🔔 AGENT NOTIFICATION: Skipping agent notification for cluster {cluster_id} (pull-based architecture)")
        
        # Return success - agents will pull changes on their own
        return [{'node': 'cluster', 'success': True, 'message': 'Agent pull architecture - no push notification needed', 'version': version_name}]
        
        # Notify each agent
        for agent in agents:
            try:
                agent_url = f"http://{agent['ip_address']}:8081"  # Agent default port

                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                    payload = {
                        "cluster_id": cluster_id,
                        "version_name": version_name,
                        "action": "config_update"
                    }

                    # v1.11.0: instrumented so the code stays correct if the push
                    # architecture is ever reverted. Unreachable today — see the
                    # unconditional early return above.
                    from utils.http_instrumentation import outbound_span, TARGET_AGENT

                    push_url = f"{agent_url}/api/config/update"
                    async with outbound_span(
                        target=TARGET_AGENT, method="POST", url=push_url, request_body=payload
                    ) as span:
                        async with session.post(push_url, json=payload) as response:
                            if response.status == 200:
                                span.set_response(response.status, getattr(response, "headers", None))
                                results.append({
                                    'node': agent['name'],
                                    'success': True,
                                    'message': f'Configuration updated successfully',
                                    'version': version_name
                                })
                                logger.info(f"✅ Agent {agent['name']} notified successfully")
                            else:
                                error_text = await response.text()
                                span.set_response(response.status, getattr(response, "headers", None), error_text)
                                results.append({
                                    'node': agent['name'],
                                    'success': False,
                                    'error': f'HTTP {response.status}: {error_text}'
                                })
                                logger.error(f"❌ Agent {agent['name']} notification failed: {response.status}")
                            
            except asyncio.TimeoutError:
                results.append({
                    'node': agent['name'],
                    'success': False,
                    'error': 'Connection timeout'
                })
                logger.error(f"❌ Agent {agent['name']} timeout")
                
            except Exception as e:
                results.append({
                    'node': agent['name'],
                    'success': False,
                    'error': str(e)
                })
                logger.error(f"❌ Agent {agent['name']} error: {e}")
        
        return results
        
    except Exception as e:
        logger.error(f"Failed to notify agents for cluster {cluster_id}: {e}")
        return [{'node': 'cluster', 'success': False, 'error': str(e)}]
        
    finally:
        if conn:
            await close_database_connection(conn)

async def get_cluster_agents_status(cluster_id: int) -> Dict[str, Any]:
    """Get status of all agents in a cluster"""
    conn = None
    try:
        conn = await get_database_connection()
        
        # Get agent count by status for this cluster
        stats = await conn.fetchrow("""
            SELECT 
                COUNT(*) as total_agents,
                COUNT(CASE WHEN a.status = 'online' THEN 1 END) as online_agents,
                COUNT(CASE WHEN a.status = 'offline' THEN 1 END) as offline_agents,
                COUNT(CASE WHEN a.status = 'warning' THEN 1 END) as warning_agents
            FROM agents a
            JOIN haproxy_cluster_pools p ON a.pool_id = p.id
            JOIN haproxy_clusters c ON c.pool_id = p.id
            WHERE c.id = $1
        """, cluster_id)
        
        return {
            "total": stats["total_agents"] or 0,
            "online": stats["online_agents"] or 0,
            "offline": stats["offline_agents"] or 0,
            "warning": stats["warning_agents"] or 0
        }
        
    except Exception as e:
        logger.error(f"Failed to get cluster agents status: {e}")
        return {"total": 0, "online": 0, "offline": 0, "warning": 0}
        
    finally:
        if conn:
            await close_database_connection(conn) 