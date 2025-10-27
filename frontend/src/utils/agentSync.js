import axios from 'axios';

/**
 * Global Agent Sync Verification Utility
 * Verifies that agents have actually applied configuration changes
 * Used across all entity management pages
 */

// CRITICAL: Real agent sync verification - checks actual deployed state on agents
export const verifyRealAgentSync = async (entities, selectedCluster) => {
  if (!selectedCluster || !entities || entities.length === 0) return false;
  
  try {
    const token = localStorage.getItem('token');
    
    // Check each entity's real deployment status on agents
    const syncResults = await Promise.all(
      entities.map(async (entity) => {
        try {
          let endpoint;
          if (entity.type === 'ssl_certificates') {
            endpoint = `/api/clusters/${selectedCluster.id}/ssl_certificates/${entity.id}/agent-sync`;
          } else {
            endpoint = `/api/clusters/${selectedCluster.id}/entity-sync/${entity.type}/${entity.id}`;
          }
          
          const response = await axios.get(endpoint, {
            headers: { Authorization: `Bearer ${token}` }
          });
          
          const syncStatus = response.data.sync_status;
          const isFullySynced = syncStatus?.synced_agents === syncStatus?.total_agents && 
                               syncStatus?.synced_agents > 0;
          
          console.log(`🔍 REAL SYNC CHECK: ${entity.type}/${entity.id} - ${syncStatus?.synced_agents}/${syncStatus?.total_agents} - ${isFullySynced ? 'SYNCED' : 'PENDING'}`);
          
          return isFullySynced;
        } catch (error) {
          console.error(`Failed to verify sync for ${entity.type}/${entity.id}:`, error);
          return false; // If we can't verify, assume not synced
        }
      })
    );
    
    const allSynced = syncResults.every(result => result === true);
    console.log(`🔍 REAL SYNC VERIFICATION: ${syncResults.filter(r => r).length}/${syncResults.length} entities synced - Overall: ${allSynced ? 'ALL SYNCED' : 'PENDING'}`);
    
    return allSynced;
  } catch (error) {
    console.error('Error verifying real agent sync:', error);
    return false;
  }
};

/**
 * Wait for entity sync completion with progress updates
 * Used when applying changes to ensure real agent deployment
 */
export const waitForEntitySync = async (entities, selectedCluster, onProgress = null) => {
  const maxAttempts = 30; // 5 minutes max (10 second intervals)
  let attempt = 0;
  
  while (attempt < maxAttempts) {
    const isFullySynced = await verifyRealAgentSync(entities, selectedCluster);
    
    if (onProgress) {
      const progress = Math.min(90, (attempt / maxAttempts) * 90); // Max 90% until fully synced
      onProgress(progress, `Verifying agent deployment... (${attempt + 1}/${maxAttempts})`);
    }
    
    if (isFullySynced) {
      if (onProgress) onProgress(100, 'All agents synced successfully!');
      return true;
    }
    
    // Wait 10 seconds before next check
    await new Promise(resolve => setTimeout(resolve, 10000));
    attempt++;
  }
  
  console.warn(`⚠️ SYNC TIMEOUT: Entities not fully synced after ${maxAttempts} attempts`);
  return false;
};

/**
 * Format entity for sync verification
 */
export const formatEntityForSync = (id, type) => ({
  id,
  type: type.endsWith('s') ? type.slice(0, -1) : type // Remove trailing 's' if present
});

/**
 * Check if entity needs sync verification based on last update time
 */
export const shouldVerifySync = (entityUpdatedAt, thresholdMinutes = 10) => {
  if (!entityUpdatedAt) return false;
  
  const entityUpdateTime = new Date(entityUpdatedAt);
  const now = new Date();
  const timeDiffMinutes = (now - entityUpdateTime) / (1000 * 60);
  
  return timeDiffMinutes <= thresholdMinutes;
};
