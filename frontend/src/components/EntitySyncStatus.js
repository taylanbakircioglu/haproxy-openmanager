import React, { useState, useEffect } from 'react';
import { Tag, Tooltip, Spin } from 'antd';
import { CheckCircleOutlined, ClockCircleOutlined, SyncOutlined } from '@ant-design/icons';
import { getConfigStatusColor } from '../utils/colors';
import { useProgress } from '../contexts/ProgressContext';
import axios from 'axios';

/**
 * EntitySyncStatus - Alternative to problematic Agent Sync
 * Uses Last Applied timestamp and Progress completion status
 */
const EntitySyncStatus = ({ 
  entityType, 
  entityId, 
  entityUpdatedAt, 
  lastConfigStatus,
  clusterId,
  selectedCluster 
}) => {
  const [syncStatus, setSyncStatus] = useState('unknown');
  const [loading, setLoading] = useState(false);
  const [lastAppliedTime, setLastAppliedTime] = useState(null);
  const [realSyncData, setRealSyncData] = useState(null);
  const [lastAppliedBy, setLastAppliedBy] = useState(null);
  const { isProgressActive } = useProgress();

  // Fetch real agent sync data
  useEffect(() => {
    const fetchRealSyncData = async () => {
      if (!entityId || !selectedCluster) return;
      
      try {
        const token = localStorage.getItem('token');
        let endpoint;
        
        if (entityType === 'ssl_certificates') {
          endpoint = `/api/clusters/${selectedCluster.id}/ssl_certificates/${entityId}/agent-sync`;
        } else {
          endpoint = `/api/clusters/${selectedCluster.id}/entity-sync/${entityType}/${entityId}`;
        }
        
        const response = await axios.get(endpoint, {
          headers: { Authorization: `Bearer ${token}` }
        });
        
        setRealSyncData({
          ...response.data.sync_status,
          entity_updated_at: response.data.entity_updated_at,
          latest_applied_version: response.data.latest_applied_version,
          latest_version_created_at: response.data.latest_version_created_at,
          latest_version_metadata: response.data.latest_version_metadata
        });
        
        // Store last_applied_by info for tooltip
        if (response.data.last_applied_by) {
          setLastAppliedBy(response.data.last_applied_by);
        }
      } catch (error) {
        // Silently handle 404 errors (entity may have been deleted)
        if (error.response?.status !== 404) {
          console.error(`Failed to fetch sync data for ${entityType}/${entityId}:`, error);
        }
        setRealSyncData(null);
      }
    };

    // Only fetch data for APPLIED entities - PENDING entities don't need API data
    if (lastConfigStatus === 'APPLIED') {
      fetchRealSyncData();
      
      // Only auto-refresh during active progress for APPLIED entities
      // This reduces unnecessary API calls and prevents cascade updates
      if (isProgressActive()) {
        const interval = setInterval(fetchRealSyncData, 8000); // Increased to 8 seconds to reduce load
        return () => clearInterval(interval);
      }
    }
  }, [entityId, selectedCluster, entityType, lastConfigStatus, isProgressActive]);

  // Determine sync status based on entity state and progress completion
  useEffect(() => {
    if (!entityId || !selectedCluster) {
      setSyncStatus('unknown');
      return;
    }

    const checkSyncStatus = () => {
      console.log(`🔍 ENTITY SYNC STATUS: ${entityType}/${entityId} - lastConfigStatus: ${lastConfigStatus}, isProgressActive: ${isProgressActive()}, realSyncData:`, realSyncData);
      
      // ENTERPRISE LOGIC: Version-based tracking for accurate sync status
      // 1. PENDING entity → Show "PENDING" (not applied yet, not sent to agents)
      // 2. APPLIED entity → Check if entity is in latest cluster version (requires API data)
      //    - If entity in latest version but agents not synced → "Applying..."
      //    - If entity not in latest version (already synced from previous apply) → "SYNCED"
      //    - If entity in latest version and agents synced → "SYNCED"
      
      // IMMEDIATE CHECK: Handle PENDING status without waiting for API data
      if (lastConfigStatus === 'PENDING') {
        setSyncStatus('pending');  // PENDING entities show "PENDING", not "APPLYING"
        console.log(`🎯 ENTERPRISE LOGIC: ${entityType}/${entityId} - Entity is PENDING, showing PENDING (not applied yet)`);
        return;
      }

      // APPLIED entities require API data for accurate version-based tracking
      if (lastConfigStatus === 'APPLIED') {
        if (realSyncData) {
          const { synced_agents, total_agents, latest_applied_version, entity_updated_at, latest_version_created_at } = realSyncData;
          
        // ENTERPRISE LOGIC: Check if entity was ACTUALLY modified in the latest apply
        // Only entities that were genuinely changed should show "APPLYING..."
        let isEntityInLatestApply = false;
        
        // CRITICAL FIX: Check metadata for restore operations
        // If latest version has "changed_entities" metadata, ONLY those entities should show "Applying"
        const latestVersionMetadata = realSyncData?.latest_version_metadata;
        if (latestVersionMetadata && latestVersionMetadata.changed_entities) {
          // Restore or selective update - check if THIS entity is in changed list
          // Normalize entity types: frontends -> frontend, backends -> backend, waf_rules -> waf_rule
          const normalizedType = entityType === 'frontends' ? 'frontend' : 
                                entityType === 'backends' ? 'backend' : 
                                entityType === 'waf_rules' ? 'waf_rule' :
                                entityType === 'backend_servers' ? 'backend_server' :
                                entityType;
          
          const isInChangedList = latestVersionMetadata.changed_entities.some(
            change => change.type === normalizedType && 
                     change.id === entityId
          );
          
          if (isInChangedList) {
            isEntityInLatestApply = true;
            console.log(`🎯 METADATA CHECK: ${entityType}/${entityId} - Entity IS in changed_entities list, showing in latest apply`);
          } else {
            isEntityInLatestApply = false;
            console.log(`🎯 METADATA CHECK: ${entityType}/${entityId} - Entity NOT in changed_entities list, showing as already synced`);
          }
        } else if (entity_updated_at && latest_version_created_at) {
          // Fallback to timestamp-based detection (for non-restore operations)
          try {
            // Backend already sends timestamps with 'Z' suffix (UTC), don't add again
            const entityTime = new Date(entity_updated_at);
            const versionTime = new Date(latest_version_created_at);
            
            // ENTERPRISE APPROACH: More restrictive criteria for "in latest apply"
            // Entity must be updated AFTER version creation (not just within window)
            // This prevents false positives from batch PENDING->APPLIED updates
            const timeDiffMinutes = (entityTime - versionTime) / (1000 * 60);
            const entityUpdatedAfterVersion = timeDiffMinutes >= 0; // Entity updated AT or AFTER version creation
            const withinReasonableWindow = timeDiffMinutes <= 5; // Within 5 minutes max
            
            // CRITICAL: Only consider entity as "in latest apply" if:
            // 1. Entity was updated AT or AFTER the version was created (indicating real change)
            // 2. Within a reasonable time window (5 minutes max)
            // 3. AND agents are not yet fully synced (if they are, it should be SYNCED)
            const agentsNotSynced = synced_agents < total_agents;
            isEntityInLatestApply = entityUpdatedAfterVersion && withinReasonableWindow;
            
            console.log(`🔍 ENTERPRISE TRACKING: ${entityType}/${entityId} - entity_time: ${entity_updated_at}, version_time: ${latest_version_created_at}, diff: ${timeDiffMinutes.toFixed(1)}min, updated_after: ${entityUpdatedAfterVersion}, agents_synced: ${synced_agents}/${total_agents}, in_latest: ${isEntityInLatestApply}`);
          } catch (error) {
            console.log(`🔍 VERSION TRACKING ERROR: ${entityType}/${entityId} - ${error.message}`);
            isEntityInLatestApply = false;
          }
        }
          
          // Apply enterprise logic based on version tracking
          if (isEntityInLatestApply) {
            // Entity was part of latest apply - check agent sync status
            if (synced_agents < total_agents) {
              setSyncStatus('applying');
              console.log(`🎯 ENTERPRISE LOGIC: ${entityType}/${entityId} - In latest apply, agents not synced (${synced_agents}/${total_agents}), showing APPLYING`);
            } else {
              setSyncStatus('synced');
              console.log(`🎯 ENTERPRISE LOGIC: ${entityType}/${entityId} - In latest apply, all agents synced (${synced_agents}/${total_agents}), showing SYNCED`);
            }
          } else {
            // Entity not in latest apply - already synced from previous operations
            setSyncStatus('synced');
            console.log(`🎯 ENTERPRISE LOGIC: ${entityType}/${entityId} - Not in latest apply, showing SYNCED (already synced from previous operations)`);
          }
          return;
        } else {
          // APPLIED entity but no API data yet - show loading state briefly
          setSyncStatus('loading');
          console.log(`🔍 ENTERPRISE LOGIC: ${entityType}/${entityId} - APPLIED entity, waiting for API data`);
          return;
        }
      }

      // Default case for unknown config status
      setSyncStatus('unknown');
      console.log(`🔍 ENTERPRISE LOGIC: ${entityType}/${entityId} - Unknown config status: ${lastConfigStatus}`);
    };

    checkSyncStatus();
  }, [entityId, entityUpdatedAt, lastConfigStatus, selectedCluster, isProgressActive, realSyncData]);

  const getSyncDisplay = () => {
    switch (syncStatus) {
      case 'pending':
        return {
          status: 'PENDING',
          color: 'orange',  // Orange for pending changes
          icon: <ClockCircleOutlined />,
          tooltip: 'Changes pending - not yet applied'
        };
      
      case 'applying':
        return {
          status: 'APPLYING',
          color: 'blue',  // Blue for in-progress
          icon: <SyncOutlined spin />,
          tooltip: 'Applying changes to agents...'
        };
      
      case 'loading':
        return {
          status: 'LOADING',
          color: 'default',  // Gray for loading
          icon: <SyncOutlined spin />,
          tooltip: 'Loading sync status...'
        };
      
      case 'recently_synced':
        // Build tooltip with optional "applied by" info
        const recentTooltipParts = ['Recently applied and synced'];
        if (lastAppliedBy) {
          const appliedTime = new Date(lastAppliedBy.applied_at).toLocaleString();
          recentTooltipParts.push(`Applied by: ${lastAppliedBy.username} at ${appliedTime}`);
        } else if (lastAppliedTime) {
          recentTooltipParts.push(`Last update: ${lastAppliedTime.toLocaleString()} (local time)`);
        }
        
        return {
          status: 'SYNCED',
          color: getConfigStatusColor('APPLIED'),   // green (same as APPLIED)
          icon: <SyncOutlined />,
          tooltip: recentTooltipParts.join(' • ')
        };
      
      case 'synced':
        // Build tooltip with optional "applied by" info
        const syncedTooltipParts = ['Configuration applied and synced'];
        if (lastAppliedBy) {
          const appliedTime = new Date(lastAppliedBy.applied_at).toLocaleString();
          syncedTooltipParts.push(`Applied by: ${lastAppliedBy.username} at ${appliedTime}`);
        } else if (lastAppliedTime) {
          syncedTooltipParts.push(`Last update: ${lastAppliedTime.toLocaleString()} (local time)`);
        }
        
        return {
          status: 'SYNCED', 
          color: getConfigStatusColor('APPLIED'),   // green (same as APPLIED)
          icon: <CheckCircleOutlined />,
          tooltip: syncedTooltipParts.join(' • ')
        };
      
      default:
        return {
          status: '-',
          color: 'default',  // Ant Design default gray
          icon: <ClockCircleOutlined />,
          tooltip: 'Sync status unknown'
        };
    }
  };

  if (loading) {
    return <Spin size="small" />;
  }

  const { status, color, icon, tooltip } = getSyncDisplay();

  return (
    <Tooltip title={tooltip}>
      <Tag color={color} icon={icon}>
        {status}
      </Tag>
    </Tooltip>
  );
};

export default EntitySyncStatus;
