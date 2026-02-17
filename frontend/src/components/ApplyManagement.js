import React, { useState, useEffect } from 'react';
import {
  Card, Button, Space, Row, Col, message, Alert, Spin, 
  Typography, Tag, Table, Modal, Divider, Badge, Empty,
  Timeline, Descriptions, Tabs, Progress, Tooltip, Collapse, Steps, Input
} from 'antd';
import { getAgentSyncColor, getConfigStatusColor, COLORS } from '../utils/colors';
import { useProgress } from '../contexts/ProgressContext';
import {
  CheckCircleOutlined, ExclamationCircleOutlined, SyncOutlined,
  ClockCircleOutlined, PlayCircleOutlined, ReloadOutlined,
  CloudServerOutlined, GlobalOutlined, SecurityScanOutlined, 
  SafetyCertificateOutlined, InfoCircleOutlined, HistoryOutlined,
  EyeOutlined, CloseOutlined, CloseCircleOutlined, RedoOutlined,
  UndoOutlined, CloudUploadOutlined, WarningOutlined, CodeOutlined,
  CopyOutlined, EditOutlined, RightOutlined
} from '@ant-design/icons';
import axios from 'axios';
import { useCluster } from '../contexts/ClusterContext';
import { Select } from 'antd';
import { useNavigate } from 'react-router-dom';
import ValidationErrorModal from './ValidationErrorModal';

const { Title, Text, Paragraph } = Typography;
const { TabPane } = Tabs;

const ApplyManagement = () => {
  const { selectedCluster } = useCluster();
  const navigate = useNavigate();
  
  // State
  const [loading, setLoading] = useState(false);
  const [applyLoading, setApplyLoading] = useState(false);
  const [pendingChanges, setPendingChanges] = useState({
    frontends: [],
    backends: [],
    waf_rules: [],
    ssl_certificates: [],
    total_count: 0
  });
  const [configVersions, setConfigVersions] = useState([]);
  const [viewChangeModalVisible, setViewChangeModalVisible] = useState(false);
  const [selectedVersion, setSelectedVersion] = useState(null);
  const [diffData, setDiffData] = useState(null);
  const [diffLoading, setDiffLoading] = useState(false);
  const [agentSync, setAgentSync] = useState(null);
  const [agentSyncLoading, setAgentSyncLoading] = useState(false);
  const [syncProgress, setSyncProgress] = useState({ visible: false, step: '', progress: 0 });
  const { startProgress, updateProgress, updateEntityCounts, completeProgress, isProgressActive } = useProgress();
  const [entitySyncStates, setEntitySyncStates] = useState({});
  
  // Validation Error Modal state
  const [validationErrorModalVisible, setValidationErrorModalVisible] = useState(false);
  const [selectedValidationError, setSelectedValidationError] = useState(null);

  // Initial load on component mount
  useEffect(() => {
    if (selectedCluster) {
      fetchPendingChanges();
      fetchConfigVersions();
      fetchAgentSync();
    }
  }, []); // Run once on mount

  // Cluster change handler
  useEffect(() => {
    if (selectedCluster) {
      // CRITICAL: Clear all state immediately when cluster changes to prevent cross-cluster contamination
      setPendingChanges({ frontends: [], backends: [], waf_rules: [], ssl_certificates: [], total_count: 0 });
      setConfigVersions([]);
      setAgentSync(null);
      setEntitySyncStates({});
      
      // Then fetch new data
      fetchPendingChanges();
      fetchConfigVersions();
      fetchAgentSync();
    } else {
      setPendingChanges({ frontends: [], backends: [], waf_rules: [], ssl_certificates: [], total_count: 0 });
      setConfigVersions([]);
      setAgentSync(null);
      setEntitySyncStates({});
    }
  }, [selectedCluster?.id]); // Use selectedCluster.id to prevent re-render on object change

  // Fetch entity sync states when pending changes are loaded
  // CRITICAL: Only fetch for the CURRENT cluster to prevent 404 errors on old entity IDs
  useEffect(() => {
    if (selectedCluster && (pendingChanges.frontends.length > 0 || pendingChanges.backends.length > 0 || 
        pendingChanges.waf_rules.length > 0 || pendingChanges.ssl_certificates.length > 0)) {
      fetchEntitySyncStates();
    }
  }, [selectedCluster?.id, pendingChanges]);

  // Auto-refresh agent sync status every 10 seconds
  useEffect(() => {
    if (!selectedCluster) return;

    const interval = setInterval(() => {
      fetchAgentSync();
      fetchEntitySyncStates(); // Also refresh entity sync states
    }, 10000); // 10 seconds

    return () => clearInterval(interval);
  }, [selectedCluster]);


  const fetchPendingChanges = async () => {
    if (!selectedCluster) return;
    
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      if (!token || token === 'null' || token.trim() === '') {
        message.error('Authentication required. Please login again.');
        return;
      }

      // Fetch pending changes from all modules
      // CRITICAL FIX: Add cache-control headers to prevent stale data
      const cacheHeaders = {
        'Authorization': `Bearer ${token}`,
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache'
      };
      
      const [frontendsRes, backendsRes, wafRes, sslRes] = await Promise.all([
        axios.get('/api/frontends', { 
          params: { cluster_id: selectedCluster.id, include_inactive: true },
          headers: cacheHeaders
        }).catch(() => ({ data: { frontends: [] } })),
        
        axios.get('/api/backends', { 
          params: { cluster_id: selectedCluster.id, include_inactive: true },
          headers: cacheHeaders
        }).catch(() => ({ data: { backends: [] } })),
        
        axios.get('/api/waf/rules', { 
          params: { cluster_id: selectedCluster.id },
          headers: cacheHeaders
        }).catch(() => ({ data: { rules: [] } })),
        
        axios.get('/api/ssl/certificates', { 
          params: { cluster_id: selectedCluster.id },
          headers: cacheHeaders
        }).catch(() => ({ data: [] }))
      ]);

      // DEBUG: Log raw backend data
      console.log('[APPLY MANAGEMENT DEBUG] Backend Data:');
      console.log('Total backends from API:', backendsRes.data.backends?.length || 0);
      
      // CRITICAL DEBUG: Log ALL backends to find the hidden pending one
      console.log('[ALL BACKENDS FROM API]:');
      (backendsRes.data.backends || []).forEach(b => {
        console.log(`  - Backend: ${b.name} (id=${b.id})`, {
          cluster_id: b.cluster_id,
          last_config_status: b.last_config_status,
          has_pending_config: b.has_pending_config,
          is_active: b.is_active
        });
      });
      
      // Filter pending changes
      const frontends = (frontendsRes.data.frontends || []).filter(f => f.has_pending_config);
      const backends = (backendsRes.data.backends || []).filter(b => b.has_pending_config);
      
      // CRITICAL DEBUG: Log ALL filtered pending backends
      console.log('[Filtered pending backends]:', backends.length);
      console.log('[PENDING BACKENDS DETAILS]:');
      backends.forEach(b => {
        console.log(`  [PENDING] ${b.name} (id=${b.id})`, {
          cluster_id: b.cluster_id,
          last_config_status: b.last_config_status,
          has_pending_config: b.has_pending_config,
          is_active: b.is_active
        });
      });
      
      const waf_rules = (wafRes.data.rules || []).filter(w => w.has_pending_config);
      const ssl_certificates = (sslRes.data.ssl_certificates || sslRes.data || []).filter(s => s.has_pending_config);

      const total_count = frontends.length + backends.length + waf_rules.length + ssl_certificates.length;

      setPendingChanges({
        frontends,
        backends,
        waf_rules,
        ssl_certificates,
        total_count
      });

    } catch (error) {
      console.error('Error fetching pending changes:', error);
      message.error('Failed to fetch pending changes');
    } finally {
      setLoading(false);
    }
  };

  const fetchConfigVersions = async () => {
    if (!selectedCluster) return;
    
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(
        `/api/clusters/${selectedCluster.id}/config-versions`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      
      setConfigVersions(response.data.config_versions || []);
    } catch (error) {
      console.error('Error fetching config versions:', error);
    }
  };

  const fetchAgentSync = async () => {
    if (!selectedCluster) return null;
    setAgentSyncLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(
        `/api/clusters/${selectedCluster.id}/agent-sync`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setAgentSync(response.data);
      return response.data; // Return the data for immediate use
    } catch (error) {
      console.error('Error fetching agent sync status:', error);
      return null;
    } finally {
      setAgentSyncLoading(false);
    }
  };

  const fetchEntitySyncStates = async () => {
    if (!selectedCluster) return;
    
    const newSyncStates = {};
    const token = localStorage.getItem('token');
    
    try {
      // Fetch sync states for all pending entities
      const allPendingEntities = [
        ...pendingChanges.frontends.map(item => ({ type: 'frontends', id: item.id, name: item.name })),
        ...pendingChanges.backends.map(item => ({ type: 'backends', id: item.id, name: item.name })),
        ...pendingChanges.waf_rules.map(item => ({ type: 'waf_rules', id: item.id, name: item.name })),
        ...pendingChanges.ssl_certificates.map(item => ({ type: 'ssl_certificates', id: item.id, name: item.name }))
      ];

      await Promise.all(
        allPendingEntities.map(async (entity) => {
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
            
            const key = `${entity.type}-${entity.id}`;
            newSyncStates[key] = {
              ...response.data.sync_status,
              status: response.data.sync_status?.synced_agents === response.data.sync_status?.total_agents ? 'synced' : 'syncing'
            };
          } catch (error) {
            const key = `${entity.type}-${entity.id}`;
            // 404 means entity was deleted - consider it as synced
            if (error.response && error.response.status === 404) {
              console.log(`ENTITY DELETED: ${entity.type}/${entity.id} - marking as synced (successfully removed)`);
              newSyncStates[key] = { status: 'synced', synced_agents: 1, total_agents: 1 };
            } else {
              console.error(`Failed to fetch sync state for ${entity.type}/${entity.id}:`, error);
              newSyncStates[key] = { status: 'unknown' };
            }
          }
        })
      );
      
      setEntitySyncStates(newSyncStates);
    } catch (error) {
      console.error('Error fetching entity sync states:', error);
    }
  };

  // CRITICAL: Real agent sync verification - checks actual deployed state on agents
  const verifyRealAgentSync = async (pendingEntities) => {
    if (!selectedCluster || pendingEntities.length === 0) return false;
    
    try {
      const token = localStorage.getItem('token');
      
      // Check each entity's real deployment status on agents
      const syncResults = await Promise.all(
        pendingEntities.map(async (entity) => {
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
            // If sync_status is null or has 0 enabled agents, consider as synced - nothing to wait for
            if (!syncStatus || syncStatus.total_agents === 0) {
              console.log(`REAL SYNC CHECK: ${entity.type}/${entity.id} - No enabled agents, considering as synced`);
              return true;
            }
            const isFullySynced = syncStatus?.synced_agents === syncStatus?.total_agents && 
                                 syncStatus?.synced_agents > 0;
            
            console.log(`REAL SYNC CHECK: ${entity.type}/${entity.id} - ${syncStatus?.synced_agents}/${syncStatus?.total_agents} - ${isFullySynced ? 'SYNCED' : 'PENDING'}`);
            
            return isFullySynced;
          } catch (error) {
            // 404 means entity was deleted - consider it as synced (successfully removed)
            if (error.response && error.response.status === 404) {
              console.log(`ENTITY DELETED: ${entity.type}/${entity.id} - considering as synced (successfully removed)`);
              return true;
            }
            console.error(`Failed to verify sync for ${entity.type}/${entity.id}:`, error);
            return false; // If we can't verify, assume not synced
          }
        })
      );
      
      const allSynced = syncResults.every(result => result === true);
      console.log(`REAL SYNC VERIFICATION: ${syncResults.filter(r => r).length}/${syncResults.length} entities synced - Overall: ${allSynced ? 'ALL SYNCED' : 'PENDING'}`);
      
      return allSynced;
    } catch (error) {
      console.error('Error verifying real agent sync:', error);
      return false;
    }
  };

  const handleApplyAllChanges = async () => {
    if (!selectedCluster) return;
    
    if (effectiveTotal === 0) {
      message.info('No pending changes to apply');
      return;
    }

    Modal.confirm({
      title: 'Apply All Configuration Changes',
      content: (
        <div>
          <p>You are about to apply <strong>{effectiveTotal}</strong> pending changes:</p>
          <ul style={{ marginTop: 10, marginBottom: 10 }}>
            {pendingChanges.frontends.length > 0 && (
              <li><strong>{pendingChanges.frontends.length}</strong> Frontend changes</li>
            )}
            {pendingChanges.backends.length > 0 && (
              <li><strong>{pendingChanges.backends.length}</strong> Backend changes</li>
            )}
            {pendingChanges.waf_rules.length > 0 && (
              <li><strong>{pendingChanges.waf_rules.length}</strong> WAF rule changes</li>
            )}
            {pendingChanges.ssl_certificates.length > 0 && (
              <li><strong>{pendingChanges.ssl_certificates.length}</strong> SSL certificate changes</li>
            )}
          </ul>
          <Alert
            message="All changes will be applied together and sent to agents"
            type="info"
            showIcon
            style={{ marginTop: 16 }}
          />
        </div>
      ),
      okText: 'Apply All Changes',
      okType: 'primary',
      cancelText: 'Cancel',
      width: 600,
      onOk: executeApplyAll
    });
  };

  const executeApplyAll = async () => {
    setApplyLoading(true);
    
      // CRITICAL DEBUG: Log what we're about to apply
      console.log('[EXECUTE APPLY ALL] Starting...');
      console.log('[Pending Changes State]:', {
        frontends: pendingChanges.frontends.length,
        backends: pendingChanges.backends.length,
        waf_rules: pendingChanges.waf_rules.length,
        ssl_certificates: pendingChanges.ssl_certificates.length,
        total: effectiveTotal
      });
      console.log('[Backend Details Being Applied]:');
      pendingChanges.backends.forEach(b => {
        console.log(`  - Backend: ${b.name} (id=${b.id})`, {
          last_config_status: b.last_config_status,
          has_pending_config: b.has_pending_config,
          is_active: b.is_active
        });
      });
    
      // CRITICAL: Mark this browser session as the one who initiated apply
      // This prevents notification confusion when multiple users share same admin account
      const applySessionId = `apply_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      sessionStorage.setItem(`apply_session_${selectedCluster.id}`, applySessionId);
      sessionStorage.setItem(`apply_timestamp_${selectedCluster.id}`, Date.now().toString());
      
      // CRITICAL: Save entities BEFORE apply (they'll be empty after apply)
      const appliedEntities = [
        ...pendingChanges.frontends.map(item => ({ type: 'frontends', id: item.id })),
        ...pendingChanges.backends.map(item => ({ type: 'backends', id: item.id })),
        ...pendingChanges.waf_rules.map(item => ({ type: 'waf_rules', id: item.id })),
        ...pendingChanges.ssl_certificates.map(item => ({ type: 'ssl_certificates', id: item.id }))
      ];
      
      // Calculate entity and agent counts for progress display
      const totalEntities = appliedEntities.length;
      const totalAgents = agentSync?.total_agents || selectedCluster?.total_agents || 1;
      const disabledAgents = agentSync?.disabled_agents || 0;
      
      // Detect if this is a restore operation (safe display-only check)
      const pendingVersions = configVersions.filter(v => v.status === 'PENDING');
      const isRestoreOperation = totalEntities === 0 && pendingVersions.some(v => v.version_name.startsWith('restore-'));
      
      if (isRestoreOperation) {
        // Restore operation: Show "Configuration" instead of "Entities"
        setSyncProgress({ visible: true, step: `Applying configuration restore... Configuration: 0/1, Agents: ⏳`, progress: 20 });
        startProgress('apply', `Applying configuration restore... Configuration: 0/1, Agents: ⏳`);
        updateEntityCounts(0, 1, 0, totalAgents, disabledAgents); // Show 1 configuration item
      } else {
        // Normal operation: Show "Entities" as usual
        setSyncProgress({ visible: true, step: `Applying configuration changes... Entities: 0/${totalEntities}, Agents: ⏳`, progress: 20 });
        startProgress('apply', `Applying configuration changes... Entities: 0/${totalEntities}, Agents: ⏳`);
        updateEntityCounts(0, totalEntities, 0, totalAgents, disabledAgents);
      }
    
    try {
      const token = localStorage.getItem('token');
      
      const response = await axios.post(
        `/api/clusters/${selectedCluster.id}/apply-changes`,
        {},
        { headers: { Authorization: `Bearer ${token}` } }
      );
      
      // CRITICAL DEBUG: Log apply response
      console.log('[APPLY ALL RESPONSE]:', response.data);
      
      setSyncProgress({ visible: true, step: `Configuration applied, syncing agents... Entities: ${totalEntities}/${totalEntities}, Agents: 0/${totalAgents}`, progress: 60 });
      updateProgress(`Configuration applied, syncing agents... Entities: ${totalEntities}/${totalEntities}, Agents: 0/${totalAgents}`, 60);
      updateEntityCounts(totalEntities, totalEntities, 0, totalAgents, disabledAgents);
      
      // Refresh data immediately
      console.log('[REFRESHING DATA] after apply...');
      await fetchPendingChanges();
      await fetchConfigVersions();
      await fetchAgentSync();
      console.log('[DATA REFRESHED] after apply');

      setSyncProgress({ visible: true, step: `Waiting for agent synchronization... Entities: ${totalEntities}/${totalEntities}, Agents: ⏳/${totalAgents}`, progress: 80 });
      updateProgress(`Waiting for agent synchronization... Entities: ${totalEntities}/${totalEntities}, Agents: ⏳/${totalAgents}`, 80);

      // Enhanced refresh with progress tracking
      let syncAttempts = 0;
      const maxAttempts = 6; // 6 attempts over 18 seconds
      
      const checkAgentSync = async () => {
        syncAttempts++;
        const freshAgentSync = await fetchAgentSync(); // Get fresh data immediately
        await fetchEntitySyncStates(); // Also update individual entity states
        
        // Use the saved appliedEntities (not pendingChanges which is now empty)
        
        // CRITICAL: Real agent sync verification - check actual deployed state
        const allSynced = await verifyRealAgentSync(appliedEntities);
        
        // CRITICAL FIX: Use allSynced result for syncedCount instead of stale entitySyncStates
        // After Apply, fetchPendingChanges() refreshes to empty (entities deleted/applied),
        // so fetchEntitySyncStates() has no entities to check, leaving entitySyncStates empty.
        // This caused syncedCount to always be 0 even when all entities are confirmed synced.
        const syncedCount = allSynced ? appliedEntities.length : appliedEntities.filter(entity => {
          const syncKey = `${entity.type}-${entity.id}`;
          const entitySync = entitySyncStates[syncKey];
          return entitySync?.status === 'synced';
        }).length;
        
        // Additional check: Verify cluster-wide agent sync is also complete
        // Use fresh data instead of stale state
        // If no enabled agents exist (all disabled), cluster sync is inherently complete
        const noEnabledAgents = freshAgentSync?.total_agents === 0 && freshAgentSync?.disabled_agents > 0;
        const clusterSyncComplete = noEnabledAgents || 
                                   (freshAgentSync?.synced_agents === freshAgentSync?.total_agents && 
                                   freshAgentSync?.synced_agents > 0);
        
        
        // Check for restore operation completion
        const isRestoreOperation = appliedEntities.length === 0;
        const shouldCompleteRestore = isRestoreOperation && clusterSyncComplete;
        const shouldCompleteNormal = allSynced && clusterSyncComplete && appliedEntities.length > 0;
        
        // CRITICAL FIX: When ALL entities are confirmed synced (including via 404 for deleted entities)
        // and we've waited long enough, complete even if cluster agent sync hasn't finished yet.
        // The agent will receive the updated config on its next poll cycle (every 30s).
        // This prevents the "stuck at Applying" bug when all entities are deleted.
        const shouldCompleteEntitiesDone = allSynced && appliedEntities.length > 0 && 
                                           !clusterSyncComplete && syncAttempts >= 4;
        
        if (shouldCompleteRestore || shouldCompleteNormal) {
          // All entities AND cluster are fully synced - complete immediately
          const successMessage = isRestoreOperation ? 
            'Configuration restore completed successfully!' : 
            'All changes deployed and synchronized!';
          
          setSyncProgress({ visible: true, step: successMessage, progress: 100 });
          completeProgress(successMessage);
          setTimeout(() => {
            setSyncProgress({ visible: false, step: '', progress: 0 });
            message.success(isRestoreOperation ? 
              'Configuration restored and synchronized successfully!' :
              'All changes applied and agents synchronized successfully!');
          }, 1500);
        } else if (shouldCompleteEntitiesDone) {
          // All entities are confirmed applied/deleted, but agent hasn't synced yet
          // Complete the progress - agent will sync on its next poll cycle
          const successMessage = 'All changes applied successfully! Agent will sync shortly.';
          
          setSyncProgress({ visible: true, step: successMessage, progress: 100 });
          completeProgress(successMessage);
          setTimeout(() => {
            setSyncProgress({ visible: false, step: '', progress: 0 });
            message.success(successMessage);
          }, 1500);
        } else if (syncAttempts < maxAttempts) {
          // Continue checking
          const clusterStatus = clusterSyncComplete ? '✓' : '⏳';
          
          let progressStep, syncedLabel, totalLabel;
          if (isRestoreOperation) {
            // For restore: Show configuration sync instead of entity sync
            const configSynced = clusterSyncComplete ? 1 : 0;
            progressStep = `Syncing... Configuration: ${configSynced}/1, Cluster: ${clusterStatus}`;
            syncedLabel = `${configSynced}/1`;
            totalLabel = 'Configuration';
          } else {
            // For normal apply: Show entity sync as usual
            progressStep = `Syncing... Entities: ${syncedCount}/${appliedEntities.length}, Cluster: ${clusterStatus}`;
            syncedLabel = `${syncedCount}/${appliedEntities.length}`;
            totalLabel = 'Entities';
          }
          
          const progressValue = 80 + (syncAttempts * 3);
          
          setSyncProgress({ 
            visible: true, 
            step: progressStep, 
            progress: progressValue 
          });
          updateProgress(progressStep, progressValue, {
            [`Synced ${totalLabel}`]: syncedLabel,
            'Cluster Status': clusterStatus === '✓' ? 'Synced' : 'Syncing'
          });
          
          if (isRestoreOperation) {
            updateEntityCounts(clusterSyncComplete ? 1 : 0, 1, freshAgentSync?.synced_agents || 0, freshAgentSync?.total_agents || totalAgents, freshAgentSync?.disabled_agents || disabledAgents);
          } else {
            updateEntityCounts(syncedCount, appliedEntities.length, freshAgentSync?.synced_agents || 0, freshAgentSync?.total_agents || totalAgents, freshAgentSync?.disabled_agents || disabledAgents);
          }
          setTimeout(checkAgentSync, 3000);
        } else {
          // Max attempts reached - use real-time sync verification
          const isAllSynced = await verifyRealAgentSync(appliedEntities);
          const finalSyncedCount = isAllSynced ? appliedEntities.length : 0;
          
          const clusterStatus = clusterSyncComplete ? '✓' : '⏳';
          
          // CRITICAL FIX: If all entities are synced, complete the progress
          // Don't stay stuck forever waiting for agent cluster sync
          if (isAllSynced) {
            const successMessage = clusterSyncComplete ?
              'All changes deployed and synchronized!' :
              'All changes applied successfully! Agent will sync shortly.';
            
            console.log('APPLY COMPLETE: All entities confirmed synced, completing progress');
            setSyncProgress({ visible: true, step: successMessage, progress: 100 });
            completeProgress(successMessage);
            setApplyLoading(false);
            
            // Only show success notification if THIS session initiated the apply
            const applySession = sessionStorage.getItem(`apply_session_${selectedCluster.id}`);
            const applyTimestamp = parseInt(sessionStorage.getItem(`apply_timestamp_${selectedCluster.id}`) || '0');
            const isRecentApply = (Date.now() - applyTimestamp) < 300000; // 5 minutes
            
            if (applySession && isRecentApply) {
              message.success(successMessage);
              sessionStorage.removeItem(`apply_session_${selectedCluster.id}`);
              sessionStorage.removeItem(`apply_timestamp_${selectedCluster.id}`);
            }
            
            return;
          }
          
          // Entities not yet synced - continue monitoring
          const progressStep = `Still syncing... Entities: ${finalSyncedCount}/${appliedEntities.length}, Cluster: ${clusterStatus}`;
          
          setSyncProgress({ 
            visible: true, 
            step: progressStep, 
            progress: 95  // Keep at 95% to show it's not complete
          });
          updateProgress(progressStep, 95, {
            'Synced Entities': `${finalSyncedCount}/${appliedEntities.length}`,
            'Cluster Status': clusterStatus === '✓' ? 'Synced' : 'Syncing',
            'Status': 'Monitoring continues...'
          });
          updateEntityCounts(finalSyncedCount, appliedEntities.length, freshAgentSync?.synced_agents || 0, freshAgentSync?.total_agents || totalAgents, freshAgentSync?.disabled_agents || disabledAgents);
          
          // Continue monitoring every 5 seconds until fully synced
          setTimeout(checkAgentSync, 5000);
        }
      };
      
      setTimeout(checkAgentSync, 2000);
      
      // Show sync results if available
      if (response.data.sync_results && response.data.sync_results.length > 0) {
        const agentResults = response.data.sync_results.filter(r => r.success);
        if (agentResults.length > 0) {
          message.info(`Configuration applied to ${agentResults.length} agent(s). HAProxy reloaded.`);
        }
      }
      
    } catch (error) {
      console.error('Apply all changes failed:', error);
      setSyncProgress({ visible: false, step: '', progress: 0 });
      completeProgress('Apply failed');
      if (error.response?.status === 401) {
        message.error('Authentication failed. Please login again.');
      } else {
        message.error(`Failed to apply changes: ${error.response?.data?.message || error.response?.data?.detail || error.message}`);
      }
    } finally {
      setApplyLoading(false);
    }
  };

  const handleRejectAllChanges = async () => {
    if (!selectedCluster) return;
    
    if (effectiveTotal === 0) {
      message.info('No pending changes to reject');
      return;
    }

    Modal.confirm({
      title: 'Reject All Configuration Changes',
      content: (
        <div>
          <p>You are about to reject <strong>{effectiveTotal}</strong> pending changes:</p>
          <ul style={{ marginTop: 10, marginBottom: 10 }}>
            {pendingChanges.frontends.length > 0 && (
              <li><strong>{pendingChanges.frontends.length}</strong> Frontend changes</li>
            )}
            {pendingChanges.backends.length > 0 && (
              <li><strong>{pendingChanges.backends.length}</strong> Backend changes</li>
            )}
            {pendingChanges.waf_rules.length > 0 && (
              <li><strong>{pendingChanges.waf_rules.length}</strong> WAF rule changes</li>
            )}
            {pendingChanges.ssl_certificates.length > 0 && (
              <li><strong>{pendingChanges.ssl_certificates.length}</strong> SSL certificate changes</li>
            )}
          </ul>
          <Alert
            message="All pending changes will be permanently discarded"
            type="warning"
            showIcon
            style={{ marginTop: 10 }}
          />
        </div>
      ),
      okText: 'Reject All Changes',
      okType: 'danger',
      cancelText: 'Cancel',
      width: 600,
      onOk: executeRejectAll
    });
  };

  const executeRejectAll = async () => {
    setApplyLoading(true);
    
    // CRITICAL DEBUG: Log what we're about to reject
    console.log('[EXECUTE REJECT ALL] Starting...');
    console.log('[Pending Changes State]:', {
      frontends: pendingChanges.frontends.length,
      backends: pendingChanges.backends.length,
      waf_rules: pendingChanges.waf_rules.length,
      ssl_certificates: pendingChanges.ssl_certificates.length,
      total: effectiveTotal
    });
    console.log('[Backend Details Being Rejected]:');
    pendingChanges.backends.forEach(b => {
      console.log(`  - Backend: ${b.name} (id=${b.id})`, {
        last_config_status: b.last_config_status,
        has_pending_config: b.has_pending_config,
        is_active: b.is_active
      });
    });
    
    try {
      const token = localStorage.getItem('token');
      
      const response = await axios.delete(
        `/api/clusters/${selectedCluster.id}/pending-changes`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      
      // CRITICAL DEBUG: Log reject response
      console.log('[REJECT ALL RESPONSE]:', response.data);
      
      message.success(response.data.message || 'All pending changes rejected successfully!');
      
      // Refresh data after successful reject
      console.log('[REFRESHING DATA] after reject...');

      await fetchPendingChanges();
      await fetchConfigVersions();
      await fetchAgentSync();
      
      console.log('[DATA REFRESHED] after reject');
      
    } catch (error) {
      console.error('Error rejecting changes:', error);
      message.error('Failed to reject changes: ' + (error.response?.data?.detail || error.message));
    } finally {
      setApplyLoading(false);
    }
  };

  const handleViewChange = async (version) => {
    setSelectedVersion(version);
    setDiffLoading(true);
    setViewChangeModalVisible(true);
    
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(
        `/api/clusters/${selectedCluster.id}/config-versions/${version.id}/diff`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      
      setDiffData(response.data);
    } catch (error) {
      console.error('Error fetching config diff:', error);
      message.error('Failed to fetch configuration changes');
      setDiffData(null);
    } finally {
      setDiffLoading(false);
    }
  };

  const handleUndoRejected = async (version) => {
    try {
      setApplyLoading(true);
      
      // Undo the rejection - mark this version as PENDING again
      const response = await axios.patch(`/api/clusters/${selectedCluster.id}/config-versions/${version.id}/undo-reject`);
      
      message.success(`Configuration "${version.version_name}" has been undone and is now PENDING. You can apply it from Configuration Changes.`);
      
      // Refresh data
      fetchPendingChanges();
      fetchConfigVersions();
      
    } catch (error) {
      const errorMsg = error.response?.data?.detail || error.message;
      message.error(`Failed to undo rejection: ${errorMsg}`);
    } finally {
      setApplyLoading(false);
    }
  };

  const getStatusColor = (status) => {
    return getConfigStatusColor(status);
  };

  const pendingVersions = configVersions.filter(v => v.status === 'PENDING');
  const appliedVersions = configVersions.filter(v => v.status === 'APPLIED');
  const rejectedVersions = configVersions.filter(v => v.status === 'REJECTED');
  const effectiveTotal = pendingChanges.total_count > 0 ? pendingChanges.total_count : pendingVersions.length;

  const renderPendingItem = (item, type, icon) => {
    // For PENDING items, don't show sync status since they haven't been applied yet
    // Just show the pending status consistently

    return (
      <div key={`${type}-${item.id}`} style={{ 
        padding: 12, 
        border: '1px solid #d9d9d9', 
        borderRadius: 6, 
        marginBottom: 8,
        display: 'flex',
        alignItems: 'center',
        backgroundColor: '#fff'
      }}>
        <div style={{ marginRight: 12, fontSize: 18 }}>
          {icon}
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 'bold' }}>{item.name}</div>
          <div style={{ color: '#666', fontSize: 12 }}>
            {type.charAt(0).toUpperCase() + type.slice(1)} • Updated: {new Date(item.updated_at).toLocaleString()}
          </div>
        </div>
        <Space>
          <Tag color="orange">PENDING</Tag>
        </Space>
      </div>
    );
  };

  if (!selectedCluster) {
    return (
      <Card>
        <Empty 
          description="Please select a cluster to view pending changes"
          image={Empty.PRESENTED_IMAGE_SIMPLE}
        />
      </Card>
    );
  }

  return (
    <div style={{ padding: 24 }}>
      <div style={{ marginBottom: 24, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <Title level={3}>
            <PlayCircleOutlined style={{ marginRight: 8 }} />
            Apply Management
          </Title>
          <Paragraph>
            Review and apply all pending configuration changes for cluster <strong>{selectedCluster.name}</strong>
          </Paragraph>
        </div>
        <Button 
          type="default"
          icon={<HistoryOutlined />}
          onClick={() => navigate('/version-history')}
          size="large"
        >
          Version History
        </Button>
      </div>

      {/* Validation Error Banner - Shows when there's a validation error from agent */}
      {agentSync?.validation_error && (
        <Alert
          type="error"
          banner
          showIcon
          icon={<ExclamationCircleOutlined />}
          style={{ 
            marginBottom: 24, 
            borderRadius: 8,
            border: '1px solid #ffccc7',
            boxShadow: '0 2px 8px rgba(255, 77, 79, 0.15)'
          }}
          message={
            <Space size="middle">
              <Text strong style={{ color: '#cf1322' }}>HAProxy Configuration Failed</Text>
              {agentSync.parsed_error?.line_number && (
                <Tag color="red">Line {agentSync.parsed_error.line_number}</Tag>
              )}
              {agentSync.parsed_error?.entity_name && (
                <Tag color="orange">
                  {agentSync.parsed_error.entity_type}: {agentSync.parsed_error.entity_name}
                </Tag>
              )}
              {agentSync.parsed_error?.has_multiple_errors && (
                <Tag color="volcano">+{agentSync.parsed_error.additional_errors_count} more errors</Tag>
              )}
            </Space>
          }
          description={
            <div style={{ marginTop: 8 }}>
              <Paragraph style={{ margin: 0, marginBottom: 12 }}>
                {agentSync.parsed_error?.suggestion || 'Configuration validation failed on agent. Please check the error details.'}
              </Paragraph>
              <Space>
                <Button 
                  type="primary" 
                  danger
                  icon={<EyeOutlined />}
                  onClick={() => {
                    setSelectedValidationError({
                      validation_error: agentSync.validation_error,
                      validation_error_reported_at: agentSync.validation_error_reported_at,
                      parsed_error: agentSync.parsed_error
                    });
                    setValidationErrorModalVisible(true);
                  }}
                >
                  View Error Details
                </Button>
                {agentSync.parsed_error?.quick_fix_available && agentSync.parsed_error?.quick_fix_url && (
                  <Button 
                    type="primary"
                    icon={<EditOutlined />}
                    onClick={() => navigate(agentSync.parsed_error.quick_fix_url)}
                  >
                    Fix: {agentSync.parsed_error.entity_name}
                  </Button>
                )}
                {agentSync.parsed_error?.entity_name && !agentSync.parsed_error?.quick_fix_available && (
                  <Button 
                    icon={<RightOutlined />}
                    onClick={() => {
                      const entityType = agentSync.parsed_error.entity_type;
                      if (entityType === 'frontend') {
                        navigate('/frontends');
                      } else if (entityType === 'backend') {
                        navigate('/backends');
                      }
                    }}
                  >
                    Go to {agentSync.parsed_error.entity_type === 'frontend' ? 'Frontends' : 'Backends'}
                  </Button>
                )}
              </Space>
            </div>
          }
        />
      )}

      {/* Remove main tabs, only show Pending Changes */}
          <Row gutter={16}>
            {/* Pending Changes Card */}
            <Col span={16}>
            <Card
              title={
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span>Configuration Changes</span>
                  <Space>
                    <Button 
                      type="primary"
                      icon={<PlayCircleOutlined />}
                      loading={applyLoading}
                      disabled={effectiveTotal === 0}
                      onClick={handleApplyAllChanges}
                      style={{ 
                        background: effectiveTotal === 0 ? undefined : 'linear-gradient(135deg, #52c41a 0%, #73d13d 100%)',
                        borderColor: effectiveTotal === 0 ? undefined : '#52c41a',
                        boxShadow: effectiveTotal === 0 ? 'none' : '0 2px 8px rgba(82, 196, 26, 0.3)',
                        fontWeight: 500,
                        height: 36,
                        transition: 'all 0.3s ease'
                      }}
                      onMouseEnter={(e) => {
                        if (effectiveTotal > 0 && !applyLoading) {
                          e.currentTarget.style.boxShadow = '0 4px 12px rgba(82, 196, 26, 0.5)';
                          e.currentTarget.style.transform = 'translateY(-1px)';
                        }
                      }}
                      onMouseLeave={(e) => {
                        if (effectiveTotal > 0 && !applyLoading) {
                          e.currentTarget.style.boxShadow = '0 2px 8px rgba(82, 196, 26, 0.3)';
                          e.currentTarget.style.transform = 'translateY(0)';
                        }
                      }}
                    >
                      Apply All
                    </Button>
                    <Button 
                      danger
                      icon={<CloseOutlined />}
                      disabled={effectiveTotal === 0}
                      onClick={handleRejectAllChanges}
                      style={{ 
                        background: effectiveTotal === 0 ? undefined : 'linear-gradient(135deg, #ff4d4f 0%, #ff7875 100%)',
                        borderColor: effectiveTotal === 0 ? undefined : '#ff4d4f',
                        color: effectiveTotal === 0 ? undefined : '#fff',
                        boxShadow: effectiveTotal === 0 ? 'none' : '0 2px 8px rgba(255, 77, 79, 0.3)',
                        fontWeight: 500,
                        height: 36,
                        transition: 'all 0.3s ease'
                      }}
                      onMouseEnter={(e) => {
                        if (effectiveTotal > 0) {
                          e.currentTarget.style.boxShadow = '0 4px 12px rgba(255, 77, 79, 0.5)';
                          e.currentTarget.style.transform = 'translateY(-1px)';
                        }
                      }}
                      onMouseLeave={(e) => {
                        if (effectiveTotal > 0) {
                          e.currentTarget.style.boxShadow = '0 2px 8px rgba(255, 77, 79, 0.3)';
                          e.currentTarget.style.transform = 'translateY(0)';
                        }
                      }}
                    >
                      Reject All
                    </Button>
                  </Space>
                  
                  {/* Progress Indicator */}
                  {syncProgress.visible && (
                    <div style={{ marginTop: 16, maxWidth: 400 }}>
                      <Progress 
                        percent={syncProgress.progress} 
                        status={syncProgress.progress === 100 ? "success" : "active"}
                        strokeColor={{
                          '0%': '#108ee9',
                          '100%': '#87d068',
                        }}
                      />
                      <div style={{ marginTop: 8, color: '#666', fontSize: '12px' }}>
                        {syncProgress.step}
                      </div>
                    </div>
                  )}
                </div>
              }
            extra={
              <Button 
                icon={<ReloadOutlined />} 
                onClick={fetchPendingChanges}
                loading={loading}
              >
                Refresh
              </Button>
            }
          >
            <Spin spinning={loading}>
              {effectiveTotal === 0 ? (
                <Empty 
                  description="No pending changes found"
                  image={Empty.PRESENTED_IMAGE_SIMPLE}
                  style={{ margin: '40px 0' }}
                />
              ) : (
                <div>
                  <Alert
                    message={`${effectiveTotal} configuration changes are ready to be applied`}
                    type="info"
                    showIcon
                    style={{ marginBottom: 16 }}
                  />
                  
                  {/* Frontend Changes */}
                  {pendingChanges.frontends.length > 0 && (
                    <div style={{ marginBottom: 16 }}>
                      <Title level={5}>
                        <GlobalOutlined style={{ marginRight: 8 }} />
                        Frontend Changes ({pendingChanges.frontends.length})
                      </Title>
                      {pendingChanges.frontends.map(item => 
                        renderPendingItem(item, 'frontend', <GlobalOutlined style={{ color: '#1890ff' }} />)
                      )}
                    </div>
                  )}

                  {/* Backend Changes */}
                  {pendingChanges.backends.length > 0 && (
                    <div style={{ marginBottom: 16 }}>
                      <Title level={5}>
                        <CloudServerOutlined style={{ marginRight: 8 }} />
                        Backend Changes ({pendingChanges.backends.length})
                      </Title>
                      {pendingChanges.backends.map(item => 
                        renderPendingItem(item, 'backend', <CloudServerOutlined style={{ color: '#52c41a' }} />)
                      )}
                    </div>
                  )}

                  {/* WAF Changes */}
                  {pendingChanges.waf_rules.length > 0 && (
                    <div style={{ marginBottom: 16 }}>
                      <Title level={5}>
                        <SecurityScanOutlined style={{ marginRight: 8 }} />
                        WAF Rule Changes ({pendingChanges.waf_rules.length})
                      </Title>
                      {pendingChanges.waf_rules.map(item => 
                        renderPendingItem(item, 'waf_rule', <SecurityScanOutlined style={{ color: '#fa8c16' }} />)
                      )}
                    </div>
                  )}

                  {/* SSL Changes */}
                  {pendingChanges.ssl_certificates.length > 0 && (
                    <div style={{ marginBottom: 16 }}>
                      <Title level={5}>
                        <SafetyCertificateOutlined style={{ marginRight: 8 }} />
                        SSL Certificate Changes ({pendingChanges.ssl_certificates.length})
                      </Title>
                      {pendingChanges.ssl_certificates.map(item => (
                        <div key={`ssl-wrapper-${item.id}`}>
                          {renderPendingItem(item, 'ssl_certificate', <SafetyCertificateOutlined style={{ color: '#eb2f96' }} />)}
                          {item.cluster_names && item.cluster_names.length > 1 && (
                            <Alert
                              type="info"
                              showIcon
                              message={`This certificate is used in ${item.cluster_names.length} clusters. Applying here will auto-apply SSL changes to all clusters.`}
                              description={item.pending_cluster_names?.length > 0
                                ? `Currently pending in: ${item.pending_cluster_names.join(', ')}`
                                : null}
                              style={{ marginBottom: 8, marginLeft: 30 }}
                            />
                          )}
                        </div>
                      ))}
                    </div>
                  )}

                  {pendingChanges.frontends.length === 0 && pendingChanges.backends.length === 0 && pendingChanges.waf_rules.length === 0 && pendingChanges.ssl_certificates.length === 0 && pendingVersions.length > 0 && (
                    <div style={{ marginTop: 8 }}>
                      {(() => {
                        const restoreVersions = pendingVersions.filter(v => v.version_name.startsWith('restore-'));
                        const bulkImportVersions = pendingVersions.filter(v => v.version_name.startsWith('bulk-import-'));
                        const otherVersions = pendingVersions.filter(v => !v.version_name.startsWith('restore-') && !v.version_name.startsWith('bulk-import-'));
                        
                        return (
                          <>
                            {restoreVersions.length > 0 && (
                              <div style={{ marginBottom: 16 }}>
                                <Title level={5}>
                                  <RedoOutlined style={{ marginRight: 8, color: '#1890ff' }} />
                                  Configuration Restore ({restoreVersions.length})
                                </Title>
                                {restoreVersions.map(v => (
                                  <div key={v.id} style={{
                                    padding: 10,
                                    border: '1px dashed #1890ff',
                                    borderRadius: 6,
                                    marginBottom: 8,
                                    display: 'flex',
                                    alignItems: 'center',
                                    justifyContent: 'space-between',
                                    backgroundColor: '#f0f8ff'
                                  }}>
                                    <span style={{ fontFamily: 'monospace' }}>{v.version_name}</span>
                                    <Tag color="orange">PENDING</Tag>
                                  </div>
                                ))}
                              </div>
                            )}
                            
                            {bulkImportVersions.length > 0 && (
                              <div style={{ marginBottom: 16 }}>
                                <Title level={5}>
                                  <CloudUploadOutlined style={{ marginRight: 8, color: '#52c41a' }} />
                                  Bulk Config Import ({bulkImportVersions.length})
                                </Title>
                                {bulkImportVersions.map(v => (
                                  <div key={v.id} style={{
                                    padding: 10,
                                    border: '1px dashed #52c41a',
                                    borderRadius: 6,
                                    marginBottom: 8,
                                    display: 'flex',
                                    alignItems: 'center',
                                    justifyContent: 'space-between',
                                    backgroundColor: '#f6ffed'
                                  }}>
                                    <span style={{ fontFamily: 'monospace' }}>{v.version_name}</span>
                                    <Tag color="orange">PENDING</Tag>
                                  </div>
                                ))}
                              </div>
                            )}
                            
                            {otherVersions.length > 0 && (
                              <div>
                                <Title level={5}>
                                  <HistoryOutlined style={{ marginRight: 8 }} />
                                  Other Pending Versions ({otherVersions.length})
                                </Title>
                                {otherVersions.map(v => (
                                  <div key={v.id} style={{
                                    padding: 10,
                                    border: '1px dashed #d9d9d9',
                                    borderRadius: 6,
                                    marginBottom: 8,
                                    display: 'flex',
                                    alignItems: 'center',
                                    justifyContent: 'space-between'
                                  }}>
                                    <span style={{ fontFamily: 'monospace' }}>{v.version_name}</span>
                                    <Tag color="orange">PENDING</Tag>
                                  </div>
                                ))}
                              </div>
                            )}
                          </>
                        );
                      })()}
                    </div>
                  )}
                </div>
              )}
            </Spin>
          </Card>
        </Col>

        {/* Status & History Card */}
        <Col span={8}>
          <Card
            title={
              <span>
                <InfoCircleOutlined style={{ marginRight: 8 }} />
                Apply Status
              </span>
            }
          >
            <div style={{ marginBottom: 16 }}>
              <Descriptions column={1} size="small">
                <Descriptions.Item label="Selected Cluster">
                  <strong>{selectedCluster.name}</strong>
                </Descriptions.Item>
                <Descriptions.Item label="Pending Versions">
                  <Tag color="orange">{pendingVersions.length}</Tag>
                </Descriptions.Item>
                <Descriptions.Item label="Last Applied">
                  {appliedVersions.length > 0 ? (
                    <div>
                      <div>{appliedVersions[0].version_name}</div>
                      <div style={{ fontSize: 12, color: '#666' }}>
                        {new Date(appliedVersions[0].created_at).toLocaleString()}
                      </div>
                    </div>
                  ) : (
                    <Text type="secondary">No applied versions</Text>
                  )}
                </Descriptions.Item>
              </Descriptions>
            </div>

            {/* Pending Versions Section */}
            {pendingVersions.length > 0 && (
              <div style={{ marginBottom: 24 }}>
                <Title level={5}>
                  <ClockCircleOutlined style={{ marginRight: 8, color: '#faad14' }} />
                  Pending Changes ({pendingVersions.length})
                </Title>
                <Timeline size="small">
                  {pendingVersions.map((version, index) => (
                    <Timeline.Item 
                      key={version.id}
                      color="orange"
                      dot={<ClockCircleOutlined style={{ color: '#faad14' }} />}
                    >
                      <div style={{ fontSize: 12 }}>
                        <div style={{ fontWeight: 'bold', marginBottom: 4 }}>{version.version_name}</div>
                        <div style={{ color: '#666', marginBottom: 8 }}>
                          {new Date(version.created_at).toLocaleString()}
                        </div>
                        <div style={{ marginBottom: 4 }}>
                          <Tag color="orange" size="small">PENDING</Tag>
                        </div>
                        <Button
                          type="link"
                          size="small"
                          icon={<EyeOutlined />}
                          onClick={() => handleViewChange(version)}
                          style={{ padding: 0, height: 'auto', fontSize: 11 }}
                        >
                          View Change
                        </Button>
                      </div>
                    </Timeline.Item>
                  ))}
                </Timeline>
              </div>
            )}

            <div>
              <Tabs defaultActiveKey="applied" size="small">
                <TabPane 
                  tab={
                    <span>
                      <CheckCircleOutlined />
                      Applied
                      <Tag color="green" style={{ marginLeft: 8 }}>{appliedVersions.length}</Tag>
                    </span>
                  } 
                  key="applied"
                >
                  {appliedVersions.length === 0 ? (
                    <Empty 
                      description="No applied versions yet"
                      image={Empty.PRESENTED_IMAGE_SIMPLE}
                      style={{ margin: '20px 0' }}
                    />
                  ) : (
                    <Timeline size="small">
                      {appliedVersions.map((version, index) => (
                        <Timeline.Item 
                          key={version.id}
                          color={index === 0 ? 'green' : 'gray'}
                          dot={index === 0 ? <CheckCircleOutlined style={{ color: '#52c41a' }} /> : undefined}
                        >
                          <div style={{ fontSize: 12 }}>
                            <div style={{ fontWeight: 'bold', marginBottom: 4 }}>{version.version_name}</div>
                            <div style={{ color: '#666', marginBottom: 8 }}>
                              {new Date(version.created_at).toLocaleString()}
                            </div>
                            <Button
                              type="link"
                              size="small"
                              icon={<EyeOutlined />}
                              onClick={() => handleViewChange(version)}
                              style={{ padding: 0, height: 'auto', fontSize: 11 }}
                            >
                              View Change
                            </Button>
                          </div>
                        </Timeline.Item>
                      ))}
                    </Timeline>
                  )}
                </TabPane>
                
                <TabPane 
                  tab={
                    <span>
                      <CloseCircleOutlined />
                      Rejected
                      <Tag color="red" style={{ marginLeft: 8 }}>{rejectedVersions.length}</Tag>
                    </span>
                  } 
                  key="rejected"
                >
                  {rejectedVersions.length === 0 ? (
                    <Empty 
                      description="No rejected versions"
                      image={Empty.PRESENTED_IMAGE_SIMPLE}
                      style={{ margin: '20px 0' }}
                    />
                  ) : (
                    <Timeline size="small">
                      {rejectedVersions.map((version, index) => (
                        <Timeline.Item 
                          key={version.id}
                          color="red"
                          dot={<CloseCircleOutlined style={{ color: '#ff4d4f' }} />}
                        >
                          <div style={{ fontSize: 12 }}>
                            <div style={{ fontWeight: 'bold', marginBottom: 4 }}>{version.version_name}</div>
                            <div style={{ color: '#666', marginBottom: 8 }}>
                              Rejected: {new Date(version.updated_at || version.created_at).toLocaleString()}
                            </div>
                            <Space size="small">
                              <Button
                                type="link"
                                size="small"
                                icon={<EyeOutlined />}
                                onClick={() => handleViewChange(version)}
                                style={{ padding: 0, height: 'auto', fontSize: 11 }}
                              >
                                View Changes
                              </Button>
                              <Button
                                type="link"
                                size="small"
                                icon={<UndoOutlined />}
                                onClick={() => handleUndoRejected(version)}
                                style={{ padding: 0, height: 'auto', fontSize: 11, color: '#1890ff' }}
                              >
                                Undo
                              </Button>
                            </Space>
                          </div>
                        </Timeline.Item>
                      ))}
                    </Timeline>
                  )}
                </TabPane>
              </Tabs>
            </div>
          </Card>

          <Card
            style={{ marginTop: 16 }}
            title={
              <span>
                <InfoCircleOutlined style={{ marginRight: 8 }} />
                Agent Sync Status
              </span>
            }
            extra={
              <Button icon={<ReloadOutlined />} onClick={fetchAgentSync} loading={agentSyncLoading}>
                Refresh
              </Button>
            }
          >
            <Spin spinning={agentSyncLoading}>
              {!agentSync ? (
                <Empty description="No data" image={Empty.PRESENTED_IMAGE_SIMPLE} />
              ) : (
                <div>
                  <Descriptions column={1} size="small" style={{ marginBottom: 12 }}>
                    <Descriptions.Item label="Latest Applied Version">
                      <Text code>{agentSync.latest_version || '-'}</Text>
                    </Descriptions.Item>
                    <Descriptions.Item label="Sync Summary">
                      <Space>
                        <Tag color="green">Synced: {agentSync.synced_agents || 0}</Tag>
                        <Tag color="red">Unsynced: {agentSync.unsynced_agents || 0}</Tag>
                        <Tag>Active: {agentSync.total_agents || 0}</Tag>
                        {agentSync.disabled_agents > 0 && (
                          <Tag color="default">Disabled: {agentSync.disabled_agents}</Tag>
                        )}
                      </Space>
                    </Descriptions.Item>
                    {agentSync.validation_error && (
                      <Descriptions.Item label="HAProxy Validation Error">
                        <Alert
                          message={
                            <Space>
                              <span>Configuration Validation Failed</span>
                              {agentSync.parsed_error?.line_number && (
                                <Tag color="red">Line {agentSync.parsed_error.line_number}</Tag>
                              )}
                              {agentSync.parsed_error?.entity_name && (
                                <Tag color="orange">
                                  {agentSync.parsed_error.entity_type}: {agentSync.parsed_error.entity_name}
                                </Tag>
                              )}
                            </Space>
                          }
                          description={
                            <div>
                              {/* Parsed suggestion */}
                              {agentSync.parsed_error?.suggestion && (
                                <div style={{ marginBottom: 12, padding: '8px 12px', background: '#fff7e6', borderRadius: 4, border: '1px solid #ffd591' }}>
                                  <Text strong style={{ color: '#ad4e00' }}>Recommendation: </Text>
                                  <Text>{agentSync.parsed_error.suggestion}</Text>
                                </div>
                              )}
                              
                              {/* Action buttons */}
                              <Space style={{ marginBottom: 12 }}>
                                <Button 
                                  type="primary" 
                                  size="small"
                                  danger
                                  icon={<EyeOutlined />}
                                  onClick={() => {
                                    setSelectedValidationError({
                                      validation_error: agentSync.validation_error,
                                      validation_error_reported_at: agentSync.validation_error_reported_at,
                                      parsed_error: agentSync.parsed_error
                                    });
                                    setValidationErrorModalVisible(true);
                                  }}
                                >
                                  View Full Details
                                </Button>
                                {agentSync.parsed_error?.quick_fix_available && agentSync.parsed_error?.quick_fix_url && (
                                  <Button 
                                    type="primary"
                                    size="small"
                                    icon={<EditOutlined />}
                                    onClick={() => navigate(agentSync.parsed_error.quick_fix_url)}
                                  >
                                    Fix: {agentSync.parsed_error.entity_name}
                                  </Button>
                                )}
                              </Space>
                              
                              {/* Truncated raw error */}
                              <Collapse size="small" ghost>
                                <Collapse.Panel header="Raw Error Output" key="raw">
                                  <pre style={{
                                    backgroundColor: '#1f1f1f',
                                    color: '#ff6b6b',
                                    padding: '12px',
                                    borderRadius: '4px',
                                    fontSize: '11px',
                                    fontFamily: 'Monaco, Menlo, monospace',
                                    maxHeight: '150px',
                                    overflowY: 'auto',
                                    whiteSpace: 'pre-wrap',
                                    wordBreak: 'break-word',
                                    margin: 0
                                  }}>
                                    {agentSync.validation_error.length > 500 
                                      ? agentSync.validation_error.substring(0, 500) + '...\n[Click "View Full Details" to see complete error]'
                                      : agentSync.validation_error
                                    }
                                  </pre>
                                </Collapse.Panel>
                              </Collapse>
                              
                              {agentSync.validation_error_reported_at && (
                                <div style={{ marginTop: 8, fontSize: '11px', color: '#8c8c8c' }}>
                                  Reported at: {new Date(agentSync.validation_error_reported_at).toLocaleString()}
                                </div>
                              )}
                            </div>
                          }
                          type="error"
                          showIcon
                          style={{ marginTop: 8 }}
                        />
                      </Descriptions.Item>
                    )}
                  </Descriptions>

                  <Table
                    size="small"
                    pagination={{ pageSize: 5 }}
                    rowKey={(r) => r.id}
                    dataSource={agentSync.agents || []}
                    columns={[
                      { 
                        title: 'Agent', 
                        dataIndex: 'name', 
                        key: 'name',
                        render: (name, record) => (
                          <span>
                            {name}
                            {record.sync_excluded && (
                              <Tag color="default" style={{ marginLeft: 6, fontSize: '10px' }}>OFF</Tag>
                            )}
                          </span>
                        )
                      },
                      { 
                        title: 'Agent Status', 
                        dataIndex: 'status', 
                        key: 'status',
                        render: (s, record) => (
                          record.sync_excluded 
                            ? <Tag color="default">disabled</Tag>
                            : <Tag color={s === 'online' ? 'green' : 'default'}>{s || '-'}</Tag>
                        )
                      },
                      { 
                        title: 'HAProxy', 
                        dataIndex: 'haproxy_status', 
                        key: 'haproxy_status',
                        render: (s, record) => (
                          record.sync_excluded 
                            ? <Tag color="default">-</Tag>
                            : <Tag color={s === 'running' ? 'green' : 'default'}>{s || '-'}</Tag>
                        )
                      },
                      { title: 'Delivered Version', dataIndex: 'delivered_version', key: 'delivered_version', render: (v) => <Text code>{v || '-'}</Text> },
                      { 
                        title: 'In Sync', 
                        dataIndex: 'in_sync', 
                        key: 'in_sync',
                        render: (val, record) => (
                          record.sync_excluded 
                            ? <Tag color="default">Excluded</Tag>
                            : <Tag color={val ? 'green' : 'red'}>{val ? 'Yes' : 'No'}</Tag>
                        )
                      },
                      { title: 'Last Seen', dataIndex: 'last_seen', key: 'last_seen', render: (v) => v ? new Date(v).toLocaleString() : '-' },
                    ]}
                  />
                </div>
              )}
            </Spin>
          </Card>
        </Col>
      </Row>

      {/* View Change Modal */}
      <Modal
        title={
          <div>
            <EyeOutlined style={{ marginRight: 8, color: '#1890ff' }} />
            Configuration Changes - {selectedVersion?.version_name}
          </div>
        }
        open={viewChangeModalVisible}
        onCancel={() => setViewChangeModalVisible(false)}
        footer={[
          <Button key="close" type="primary" onClick={() => setViewChangeModalVisible(false)}>
            Close
          </Button>,
        ]}
        width={1200}
        bodyStyle={{ padding: '16px' }}
      >
        {selectedVersion && (
          <div>
            <Alert
              message="Configuration Change Summary"
              description={
                <div>
                  <div><strong>Version:</strong> {selectedVersion.version_name}</div>
                  <div><strong>Type:</strong> {selectedVersion.type}</div>
                  <div><strong>Created:</strong> {new Date(selectedVersion.created_at).toLocaleString()}</div>
                  <div><strong>Status:</strong> <Tag color={getStatusColor(selectedVersion.status)}>{selectedVersion.status}</Tag></div>
                </div>
              }
              type="info"
              showIcon
              style={{ marginBottom: 16 }}
            />

            {diffLoading ? (
              <div style={{ textAlign: 'center', padding: '40px 0' }}>
                <Spin size="large" />
                <div style={{ marginTop: 16 }}>Loading configuration changes...</div>
              </div>
            ) : diffData ? (
              <div>
                <Title level={5}>Configuration Changes:</Title>
                <div style={{ border: '1px solid #d9d9d9', borderRadius: 6, backgroundColor: '#fafafa' }}>
                  <div style={{ padding: '12px', borderBottom: '1px solid #d9d9d9', backgroundColor: '#f0f0f0' }}>
                    <Text strong>Changes from previous version:</Text>
                  </div>
                  <div style={{ padding: '16px', fontFamily: 'monospace', fontSize: '12px', lineHeight: '1.4', maxHeight: '400px', overflowY: 'auto' }}>
                    {diffData.changes && diffData.changes.length > 0 ? (
                      diffData.changes.map((change, index) => (
                        <div key={index} style={{ marginBottom: '4px' }}>
                          {change.type === 'added' && (
                            <div style={{ backgroundColor: '#f6ffed', color: '#52c41a', padding: '2px 8px', borderLeft: '3px solid #52c41a' }}>
                              + {change.line}
                            </div>
                          )}
                          {change.type === 'removed' && (
                            <div style={{ backgroundColor: '#fff2f0', color: '#ff4d4f', padding: '2px 8px', borderLeft: '3px solid #ff4d4f' }}>
                              - {change.line}
                            </div>
                          )}
                          {change.type === 'context' && (
                            <div style={{ color: '#666', padding: '2px 8px' }}>
                              {change.line}
                            </div>
                          )}
                        </div>
                      ))
                    ) : (
                      <div style={{ textAlign: 'center', padding: '40px 0', color: '#666' }}>
                        No changes detected or this is the first version
                      </div>
                    )}
                  </div>
                </div>
                {diffData.summary && (
                  <div style={{ marginTop: 16 }}>
                    <Title level={5}>Summary:</Title>
                    <div style={{ backgroundColor: '#f9f9f9', padding: '12px', borderRadius: '6px', border: '1px solid #d9d9d9' }}>
                      <Row gutter={16}>
                        <Col span={8}>
                          <div style={{ textAlign: 'center' }}>
                            <div style={{ fontSize: '20px', fontWeight: 'bold', color: '#52c41a' }}>
                              +{diffData.summary.added || 0}
                            </div>
                            <div style={{ fontSize: '12px', color: '#666' }}>Added Lines</div>
                          </div>
                        </Col>
                        <Col span={8}>
                          <div style={{ textAlign: 'center' }}>
                            <div style={{ fontSize: '20px', fontWeight: 'bold', color: '#ff4d4f' }}>
                              -{diffData.summary.removed || 0}
                            </div>
                            <div style={{ fontSize: '12px', color: '#666' }}>Removed Lines</div>
                          </div>
                        </Col>
                        <Col span={8}>
                          <div style={{ textAlign: 'center' }}>
                            <div style={{ fontSize: '20px', fontWeight: 'bold', color: '#1890ff' }}>
                              {diffData.summary.total_changes || 0}
                            </div>
                            <div style={{ fontSize: '12px', color: '#666' }}>Total Changes</div>
                          </div>
                        </Col>
                      </Row>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '40px 0', color: '#666' }}>
                <ExclamationCircleOutlined style={{ fontSize: '24px', marginBottom: '8px' }} />
                <div>Failed to load configuration changes</div>
              </div>
            )}
          </div>
        )}
      </Modal>

      {/* Validation Error Modal */}
      <ValidationErrorModal
        visible={validationErrorModalVisible}
        onClose={() => {
          setValidationErrorModalVisible(false);
          setSelectedValidationError(null);
        }}
        validationError={selectedValidationError?.validation_error}
        validationErrorReportedAt={selectedValidationError?.validation_error_reported_at}
        parsedError={selectedValidationError?.parsed_error}
      />
    </div>
  );
};

export default ApplyManagement;