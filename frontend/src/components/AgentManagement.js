// Agent Management Component - Database-backed script templates enabled - Pipeline trigger v2
import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import {
  Card,
  Table,
  Button,
  Space,
  Tag,
  Modal,
  Form,
  Input,
  Select,
  message,
  Popconfirm,
  Badge,
  Descriptions,
  Tabs,
  Typography,
  Alert,
  Tooltip,
  Row,
  Col,
  Statistic,
  Divider,
  Progress,
  Spin,
  notification,
  Switch,
  AutoComplete,
  Steps,
  Radio,
  List,
  Collapse,
  Timeline
} from 'antd';
import {
  PlusOutlined,
  DeleteOutlined,
  EyeOutlined,
  DownloadOutlined,
  ReloadOutlined,
  DesktopOutlined,
  AppleOutlined,
  LinuxOutlined,
  HeartTwoTone,
  WarningOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  ClockCircleOutlined,
  CodeOutlined,
  TeamOutlined,
  SyncOutlined,
  WifiOutlined,
  DisconnectOutlined,
  PlayCircleOutlined,
  PauseCircleOutlined,
  InfoCircleOutlined,
  ExclamationCircleOutlined,
  CopyOutlined,
  SettingOutlined,
  CloudDownloadOutlined,
  ToolOutlined,
  PoweroffOutlined,
  RocketOutlined,
  ArrowUpOutlined,
  ArrowDownOutlined,
  TagOutlined,
  SaveOutlined,
  FileTextOutlined,
  SafetyOutlined
} from '@ant-design/icons';
import axios from 'axios';
import { useCluster } from '../contexts/ClusterContext';
import { useAuth } from '../contexts/AuthContext';
import AceEditor from 'react-ace';

// Import ace editor modes and themes
import 'ace-builds/src-noconflict/mode-sh';
import 'ace-builds/src-noconflict/theme-monokai';
import 'ace-builds/src-noconflict/ext-language_tools';

// Configure ACE to use CDN for workers to avoid webpack/production issues
import ace from 'ace-builds/src-noconflict/ace';
ace.config.set('basePath', 'https://cdn.jsdelivr.net/npm/ace-builds@1.4.14/src-noconflict/');
ace.config.set('workerPath', 'https://cdn.jsdelivr.net/npm/ace-builds@1.4.14/src-noconflict/');

const { Option } = Select;
const { TabPane } = Tabs;
const { Text, Title, Paragraph, Code } = Typography;
const { TextArea } = Input;
const { Step } = Steps;
const { Panel } = Collapse;

// Error Boundary Component
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Agent Management Error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <Alert
          message="Something went wrong"
          description="There was an error loading the Agent Management interface. Please refresh the page."
          type="error"
          showIcon
          action={
            <Button size="small" danger onClick={() => window.location.reload()}>
              Refresh Page
            </Button>
          }
        />
      );
    }

    return this.props.children;
  }
}

const AgentManagement = () => {
  // === State Management ===
  const [agents, setAgents] = useState([]);
  const [filteredAgents, setFilteredAgents] = useState([]);
  const [searchText, setSearchText] = useState('');
  const [loading, setLoading] = useState(false);
  // Store upgrade types in ref to avoid re-render loops
  const upgradeTypesRef = useRef({});
  const [agentDetailModalVisible, setAgentDetailModalVisible] = useState(false);
  const [selectedAgent, setSelectedAgent] = useState(null);
  const [agentLogsModalVisible, setAgentLogsModalVisible] = useState(false);
  const [agentLogs, setAgentLogs] = useState([]);
  const [agentLogsLoading, setAgentLogsLoading] = useState(false);
  const [pools, setPools] = useState([]);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [lastRefresh, setLastRefresh] = useState(null);
  const [refreshProgress, setRefreshProgress] = useState(0);
  const [connectionStatus, setConnectionStatus] = useState('checking');
  
  // Agent setup state
  const [setupModalVisible, setSetupModalVisible] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [selectedPlatform, setSelectedPlatform] = useState('linux');
  const [selectedArchitecture, setSelectedArchitecture] = useState('amd64');
  const [agentName, setAgentName] = useState('');
  const [hostnamePrefix, setHostnamePrefix] = useState('');
  const [selectedPoolId, setSelectedPoolId] = useState(null);
  const [poolClusters, setPoolClusters] = useState([]);
  const [selectedClusterId, setSelectedClusterId] = useState(null);
  const [installScript, setInstallScript] = useState('');
  const [scriptGenerating, setScriptGenerating] = useState(false);
  
  // Pools state for the setup wizard
  const [supportedPlatforms, setSupportedPlatforms] = useState({});
  
  // Agent Script Version Management state
  const [agentVersions, setAgentVersions] = useState({});
  const [agentVersionLoading, setAgentVersionLoading] = useState(false);
  const [versionUpdateModal, setVersionUpdateModal] = useState(false);
  const [selectedVersionPlatform, setSelectedVersionPlatform] = useState(null);
  const [versionForm] = Form.useForm();
  const [scriptViewModal, setScriptViewModal] = useState(false);
  const [selectedScript, setSelectedScript] = useState('');
  const [originalScript, setOriginalScript] = useState(''); // Store original script for comparison
  const [scriptHasChanges, setScriptHasChanges] = useState(false); // Track if script has changes
  const [scriptSaving, setScriptSaving] = useState(false); // Track script saving state
  const [currentEditingPlatform, setCurrentEditingPlatform] = useState(null); // Track which platform is being edited
  
  const { clusters, selectedCluster } = useCluster();
  const { hasPermission, isAdmin } = useAuth();
  const refreshIntervalRef = useRef(null);
  const progressIntervalRef = useRef(null);

  // Platform configuration
  const platformConfig = {
    linux: {
      name: 'Linux',
      icon: <LinuxOutlined style={{ fontSize: '24px', color: '#1890ff' }} />,
      color: '#1890ff',
      defaultArch: 'amd64'  // x86-64 (amd64) default for Linux
    },
    darwin: {
      name: 'macOS',
      icon: <AppleOutlined style={{ fontSize: '24px', color: '#722ed1' }} />,
      color: '#722ed1',
      defaultArch: 'arm64'  // Apple Silicon default
    }
  };


  // Add throttling to prevent excessive API calls
  const lastFetchTime = useRef(0);
  const FETCH_THROTTLE_MS = 2000; // Minimum 2 seconds between fetches

  // Fetch agents from API
  const fetchAgents = useCallback(async (force = false, clusterOverride = null) => {
    // Use override cluster if provided, otherwise use selectedCluster
    const targetCluster = clusterOverride || selectedCluster;
    
    console.log(`🔍 fetchAgents CALLED: force=${force}, targetCluster=${targetCluster?.name}, current agents count=${agents.length}`);
    
    // CRITICAL FIX: Don't fetch if no cluster selected
    if (!targetCluster) {
      console.log('⚠️ fetchAgents: No cluster selected, skipping fetch');
      setAgents([]);
      setFilteredAgents([]);
      setConnectionStatus('no-agents');
      return;
    }
    
    // Prevent concurrent fetches
    if (!force && loading) {
      console.log('⚠️ fetchAgents: Already loading, skipping fetch');
      return;
    }

    // THROTTLING: Prevent excessive API calls (except when forced)
    const now = Date.now();
    if (!force && (now - lastFetchTime.current) < FETCH_THROTTLE_MS) {
      console.log(`🛑 fetchAgents: Throttled (${now - lastFetchTime.current}ms < ${FETCH_THROTTLE_MS}ms), skipping fetch`);
      return;
    }
    lastFetchTime.current = now;
    
    setLoading(true);
    console.log(`📡 fetchAgents: Fetching agents for pool_id=${targetCluster.pool_id}`);
    try {
      const params = { pool_id: targetCluster.pool_id };
      const response = await axios.get('/api/agents', { 
        params, 
        timeout: 10000,
        headers: {
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache'
        }
      });
      const agentsData = response.data.agents || [];
      console.log(`✅ fetchAgents: Received ${agentsData.length} agents from API`);
      
      // Use ref for _upgradeType (no re-render triggers)
      const mergedAgents = agentsData.map(backendAgent => {
        const upgradeType = upgradeTypesRef.current[backendAgent.id];
        
        if (upgradeType) {
          return { ...backendAgent, _upgradeType: upgradeType };
        }
        return backendAgent;
      });
      
      setAgents(mergedAgents);
      setFilteredAgents(mergedAgents);
      
      // Clean up ref for completed upgrades (delayed)
      const onlineAgentIds = mergedAgents.filter(a => a.status === 'online').map(a => a.id);
      onlineAgentIds.forEach(agentId => {
        if (upgradeTypesRef.current[agentId]) {
          setTimeout(() => {
            delete upgradeTypesRef.current[agentId];
          }, 5000); // 5 second delay
        }
      });
      
      // Update connection status based on agents
      if (agentsData.length > 0) {
        const healthyAgents = agentsData.filter(agent => agent.status === 'online').length;
        setConnectionStatus(healthyAgents > 0 ? 'connected' : 'disconnected');
      } else {
        setConnectionStatus('no-agents');
      }
    } catch (error) {
      console.error('Failed to fetch agents:', error);
      message.error('Failed to fetch agents: ' + (error.response?.data?.detail || error.message));
      setConnectionStatus('error');
    } finally {
      setLoading(false);
    }
  }, [selectedCluster]);

  // Search/filter agents
  const handleSearch = (value) => {
    setSearchText(value);
    if (!value) {
      setFilteredAgents(agents);
    } else {
      const filtered = agents.filter(agent =>
        agent.name.toLowerCase().includes(value.toLowerCase()) ||
        agent.hostname.toLowerCase().includes(value.toLowerCase()) ||
        agent.pool_name?.toLowerCase().includes(value.toLowerCase()) ||
        agent.platform.toLowerCase().includes(value.toLowerCase()) ||
        agent.ip_address?.toLowerCase().includes(value.toLowerCase())
      );
      setFilteredAgents(filtered);
    }
  };

  // Update filteredAgents when agents change  
  useEffect(() => {
    handleSearch(searchText);
  }, [agents, searchText]);

  // Fetch pools and supported platforms
  const fetchPools = useCallback(async () => {
    try {
      const [poolsResponse, platformsResponse] = await Promise.all([
        axios.get('/api/haproxy-cluster-pools', { 
          timeout: 5000,
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('authToken') || ''}`,
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache'
          },
        }),
        axios.get('/api/agents/platforms', { 
          timeout: 5000,
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('authToken') || ''}`,
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache'
          },
        })
      ]);
      
      setPools(poolsResponse.data.pools || []);
      setSupportedPlatforms(platformsResponse.data.platforms || {});
    } catch (error) {
      console.error('Failed to fetch pools or platforms:', error);
      message.warning('Failed to load some configuration data.');
    }
  }, []);

  // Auto-refresh progress indicator
  const startProgressIndicator = useCallback(() => {
    setRefreshProgress(0);
    if (progressIntervalRef.current) {
      clearInterval(progressIntervalRef.current);
    }
    
    progressIntervalRef.current = setInterval(() => {
      setRefreshProgress(prev => {
        if (prev >= 100) {
          return 0;
        }
        return prev + (100 / 30);
      });
    }, 1000);
  }, []);

  // Auto-refresh agents
  const setupAutoRefresh = useCallback(() => {
    if (refreshIntervalRef.current) {
      clearInterval(refreshIntervalRef.current);
    }

    if (autoRefresh) {
      refreshIntervalRef.current = setInterval(() => {
        fetchAgents();
        setLastRefresh(new Date());
      }, 30000); // Every 30 seconds

      startProgressIndicator();
    }
  }, [autoRefresh, fetchAgents, startProgressIndicator]);

  // Setup auto-refresh
  useEffect(() => {
    setupAutoRefresh();
    return () => {
      if (refreshIntervalRef.current) {
        clearInterval(refreshIntervalRef.current);
      }
      if (progressIntervalRef.current) {
        clearInterval(progressIntervalRef.current);
      }
    };
  }, [setupAutoRefresh]);

  // CRITICAL FIX: Clear agents immediately when cluster changes (prevent cache/mixing)
  useEffect(() => {
    if (selectedCluster) {
      console.log(`🔄 CLUSTER CHANGED: ${selectedCluster.name} (ID: ${selectedCluster.id}) - Clearing agents to prevent mixing...`);
      setAgents([]);
      setFilteredAgents([]);
      setConnectionStatus('checking');
      // Clear upgrade types ref for new cluster
      upgradeTypesRef.current = {};
    }
  }, [selectedCluster?.id]); // Trigger on cluster ID change only

  // Initial load and cluster change
  useEffect(() => {
    fetchAgents();
    fetchPools();
    fetchAgentVersions(); // Auto-load agent versions on component mount
  }, [fetchAgents, fetchPools, selectedCluster]); // CRITICAL FIX: Re-fetch when cluster changes

  // Generate installation script
  const generateInstallScript = async () => {
    if (!agentName.trim()) {
      message.error('Agent name is required');
      return;
    }
    if (!hostnamePrefix.trim()) {
      message.error('Hostname Prefix is required');
      return;
    }
    if (!selectedPoolId) {
      message.error('Please select a HAProxy Cluster Pool');
      return;
    }

    // Check if cluster is selected (required when multiple clusters exist for the pool)
    if (!selectedClusterId) {
      message.error('Please select a cluster for the chosen pool');
      return;
    }

    // Find the selected cluster
    console.log('🔍 AGENT SCRIPT DEBUG - Selected Pool ID:', selectedPoolId);
    console.log('🔍 AGENT SCRIPT DEBUG - Selected Cluster ID:', selectedClusterId);
    console.log('🔍 AGENT SCRIPT DEBUG - Available Clusters:', clusters);
    
    const targetCluster = clusters.find(c => c.id === selectedClusterId);
    console.log('🔍 AGENT SCRIPT DEBUG - Found Target Cluster:', targetCluster);
    
    if (!targetCluster) {
      message.error('Could not find the selected cluster. Please refresh and try again.');
      return;
    }

    setScriptGenerating(true);
    try {
      const response = await axios.post('/api/agents/generate-install-script', {
        platform: selectedPlatform,
        architecture: selectedArchitecture,
        pool_id: selectedPoolId,
        cluster_id: targetCluster.id,  // ✅ FIXED: Send specific cluster ID
        agent_name: agentName.trim(),
        hostname_prefix: hostnamePrefix.trim(),
        // Pass dynamic paths to the backend
        haproxy_bin_path: targetCluster.haproxy_bin_path,
        haproxy_config_path: targetCluster.haproxy_config_path,
        stats_socket_path: targetCluster.stats_socket_path
      }, {
        timeout: 15000,
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('authToken') || ''}`,
        },
      });
      
      setInstallScript(response.data.script);
      setCurrentStep(3); // Move to script step
      
      notification.success({
        message: 'Installation Script Generated',
        description: `${platformConfig[selectedPlatform].name} installation script has been generated successfully.`,
        duration: 4
      });
    } catch (error) {
      const errorMessage = error.response?.data?.detail || error.message;
      notification.error({
        message: 'Script Generation Failed',
        description: `Failed to generate installation script: ${errorMessage}`,
        duration: 6
      });
    } finally {
      setScriptGenerating(false);
    }
  };

  // Open agent setup modal
  const openSetupModal = () => {
    setSetupModalVisible(true);
    setCurrentStep(0);
    setSelectedPlatform('linux');
    setSelectedArchitecture('amd64');
    setAgentName('');
    setHostnamePrefix(generateRandomHostname());
    setSelectedPoolId(null);
    setPoolClusters([]);
    setSelectedClusterId(null);
    setInstallScript('');
  };

  // Generate random hostname
  const generateRandomHostname = () => {
    const prefixes = ['haproxy', 'web-proxy', 'lb-node', 'loadbalancer'];
    const suffixes = ['01', '02', '03', 'main', 'backup', 'primary'];
    const prefix = prefixes[Math.floor(Math.random() * prefixes.length)];
    const suffix = suffixes[Math.floor(Math.random() * suffixes.length)];
    return `${prefix}-${suffix}`;
  };

  // Handle pool selection and find associated clusters
  const handlePoolSelection = (poolId) => {
    setSelectedPoolId(poolId);
    setSelectedClusterId(null); // Reset cluster selection
    
    if (!poolId) {
      setPoolClusters([]);
      return;
    }

    // Find all clusters associated with this pool
    const associatedClusters = clusters.filter(c => c.pool_id === poolId);
    setPoolClusters(associatedClusters);
    
    console.log('🔍 POOL SELECTION DEBUG - Pool ID:', poolId);
    console.log('🔍 POOL SELECTION DEBUG - Associated Clusters:', associatedClusters);
    
    // Auto-select if only one cluster
    if (associatedClusters.length === 1) {
      setSelectedClusterId(associatedClusters[0].id);
      console.log('🔍 POOL SELECTION DEBUG - Auto-selected cluster:', associatedClusters[0].id);
    } else if (associatedClusters.length === 0) {
      message.error({
        content: 'No clusters found for this pool. Please create a cluster or select a different pool.',
        duration: 5
      });
      console.warn('⚠️ VALIDATION: Pool has no clusters - agent creation should be blocked');
    }
  };

  // Enhanced delete agent
  const deleteAgent = async (agentId, agentName) => {
    const hide = message.loading(`Deleting agent ${agentName}...`);
    try {
      // Optimistic update: Remove agent from local state immediately
      const updatedAgents = agents.filter(agent => agent.id !== agentId);
      setAgents(updatedAgents);
      setFilteredAgents(updatedAgents.filter(agent => 
        agent.name.toLowerCase().includes(searchText.toLowerCase()) ||
        agent.hostname?.toLowerCase().includes(searchText.toLowerCase()) ||
        agent.cluster_name?.toLowerCase().includes(searchText.toLowerCase())
      ));
      
      // Then perform the actual delete
      await axios.delete(`/api/agents/${agentId}`, { timeout: 10000 });
      
      notification.success({
        message: 'Agent Deleted',
        description: `Agent "${agentName}" has been successfully removed.`,
        duration: 4
      });
      
      // Refresh from server to ensure consistency (force=true to bypass throttling)
      await fetchAgents(true);
    } catch (error) {
      const errorMessage = error.response?.data?.detail || error.message;
      notification.error({
        message: 'Delete Failed',
        description: `Failed to delete agent "${agentName}": ${errorMessage}`,
        duration: 6
      });
      
      // Revert optimistic update on error (force=true to bypass throttling)
      await fetchAgents(true);
    } finally {
      hide();
    }
  };

  // Toggle agent enabled/disabled
  const toggleAgent = async (agentId, currentEnabled, agentName) => {
    const newStatus = !currentEnabled;
    const hide = message.loading(`${newStatus ? 'Enabling' : 'Disabling'} agent ${agentName}...`);
    try {
      await axios.put(`/api/agents/${agentId}/toggle`, { enabled: newStatus }, { timeout: 10000 });
      notification.success({
        message: 'Agent Status Updated',
        description: `Agent "${agentName}" has been ${newStatus ? 'enabled' : 'disabled'}.`,
        duration: 4
      });
      fetchAgents(false);
    } catch (error) {
      const errorMessage = error.response?.data?.detail || error.message;
      notification.error({
        message: 'Toggle Failed',
        description: `Failed to ${newStatus ? 'enable' : 'disable'} agent "${agentName}": ${errorMessage}`,
        duration: 6
      });
    } finally {
      hide();
    }
  };

  // Upgrade agent to latest version
  // Agent Script Version Management Functions
  const fetchAgentVersions = async () => {
    setAgentVersionLoading(true);
    try {
      // Use database-driven endpoint for current versions
      const response = await axios.get('/api/agents/versions', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('authToken') || ''}`,
        },
      });
      
      // Transform database response to match UI format
      const platforms = {};
      const dbPlatforms = response.data.platforms || {};
      
      Object.keys(dbPlatforms).forEach(platform => {
        const versions = dbPlatforms[platform] || [];
        const currentVersion = versions.find(v => v.is_active) || versions[0];
        
        if (currentVersion) {
          platforms[platform] = {
            available_version: currentVersion.version,  // Renamed from current_version for clarity
            description: platform === 'macos' ? 'macOS / Darwin Agent Scripts' : 'Linux Agent Scripts (Ubuntu, RHEL, CentOS, etc.)',
            supported_versions: versions.map(v => v.version),
            last_updated: currentVersion.created_at || currentVersion.release_date
          };
        }
      });
      
      setAgentVersions(platforms);
    } catch (error) {
      message.error('Failed to fetch agent versions: ' + (error.response?.data?.detail || error.message));
    } finally {
      setAgentVersionLoading(false);
    }
  };

  // Reset agent scripts to file-based defaults
  const [resetVersionModalVisible, setResetVersionModalVisible] = useState(false);
  const [resetVersionForm] = Form.useForm();
  
  const showResetVersionModal = () => {
    // Get current linux version and suggest next version
    const currentLinuxVersion = agentVersions['linux']?.available_version || '1.0.0';
    const parts = currentLinuxVersion.split('.');
    const suggestedVersion = parts.length === 3 
      ? `${parts[0]}.${parts[1]}.${parseInt(parts[2]) + 1}`
      : '1.0.1';
    
    resetVersionForm.setFieldsValue({ targetVersion: suggestedVersion });
    setResetVersionModalVisible(true);
  };
  
  const resetScriptsToDefaults = async (values) => {
    const hide = message.loading('Resetting agent scripts to defaults...', 0);
    setResetVersionModalVisible(false);
    
    try {
      // Backend expects target_version as query parameter, not in body
      const queryParams = values?.targetVersion ? { target_version: values.targetVersion } : {};
      const response = await axios.post('/api/agents/sync-scripts-from-files', {}, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('authToken') || ''}`,
        },
        params: queryParams  // Query string parameters
      });
      
      hide();
      
      if (response.data.status === 'success') {
        // Show success notification with details
        notification.success({
          message: 'Scripts Reset Successfully',
          description: (
            <div>
              <Text strong>Agent scripts have been reset to file-based defaults:</Text>
              <ul style={{ marginTop: '8px', marginBottom: '0', paddingLeft: '20px' }}>
                {response.data.results.map((result, index) => (
                  <li key={index}>
                    <Text strong>{result.platform}</Text>: {result.message} 
                    {values?.targetVersion && <Text type="success"> → v{values.targetVersion}</Text>}
                  </li>
                ))}
              </ul>
              <Text type="secondary" style={{ marginTop: '8px', display: 'block' }}>
                💡 Agents can now upgrade to the latest script
              </Text>
            </div>
          ),
          duration: 10,
        });
        
        // Refresh agent versions to show new versions
        await fetchAgentVersions();
        
        // Refresh agents list to update Available column and show Upgrade button
        await fetchAgents();
      }
    } catch (error) {
      hide();
      message.error('Failed to reset scripts: ' + (error.response?.data?.detail || error.message));
    }
  };

  const updateAgentVersion = async (values) => {
    try {
      // Use database-driven endpoint for version updates
      const response = await axios.post('/api/agents/versions', {
        platform: selectedVersionPlatform,
        version: values.version,
        changelog: values.changelog ? values.changelog.split('\n').filter(line => line.trim()) : []
      }, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('authToken') || ''}`,
        },
      });
      
      message.success(`${selectedVersionPlatform} agent version updated to ${values.version}`);
      setVersionUpdateModal(false);
      versionForm.resetFields();
      
      // Refresh data to show new version
      await fetchAgentVersions();
      await fetchAgents(); // Refresh agents to show new available versions
      
      notification.success({
        message: 'Version Updated Successfully',
        description: `${selectedVersionPlatform} agent version ${values.version} is now available. New agent deployments will use this version automatically. Existing agents can be upgraded via the upgrade button.`,
        duration: 8
      });
      
    } catch (error) {
      message.error('Failed to update version: ' + (error.response?.data?.detail || error.message));
    }
  };

  const handleVersionUpdate = (platform) => {
    setSelectedVersionPlatform(platform);
    const currentVersion = agentVersions[platform]?.available_version || '';
    versionForm.setFieldsValue({
      version: currentVersion,
      changelog: ''
    });
    setVersionUpdateModal(true);
  };

  const viewScript = async (platform) => {
    try {
      // First try to get script template from database
      const response = await axios.get(`/api/agents/script-templates/${platform}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('authToken') || ''}`,
        },
      });
      
      const scriptContent = response.data.script_content || 'Script not available';
      setSelectedScript(scriptContent);
      setOriginalScript(scriptContent); // Store original for comparison
      setCurrentEditingPlatform(platform);
      setScriptHasChanges(false); // Reset changes state
      setScriptViewModal(true);
    } catch (error) {
      // Fallback to generate-install-script if template not found
      try {
        const fallbackResponse = await axios.post('/api/agents/generate-install-script', {
          platform: platform,
          architecture: platform === 'macos' ? 'arm64' : 'x86_64',
          pool_id: 1,
          cluster_id: selectedCluster?.id || 1,
          agent_name: `${platform}-preview`,
          hostname_prefix: 'preview',
          haproxy_config_path: '/etc/haproxy/haproxy.cfg',
          haproxy_bin_path: platform === 'macos' ? '/opt/homebrew/bin/haproxy' : '/usr/sbin/haproxy',
          stats_socket_path: platform === 'macos' ? '/opt/homebrew/var/run/haproxy/admin.sock' : '/var/run/haproxy/admin.sock'
        }, {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('authToken') || ''}`,
          },
        });
        
        const scriptContent = fallbackResponse.data.script || 'Script not available';
        setSelectedScript(scriptContent);
        setOriginalScript(scriptContent);
        setCurrentEditingPlatform(platform);
        setScriptHasChanges(false);
        setScriptViewModal(true);
      } catch (fallbackError) {
        message.error('Failed to load script template: ' + (fallbackError.response?.data?.detail || fallbackError.message));
      }
    }
  };

  // Handle script content changes
  const handleScriptChange = useCallback((newScript) => {
    console.log('Script changed:', { 
      newScript: newScript?.length, 
      original: originalScript?.length,
      hasChanges: newScript !== originalScript 
    });
    setSelectedScript(newScript);
    setScriptHasChanges(newScript !== originalScript);
  }, [originalScript]);

  // Save script changes and trigger version update
  const saveScriptChanges = async () => {
    if (!scriptHasChanges || !currentEditingPlatform) {
      message.warning('No changes to save');
      return;
    }

    setScriptSaving(true);
    try {
      // Auto-increment version for the platform
      const currentVersion = agentVersions[currentEditingPlatform]?.available_version || '1.0.0';
      const versionParts = currentVersion.split('.');
      const newPatchVersion = parseInt(versionParts[2] || '0') + 1;
      const newVersion = `${versionParts[0]}.${versionParts[1]}.${newPatchVersion}`;
      
      // Save script template to database with new version
      await axios.post(`/api/agents/script-templates/${currentEditingPlatform}`, {
        script_content: selectedScript,
        version: newVersion
      }, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('authToken') || ''}`,
        },
      });
      
      message.success('Script template saved successfully');
      setOriginalScript(selectedScript);
      setScriptHasChanges(false);
      
      // Close script modal and open version update modal
      setScriptViewModal(false);
      
      // Open version update modal with suggested new version
      setSelectedVersionPlatform(currentEditingPlatform);
      versionForm.setFieldsValue({
        version: newVersion,
        changelog: `Updated ${currentEditingPlatform} agent script\n- Script modifications applied\n- Ready for deployment`
      });
      setVersionUpdateModal(true);
      
      notification.success({
        message: 'Script Saved',
        description: `Script template saved with version ${newVersion}. Please update the version to deploy the new script to agents.`,
        duration: 6
      });
      
    } catch (error) {
      message.error('Failed to save script changes: ' + (error.response?.data?.detail || error.message));
    } finally {
      setScriptSaving(false);
    }
  };

  // Reset script changes
  const resetScriptChanges = useCallback(() => {
    console.log('🔄 Resetting script changes to original');
    setSelectedScript(originalScript);
    setScriptHasChanges(false);
  }, [originalScript]);

  const upgradeAgent = async (agentId, agentName, currentVersion, availableVersion, agentRecord = null) => {
    // CRITICAL: Use multiple sources for cluster info to handle context timing issues
    // 1st priority: selectedCluster from context
    // 2nd priority: cluster info from agent record
    // 3rd priority: find cluster from pools
    let clusterAtStart = selectedCluster;
    
    if (!clusterAtStart && agentRecord) {
      // Fallback: Find cluster from agent's pool_id
      console.log(`⚠️ selectedCluster is undefined, using agent record fallback`);
      console.log(`🔍 agentRecord:`, agentRecord);
      console.log(`🔍 available clusters:`, clusters);
      
      // First try: Find from clusters array
      clusterAtStart = clusters.find(c => c.pool_id === agentRecord.pool_id);
      
      // Second try: If clusters array is empty, create minimal cluster object from agent record
      if (!clusterAtStart && agentRecord.pool_id) {
        console.log(`🔧 Creating minimal cluster object from agent record`);
        clusterAtStart = {
          id: agentRecord.cluster_id || agentRecord.pool_id, // Use cluster_id if available, fallback to pool_id
          pool_id: agentRecord.pool_id,
          name: agentRecord.pool_name || `pool-${agentRecord.pool_id}`,
        };
        console.log(`🔧 Created minimal cluster:`, clusterAtStart);
      }
      
      console.log(`🔄 Found cluster from agent record:`, clusterAtStart);
    }
    
    if (!clusterAtStart) {
      console.log(`🔍 Final debug - selectedCluster: ${selectedCluster}, agentRecord: ${agentRecord}, clusters.length: ${clusters.length}`);
    }
    
    console.log(`🔄 UPGRADE START: agentId=${agentId}, selectedCluster=${clusterAtStart?.name}, pool_id=${clusterAtStart?.pool_id}`);
    
    // CRITICAL FIX: Validate cluster before proceeding
    if (!clusterAtStart) {
      console.error('❌ UPGRADE FAILED: No cluster selected and cannot determine from agent record!');
      message.error('Cannot determine cluster for this agent. Please refresh the page and try again.');
      return;
    }
    
    // SIMPLIFIED: No upgrade/downgrade distinction - always "Upgrade"
    // Agent will sync to the latest script version from database
    const actionType = 'Upgrade';
    const actionVerb = 'Upgrading';
    
    // CRITICAL FIX: Immediately update agent status in local state to prevent disappearing
    console.log(`🔄 Setting agent ${agentId} to upgrading status (action: ${actionType}) BEFORE API call`);
    
    // Store upgrade type in ref (doesn't trigger re-renders)
    upgradeTypesRef.current[agentId] = 'upgrade';
    console.log(`🔄 Stored in ref - Agent ${agentId}: upgrade`);
    
    setAgents(prevAgents => 
      prevAgents.map(agent => 
        agent.id === agentId 
          ? { 
              ...agent, 
              status: 'upgrading',
              _upgradeType: 'upgrade' // Always upgrade
            } 
          : agent
      )
    );
    setFilteredAgents(prevAgents => 
      prevAgents.map(agent => 
        agent.id === agentId 
          ? { 
              ...agent, 
              status: 'upgrading',
              _upgradeType: 'upgrade' // Always upgrade
            } 
          : agent
      )
    );
    
    const hide = message.loading(`${actionVerb} agent ${agentName}...`);
    try {
      console.log(`🔄 Calling upgrade API for agent ${agentId}`);
      await axios.post(`/api/agents/${agentId}/upgrade`, {}, { 
        timeout: 15000,
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('authToken') || ''}`,
        },
      });
      console.log(`✅ Upgrade API call successful for agent ${agentId}`);
      
      notification.success({
        message: `Agent ${actionType} Initiated`,
        description: `Agent "${agentName}" ${actionType.toLowerCase()} from v${currentVersion} to v${availableVersion} has been initiated. The agent will update automatically.`,
        duration: 6
      });
      
      // Immediate refresh to sync with backend
      console.log(`🔄 Fetching agents after upgrade (immediate)`);
      await fetchAgents(true, clusterAtStart);
      
      // Also refresh after delay to ensure final state is updated
      // CRITICAL: Only refresh if user is still on the same cluster
      setTimeout(() => {
        // Check if user is still on the same cluster before refreshing
        if (selectedCluster?.pool_id === clusterAtStart?.pool_id) {
          console.log(`🔄 Fetching agents after upgrade (delayed 1s)`);
          fetchAgents(true, clusterAtStart);
        } else {
          console.log(`⚠️ User switched clusters during upgrade. Skipping delayed refresh for ${agentName}`);
        }
      }, 1000); // 1s delay for agent to complete upgrade (reduced from 3s)
    } catch (error) {
      const errorMessage = error.response?.data?.detail || error.message;
      console.error(`❌ Upgrade failed for agent ${agentId}:`, errorMessage);
      notification.error({
        message: `${actionType} Failed`,
        description: `Failed to ${actionType.toLowerCase()} agent "${agentName}": ${errorMessage}`,
        duration: 6
      });
      // Immediate refresh even on error to show correct state
      // Use captured cluster for consistency
      console.log(`🔄 Fetching agents after upgrade error`);
      await fetchAgents(true, clusterAtStart);
    } finally {
      hide();
    }
  };

  // Show agent details
  const showAgentDetails = (agent) => {
    setSelectedAgent(agent);
    setAgentDetailModalVisible(true);
  };

  // Show agent activity logs
  const showAgentLogs = async (agent) => {
    setSelectedAgent(agent);
    setAgentLogsModalVisible(true);
    setAgentLogsLoading(true);
    
    try {
      const response = await axios.get(`/api/agents/${agent.name}/activity-logs`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('authToken') || ''}`,
        },
        params: { limit: 50 }
      });
      
      setAgentLogs(response.data.logs || []);
    } catch (error) {
      message.error('Failed to load activity logs: ' + (error.response?.data?.detail || error.message));
      setAgentLogs([]);
    } finally {
      setAgentLogsLoading(false);
    }
  };

  // Enhanced status badge with more information
  const getStatusBadge = (health, status, lastSeen, upgradeType) => {
    const statusConfig = {
      healthy: { 
        status: 'success', 
        icon: <CheckCircleOutlined />, 
        text: 'Online',
        color: '#52c41a'
      },
      warning: { 
        status: 'warning', 
        icon: <WarningOutlined />, 
        text: 'Warning',
        color: '#faad14'
      },
      offline: { 
        status: 'error', 
        icon: <CloseCircleOutlined />, 
        text: 'Offline',
        color: '#ff4d4f'
      },
      upgrading: {
        status: 'processing',
        icon: <SyncOutlined spin />,
        text: 'Upgrading',
        color: '#1890ff'
      },
      downgrading: {
        status: 'processing',
        icon: <SyncOutlined spin />,
        text: 'Downgrading',
        color: '#faad14'
      },
      unknown: { 
        status: 'default', 
        icon: <ClockCircleOutlined />, 
        text: 'Unknown',
        color: '#d9d9d9'
      }
    };
    
    // Check for upgrading status first
    let config;
    if (status === 'upgrading') {
      // Always use upgrading config (no downgrade distinction)
      config = statusConfig.upgrading;
    } else {
      config = statusConfig[health] || statusConfig.unknown;
    }
    
    const getLastSeenText = () => {
      if (!lastSeen) return 'Never connected';
      const date = new Date(lastSeen);
      const now = new Date();
      const diffMinutes = Math.floor((now - date) / (1000 * 60));
      
      if (diffMinutes < 1) return 'Just now';
      if (diffMinutes < 60) return `${diffMinutes}m ago`;
      if (diffMinutes < 1440) return `${Math.floor(diffMinutes / 60)}h ago`;
      return `${Math.floor(diffMinutes / 1440)}d ago`;
    };
    
    return (
      <Tooltip title={`Status: ${config.text} | Last seen: ${getLastSeenText()}`}>
        <Badge 
          status={config.status} 
          text={config.text}
          style={{ color: config.color }}
        />
      </Tooltip>
    );
  };

  // Get platform icon
  const getPlatformIcon = (platform) => {
    return platformConfig[platform]?.icon || <DesktopOutlined style={{ fontSize: '16px' }} />;
  };

  // Enhanced table columns
  const columns = useMemo(() => {
    const baseColumns = [
    {
      title: 'Agent Info',
      key: 'agent_info',
      render: (text, record) => (
        <Space direction="vertical" size="small">
          <Space>
            {getPlatformIcon(record.platform)}
            <Text strong>{record.name}</Text>
            {record.health === 'healthy' && (
              <HeartTwoTone twoToneColor="#eb2f96" />
            )}
          </Space>
          <Text type="secondary" style={{ fontSize: '12px' }}>
            {record.hostname || 'Unknown hostname'}
          </Text>
          {record.ip_address && (
            <Text type="secondary" style={{ fontSize: '11px' }}>
              IP: {record.ip_address}
            </Text>
          )}
        </Space>
      ),
      width: 220,
    },
    {
      title: 'Agent Pool',
      dataIndex: 'pool_name',
      key: 'pool_name',
      render: (text, record) => (
        <Space direction="vertical" size="small">
          <Text>{text || 'Unknown'}</Text>
          <Text type="secondary" style={{ fontSize: '12px' }}>
            {record.pool_environment || 'Unknown environment'}
          </Text>
        </Space>
      ),
      width: 180,
    },
    {
      title: 'System Info',
      key: 'system_info',
      render: (_, record) => (
        <Space direction="vertical" size="small">
          <Space>
            <Tag color="blue" style={{ textTransform: 'capitalize' }}>
              {record.platform}
            </Tag>
            <Tag color="cyan" size="small">
              {record.architecture}
            </Tag>
          </Space>
          {record.operating_system && (
            <Text type="secondary" style={{ fontSize: '11px' }}>
              OS: {record.operating_system}
            </Text>
          )}
          {record.kernel_version && (
            <Text type="secondary" style={{ fontSize: '10px' }}>
              Kernel: {record.kernel_version}
            </Text>
          )}
        </Space>
      ),
      width: 180,
    },
    {
      title: 'Resources',
      key: 'resources',
      render: (_, record) => (
        <Space direction="vertical" size="small">
          {record.cpu_count && (
            <Text style={{ fontSize: '11px' }}>
              🖥️ CPU: {record.cpu_count} cores
            </Text>
          )}
          {record.memory_total && (
            <Text style={{ fontSize: '11px' }}>
              💾 RAM: {(record.memory_total / 1024 / 1024 / 1024).toFixed(1)}GB
            </Text>
          )}
          {record.disk_space && (
            <Text style={{ fontSize: '11px' }}>
              💿 Disk: {(record.disk_space / 1024 / 1024 / 1024).toFixed(1)}GB
            </Text>
          )}
          {record.uptime && (
            <Text type="secondary" style={{ fontSize: '10px' }}>
              ⏱️ Uptime: {Math.floor(record.uptime / 3600)}h
            </Text>
          )}
        </Space>
      ),
      width: 160,
    },
    {
      title: 'HAProxy',
      key: 'haproxy_info',
      render: (_, record) => (
        <Tag 
          color={record.haproxy_status === 'running' ? 'green' : 
                record.haproxy_status === 'stopped' ? 'red' : 'orange'}
          size="small"
        >
          {record.haproxy_status || 'unknown'}
        </Tag>
      ),
      width: 120,
    },
    {
      title: 'Status',
      key: 'status',
      render: (_, record) => getStatusBadge(record.health, record.status, record.last_seen, record._upgradeType),
      width: 120,
    },
    {
      title: 'Last Activity',
      dataIndex: 'last_action_time',
      key: 'last_action_time',
      render: (lastActionTime) => {
        if (!lastActionTime) return <Text type="secondary">Never</Text>;
        
        const date = new Date(lastActionTime);
        const now = new Date();
        const diffMinutes = Math.floor((now - date) / (1000 * 60));
        
        let displayText, color;
        if (diffMinutes < 1) {
          displayText = 'Just now';
          color = '#52c41a';
        } else if (diffMinutes < 5) {
          displayText = `${diffMinutes}m ago`;
          color = '#52c41a';
        } else if (diffMinutes < 60) {
          displayText = `${diffMinutes}m ago`;
          color = '#faad14';
        } else if (diffMinutes < 1440) {
          displayText = `${Math.floor(diffMinutes / 60)}h ago`;
          color = '#ff4d4f';
        } else {
          displayText = `${Math.floor(diffMinutes / 1440)}d ago`;
          color = '#ff4d4f';
        }
        
        // Display local time in tooltip (browser timezone)
        const options = { 
          year: 'numeric', 
          month: 'short', 
          day: 'numeric', 
          hour: '2-digit', 
          minute: '2-digit',
          second: '2-digit'
        };
        const localTime = date.toLocaleString(undefined, options);
        
        return (
          <Tooltip title={`Last seen: ${localTime} (your timezone)`}>
            <Text style={{ color }}>{displayText}</Text>
          </Tooltip>
        );
      },
      width: 120,
      sorter: (a, b) => {
        const aTime = a.last_action_time ? new Date(a.last_action_time).getTime() : 0;
        const bTime = b.last_action_time ? new Date(b.last_action_time).getTime() : 0;
        return bTime - aTime;
      },
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Space>
          <Tooltip title={record.enabled ? "Disable Agent" : "Enable Agent"}>
            <Switch
              size="small"
              checked={record.enabled}
              onChange={() => toggleAgent(record.id, record.enabled, record.name)}
              checkedChildren="ON"
              unCheckedChildren="OFF"
            />
          </Tooltip>
          {(hasPermission('agents', 'upgrade') || isAdmin()) && record.upgrade_available && record.status !== 'upgrading' && (() => {
            // Version comparison logic
            const currentVer = record.current_version || '0.0.0';
            const availableVer = record.available_version || '0.0.0';
            
            // SIMPLIFIED: Always show "Upgrade" when versions differ
            const actionType = 'Upgrade';
            const actionIcon = <ArrowUpOutlined />;
            const buttonColor = { backgroundColor: '#52c41a', borderColor: '#52c41a' };
            
            return (
              <Tooltip title={`${actionType} from v${currentVer} to v${availableVer}`}>
                <Popconfirm
                  title={`${actionType} Agent?`}
                  description={`This will ${actionType.toLowerCase()} agent "${record.name}" from v${currentVer} to v${availableVer}. The process is automatic and will take a few minutes.`}
                  onConfirm={() => upgradeAgent(record.id, record.name, currentVer, availableVer, record)}
                  okText={actionType}
                  cancelText="Cancel"
                  okButtonProps={{ type: 'primary' }}
                  icon={actionIcon}
                >
                  <Button
                    type="primary"
                    size="small"
                    icon={actionIcon}
                    style={buttonColor}
                  >
                    {actionType}
                  </Button>
                </Popconfirm>
              </Tooltip>
            );
          })()}
          {(hasPermission('agents', 'version') || isAdmin()) && record.status === 'upgrading' && (() => {
            // SIMPLIFIED: Always show "Upgrading"
            const actionText = 'Upgrading';
            const tooltipText = 'Agent is currently upgrading';
            
            return (
              <Tooltip title={tooltipText}>
                <Button
                  type="primary"
                  size="small"
                  icon={<SyncOutlined spin />}
                  disabled
                  style={{ backgroundColor: '#faad14', borderColor: '#faad14' }}
                >
                  {actionText}
                </Button>
              </Tooltip>
            );
          })()}
          <Tooltip title="Activity Logs">
            <Button
              size="small"
              icon={<FileTextOutlined />}
              onClick={() => showAgentLogs(record)}
            />
          </Tooltip>
          <Tooltip title="View Details">
            <Button
              type="primary"
              size="small"
              icon={<EyeOutlined />}
              onClick={() => showAgentDetails(record)}
            />
          </Tooltip>
          <Popconfirm
            title={`Delete Agent "${record.name}"?`}
            description="This action cannot be undone. The agent will need to be reinstalled."
            onConfirm={() => deleteAgent(record.id, record.name)}
            okText="Delete"
            cancelText="Cancel"
            okButtonProps={{ danger: true }}
            icon={<ExclamationCircleOutlined style={{ color: 'red' }} />}
          >
            <Tooltip title="Delete Agent">
              <Button
                type="primary"
                danger
                size="small"
                icon={<DeleteOutlined />}
              />
            </Tooltip>
          </Popconfirm>
        </Space>
      ),
      width: 220,
      fixed: 'right',
    },
  ];

    // Add Agent Version column if user has permission or is admin
    if (hasPermission('agents', 'version') || isAdmin()) {
      baseColumns.splice(-2, 0, {
        title: 'Agent Version',
        key: 'agent_version',
        render: (_, record) => (
          <Space direction="vertical" size="small">
            <Space>
              <TagOutlined style={{ color: '#1890ff' }} />
              <Text style={{ fontSize: '12px' }}>
                Current: <Text strong>{record.current_version || '1.0.0'}</Text>
              </Text>
            </Space>
            <Text style={{ fontSize: '11px' }} type="secondary">
              Available: {record.available_version || '1.1.0'}
            </Text>
            {record.upgrade_available && (
              <Tag color="orange" size="small">
                Update Available
              </Tag>
            )}
          </Space>
        ),
        width: 160,
      });
    }

    return baseColumns;
  }, [hasPermission]);

  // Get agent statistics
  const getAgentStats = () => {
    const total = agents.length;
    const healthy = agents.filter(a => a.health === 'healthy').length;
    const warning = agents.filter(a => a.health === 'warning').length;
    const offline = agents.filter(a => a.health === 'offline').length;
    
    return { total, healthy, warning, offline };
  };

  const stats = getAgentStats();

  // Connection status indicator
  const getConnectionStatusIndicator = () => {
    const statusConfig = {
      checking: { color: 'orange', icon: <SyncOutlined spin />, text: 'Checking...' },
      connecting: { color: 'blue', icon: <SyncOutlined spin />, text: 'Connecting...' },
      connected: { color: 'green', icon: <WifiOutlined />, text: 'Connected' },
      disconnected: { color: 'red', icon: <DisconnectOutlined />, text: 'Disconnected' },
      'no-agents': { color: 'gray', icon: <DisconnectOutlined />, text: 'No Agents' },
      error: { color: 'red', icon: <DisconnectOutlined />, text: 'Error' }
    };
    
    const config = statusConfig[connectionStatus] || statusConfig.checking;
    
    return (
      <Space>
        <Badge color={config.color} />
        {config.icon}
        <Text style={{ color: config.color, fontSize: '12px' }}>
          {config.text}
        </Text>
      </Space>
    );
  };

  // Agent setup steps
  const setupSteps = [
    {
      title: 'Get the agent',
      description: 'Select platform and configure options',
      icon: <CloudDownloadOutlined />
    },
    {
      title: 'Configure',
      description: 'Set agent name and target settings',
      icon: <SettingOutlined />
    },
    {
      title: 'Download script',
      description: 'Generate installation script',
      icon: <CodeOutlined />
    },
    {
      title: 'Run script',
      description: 'Execute on your server',
      icon: <RocketOutlined />
    }
  ];

  return (
    <ErrorBoundary>
      {/* Reset Version Modal */}
      <Modal
        title="Reset Agent Scripts to Defaults"
        open={resetVersionModalVisible}
        onCancel={() => setResetVersionModalVisible(false)}
        onOk={() => resetVersionForm.submit()}
        okText="Reset & Sync"
        okButtonProps={{ danger: true }}
        width={600}
      >
        <Form
          form={resetVersionForm}
          layout="vertical"
          onFinish={resetScriptsToDefaults}
        >
          <Alert
            message="This will sync agent scripts from files to database"
            description={
              <ul style={{ marginTop: '8px', paddingLeft: '20px', marginBottom: 0 }}>
                <li>Override any manual script edits in database</li>
                <li>All existing agents will detect new version</li>
                <li>Agents can upgrade to latest script</li>
              </ul>
            }
            type="warning"
            showIcon
            style={{ marginBottom: '16px' }}
          />
          
          <Form.Item
            label="Target Version"
            name="targetVersion"
            rules={[
              { required: true, message: 'Please enter version' },
              { pattern: /^\d+\.\d+\.\d+$/, message: 'Version must be in format: 1.0.0' }
            ]}
            extra="Scripts will be synced with this version number. Agents on different versions will see upgrade available."
          >
            <Input placeholder="1.0.1" />
          </Form.Item>
        </Form>
      </Modal>

      <div style={{ padding: '24px' }}>
        <div style={{ marginBottom: '24px' }}>
          <Title level={2}>
            <Space>
              <TeamOutlined />
              Agent Management
            </Space>
          </Title>
          <Paragraph>
            Deploy HAProxy agents to remote servers for automated configuration management. 
            These agents provide secure, automated management without requiring SSH access.
          </Paragraph>
          
          {/* Connection Status and Controls */}
          <div style={{ 
            display: 'flex', 
            justifyContent: 'space-between', 
            alignItems: 'center',
            background: '#fafafa',
            padding: '12px 16px',
            borderRadius: '6px',
            marginBottom: '16px'
          }}>
            <Space>
              {getConnectionStatusIndicator()}
              {lastRefresh && (
                <Text type="secondary" style={{ fontSize: '12px' }}>
                  Last updated: {lastRefresh.toLocaleTimeString()}
                </Text>
              )}
            </Space>
            
            <Space>
              <Tooltip title={autoRefresh ? 'Auto-refresh enabled (30s)' : 'Auto-refresh disabled'}>
                <Space>
                  <Text style={{ fontSize: '12px' }}>Auto-refresh</Text>
                  <Switch
                    size="small"
                    checked={autoRefresh}
                    onChange={setAutoRefresh}
                    checkedChildren={<PlayCircleOutlined />}
                    unCheckedChildren={<PauseCircleOutlined />}
                  />
                </Space>
              </Tooltip>
              
              {autoRefresh && (
                <div style={{ width: '60px' }}>
                  <Progress 
                    percent={refreshProgress} 
                    size="small" 
                    showInfo={false}
                    strokeColor="#1890ff"
                  />
                </div>
              )}
            </Space>
          </div>
        </div>

        {/* Main Content - Two sections */}
        <Row gutter={24}>
          {/* Agent Setup Section */}
          <Col xs={24} lg={12}>
            <Card
              title={
                <Space>
                  <PlusOutlined />
                  <span>New Agent Setup</span>
                </Space>
              }
              style={{ height: '100%' }}
            >
              <div style={{ textAlign: 'center', padding: '40px 20px' }}>
                <CloudDownloadOutlined style={{ fontSize: '64px', color: '#1890ff', marginBottom: '24px' }} />
                <Title level={3}>Deploy New Agent</Title>
                <Paragraph type="secondary">
                  Set up a new HAProxy management agent on your servers. 
                  Follow the step-by-step process for easy deployment.
                </Paragraph>
                <Button 
                  type="primary" 
                  size="large"
                  icon={<RocketOutlined />}
                  onClick={openSetupModal}
                  style={{ marginTop: '16px' }}
                >
                  Start Agent Setup
                </Button>
              </div>
            </Card>
          </Col>

          {/* Agent Statistics */}
          <Col xs={24} lg={12}>
            <Card
              title={
                <Space>
                  <TeamOutlined />
                  <span>Agent Overview</span>
                </Space>
              }
              style={{ height: '100%' }}
            >
              <Row gutter={16}>
                <Col span={12}>
                  <Card size="small" hoverable>
                    <Statistic
                      title="Total Agents"
                      value={stats.total}
                      prefix={<DesktopOutlined />}
                      valueStyle={{ color: '#1890ff' }}
                    />
                  </Card>
                </Col>
                <Col span={12}>
                  <Card size="small" hoverable>
                    <Statistic
                      title="Online"
                      value={stats.healthy}
                      prefix={<CheckCircleOutlined />}
                      valueStyle={{ color: '#3f8600' }}
                      suffix={stats.total > 0 ? `(${Math.round(stats.healthy / stats.total * 100)}%)` : ''}
                    />
                  </Card>
                </Col>
                <Col span={12} style={{ marginTop: '16px' }}>
                  <Card size="small" hoverable>
                    <Statistic
                      title="Warning"
                      value={stats.warning}
                      prefix={<WarningOutlined />}
                      valueStyle={{ color: '#faad14' }}
                      suffix={stats.total > 0 ? `(${Math.round(stats.warning / stats.total * 100)}%)` : ''}
                    />
                  </Card>
                </Col>
                <Col span={12} style={{ marginTop: '16px' }}>
                  <Card size="small" hoverable>
                    <Statistic
                      title="Offline"
                      value={stats.offline}
                      prefix={<CloseCircleOutlined />}
                      valueStyle={{ color: '#cf1322' }}
                      suffix={stats.total > 0 ? `(${Math.round(stats.offline / stats.total * 100)}%)` : ''}
                    />
                  </Card>
                </Col>
              </Row>
            </Card>
          </Col>
        </Row>

        <Divider />

        {/* Registered Agents and Script Management */}
        <Tabs defaultActiveKey="agents">
          <TabPane 
            tab={
              <Space>
                <TeamOutlined />
                Registered Agents
                <Badge count={stats.total} style={{ backgroundColor: '#52c41a' }} />
              </Space>
            } 
            key="agents"
          >
            <Card
          extra={
            <Space>
              <div style={{ 
                position: 'relative', 
                display: 'inline-block',
                width: 250
              }}>
                <input
                  type="text"
                  placeholder="Search agents..."
                  value={searchText}
                  onChange={(e) => handleSearch(e.target.value)}
                  style={{
                    width: '100%',
                    height: 32,
                    paddingLeft: 8,
                    paddingRight: searchText ? 32 : 8,
                    border: '1px solid #d9d9d9',
                    borderRadius: 6,
                    fontSize: 14,
                    outline: 'none',
                    boxShadow: 'none',
                    backgroundColor: '#fff',
                    transition: 'border-color 0.3s ease'
                  }}
                  onFocus={(e) => {
                    e.target.style.borderColor = '#1890ff';
                    e.target.style.outline = 'none';
                    e.target.style.boxShadow = 'none';
                  }}
                  onBlur={(e) => {
                    e.target.style.borderColor = '#d9d9d9';
                  }}
                  onMouseOver={(e) => {
                    if (e.target !== document.activeElement) {
                      e.target.style.borderColor = '#40a9ff';
                    }
                  }}
                  onMouseOut={(e) => {
                    if (e.target !== document.activeElement) {
                      e.target.style.borderColor = '#d9d9d9';
                    }
                  }}
                />
                {searchText && (
                  <CloseCircleOutlined
                    onClick={() => handleSearch('')}
                    style={{
                      position: 'absolute',
                      right: 8,
                      top: '50%',
                      transform: 'translateY(-50%)',
                      cursor: 'pointer',
                      color: '#bfbfbf',
                      fontSize: 14,
                      transition: 'color 0.3s ease'
                    }}
                    onMouseOver={(e) => {
                      e.target.style.color = '#8c8c8c';
                    }}
                    onMouseOut={(e) => {
                      e.target.style.color = '#bfbfbf';
                    }}
                  />
                )}
              </div>
              <Button
                icon={<ReloadOutlined />}
                onClick={() => fetchAgents()}
                loading={loading}
                type="primary"
                ghost
              >
                Refresh Now
              </Button>
            </Space>
          }
        >
          {agents.length === 0 && !loading ? (
            <div style={{ 
              textAlign: 'center', 
              padding: '60px 20px',
              background: '#fafafa',
              borderRadius: '6px'
            }}>
              <TeamOutlined style={{ fontSize: '64px', color: '#d9d9d9', marginBottom: '16px' }} />
              <Title level={3} type="secondary">No Agents Registered</Title>
              <Paragraph type="secondary">
                No HAProxy agents have been registered yet. Use the "Start Agent Setup" button above to configure and deploy your first agent.
              </Paragraph>
            </div>
          ) : (
            <Spin spinning={loading} tip="Loading agents...">
              <Table
                columns={columns}
                dataSource={filteredAgents}
                rowKey="id"
                pagination={{
                  pageSize: 10,
                  showSizeChanger: true,
                  showQuickJumper: true,
                  showTotal: (total, range) => 
                    `${range[0]}-${range[1]} of ${total} agents`,
                  responsive: true,
                }}
                scroll={{ x: 1000 }}
                size="middle"
                rowClassName={(record) => 
                  record.health === 'offline' ? 'agent-offline' : ''
                }
              />
            </Spin>
          )}
        </Card>
          </TabPane>
          
          <TabPane 
            tab={
              <Space>
                <CodeOutlined />
                Agent Script Management
              </Space>
            } 
            key="agent-scripts"
            disabled={!hasPermission('agents', 'version') && !isAdmin()}
          >
            <Card 
              title={<Title level={4}><CodeOutlined /> Manage Agent Script Versions</Title>}
              extra={
                <Space>
                  <Text type="secondary" style={{ fontSize: '12px' }}>
                    Versions loaded automatically
                  </Text>
                  <Popconfirm
                    title="Reset Agent Scripts to Default?"
                    description={
                      <div style={{ maxWidth: '400px' }}>
                        <Text strong>⚠️ This will:</Text>
                        <ul style={{ marginTop: '8px', marginBottom: '8px', paddingLeft: '20px' }}>
                          <li>Reset all agent scripts to file-based defaults (from code)</li>
                          <li>Discard any UI edits you've made</li>
                          <li>Create new versions with latest bug fixes</li>
                          <li>All existing agents will need to be upgraded</li>
                        </ul>
                        <Text type="warning">
                          💡 Use this after code updates to apply fixes to database
                        </Text>
                      </div>
                    }
                    onConfirm={showResetVersionModal}
                    okText="Yes, Reset to Defaults"
                    cancelText="Cancel"
                    okButtonProps={{ danger: true }}
                    icon={<ExclamationCircleOutlined style={{ color: 'red' }} />}
                  >
                    <Button 
                      icon={<ToolOutlined />}
                      size="small"
                      danger
                    >
                      Reset to Defaults
                    </Button>
                  </Popconfirm>
                  <Button 
                    icon={<ReloadOutlined />} 
                    onClick={fetchAgentVersions} 
                    loading={agentVersionLoading}
                    size="small"
                    type="text"
                  >
                    Refresh
                  </Button>
                </Space>
              }
              style={{ marginBottom: '24px' }}
            >
              <Spin spinning={agentVersionLoading}>
                <List
                  itemLayout="horizontal"
                  dataSource={Object.keys(agentVersions)}
                  renderItem={platform => (
                    <List.Item
                      actions={[
                        <Button 
                          icon={<CodeOutlined />} 
                          onClick={() => viewScript(platform)}
                          disabled={!hasPermission('agents', 'version') && !isAdmin()}
                        >
                          Edit Script
                        </Button>,
                        <Button 
                          type="primary" 
                          icon={<SaveOutlined />} 
                          onClick={() => handleVersionUpdate(platform)}
                          disabled={!hasPermission('agents', 'version') && !isAdmin()}
                        >
                          Update Version
                        </Button>
                      ]}
                    >
                      <List.Item.Meta
                        avatar={<Tag color="blue">{platform.toUpperCase()}</Tag>}
                        title={<Text strong>{agentVersions[platform].description}</Text>}
                        description={
                          <Space direction="vertical">
                            <Text>Available Version: <Tag color="green">{agentVersions[platform].available_version}</Tag></Text>
                            <Text type="secondary">Last Updated: {new Date(agentVersions[platform].last_updated).toLocaleString()}</Text>
                          </Space>
                        }
                      />
                    </List.Item>
                  )}
                />
              </Spin>
            </Card>
          </TabPane>
        </Tabs>

        {/* Agent Setup Modal */}
        <Modal
          title={
            <Space>
              <CloudDownloadOutlined />
              <span>Get the agent</span>
            </Space>
          }
          visible={setupModalVisible}
          onCancel={() => setSetupModalVisible(false)}
          width={1000}
          footer={null}
          destroyOnClose
        >
          <div style={{ marginBottom: '24px' }}>
            <Steps current={currentStep} size="small">
              {setupSteps.map((step, index) => (
                <Step 
                  key={index} 
                  title={step.title} 
                  description={step.description}
                  icon={step.icon}
                />
              ))}
            </Steps>
          </div>

          {/* Step 0: Platform Selection */}
          {currentStep === 0 && (
            <div>
              <Title level={4}>Select Platform</Title>
              <Paragraph>Choose the platform where you want to install the HAProxy agent.</Paragraph>
              
              <Row gutter={16} style={{ marginBottom: '24px' }}>
                {Object.entries(platformConfig).map(([key, config]) => (
                  <Col key={key} span={8}>
                    <Card
                      hoverable
                      style={{ 
                        textAlign: 'center',
                        border: selectedPlatform === key ? `2px solid ${config.color}` : '1px solid #d9d9d9',
                        backgroundColor: selectedPlatform === key ? `${config.color}10` : '#fff'
                      }}
                      onClick={() => {
                        setSelectedPlatform(key);
                        setSelectedArchitecture(config.defaultArch);
                      }}
                    >
                      <div style={{ padding: '20px' }}>
                        {config.icon}
                        <Title level={5} style={{ margin: '12px 0 0 0' }}>
                          {config.name}
                        </Title>
                      </div>
                    </Card>
                  </Col>
                ))}
              </Row>

              {/* Architecture Selection */}
              {supportedPlatforms[selectedPlatform] && (
                <div style={{ marginBottom: '24px' }}>
                  <Title level={5}>Architecture</Title>
                  <Radio.Group
                    value={selectedArchitecture}
                    onChange={(e) => setSelectedArchitecture(e.target.value)}
                  >
                    {Object.entries(supportedPlatforms[selectedPlatform].architectures || {}).map(([arch, info]) => (
                      <Radio.Button key={arch} value={arch}>
                        {info.display}
                      </Radio.Button>
                    ))}
                  </Radio.Group>
                </div>
              )}

              <div style={{ textAlign: 'right' }}>
                <Button 
                  type="primary" 
                  onClick={() => setCurrentStep(1)}
                  icon={<SettingOutlined />}
                >
                  Next: Configure
                </Button>
              </div>
            </div>
          )}

          {/* Step 1: Configuration */}
          {currentStep === 1 && (
            <div>
              <Title level={4}>Configure your agent</Title>
              <Paragraph>Configure your agent by setting the name, hostname, and target cluster.</Paragraph>
              
              <Form layout="vertical" style={{ marginBottom: '24px' }}>
                <Row gutter={16}>
                  <Col span={12}>
                    <Form.Item label="HAProxy Cluster Pool" required>
                      <Select
                        value={selectedPoolId}
                        onChange={handlePoolSelection}
                        placeholder="Select HAProxy cluster pool"
                        showSearch
                        optionFilterProp="children"
                      >
                        {pools.map(pool => (
                          <Option key={pool.id} value={pool.id} title={pool.description || `${pool.name} - ${pool.environment} environment`}>
                            <Space style={{ width: '100%', justifyContent: 'space-between' }}>
                              <Text strong>{pool.name}</Text>
                              <Tag color={pool.environment === 'production' ? 'red' : pool.environment === 'staging' ? 'orange' : 'blue'} size="small">
                                {pool.environment}
                              </Tag>
                            </Space>
                          </Option>
                        ))}
                      </Select>
                    </Form.Item>
                  </Col>
                  <Col span={12}>
                    <Form.Item label="Platform & Architecture">
                      <Input 
                        value={`${platformConfig[selectedPlatform].name} (${selectedArchitecture})`}
                        disabled
                      />
                    </Form.Item>
                  </Col>
                </Row>

                {/* Cluster Selection - Show only if multiple clusters exist for selected pool */}
                {poolClusters.length > 1 && (
                  <Row gutter={16}>
                    <Col span={24}>
                      <Form.Item label="HAProxy Cluster" required>
                        <Select
                          value={selectedClusterId}
                          onChange={setSelectedClusterId}
                          placeholder="Select cluster from the pool"
                          showSearch
                          optionFilterProp="children"
                        >
                          {poolClusters.map(cluster => (
                            <Option key={cluster.id} value={cluster.id}>
                              <Space>
                                <Text>{cluster.name}</Text>
                                <Text type="secondary">({cluster.description || 'No description'})</Text>
                              </Space>
                            </Option>
                          ))}
                        </Select>
                      </Form.Item>
                    </Col>
                  </Row>
                )}

                {/* Show cluster info when selected */}
                {selectedClusterId && poolClusters.length === 1 && (
                  <Row gutter={16}>
                    <Col span={24}>
                      <Alert
                        message="Cluster Auto-Selected"
                        description={`Only one cluster found for this pool: ${poolClusters[0].name}`}
                        type="info"
                        showIcon
                        style={{ marginBottom: 16 }}
                      />
                    </Col>
                  </Row>
                )}
                
                <Row gutter={16}>
                  <Col span={12}>
                    <Form.Item label="Agent Name" required>
                      <Input
                        value={agentName}
                        onChange={(e) => setAgentName(e.target.value)}
                        placeholder="haproxy-agent-01"
                      />
                    </Form.Item>
                  </Col>
                  <Col span={12}>
                    <Form.Item label="Hostname Prefix" required>
                      <Input
                        value={hostnamePrefix}
                        onChange={(e) => setHostnamePrefix(e.target.value)}
                        placeholder="web-server"
                      />
                    </Form.Item>
                  </Col>
                </Row>
              </Form>

              {/* Validation Alert - Pool has no clusters */}
              {selectedPoolId && poolClusters.length === 0 && (
                <Alert
                  message="Pool Has No Clusters"
                  description={
                    <div>
                      <p>The selected pool does not have any clusters assigned.</p>
                      <p><strong>Action required:</strong></p>
                      <ul style={{ marginBottom: 0 }}>
                        <li>Create a new cluster and assign it to this pool, OR</li>
                        <li>Edit an existing cluster and assign it to this pool, OR</li>
                        <li>Select a different pool that has clusters</li>
                      </ul>
                    </div>
                  }
                  type="error"
                  showIcon
                  style={{ marginBottom: '16px' }}
                />
              )}

              <div style={{ textAlign: 'right' }}>
                <Space>
                  <Button onClick={() => setCurrentStep(0)}>
                    Back
                  </Button>
                  <Button 
                    type="primary" 
                    onClick={() => setCurrentStep(2)}
                    icon={<CodeOutlined />}
                    disabled={!agentName.trim() || !hostnamePrefix.trim() || !selectedPoolId || poolClusters.length === 0}
                  >
                    Next: Generate Script
                  </Button>
                </Space>
              </div>
            </div>
          )}

          {/* Step 2: Generate Script */}
          {currentStep === 2 && (
            <div>
              <Title level={4}>Download the agent</Title>
              <Paragraph>Generate and download the installation script for your platform.</Paragraph>
              
              <Alert
                message="Ready to Generate"
                description={`Installation script will be generated for ${platformConfig[selectedPlatform].name} (${selectedArchitecture}) platform.`}
                type="info"
                showIcon
                style={{ marginBottom: '24px' }}
              />

              <div style={{ textAlign: 'center', marginBottom: '24px' }}>
                <Button 
                  type="primary" 
                  size="large"
                  icon={<DownloadOutlined />}
                  loading={scriptGenerating}
                  onClick={generateInstallScript}
                >
                  Generate Installation Script
                </Button>
              </div>

              <div style={{ textAlign: 'right' }}>
                <Button onClick={() => setCurrentStep(1)}>
                  Back
                </Button>
              </div>
            </div>
          )}

          {/* Step 3: Script Generated */}
          {currentStep === 3 && installScript && (
            <div>
              <Title level={4}>Run the agent</Title>
              <Paragraph>
                Copy and run the script below on your target server with root/administrator privileges.
              </Paragraph>
              
              <Alert
                message="Installation Script Ready"
                description={`Script generated for ${agentName} on a server with prefix '${hostnamePrefix}' (${platformConfig[selectedPlatform].name})`}
                type="success"
                showIcon
                style={{ marginBottom: '24px' }}
              />

              <div style={{ position: 'relative', marginBottom: '24px' }}>
                <TextArea
                  value={installScript}
                  rows={12}
                  readOnly
                  style={{ 
                    fontFamily: 'Monaco, Menlo, "Ubuntu Mono", monospace', 
                    fontSize: '12px',
                    lineHeight: '1.4'
                  }}
                />
                <Button
                  size="small"
                  icon={<CopyOutlined />}
                  style={{ 
                    position: 'absolute', 
                    top: '8px', 
                    right: '8px', 
                    zIndex: 1 
                  }}
                  onClick={() => {
                    navigator.clipboard.writeText(installScript);
                    message.success('Script copied to clipboard');
                  }}
                >
                  Copy
                </Button>
              </div>

              <div style={{ marginBottom: '24px' }}>
                <Title level={5}>Next Steps:</Title>
                <List
                  size="small"
                  dataSource={[
                    'Save the script to your target server',
                    'Make sure you have root/administrator privileges',
                    'Run the script on your server',
                    'The agent will appear in the agents list when successfully connected'
                  ]}
                  renderItem={(item, index) => (
                    <List.Item>
                      <Text>
                        <Text strong>{index + 1}.</Text> {item}
                      </Text>
                    </List.Item>
                  )}
                />
              </div>

              <div style={{ textAlign: 'right' }}>
                <Space>
                  <Button
                    type="default"
                    icon={<DownloadOutlined />}
                    onClick={() => {
                      const element = document.createElement('a');
                      const file = new Blob([installScript], { type: 'text/plain' });
                      element.href = URL.createObjectURL(file);
                      element.download = `install-haproxy-agent-${selectedPlatform}.sh`;
                      document.body.appendChild(element);
                      element.click();
                      document.body.removeChild(element);
                      message.success('Script downloaded successfully');
                    }}
                  >
                    Download Script
                  </Button>
                  <Button 
                    type="primary" 
                    onClick={() => {
                      setSetupModalVisible(false);
                      fetchAgents(true); // Refresh agents list
                    }}
                  >
                    Finish Setup
                  </Button>
                </Space>
              </div>
            </div>
          )}
        </Modal>

        {/* Agent Details Modal */}
        <Modal
          title={
            <Space>
              <TeamOutlined />
              <span>Agent Details: {selectedAgent?.name}</span>
            </Space>
          }
          visible={agentDetailModalVisible}
          onCancel={() => setAgentDetailModalVisible(false)}
          width={900}
          footer={[
            <Button key="close" onClick={() => setAgentDetailModalVisible(false)}>
              Close
            </Button>
          ]}
        >
          {selectedAgent && (
            <Tabs defaultActiveKey="1">
              <TabPane 
                tab={
                  <Space>
                    <InfoCircleOutlined />
                    Overview
                  </Space>
                } 
                key="1"
              >
                <Descriptions bordered column={2} size="small">
                  <Descriptions.Item label="Agent ID" span={2}>
                    <Text copyable={{ text: selectedAgent.id }}>
                      {selectedAgent.id}
                    </Text>
                  </Descriptions.Item>
                  <Descriptions.Item label="Name">
                    {selectedAgent.name}
                  </Descriptions.Item>
                  <Descriptions.Item label="Platform">
                    <Space>
                      {getPlatformIcon(selectedAgent.platform)}
                      <Text style={{ textTransform: 'capitalize' }}>
                        {selectedAgent.platform}
                      </Text>
                    </Space>
                  </Descriptions.Item>

                  <Descriptions.Item label="Status">
                    {getStatusBadge(selectedAgent.health, selectedAgent.status, selectedAgent.last_seen, selectedAgent._upgradeType)}
                  </Descriptions.Item>
                  <Descriptions.Item label="HAProxy Status">
                    <Tag color={selectedAgent.haproxy_status === 'running' ? 'green' : 'red'}>
                      {selectedAgent.haproxy_status || 'unknown'}
                    </Tag>
                  </Descriptions.Item>
                  <Descriptions.Item label="Config Version">
                    {selectedAgent.config_version || 'None'}
                  </Descriptions.Item>
                  <Descriptions.Item label="HAProxy Pool">
                    <Space direction="vertical" size="small">
                      <Text>{selectedAgent.pool_name || 'Unknown'}</Text>
                      <Text type="secondary" style={{ fontSize: '12px' }}>
                        Environment: {selectedAgent.pool_environment || 'Unknown'}
                      </Text>
                    </Space>
                  </Descriptions.Item>
                  <Descriptions.Item label="Registered At">
                    {new Date(selectedAgent.registered_at).toLocaleString()}
                  </Descriptions.Item>
                  <Descriptions.Item label="Last Seen">
                    {selectedAgent.last_seen ? 
                      new Date(selectedAgent.last_seen).toLocaleString() : 
                      'Never'
                    }
                  </Descriptions.Item>
                </Descriptions>
              </TabPane>
              
              <TabPane 
                tab={
                  <Space>
                    <CheckCircleOutlined />
                    Capabilities
                  </Space>
                } 
                key="2"
              >
                <div style={{ minHeight: '200px' }}>
                  {(() => {
                    let capabilities = [];
                    try {
                      if (typeof selectedAgent.capabilities === 'string') {
                        capabilities = JSON.parse(selectedAgent.capabilities);
                      } else if (Array.isArray(selectedAgent.capabilities)) {
                        capabilities = selectedAgent.capabilities;
                      }
                    } catch (e) {
                      console.warn('Failed to parse capabilities:', selectedAgent.capabilities);
                      capabilities = [];
                    }
                    
                    return capabilities && capabilities.length > 0 ? (
                      <div>
                        <Paragraph>This agent supports the following capabilities:</Paragraph>
                        <div>
                          {capabilities.map((capability, index) => (
                            <Tag key={index} color="blue" style={{ margin: '4px' }}>
                              {capability}
                            </Tag>
                          ))}
                        </div>
                      </div>
                    ) : (
                      <div style={{ textAlign: 'center', padding: '40px' }}>
                        <InfoCircleOutlined style={{ fontSize: '32px', color: '#d9d9d9' }} />
                        <Paragraph type="secondary" style={{ marginTop: '16px' }}>
                          No capability information available for this agent.
                        </Paragraph>
                      </div>
                    );
                  })()}
                </div>
              </TabPane>
              
              <TabPane 
                tab={
                  <Space>
                    <DesktopOutlined />
                    System Info
                  </Space>
                } 
                key="3"
              >
                <div style={{ minHeight: '200px' }}>
                  {selectedAgent.system_info ? (
                    <pre style={{ 
                      background: '#f6f8fa', 
                      padding: '16px', 
                      borderRadius: '6px',
                      fontSize: '12px',
                      lineHeight: '1.4',
                      overflow: 'auto'
                    }}>
                      {JSON.stringify(selectedAgent.system_info, null, 2)}
                    </pre>
                  ) : (
                    <div style={{ textAlign: 'center', padding: '40px' }}>
                      <DesktopOutlined style={{ fontSize: '32px', color: '#d9d9d9' }} />
                      <Paragraph type="secondary" style={{ marginTop: '16px' }}>
                        No system information available for this agent.
                      </Paragraph>
                    </div>
                  )}
                </div>
              </TabPane>
            </Tabs>
          )}
        </Modal>

        {/* Version Update Modal */}
        <Modal
          title={<Title level={4}><SaveOutlined /> Update Agent Version for {selectedVersionPlatform?.toUpperCase()}</Title>}
          visible={versionUpdateModal}
          onCancel={() => setVersionUpdateModal(false)}
          footer={null}
        >
          <Form form={versionForm} layout="vertical" onFinish={updateAgentVersion}>
            <Form.Item
              name="version"
              label="New Version"
              rules={[{ required: true, message: 'Please enter the new version!' }]}
            >
              <Input placeholder="e.g., 2.1.0" />
            </Form.Item>
            <Form.Item
              name="changelog"
              label="Changelog (one item per line)"
            >
              <TextArea rows={4} placeholder="e.g.,&#10;- Fixed critical bug&#10;- Added new feature" />
            </Form.Item>
            <Form.Item>
              <Button type="primary" htmlType="submit" icon={<SaveOutlined />}>
                Update Version
              </Button>
            </Form.Item>
          </Form>
        </Modal>

        {/* Script View Modal */}
        <Modal
          title={
            <Space>
              <CodeOutlined /> 
              <span>Agent Script Editor - {currentEditingPlatform?.toUpperCase()}</span>
              {scriptHasChanges && <Tag color="orange">Modified</Tag>}
            </Space>
          }
          visible={scriptViewModal}
          onCancel={() => {
            if (scriptHasChanges) {
              Modal.confirm({
                title: 'Unsaved Changes',
                content: 'You have unsaved changes. Are you sure you want to close without saving?',
                onOk: () => {
                  setScriptViewModal(false);
                  setScriptHasChanges(false);
                }
              });
            } else {
              setScriptViewModal(false);
            }
          }}
          width="90%"
          footer={[
            <Button 
              key="reset" 
              onClick={() => {
                console.log('🔄 Reset clicked, scriptHasChanges:', scriptHasChanges, 'originalScript length:', originalScript?.length, 'selectedScript length:', selectedScript?.length);
                resetScriptChanges();
              }}
              disabled={!scriptHasChanges}
              style={{ 
                backgroundColor: scriptHasChanges ? '#52c41a' : undefined,
                borderColor: scriptHasChanges ? '#52c41a' : undefined,
                color: scriptHasChanges ? 'white' : undefined
              }}
            >
              Reset Changes {scriptHasChanges ? '✅' : '❌'}
            </Button>,
            <Button 
              key="save" 
              type="primary" 
              onClick={() => {
                console.log('💾 Save clicked, scriptHasChanges:', scriptHasChanges, 'originalScript length:', originalScript?.length, 'selectedScript length:', selectedScript?.length);
                saveScriptChanges();
              }}
              loading={scriptSaving}
              disabled={!scriptHasChanges}
              icon={<SaveOutlined />}
              style={{ 
                backgroundColor: scriptHasChanges ? '#1890ff' : undefined,
                opacity: scriptHasChanges ? 1 : 0.5
              }}
            >
              Save & Update Version {scriptHasChanges ? '✅' : '❌'}
            </Button>,
            <Button key="close" onClick={() => setScriptViewModal(false)}>
              Close
            </Button>,
          ]}
        >
          <div style={{ marginBottom: '16px' }}>
            <Alert
              message="Script Editor"
              description={
                <Space direction="vertical" size="small">
                  <Text>
                    You can edit the {currentEditingPlatform} agent installation script below. 
                    Changes will be saved and a new version will be created automatically.
                  </Text>
                  <Text type="secondary" style={{ fontSize: '12px' }}>
                    • Make your changes in the editor below
                    • Click "Save & Update Version" to save changes and increment version
                    • New agents will automatically use the updated script
                    • Existing agents can be upgraded to use the new script
                  </Text>
                </Space>
              }
              type="info"
              showIcon
              style={{ marginBottom: '16px' }}
            />
          </div>
          
          <div style={{ border: '1px solid #d9d9d9', borderRadius: '6px', overflow: 'hidden' }}>
            <div style={{ 
              background: '#001529', 
              color: 'white', 
              padding: '8px 12px', 
              fontSize: '12px',
              borderBottom: '1px solid #434343',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center'
            }}>
              <span>Shell Script Editor - {currentEditingPlatform?.toUpperCase()}</span>
              <span style={{ fontSize: '11px', opacity: 0.8 }}>
                Lines: {selectedScript?.split('\n').length || 0} | 
                Chars: {selectedScript?.length || 0}
              </span>
            </div>
            <AceEditor
              mode="sh"
              theme="monokai"
              value={selectedScript}
              onChange={(newValue) => {
                console.log('🎨 AceEditor changed:', {
                  newLength: newValue?.length,
                  originalLength: originalScript?.length,
                  hasChanges: newValue !== originalScript,
                  platform: currentEditingPlatform
                });
                setSelectedScript(newValue);
                setScriptHasChanges(newValue !== originalScript);
              }}
              name={`script-editor-${currentEditingPlatform}`}
              editorProps={{ $blockScrolling: true }}
              width="100%"
              height="600px"
              fontSize={14}
              showPrintMargin={true}
              showGutter={true}
              highlightActiveLine={true}
              setOptions={{
                enableBasicAutocompletion: true,
                enableLiveAutocompletion: true,
                enableSnippets: true,
                showLineNumbers: true,
                tabSize: 2,
                useWorker: false
              }}
              style={{
                fontFamily: 'Monaco, Menlo, "Ubuntu Mono", monospace'
              }}
            />
          </div>
          
          {scriptHasChanges && (
            <div style={{ 
              marginTop: '16px', 
              padding: '12px', 
              background: '#fff7e6', 
              border: '1px solid #ffd591',
              borderRadius: '6px'
            }}>
              <Space>
                <WarningOutlined style={{ color: '#fa8c16' }} />
                <Text strong style={{ color: '#fa8c16' }}>
                  You have unsaved changes
                </Text>
                <Text type="secondary">
                  Click "Save & Update Version" to save your changes and create a new version.
                </Text>
              </Space>
            </div>
          )}
        </Modal>

        {/* Agent Activity Logs Modal */}
        <Modal
          title={
            <Space>
              <FileTextOutlined />
              <span>Activity Logs - {selectedAgent?.name}</span>
            </Space>
          }
          open={agentLogsModalVisible}
          onCancel={() => {
            setAgentLogsModalVisible(false);
            setAgentLogs([]);
          }}
          footer={[
            <Button key="close" onClick={() => setAgentLogsModalVisible(false)}>
              Close
            </Button>
          ]}
          width={800}
        >
          {agentLogsLoading ? (
            <div style={{ textAlign: 'center', padding: '40px' }}>
              <SyncOutlined spin style={{ fontSize: '32px', color: '#1890ff' }} />
              <div style={{ marginTop: '16px' }}>Loading activity logs...</div>
            </div>
          ) : agentLogs.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '40px' }}>
              <InfoCircleOutlined style={{ fontSize: '48px', color: '#d9d9d9' }} />
              <div style={{ marginTop: '16px', color: '#999' }}>
                No activity logs found for this agent
              </div>
            </div>
          ) : (
            <div style={{ maxHeight: '500px', overflowY: 'auto' }}>
              <Timeline>
                {agentLogs.map((log) => {
                  const actionIcons = {
                    'config_applied': <CheckCircleOutlined style={{ color: '#52c41a' }} />,
                    'upgrade': <ArrowUpOutlined style={{ color: '#1890ff' }} />,
                    'ssl_deployed': <SafetyOutlined style={{ color: '#722ed1' }} />,
                    'registered': <RocketOutlined style={{ color: '#13c2c2' }} />,
                    'haproxy_reload': <ReloadOutlined style={{ color: '#faad14' }} />
                  };

                  const actionLabels = {
                    'config_applied': 'Config Applied',
                    'upgrade': 'Agent Upgraded',
                    'ssl_deployed': 'SSL Certificate Deployed',
                    'registered': 'Agent Registered',
                    'haproxy_reload': 'HAProxy Reloaded'
                  };

                  const icon = actionIcons[log.action_type] || <InfoCircleOutlined />;
                  const label = actionLabels[log.action_type] || log.action_type;
                  const timestamp = new Date(log.timestamp);
                  const localTime = timestamp.toLocaleString(undefined, {
                    year: 'numeric',
                    month: 'short',
                    day: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit'
                  });

                  return (
                    <Timeline.Item key={log.id} dot={icon}>
                      <div>
                        <Text strong>{label}</Text>
                        <br />
                        <Text type="secondary" style={{ fontSize: '12px' }}>
                          {localTime}
                        </Text>
                        {log.action_details && Object.keys(log.action_details).length > 0 && (
                          <div style={{ marginTop: '8px' }}>
                            {log.action_details.version && (
                              <Tag color="blue">Version: {log.action_details.version}</Tag>
                            )}
                            {log.action_details.status && (
                              <Tag color={log.action_details.status === 'completed' ? 'green' : 'red'}>
                                {log.action_details.status}
                              </Tag>
                            )}
                            {log.action_details.domain && (
                              <Tag color="purple">Domain: {log.action_details.domain}</Tag>
                            )}
                          </div>
                        )}
                      </div>
                    </Timeline.Item>
                  );
                })}
              </Timeline>
            </div>
          )}
        </Modal>

        {/* Custom Styles */}
        <style jsx>{`
          .agent-offline {
            background-color: #fff2f0 !important;
          }
          .agent-offline:hover {
            background-color: #ffebe6 !important;
          }
        `}</style>
      </div>
    </ErrorBoundary>
  );
};

export default AgentManagement; 