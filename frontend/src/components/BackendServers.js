import React, { useState, useEffect } from 'react';
import {
  Card, Table, Button, Space, Tag, Modal, Form, Input, InputNumber,
  Select, Row, Col, message, Popconfirm, Tooltip, Badge, Switch, 
  Tabs, Divider, Typography, List, Avatar, Alert, Spin
} from 'antd';
import { getAgentSyncColor, getConfigStatusColor, getEntityStatusColor } from '../utils/colors';
import EntitySyncStatus from './EntitySyncStatus';
import {
  PlusOutlined, EditOutlined, DeleteOutlined, ReloadOutlined,
  PlayCircleOutlined, PauseCircleOutlined, 
  CloudServerOutlined, SettingOutlined, UserOutlined, SearchOutlined,
  HistoryOutlined, ContainerOutlined
} from '@ant-design/icons';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { useCluster } from '../contexts/ClusterContext';
import { VersionHistory } from './VersionHistory';

// Error Boundary Component
class BackendErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Backend Servers Error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <Alert
          message="Backend Management Error"
          description="There was an error loading Backend Management. Please refresh the page."
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

const { Option } = Select;
const { TabPane } = Tabs;
const { Text, Title } = Typography;

const BackendServers = () => {
  const { selectedCluster } = useCluster();
  const navigate = useNavigate();
  const [backends, setBackends] = useState([]);
  const [frontends, setFrontends] = useState([]);
  const [sslCertificates, setSslCertificates] = useState([]);
  const [filteredBackends, setFilteredBackends] = useState([]);
  const [showPending, setShowPending] = useState(true);  // Default TRUE: users must see their changes
  const [showRejected, setShowRejected] = useState(true);  // Default TRUE: users must see rejected items

  // Persist toggle states across navigation
  useEffect(() => {
    const sp = localStorage.getItem('backend:showPending');
    const sr = localStorage.getItem('backend:showRejected');
    if (sp !== null) setShowPending(sp === 'true');
    if (sr !== null) setShowRejected(sr === 'true');
  }, []);
  const onToggleShowPending = (checked) => {
    setShowPending(checked);
    localStorage.setItem('backend:showPending', String(checked));
  };
  const onToggleShowRejected = (checked) => {
    setShowRejected(checked);
    localStorage.setItem('backend:showRejected', String(checked));
  };
  const [searchText, setSearchText] = useState('');
  const [loading, setLoading] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);
  const [backendModalVisible, setBackendModalVisible] = useState(false);
  const [serverModalVisible, setServerModalVisible] = useState(false);
  const [editingBackend, setEditingBackend] = useState(null);
  const [editingServer, setEditingServer] = useState(null);
  const [selectedBackend, setSelectedBackend] = useState(null);
  const [activeTab, setActiveTab] = useState('1');
  const [submittingBackend, setSubmittingBackend] = useState(false);
  const [submittingServer, setSubmittingServer] = useState(false);
  const [applyLoading, setApplyLoading] = useState(false);
  const [pendingChanges, setPendingChanges] = useState(false);
  const [versionModalVisible, setVersionModalVisible] = useState(false);
  const [selectedEntityForVersion, setSelectedEntityForVersion] = useState(null);
  const [backendForm] = Form.useForm();
  const [serverForm] = Form.useForm();

  // Status filter function - defined before fetchBackends to avoid hoisting issues
  const applyStatusFilters = (items) => {
    return (items || []).filter(item => {
      const isPending = !!item.has_pending_config;
      const status = item.config_status || (isPending ? 'PENDING' : 'APPLIED');
      if (!showPending && isPending) return false;
      if (!showRejected && status === 'REJECTED') return false;
      return true;
    });
  };

  useEffect(() => {
    // CRITICAL FIX: Clear state when cluster changes to prevent showing other cluster's data
    // Race condition: Old cluster data remains visible while new cluster data is fetching
    if (selectedCluster) {
      setBackends([]);
      setFilteredBackends([]);
      setFrontends([]);
      setSslCertificates([]);
    }
    
    fetchBackends();
    fetchFrontends();
    fetchSSLCertificates();
    checkPendingChanges();
  }, [selectedCluster]);

  const fetchBackends = async () => {
    // CRITICAL FIX: Don't fetch if no cluster selected to prevent race condition
    // Race condition: First fetch (cluster=undefined) returns all backends and overwrites filtered results
    if (!selectedCluster) {
      console.log('FETCH BACKENDS: No cluster selected, skipping fetch');
      setBackends([]);
      setFilteredBackends([]);
      return;
    }
    
    setLoading(true);
    try {
      const params = { cluster_id: selectedCluster.id };
      
      // CRITICAL DEBUG: Log what we're sending to API
      console.log('FETCH BACKENDS DEBUG:', {
        selectedCluster: selectedCluster?.name,
        cluster_id: selectedCluster?.id,
        params: params,
        url: '/api/backends'
      });
      
      // CRITICAL FIX: Add cache busting to prevent stale data from appearing
      // Browser/axios may cache GET requests, causing deleted backends to reappear
      const response = await axios.get('/api/backends', { 
        params,
        headers: {
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache',
          'Expires': '0'
        }
      });
      const fetchedBackends = response.data.backends || [];
      
      // CRITICAL DEBUG: Log what API returned
      console.log('FETCH BACKENDS RESPONSE:', {
        total_received: fetchedBackends.length,
        backend_ids: fetchedBackends.map(b => b.id),
        backend_cluster_ids: fetchedBackends.map(b => ({id: b.id, name: b.name, cluster_id: b.cluster_id}))
      });
      
      setBackends(fetchedBackends);
      // CRITICAL FIX: Apply status filters after fetching to maintain filter state
      // This prevents backends from disappearing when updated (e.g., APPLIED → PENDING)
      setFilteredBackends(applyStatusFilters(fetchedBackends));
    } catch (error) {
      message.error('Failed to fetch backends: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  const fetchFrontends = async () => {
    try {
      const params = selectedCluster ? { cluster_id: selectedCluster.id } : {};
      const response = await axios.get('/api/frontends', { 
        params,
        headers: {
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache'
        }
      });
      setFrontends(response.data.frontends || []);
    } catch (error) {
      console.error('Failed to fetch frontends:', error);
      // Don't show error message for frontends as it's just for dependency checking
    }
  };

  const fetchSSLCertificates = async () => {
    if (!selectedCluster) return;
    
    try {
      const token = localStorage.getItem('token');
      // CRITICAL FIX: Use same endpoint as Frontend (/api/ssl/certificates not /api/ssl-certificates)
      const response = await axios.get(`/api/ssl/certificates?cluster_id=${selectedCluster.id}`, {
        headers: { 
          'Authorization': `Bearer ${token}`,
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache'
        }
      });
      
      // CRITICAL FIX: API returns array directly, not wrapped in {certificates: [...]}
      const certificates = Array.isArray(response.data) ? response.data : (response.data.certificates || []);
      
      console.log('🔍 SSL FETCH DEBUG (BackendServers):', {
        cluster_id: selectedCluster.id,
        certificates_count: certificates.length,
        certificates: certificates.map(c => ({ id: c.id, name: c.name, ssl_type: c.ssl_type }))
      });
      
      setSslCertificates(certificates);
    } catch (error) {
      console.error('Failed to fetch SSL certificates:', error);
      setSslCertificates([]);
      // Don't show error message as SSL is optional
    }
  };

  // Search filter function
  const handleSearch = (value) => {
    setSearchText(value);
    if (!value) {
      setFilteredBackends(applyStatusFilters(backends));
    } else {
      const filtered = backends.filter(backend =>
        backend.name.toLowerCase().includes(value.toLowerCase()) ||
        backend.balance_method.toLowerCase().includes(value.toLowerCase()) ||
        backend.mode.toLowerCase().includes(value.toLowerCase())
      );
      setFilteredBackends(applyStatusFilters(filtered));
    }
  };

  // Update filtered data when backends change
  useEffect(() => {
    if (searchText) {
      handleSearch(searchText);
    } else {
      setFilteredBackends(applyStatusFilters(backends));
    }
  }, [backends, searchText, showPending, showRejected]);

  // Check for pending configuration changes
  const checkPendingChanges = async () => {
    if (!selectedCluster) return;
    
    try {
      const response = await axios.get(`/api/clusters/${selectedCluster.id}/config-versions`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      
      const versions = response.data.versions || [];
      const hasPending = versions.some(version => version.status === 'PENDING');
      setPendingChanges(hasPending);
    } catch (error) {
      console.error('Failed to check pending changes:', error);
    }
  };

  const fetchEntityAgentSync = async (entityType, entityId) => {
    if (!selectedCluster) return null;
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`/api/clusters/${selectedCluster.id}/entity-sync/${entityType}/${entityId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      return response.data;
    } catch (error) {
      console.error(`Failed to fetch entity sync for ${entityType}/${entityId}:`, error);
      return null;
    }
  };

  // Validate that all backends have at least one server
  const validateBackendsHaveServers = () => {
    const backendsWithoutServers = backends.filter(backend => 
      !backend.servers || backend.servers.length === 0
    );
    
    if (backendsWithoutServers.length > 0) {
      const backendNames = backendsWithoutServers.map(b => b.name).join(', ');
      
      Modal.warning({
        title: '⚠️ Backend Configuration Error',
        content: (
          <div>
            <p><strong>Cannot apply configuration!</strong></p>
            <p>The following backend(s) have no servers defined:</p>
            <ul style={{ marginTop: 10, marginBottom: 10 }}>
              {backendsWithoutServers.map(backend => (
                <li key={backend.id} style={{ color: '#ff4d4f' }}>
                  <strong>{backend.name}</strong>
                </li>
              ))}
            </ul>
            <p>❌ <strong>HAProxy validation will fail</strong> if backends have no servers.</p>
            <p>✅ Please add at least one server to each backend before applying changes.</p>
            <br />
            <p><strong>How to fix:</strong></p>
            <ol>
              <li>Click on the backend name to expand server list</li>
              <li>Click "Add Server" button</li>
              <li>Enter server details (name, IP, port)</li>
              <li>Save the server</li>
              <li>Then try "Apply Changes" again</li>
            </ol>
          </div>
        ),
        width: 600,
        okText: 'I Understand',
        okType: 'primary'
      });
      
      return false;
    }
    
    return true;
  };

  // Apply pending configuration changes
  const handleApplyChanges = async () => {
    if (!selectedCluster) return;
    
    // Validate that all backends have servers before applying
    if (!validateBackendsHaveServers()) {
      return; // Stop if validation fails
    }
    
    setApplyLoading(true);
    try {
      const token = localStorage.getItem('token');
      if (!token || token === 'null' || token.trim() === '') {
        message.error('Authentication required. Please login again.');
        return;
      }
      
      const response = await axios.post(
        `/api/clusters/${selectedCluster.id}/apply-changes`,
        {},
        {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        }
      );
      
      message.success(response.data.message);
      
      // Refresh pending changes status from server
      await checkPendingChanges();
      
      // Also refresh the backends list to update Config Status column
      fetchBackends();
      
      // Show sync results if available
      if (response.data.sync_results && response.data.sync_results.length > 0) {
        const agentResults = response.data.sync_results.filter(r => r.success);
        if (agentResults.length > 0) {
          message.info(`Configuration applied to ${agentResults.length} agent(s). HAProxy reloaded.`);
        }
      }
      
    } catch (error) {
      console.error('Apply changes failed:', error);
      if (error.response?.status === 401) {
        message.error('Authentication failed. Please login again.');
      } else if (error.response?.data?.error === 'COMPREHENSIVE_VALIDATION_FAILED') {
        // Handle comprehensive validation errors from API
        const validationErrors = error.response.data.validation_errors || [];
        
        Modal.error({
          title: '🚫 Configuration Validation Failed',
          content: (
            <div>
              <p><strong>Multiple configuration issues detected!</strong></p>
              <p style={{ color: '#ff4d4f', marginBottom: 16 }}>{error.response.data.message}</p>
              
              {validationErrors.map((error, index) => (
                <div key={index} style={{ 
                  marginBottom: 16, 
                  padding: 12, 
                  border: '1px solid #ffccc7', 
                  borderRadius: 6,
                  backgroundColor: '#fff2f0'
                }}>
                  <h4 style={{ color: '#cf1322', margin: '0 0 8px 0' }}>
                    {error.type === 'BACKENDS_WITHOUT_SERVERS' && '🔸 Backends Missing Servers'}
                    {error.type === 'UNUSED_BACKENDS' && '🔸 Unused Backends'}
                    {error.type === 'FRONTENDS_WITH_MISSING_BACKENDS' && '🔸 Frontend → Backend Mismatch'}
                    {error.type === 'NO_FRONTENDS' && '🔸 No Frontends Defined'}
                  </h4>
                  <p style={{ margin: '0 0 8px 0' }}>{error.message}</p>
                  <p style={{ margin: '0 0 8px 0', fontWeight: 'bold' }}>Items:</p>
                  <ul style={{ margin: '0 0 8px 20px' }}>
                    {error.items.map((item, idx) => (
                      <li key={idx} style={{ color: '#d4380d' }}>{item}</li>
                    ))}
                  </ul>
                  <p style={{ margin: 0, color: '#389e0d' }}>
                    <strong>💡 Solution:</strong> {error.solution}
                  </p>
                </div>
              ))}
              
              <div style={{ 
                marginTop: 16, 
                padding: 12, 
                backgroundColor: '#f6ffed', 
                border: '1px solid #b7eb8f',
                borderRadius: 6 
              }}>
                <p style={{ margin: 0, color: '#389e0d' }}>
                  <strong>🎯 Quick Actions:</strong>
                </p>
                <div style={{ marginTop: 8 }}>
                  <Button 
                    type="primary" 
                    size="small"
                    onClick={() => window.location.href = '/frontend-management'}
                    style={{ marginRight: 8 }}
                  >
                    Manage Frontends
                  </Button>
                  <Button 
                    type="default" 
                    size="small"
                    onClick={() => window.location.reload()}
                  >
                    Refresh Page
                  </Button>
                </div>
              </div>
            </div>
          ),
          width: 800,
          okText: 'I Understand',
          okType: 'primary'
        });
      } else if (error.response?.data?.error === 'BACKEND_VALIDATION_FAILED') {
        // Legacy: Handle old backend validation error from API  
        const backendNames = error.response.data.details?.backends_without_servers || [];
        
        Modal.error({
          title: '🚫 Configuration Apply Failed',
          content: (
            <div>
              <p><strong>Backend validation failed on server!</strong></p>
              <p style={{ color: '#ff4d4f' }}>{error.response.data.message}</p>
              <br />
              <p><strong>Backends without servers:</strong></p>
              <ul style={{ marginTop: 10, marginBottom: 10 }}>
                {backendNames.map(name => (
                  <li key={name} style={{ color: '#ff4d4f' }}>
                    <strong>{name}</strong>
                  </li>
                ))}
              </ul>
              <p>✅ <strong>Solution:</strong> {error.response.data.details?.solution}</p>
            </div>
          ),
          width: 600,
          okText: 'Fix Backends',
          okType: 'primary'
        });
      } else {
        message.error(`Failed to apply changes: ${error.response?.data?.message || error.response?.data?.detail || error.message}`);
      }
    } finally {
      setApplyLoading(false);
    }
  };

  // Backend Operations
  const handleAddBackend = () => {
    setEditingBackend(null);
    backendForm.resetFields();
    backendForm.setFieldsValue({
      balance_method: 'roundrobin',
      mode: 'http',
      health_check_interval: 2000,
      timeout_connect: 10000,
      timeout_server: 60000,
      timeout_queue: 60000
    });
    setBackendModalVisible(true);
  };

  const handleEditBackend = (backend) => {
    setEditingBackend(backend);
    backendForm.setFieldsValue({
      ...backend,
      health_check_interval: backend.health_check_interval || 2000,
      timeout_connect: backend.timeout_connect || 10000,
      timeout_server: backend.timeout_server || 60000,
      timeout_queue: backend.timeout_queue || 60000
    });
    setBackendModalVisible(true);
  };

  const handleDeleteBackend = async (backendId) => {
    if (!selectedCluster) {
      message.warning('Please select a HAProxy cluster first');
      return;
    }

    // Find the backend to get details for confirmation
    const backend = backends.find(b => b.id === backendId);
    if (!backend) {
      message.error('Backend not found');
      return;
    }

    // Check dependencies and show confirmation dialog
    const serverCount = backend.servers ? backend.servers.length : 0;
    const frontendCount = backends.filter(b => 
      frontends.some(f => f.default_backend === backend.name)
    ).length;

    let confirmMessage = `Are you sure you want to delete backend "${backend.name}"?`;
    let warningDetails = [];
    
    if (serverCount > 0) {
      warningDetails.push(`${serverCount} server(s) will also be deleted`);
    }
    
    // Check if any frontend uses this backend
    const usingFrontends = frontends.filter(f => f.default_backend === backend.name);
    if (usingFrontends.length > 0) {
      const frontendNames = usingFrontends.map(f => f.name).join(', ');
      warningDetails.push(`${usingFrontends.length} frontend(s) (${frontendNames}) will be updated (default backend cleared)`);
    }

    if (warningDetails.length > 0) {
      confirmMessage += '\n\nThis action will also:';
      warningDetails.forEach(detail => {
        confirmMessage += `\n• ${detail}`;
      });
    }

    // Show confirmation modal
    Modal.confirm({
      title: 'Delete Backend',
      content: (
        <div>
          <p>{confirmMessage.split('\n')[0]}</p>
          {warningDetails.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <p><strong>This action will also:</strong></p>
              <ul style={{ marginBottom: 0, paddingLeft: 20 }}>
                {warningDetails.map((detail, index) => (
                  <li key={index}>{detail}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      ),
      okText: 'Delete',
      okType: 'danger',
      cancelText: 'Cancel',
      onOk: async () => {
        try {
          const response = await axios.delete(`/api/backends/${backendId}`, {
            data: { cluster_id: selectedCluster.id }
          });
      
          // Show backend deletion success with details
          const backendMessage = response.data.message || 'Backend deleted successfully';
          
          if (response.data.sync_results) {
            const syncResults = response.data.sync_results;
            const successCount = syncResults.filter(r => r.success).length;
            const totalNodes = syncResults.length;
            
            if (successCount === totalNodes) {
              message.success(
                <div>
                  <div><strong>{backendMessage}</strong></div>
                  <div style={{ marginTop: 4, fontSize: '12px' }}>
                    ✅ Configuration updated on {successCount} cluster node(s)
                    <br />📅 Completed: {new Date().toLocaleString()}
                  </div>
                </div>,
                8
              );
            } else {
              message.warning(
                <div>
                  <div><strong>{backendMessage}</strong></div>
                  <div style={{ marginTop: 4, fontSize: '12px' }}>
                    ⚠️ {successCount}/{totalNodes} cluster node(s) updated successfully
                    <br />📅 Completed: {new Date().toLocaleString()}
                  </div>
                </div>,
                10
              );
            }
          } else {
            message.success(backendMessage, 6);
          }
          
          fetchBackends();
          checkPendingChanges();
        } catch (error) {
          const errorMsg = error.response?.data?.detail || error.message;
          message.error(
            <div>
              <div><strong>Failed to delete backend</strong></div>
              <div style={{ marginTop: 4, fontSize: '12px', color: '#ff4d4f' }}>
                {errorMsg}
              </div>
            </div>,
            8
          );
        }
      }
    });
  };

  // Version history modal handlers
  const handleShowVersionHistory = (record) => {
    setSelectedEntityForVersion({
      entityType: 'backend',
      entityId: record.id
    });
    setVersionModalVisible(true);
  };

  const handleVersionModalCancel = () => {
    setVersionModalVisible(false);
    setSelectedEntityForVersion(null);
  };

  const handleRestoreSuccess = (restoreData) => {
    // Refresh pending changes status after successful restore
    checkPendingChanges();
    // Refresh backends list to show updated data
    fetchBackends();
    message.info(
      <div>
        <div><strong>Configuration restored as PENDING</strong></div>
        <div style={{ fontSize: '12px', marginTop: 4 }}>
          Use "Apply Changes" button to activate the restored configuration
        </div>
      </div>,
      4
    );
  };

  const handleBackendSubmit = async (values) => {
    if (!selectedCluster) {
      message.warning('Please select a HAProxy cluster first');
      return;
    }

    setSubmittingBackend(true);
    try {
      const requestData = {
        ...values,
        cluster_id: selectedCluster.id
      };

      let response;
      if (editingBackend) {
        response = await axios.put(`/api/backends/${editingBackend.id}`, requestData);
        
        // Show agent sync results
        if (response.data.sync_results) {
          const syncResults = response.data.sync_results;
          const agentCount = syncResults.length;
          
          message.success(
            <div>
              <div><strong>Backend updated successfully!</strong></div>
              <div style={{ marginTop: 4, fontSize: '12px' }}>
                📝 Changes created as PENDING
                <br />🔄 Click "Apply Changes" to activate configuration
                <br />📅 Updated: {new Date().toLocaleString()}
              </div>
            </div>,
            6
          );
        } else {
          message.success('Backend updated successfully');
        }
      } else {
        response = await axios.post('/api/backends', requestData);
        
        // Show cluster sync results
        if (response.data.sync_results) {
          const syncResults = response.data.sync_results;
          const successCount = syncResults.filter(r => r.success).length;
          const totalNodes = syncResults.length;
          
          message.success(
            <div>
              <div><strong>Backend created successfully!</strong></div>
              <div style={{ marginTop: 4, fontSize: '12px' }}>
                📝 Changes created as PENDING
                <br />🔄 Click "Apply Changes" to activate configuration
                <br />📅 Created: {new Date().toLocaleString()}
              </div>
            </div>,
            6
          );
        } else {
          message.success('Backend created successfully');
        }
      }
      
      setBackendModalVisible(false);
          fetchBackends();
    checkPendingChanges();
    } catch (error) {
      const errorMsg = error.response?.data?.detail || error.message;
      message.error(
        <div>
          <div><strong>Failed to save backend</strong></div>
          <div style={{ marginTop: 4, fontSize: '12px', color: '#ff4d4f' }}>
            {errorMsg}
          </div>
        </div>,
        8
      );
    } finally {
      setSubmittingBackend(false);
    }
  };

  // Server Operations
  const handleAddServer = (backend) => {
    setSelectedBackend(backend);
    setEditingServer(null);
    serverForm.resetFields();
    serverForm.setFieldsValue({
      weight: 100,
      check_enabled: true,
      backup_server: false,
      ssl_enabled: false
    });
    setServerModalVisible(true);
  };

  const handleEditServer = (server, backend) => {
    setSelectedBackend(backend);
    setEditingServer(server);
    
    // Parse address to get IP and port
    const [address, port] = server.address.split(':');
    
    serverForm.setFieldsValue({
      server_name: server.name,
      server_address: address,
      server_port: parseInt(port),
      weight: server.weight,
      check_enabled: server.check_enabled,
      check_port: server.check_port || null,
      backup_server: server.backup_server,
      ssl_enabled: server.ssl_enabled || false,
      ssl_verify: server.ssl_verify || null,
      ssl_certificate_id: server.ssl_certificate_id || null,
      cookie_value: server.cookie_value || null,
      inter: server.inter || null,
      fall: server.fall || null,
      rise: server.rise || null
    });
    setServerModalVisible(true);
  };

  const handleDeleteServer = async (serverId) => {
    if (!selectedCluster) {
      message.warning('Please select a HAProxy cluster first');
      return;
    }

    try {
      const response = await axios.delete(`/api/servers/${serverId}`, {
        data: { cluster_id: selectedCluster.id }
      });
      
      // Show cluster sync results
      if (response.data.sync_results) {
        const syncResults = response.data.sync_results;
        const successCount = syncResults.filter(r => r.success).length;
        const totalNodes = syncResults.length;
        
        if (successCount === totalNodes) {
          message.success(
            <div>
              <div><strong>Server deleted successfully!</strong></div>
              <div style={{ marginTop: 4, fontSize: '12px' }}>
                ✅ Configuration removed from {successCount} cluster node(s)
                <br />📅 Deleted: {new Date().toLocaleString()}
              </div>
            </div>,
            6
          );
        } else {
          message.warning(
            <div>
              <div><strong>Server deleted with warnings</strong></div>
              <div style={{ marginTop: 4, fontSize: '12px' }}>
                ✅ {successCount}/{totalNodes} nodes updated successfully
                <br />⚠️ Some nodes may need manual cleanup
              </div>
            </div>,
            8
          );
        }
      } else {
        message.success('Server deleted successfully');
      }
      
      fetchBackends();
    } catch (error) {
      const errorMsg = error.response?.data?.detail || error.message;
      message.error(
        <div>
          <div><strong>Failed to delete server</strong></div>
          <div style={{ marginTop: 4, fontSize: '12px', color: '#ff4d4f' }}>
            {errorMsg}
          </div>
        </div>,
        8
      );
    }
  };

  const handleServerSubmit = async (values) => {
    if (!selectedCluster) {
      message.warning('Please select a HAProxy cluster first');
      return;
    }

    setSubmittingServer(true);
    try {
      // Don't include cluster_id - backend endpoint gets it from the backend record
      const requestData = {
        ...values
      };

      let response;
      if (editingServer) {
        response = await axios.put(`/api/backends/servers/${editingServer.id}`, requestData);
        
        // Show cluster sync results
        if (response.data.sync_results) {
          const syncResults = response.data.sync_results;
          const successCount = syncResults.filter(r => r.success).length;
          const totalNodes = syncResults.length;
          
          if (successCount === totalNodes) {
            message.success(
              <div>
                <div><strong>Server updated successfully!</strong></div>
                <div style={{ marginTop: 4, fontSize: '12px' }}>
                  ✅ Configuration synchronized to {successCount} cluster node(s)
                  <br />📅 Last update: {new Date().toLocaleString()}
                </div>
              </div>,
              6
            );
          } else {
            message.warning(
              <div>
                <div><strong>Server updated with warnings</strong></div>
                <div style={{ marginTop: 4, fontSize: '12px' }}>
                  ✅ {successCount}/{totalNodes} nodes updated successfully
                  <br />⚠️ Some nodes may need manual intervention
                </div>
              </div>,
              8
            );
          }
        } else {
          message.success('Server updated successfully');
        }
      } else {
        response = await axios.post(`/api/backends/${selectedBackend.id}/servers`, requestData);
        
        // Show cluster sync results
        if (response.data.sync_results) {
          const syncResults = response.data.sync_results;
          const pendingResults = syncResults.filter(r => r.status === 'PENDING');
          
          if (pendingResults.length > 0) {
            message.success(
              <div>
                <div><strong>Server added successfully!</strong></div>
                <div style={{ marginTop: 4, fontSize: '12px' }}>
                  📝 Changes created as PENDING
                  <br />🔄 Click "Apply Changes" to activate configuration
                  <br />📅 Added: {new Date().toLocaleString()}
                </div>
              </div>,
              6
            );
          } else {
            const successCount = syncResults.filter(r => r.success).length;
            const totalNodes = syncResults.length;
            
            if (successCount === totalNodes) {
              message.success(
                <div>
                  <div><strong>Server added successfully!</strong></div>
                  <div style={{ marginTop: 4, fontSize: '12px' }}>
                    ✅ Configuration deployed to {successCount} cluster node(s)
                    <br />📅 Added: {new Date().toLocaleString()}
                  </div>
                </div>,
                6
              );
            } else {
              message.warning(
                <div>
                  <div><strong>Server added with warnings</strong></div>
                  <div style={{ marginTop: 4, fontSize: '12px' }}>
                    ✅ {successCount}/{totalNodes} nodes configured successfully
                    <br />⚠️ Some nodes may need manual intervention
                  </div>
                </div>,
                8
              );
            }
          }
        } else {
          message.success('Server added successfully');
        }
      }
      
      setServerModalVisible(false);
      fetchBackends();
      checkPendingChanges();
    } catch (error) {
      const errorMsg = error.response?.data?.detail || error.message;
      message.error(
        <div>
          <div><strong>Failed to save server</strong></div>
          <div style={{ marginTop: 4, fontSize: '12px', color: '#ff4d4f' }}>
            {errorMsg}
          </div>
        </div>,
        8
      );
    } finally {
      setSubmittingServer(false);
    }
  };

  const handleToggleServer = async (serverId, isActive) => {
    console.log('🔄 FRONTEND DEBUG: handleToggleServer called', { serverId, isActive });
    try {
      console.log('🔄 FRONTEND DEBUG: Making API call to:', `/api/backends/servers/${serverId}/toggle`);
      const response = await axios.put(`/api/backends/servers/${serverId}/toggle`);
      console.log('🔄 FRONTEND DEBUG: API response:', response.data);
      message.success(response.data.message || `Server ${isActive ? 'disabled' : 'enabled'} successfully`);
      fetchBackends();
      checkPendingChanges(); // Check for pending changes after toggle
    } catch (error) {
      console.error('🔄 FRONTEND DEBUG: API error:', error);
      const errorMsg = error.response?.data?.detail || error.message;
      message.error('Failed to toggle server: ' + errorMsg);
    }
  };

  const backendColumns = [
    {
      title: 'Backend Name',
      dataIndex: 'name',
      key: 'name',
      render: (text, record) => (
        <Space>
          <CloudServerOutlined style={{ color: '#1890ff' }} />
          <strong>{text}</strong>
          {!record.is_active && <Tag color="red">Inactive</Tag>}
        </Space>
      ),
    },
    {
      title: 'Sync Status',
      key: 'agent_sync',
      render: (_, record) => (
        <EntitySyncStatus
          key={`${record.id}-${refreshKey}`}
          entityType="backends"
          entityId={record.id}
          entityUpdatedAt={record.updated_at}
          lastConfigStatus={record.last_config_status}
          clusterId={selectedCluster?.id}
          selectedCluster={selectedCluster}
        />
      ),
    },
    {
      title: 'Balance Method',
      dataIndex: 'balance_method',
      key: 'balance_method',
      render: (method) => (
        <Tag color="blue">{method}</Tag>
      ),
    },
    {
      title: 'Mode',
      dataIndex: 'mode',
      key: 'mode',
      render: (mode) => (
        <Tag color={mode === 'http' ? 'green' : 'orange'}>{mode.toUpperCase()}</Tag>
      ),
    },
    {
      title: 'Servers',
      dataIndex: 'servers',
      key: 'servers',
      render: (servers) => {
        const activeServers = servers.filter(s => s.is_active).length;
        const totalServers = servers.length;
        return (
          <Space>
            <Tag color="green">{activeServers}</Tag>
            <span>/{totalServers}</span>
            <Text type="secondary">active</Text>
          </Space>
        );
      },
    },
    {
      title: 'Health Check',
      dataIndex: 'health_check_uri',
      key: 'health_check',
      render: (uri) => uri ? (
        <Tag color="cyan">{uri}</Tag>
      ) : <Text type="secondary">None</Text>,
    },
    {
      title: 'Created',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (date) => date ? new Date(date).toLocaleString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      }) : '-',
    },
    {
      title: 'Last Update',
      dataIndex: 'updated_at',
      key: 'updated_at',
      render: (date) => date ? new Date(date).toLocaleString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      }) : '-',
    },
    {
      title: 'Status',
      dataIndex: 'is_active',
      key: 'status',
      render: (isActive) => (
        <Badge 
          status={isActive ? 'success' : 'error'} 
          text={isActive ? 'Active' : 'Inactive'} 
        />
      ),
    },
    {
      title: 'Config Status',
      key: 'config_status',
      render: (_, record) => {
        const status = record.config_status || (record.has_pending_config ? 'PENDING' : 'APPLIED');
        const color = getConfigStatusColor(status);
        return <Tag color={color}>{status}</Tag>;
      },
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Space size="small">
          {(record.has_pending_config || false) && (
            <Tooltip title="Apply pending configuration changes">
              <Button
                type="primary"
                size="small"
                icon={<PlayCircleOutlined />}
                onClick={() => window.location.href = '/apply-management'}
                style={{
                  backgroundColor: '#1890ff',
                  borderColor: '#1890ff',
                }}
              >
                Apply
              </Button>
            </Tooltip>
          )}

          <Tooltip title="Add Server">
            <Button
              type="primary"
              size="small"
              icon={<PlusOutlined />}
              onClick={() => handleAddServer(record)}
            />
          </Tooltip>
          <Tooltip title="Edit Backend">
            <Button
              size="small"
              icon={<EditOutlined />}
              onClick={() => handleEditBackend(record)}
            />
          </Tooltip>
          <Popconfirm
            title="Are you sure you want to delete this backend and all its servers?"
            onConfirm={() => handleDeleteBackend(record.id)}
            okText="Yes"
            cancelText="No"
          >
            <Tooltip title="Delete Backend">
              <Button
                danger
                size="small"
                icon={<DeleteOutlined />}
              />
            </Tooltip>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  const serverColumns = [
    {
      title: 'Server',
      dataIndex: 'name',
      key: 'name',
      render: (text, record) => (
        <Space>
          <Avatar 
            size="small" 
            icon={<ContainerOutlined />} 
            style={{ backgroundColor: record.is_active ? '#52c41a' : '#ff4d4f' }}
          />
          <strong>{text}</strong>
          {record.backup_server && <Tag color="orange">Backup</Tag>}
        </Space>
      ),
    },
    {
      title: 'Backend',
      dataIndex: 'backend_name',
      key: 'backend_name',
      render: (backend_name) => (
        <Tag color="blue">{backend_name}</Tag>
      ),
    },
    {
      title: 'Address',
      dataIndex: 'address',
      key: 'address',
      render: (address) => <Text code>{address}</Text>,
    },
    {
      title: 'Weight',
      dataIndex: 'weight',
      key: 'weight',
      render: (weight) => (
        <Tag color="purple">{weight}</Tag>
      ),
    },
    {
      title: 'Health Check',
      dataIndex: 'check_enabled',
      key: 'check_enabled',
      render: (enabled) => (
        <Badge 
          status={enabled ? 'success' : 'default'} 
          text={enabled ? 'Enabled' : 'Disabled'} 
        />
      ),
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      render: (status, record) => {
        // Map HAProxy server status to Badge configuration
        const getStatusConfig = (status) => {
          // Handle status with age info like "DOWN (stale)" or "UP (fresh)"
          const cleanStatus = status ? status.split(' ')[0] : 'UNKNOWN';
          
          switch (cleanStatus) {
            case 'UP':
              return { status: 'success', text: status, color: '#52c41a' };
            case 'DOWN':
              return { status: 'error', text: status, color: '#ff4d4f' };
            case 'MAINT':
              return { status: 'warning', text: status, color: '#fadb14' };
            case 'DRAIN':
              return { status: 'processing', text: status, color: '#1890ff' };
            case 'NOLB':
              return { status: 'warning', text: status, color: '#fa8c16' };
            case 'AGENT_OFFLINE':
              return { status: 'default', text: 'Agent Offline', color: '#8c8c8c' };
            case 'TIMEOUT':
              return { status: 'processing', text: 'Timeout', color: '#722ed1' };
            case 'NETWORK_ERROR':
              return { status: 'error', text: 'Network Error', color: '#ff7875' };
            case 'NO_AGENT_ASSIGNED':
              return { status: 'warning', text: 'No Agent Assigned', color: '#faad14' };
            case 'UNKNOWN':
              return { status: 'default', text: status || 'Unknown', color: '#d9d9d9' };
            default:
              return { status: 'default', text: status || 'Unknown', color: '#d9d9d9' };
          }
        };
        
        const statusConfig = getStatusConfig(status);
        const cleanStatus = status ? status.split(' ')[0] : 'UNKNOWN';
        
        return (
          <Space>
            <Tag 
              color={cleanStatus === 'UP' ? 'green' : cleanStatus === 'DOWN' ? 'red' : 'orange'}
            >
              {statusConfig.text}
            </Tag>
            <Switch
              size="small"
              checked={record.is_active}
              onChange={() => handleToggleServer(record.id, record.is_active)}
              checkedChildren="ON"
              unCheckedChildren="OFF"
            />
          </Space>
        );
      },
    },
  ];

  const renderServerList = () => {
    const allServers = backends.flatMap(backend => 
      backend.servers.map(server => ({
        ...server,
        backend_name: backend.name,
        backend_id: backend.id
      }))
    );

    return (
      <Table
        columns={[
          ...serverColumns,
          {
            title: 'Backend',
            dataIndex: 'backend_name',
            key: 'backend_name',
            render: (name) => <Tag color="blue">{name}</Tag>,
          },
          {
            title: 'Actions',
            key: 'actions',
            render: (_, record) => (
              <Space size="small">
                <Tooltip title="Edit Server">
                  <Button
                    size="small"
                    icon={<EditOutlined />}
                    onClick={() => handleEditServer(record, { id: record.backend_id, name: record.backend_name })}
                  />
                </Tooltip>
                <Popconfirm
                  title="Are you sure you want to delete this server?"
                  onConfirm={() => handleDeleteServer(record.id)}
                  okText="Yes"
                  cancelText="No"
                >
                  <Tooltip title="Delete Server">
                    <Button
                      danger
                      size="small"
                      icon={<DeleteOutlined />}
                    />
                  </Tooltip>
                </Popconfirm>
              </Space>
            ),
          },
        ]}
        dataSource={allServers}
        rowKey="id"
        loading={loading}
        pagination={{
          showSizeChanger: true,
          showQuickJumper: true,
          showTotal: (total, range) =>
            `${range[0]}-${range[1]} of ${total} servers`,
        }}
      />
    );
  };

  // Show empty state when no cluster is selected
  if (!selectedCluster) {
    return (
      <div>
        <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
          <Col span={12}>
            <Title level={2} style={{ margin: 0 }}>
              <CloudServerOutlined style={{ marginRight: 8, color: '#1890ff' }} />
              Backend & Server Management
            </Title>
          </Col>
        </Row>
        
        <Card style={{ textAlign: 'center', padding: '60px 20px' }}>
          <div style={{ fontSize: '48px', color: '#d9d9d9', marginBottom: '16px' }}>
            <CloudServerOutlined />
          </div>
          <Title level={3} style={{ color: '#595959', marginBottom: '8px' }}>
            No HAProxy Cluster Selected
          </Title>
          <Text style={{ color: '#8c8c8c', fontSize: '16px' }}>
            Please create and select a HAProxy cluster to manage backends and servers.
          </Text>
          <div style={{ marginTop: '24px' }}>
            <Button 
              type="primary" 
              size="large"
              onClick={() => navigate('/clusters')}
            >
              Go to Cluster Management
            </Button>
          </div>
        </Card>
      </div>
    );
  }

  return (
    <div>
      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col span={12}>
          <Title level={2} style={{ margin: 0 }}>
            <CloudServerOutlined style={{ marginRight: 8, color: '#1890ff' }} />
            Backend & Server Management
          </Title>
        </Col>
        <Col span={12} style={{ textAlign: 'right' }}>
          <Space>
            <Space>
              <span style={{ fontSize: 12 }}>Pending</span>
              <Switch
                checked={showPending}
                onChange={onToggleShowPending}
                size="small"
              />
            </Space>
            <Space>
              <span style={{ fontSize: 12 }}>Rejected</span>
              <Switch
                checked={showRejected}
                onChange={onToggleShowRejected}
                size="small"
              />
            </Space>
            <div style={{ 
              position: 'relative', 
              display: 'inline-block',
              width: 250
            }}>
              <SearchOutlined style={{
                position: 'absolute',
                left: 8,
                top: '50%',
                transform: 'translateY(-50%)',
                color: '#bfbfbf',
                zIndex: 1
              }} />
              <input
                type="text"
                placeholder="Search backends..."
                value={searchText}
                onChange={(e) => handleSearch(e.target.value)}
                style={{
                  width: '100%',
                  height: 32,
                  paddingLeft: 30,
                  paddingRight: 8,
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
            </div>
            <Button
              icon={<ReloadOutlined />}
              onClick={() => {
                fetchBackends();
                setRefreshKey(prev => prev + 1); // Force EntitySyncStatus refresh
              }}
              loading={loading}
            >
              Refresh
            </Button>
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={handleAddBackend}
            >
              Add Backend
            </Button>
            {pendingChanges && (
              <Button
                type="primary"
                icon={<PlayCircleOutlined />}
                onClick={() => window.location.href = '/apply-management'}
                style={{
                  backgroundColor: '#1890ff',
                  borderColor: '#1890ff',
                  animation: 'pulse 1.5s infinite'
                }}
              >
                Go to Apply Management
              </Button>
            )}
          </Space>
        </Col>
      </Row>

      <Card>
        <Tabs activeKey={activeTab} onChange={setActiveTab}>
          <TabPane tab="Backends" key="1">
            <Table
              columns={backendColumns}
              dataSource={filteredBackends}
              rowKey="id"
              loading={loading}
              expandable={{
                expandedRowRender: record => (
                  <div style={{ margin: 0 }}>
                    <Title level={5}>Servers in {record.name}:</Title>
                    {record.servers.length > 0 ? (
                      <Table
                        columns={serverColumns.concat([
                          {
                            title: 'Actions',
                            key: 'actions',
                            render: (_, server) => (
                              <Space size="small">
                                <Tooltip title="Edit Server">
                                  <Button
                                    size="small"
                                    icon={<EditOutlined />}
                                    onClick={() => handleEditServer(server, record)}
                                  />
                                </Tooltip>
                                <Popconfirm
                                  title="Are you sure you want to delete this server?"
                                  onConfirm={() => handleDeleteServer(server.id)}
                                  okText="Yes"
                                  cancelText="No"
                                >
                                  <Tooltip title="Delete Server">
                                    <Button
                                      danger
                                      size="small"
                                      icon={<DeleteOutlined />}
                                    />
                                  </Tooltip>
                                </Popconfirm>
                              </Space>
                            ),
                          },
                        ])}
                        dataSource={record.servers}
                        rowKey="id"
                        pagination={false}
                        size="small"
                      />
                    ) : (
                      <div style={{ textAlign: 'center', padding: 20 }}>
                        <Text type="secondary">No servers configured</Text>
                        <br />
                        <Button
                          type="link"
                          icon={<PlusOutlined />}
                          onClick={() => handleAddServer(record)}
                        >
                          Add First Server
                        </Button>
                      </div>
                    )}
                  </div>
                ),
              }}
              pagination={{
                showSizeChanger: true,
                showQuickJumper: true,
                showTotal: (total, range) =>
                  `${range[0]}-${range[1]} of ${total} backends`,
              }}
            />
          </TabPane>
          <TabPane tab="All Servers" key="2">
            {renderServerList()}
          </TabPane>
        </Tabs>
      </Card>

      {/* Backend Modal */}
      <Modal
        title={editingBackend ? 'Edit Backend' : 'Add New Backend'}
        open={backendModalVisible}
        onCancel={() => setBackendModalVisible(false)}
        footer={null}
        width={700}
      >
        <Form
          form={backendForm}
          layout="vertical"
          onFinish={handleBackendSubmit}
        >
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item
                name="name"
                label="Backend Name"
                rules={[
                  { required: true, message: 'Please enter backend name' },
                  { pattern: /^[a-zA-Z0-9_-]+$/, message: 'Only alphanumeric, underscore and dash allowed' }
                ]}
              >
                <Input placeholder="e.g., web_servers" />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item
                name="mode"
                label="Mode"
                rules={[{ required: true, message: 'Please select mode' }]}
              >
                <Select>
                  <Option value="http">HTTP</Option>
                  <Option value="tcp">TCP</Option>
                  <Option value="health">Health</Option>
                </Select>
              </Form.Item>
            </Col>
          </Row>

          <Row gutter={16}>
            <Col span={12}>
              <Form.Item
                name="balance_method"
                label="Balance Method"
                rules={[{ required: true, message: 'Please select balance method' }]}
              >
                <Select>
                  <Option value="roundrobin">Round Robin</Option>
                  <Option value="leastconn">Least Connections</Option>
                  <Option value="source">Source IP</Option>
                  <Option value="uri">URI</Option>
                  <Option value="static-rr">Static Round Robin</Option>
                </Select>
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item
                name="health_check_uri"
                label="Health Check URI"
              >
                <Input placeholder="/health" />
              </Form.Item>
            </Col>
          </Row>

          <Row gutter={16}>
            <Col span={12}>
              <Form.Item
                name="health_check_interval"
                label="Health Check Interval (ms)"
              >
                <InputNumber 
                  style={{ width: '100%' }} 
                  min={1000} 
                  max={60000} 
                  placeholder="2000" 
                />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item
                name="timeout_connect"
                label="Connect Timeout (ms)"
              >
                <InputNumber 
                  style={{ width: '100%' }} 
                  min={1000} 
                  max={60000} 
                  placeholder="10000" 
                />
              </Form.Item>
            </Col>
          </Row>

          <Row gutter={16}>
            <Col span={12}>
              <Form.Item
                name="timeout_server"
                label="Server Timeout (ms)"
              >
                <InputNumber 
                  style={{ width: '100%' }} 
                  min={1000} 
                  max={300000} 
                  placeholder="60000" 
                />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item
                name="timeout_queue"
                label="Queue Timeout (ms)"
              >
                <InputNumber 
                  style={{ width: '100%' }} 
                  min={1000} 
                  max={300000} 
                  placeholder="60000" 
                />
              </Form.Item>
            </Col>
          </Row>

          <Row gutter={16}>
            <Col span={12}>
              <Form.Item
                name="health_check_expected_status"
                label="Expected HTTP Status"
                tooltip="Expected HTTP status code for health checks (100-599)"
              >
                <InputNumber 
                  style={{ width: '100%' }} 
                  min={100} 
                  max={599} 
                  placeholder="200" 
                />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item
                name="fullconn"
                label="Full Connections"
                tooltip="Maximum concurrent connections for this backend"
              >
                <InputNumber 
                  style={{ width: '100%' }} 
                  min={1} 
                  placeholder="15000" 
                />
              </Form.Item>
            </Col>
          </Row>

          <Row gutter={16}>
            <Col span={12}>
              <Form.Item
                name="cookie_name"
                label="Session Cookie Name"
                tooltip="Cookie name for session persistence (e.g., 'SERVERID')"
              >
                <Input placeholder="e.g., SERVERID" />
              </Form.Item>
            </Col>
            <Col span={24}>
              <Form.Item
                name="cookie_options"
                label="Cookie Options"
                tooltip="Cookie options: insert, indirect, nocache, httponly, secure, etc."
              >
                <Input placeholder="e.g., insert indirect nocache httponly secure" />
              </Form.Item>
            </Col>
          </Row>

          <Divider>Default Server Settings</Divider>

          <Row gutter={16}>
            <Col span={8}>
              <Form.Item
                name="default_server_inter"
                label="Default Check Interval (ms)"
                tooltip="Default health check interval for all servers"
              >
                <InputNumber 
                  style={{ width: '100%' }} 
                  min={1000} 
                  placeholder="2000" 
                />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item
                name="default_server_fall"
                label="Default Fall Count"
                tooltip="Number of failed checks before marking server down"
              >
                <InputNumber 
                  style={{ width: '100%' }} 
                  min={1} 
                  placeholder="3" 
                />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item
                name="default_server_rise"
                label="Default Rise Count"
                tooltip="Number of successful checks before marking server up"
              >
                <InputNumber 
                  style={{ width: '100%' }} 
                  min={1} 
                  placeholder="2" 
                />
              </Form.Item>
            </Col>
          </Row>

          <Divider>HTTP Headers (Advanced)</Divider>

          <Row gutter={16}>
            <Col span={12}>
              <Form.Item
                name="request_headers"
                label="Request Headers"
                tooltip="HTTP request header modifications (one per line)"
              >
                <Input.TextArea 
                  rows={4} 
                  placeholder="e.g., http-request set-header X-Forwarded-For %[src]" 
                />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item
                name="response_headers"
                label="Response Headers"
                tooltip="HTTP response header modifications (one per line)"
              >
                <Input.TextArea 
                  rows={4} 
                  placeholder="e.g., http-response add-header X-Custom-Header value" 
                />
              </Form.Item>
            </Col>
          </Row>

          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space>
              <Button onClick={() => setBackendModalVisible(false)}>
                Cancel
              </Button>
              <Button type="primary" htmlType="submit" loading={submittingBackend}>
                {submittingBackend 
                  ? (editingBackend ? 'Updating...' : 'Creating...') 
                  : (editingBackend ? 'Update' : 'Create')} Backend
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* Server Modal */}
      <Modal
        title={editingServer ? 'Edit Server' : `Add Server to ${selectedBackend?.name}`}
        open={serverModalVisible}
        onCancel={() => setServerModalVisible(false)}
        footer={null}
        width={600}
      >
        <Form
          form={serverForm}
          layout="vertical"
          onFinish={handleServerSubmit}
        >
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item
                name="server_name"
                label="Server Name"
                rules={[
                  { required: true, message: 'Please enter server name' },
                  { pattern: /^[a-zA-Z0-9_-]+$/, message: 'Only alphanumeric, underscore and dash allowed' }
                ]}
              >
                <Input placeholder="e.g., web1" />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item
                name="weight"
                label="Weight"
                rules={[{ required: true, message: 'Please enter weight' }]}
              >
                <InputNumber 
                  style={{ width: '100%' }} 
                  min={1} 
                  max={256} 
                  placeholder="100" 
                />
              </Form.Item>
            </Col>
          </Row>

          <Row gutter={16}>
            <Col span={16}>
              <Form.Item
                name="server_address"
                label="IP Address"
                rules={[{ required: true, message: 'Please enter IP address' }]}
              >
                <Input placeholder="192.168.1.10" />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item
                name="server_port"
                label="Port"
                rules={[
                  { required: true, message: 'Please enter port' },
                  { type: 'number', min: 1, max: 65535, message: 'Port must be between 1-65535' }
                ]}
              >
                <InputNumber style={{ width: '100%' }} placeholder="80" />
              </Form.Item>
            </Col>
          </Row>

          <Form.Item
            name="max_connections"
            label="Max Connections (Optional)"
          >
            <InputNumber 
              style={{ width: '100%' }} 
              min={1} 
              max={10000} 
              placeholder="Leave empty for unlimited" 
            />
          </Form.Item>

          <Row gutter={16}>
            <Col span={8}>
              <Form.Item
                name="check_enabled"
                label="Health Check"
                valuePropName="checked"
              >
                <Switch checkedChildren="ON" unCheckedChildren="OFF" />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item
                name="backup_server"
                label="Backup Server"
                valuePropName="checked"
              >
                <Switch checkedChildren="YES" unCheckedChildren="NO" />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item
                name="ssl_enabled"
                label="SSL Enabled"
                valuePropName="checked"
              >
                <Switch checkedChildren="SSL" unCheckedChildren="Plain" />
              </Form.Item>
            </Col>
          </Row>

          <Row gutter={16}>
            <Col span={12}>
              <Form.Item
                name="check_port"
                label="Health Check Port"
                tooltip="Custom port for health checks (different from server port)"
              >
                <InputNumber 
                  style={{ width: '100%' }} 
                  min={1} 
                  max={65535} 
                  placeholder="Leave empty to use server port" 
                />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item
                name="ssl_verify"
                label="SSL Verification"
                tooltip="SSL certificate verification method"
              >
                <Select allowClear placeholder="Select SSL verification">
                  <Option value="none">None</Option>
                  <Option value="required">Required</Option>
                </Select>
              </Form.Item>
            </Col>
          </Row>

          <Form.Item noStyle shouldUpdate={(prevValues, currentValues) => prevValues.ssl_enabled !== currentValues.ssl_enabled}>
            {({ getFieldValue }) =>
              getFieldValue('ssl_enabled') ? (
                <Row gutter={16}>
                  <Col span={24}>
                    <Form.Item
                      name="ssl_certificate_id"
                      label="SSL Certificate"
                      tooltip="Select SSL certificate for backend server (required if ssl_verify is 'required')"
                      rules={[
                        ({ getFieldValue }) => ({
                          validator(_, value) {
                            const sslVerify = getFieldValue('ssl_verify');
                            if (sslVerify === 'required' && !value) {
                              return Promise.reject(new Error('SSL Certificate is required when SSL verification is set to "required"'));
                            }
                            return Promise.resolve();
                          },
                        }),
                      ]}
                    >
                      <Select
                        allowClear
                        placeholder="Select an SSL certificate (optional unless verify=required)"
                        showSearch
                        filterOption={(input, option) =>
                          (option.label || '').toLowerCase().includes(input.toLowerCase())
                        }
                        optionLabelProp="label"
                      >
                        {sslCertificates.map((cert) => {
                          // Status icon based on certificate validity
                          const statusIcon = cert.status === 'valid' ? 'Valid' : 
                                            cert.status === 'expiring_soon' ? 'Expiring' : 'Expired';
                          const expiryInfo = cert.days_until_expiry !== undefined ? 
                            `(${cert.days_until_expiry} days)` : '';
                          const sslTypeTag = cert.ssl_type === 'Global' ? 'Global' : 'Cluster';
                          
                          return (
                            <Option 
                              key={cert.id} 
                              value={cert.id}
                              label={`${cert.name} - ${cert.domain}`}
                            >
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <span>
                                  <strong>{cert.name}</strong> - {cert.domain}
                                  <Tag 
                                    color={cert.ssl_type === 'Global' ? 'blue' : 'green'} 
                                    style={{ marginLeft: 8, fontSize: '10px' }}
                                  >
                                    {sslTypeTag}
                                  </Tag>
                                </span>
                                <span style={{ fontSize: '12px', color: '#666', marginLeft: 12 }}>
                                  {statusIcon} {expiryInfo}
                                </span>
                              </div>
                            </Option>
                          );
                        })}
                      </Select>
                    </Form.Item>
                  </Col>
                </Row>
              ) : null
            }
          </Form.Item>

          <Row gutter={16}>
            <Col span={24}>
              <Form.Item
                name="cookie_value"
                label="Session Cookie Value"
                tooltip="Cookie value for session persistence (used with backend cookie)"
              >
                <Input placeholder="e.g., srv1" />
              </Form.Item>
            </Col>
          </Row>

          <Divider>Health Check Settings (Optional)</Divider>

          <Row gutter={16}>
            <Col span={8}>
              <Form.Item
                name="inter"
                label="Check Interval (ms)"
                tooltip="Health check interval in milliseconds"
              >
                <InputNumber 
                  style={{ width: '100%' }} 
                  min={1000} 
                  placeholder="2000" 
                />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item
                name="fall"
                label="Fall Count"
                tooltip="Number of failed checks before marking down"
              >
                <InputNumber 
                  style={{ width: '100%' }} 
                  min={1} 
                  placeholder="3" 
                />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item
                name="rise"
                label="Rise Count"
                tooltip="Number of successful checks before marking up"
              >
                <InputNumber 
                  style={{ width: '100%' }} 
                  min={1} 
                  placeholder="2" 
                />
              </Form.Item>
            </Col>
          </Row>

          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space>
              <Button onClick={() => setServerModalVisible(false)}>
                Cancel
              </Button>
              <Button type="primary" htmlType="submit" loading={submittingServer}>
                {submittingServer 
                  ? (editingServer ? 'Updating...' : 'Adding...') 
                  : (editingServer ? 'Update' : 'Add')} Server
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* Version History Modal */}
      <VersionHistory
        visible={versionModalVisible}
        onCancel={handleVersionModalCancel}
        entityType={selectedEntityForVersion?.entityType}
        entityId={selectedEntityForVersion?.entityId}
        onRestoreSuccess={handleRestoreSuccess}
      />
    </div>
  );
};

export default function BackendServersWithErrorBoundary() {
  return (
    <BackendErrorBoundary>
      <BackendServers />
    </BackendErrorBoundary>
  );
}