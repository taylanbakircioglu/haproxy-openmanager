import React, { useState, useEffect } from 'react';
import {
  Card, Table, Button, Modal, Form, Input, InputNumber, Select, Switch,
  Space, message, Popconfirm, Tag, Tooltip, Row, Col, Typography,
  Divider, Checkbox, Collapse, Alert, InputNumber as AntInputNumber, Spin, Progress
} from 'antd';
import { getAgentSyncColor, getConfigStatusColor, getEntityStatusColor, getSSLExpiryInfo } from '../utils/colors';
import EntitySyncStatus from './EntitySyncStatus';
import {
  PlusOutlined, EditOutlined, DeleteOutlined, ReloadOutlined,
  GlobalOutlined, SettingOutlined, LockOutlined, SafetyCertificateOutlined,
  WarningOutlined, SearchOutlined, HistoryOutlined, PlayCircleOutlined, LoadingOutlined
} from '@ant-design/icons';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { useCluster } from '../contexts/ClusterContext';
import { VersionHistory } from './VersionHistory';

// Error Boundary Component
class FrontendErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Frontend Management Error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <Alert
          message="Frontend Management Error"
          description="There was an error loading Frontend Management. Please refresh the page."
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
const { Title, Text } = Typography;
const { Panel } = Collapse;
const { TextArea } = Input;

const FrontendManagement = () => {
  const { selectedCluster } = useCluster();
  const navigate = useNavigate();
  const [frontends, setFrontends] = useState([]);
  const [backends, setBackends] = useState([]);
  const [sslCertificates, setSslCertificates] = useState([]);

  // Port conflict validation helper
  const validatePortConflict = (port, sslPort, currentFrontendId = null) => {
    const conflicts = [];
    
    frontends.forEach(frontend => {
      // Skip current frontend when editing
      if (currentFrontendId && frontend.id === currentFrontendId) return;
      
      // Check HTTP port conflicts
      if (frontend.bind_port === port) {
        conflicts.push(`Port ${port} is already used by frontend "${frontend.name}" (HTTP)`);
      }
      
      // Check HTTPS port conflicts (if frontend has SSL enabled)
      if (frontend.ssl_enabled && frontend.ssl_port === port) {
        conflicts.push(`Port ${port} is already used by frontend "${frontend.name}" (HTTPS)`);
      }
      
      // Check if our SSL port conflicts with existing HTTP ports
      if (sslPort && frontend.bind_port === sslPort) {
        conflicts.push(`HTTPS port ${sslPort} is already used by frontend "${frontend.name}" (HTTP)`);
      }
      
      // Check if our SSL port conflicts with existing HTTPS ports
      if (sslPort && frontend.ssl_enabled && frontend.ssl_port === sslPort) {
        conflicts.push(`HTTPS port ${sslPort} is already used by frontend "${frontend.name}" (HTTPS)`);
      }
    });
    
    return conflicts;
  };
  const [loading, setLoading] = useState(false);
  const [sslLoading, setSslLoading] = useState(false);
  const [modalVisible, setModalVisible] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);
  const [editingFrontend, setEditingFrontend] = useState(null);
  const [searchText, setSearchText] = useState('');
  const [filteredFrontends, setFilteredFrontends] = useState([]);
  const [showPending, setShowPending] = useState(true);  // Default TRUE: users must see their changes
  const [showRejected, setShowRejected] = useState(true);  // Default TRUE: users must see rejected items

  // Persist toggle states across navigation
  useEffect(() => {
    const sp = localStorage.getItem('frontend:showPending');
    const sr = localStorage.getItem('frontend:showRejected');
    if (sp !== null) setShowPending(sp === 'true');
    if (sr !== null) setShowRejected(sr === 'true');
  }, []);
  const onToggleShowPending = (checked) => {
    setShowPending(checked);
    localStorage.setItem('frontend:showPending', String(checked));
  };
  const onToggleShowRejected = (checked) => {
    setShowRejected(checked);
    localStorage.setItem('frontend:showRejected', String(checked));
  };
  const [submitting, setSubmitting] = useState(false);
  const [applyLoading, setApplyLoading] = useState(false);
  const [pendingChanges, setPendingChanges] = useState(false);
  const [versionModalVisible, setVersionModalVisible] = useState(false);
  const [selectedEntityForVersion, setSelectedEntityForVersion] = useState(null);
  const [form] = Form.useForm();

  // SSL visibility control - fields start visible for proper form registration
  const updateSSLVisibility = (sslEnabled) => {
    const sslFields = document.querySelectorAll('.ssl-fields');
    sslFields.forEach(field => {
      field.style.display = sslEnabled ? 'block' : 'none';
    });
  };

  // Status filter function - defined before fetchFrontends to avoid hoisting issues
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
      setFrontends([]);
      setFilteredFrontends([]);
      setBackends([]);
      setSslCertificates([]);
    }
    
    fetchFrontends();
    fetchBackends();
    fetchSSLCertificates();
    checkPendingChanges();
  }, [selectedCluster]);

  const fetchFrontends = async () => {
    setLoading(true);
    try {
      const params = selectedCluster ? { cluster_id: selectedCluster.id } : {};
      const response = await axios.get('/api/frontends', { 
        params,
        headers: {
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache'
        }
      });
      
      // 🔍 DEBUG: Log frontend data to check SSL fields
      console.log('🔍 FRONTEND FETCH DEBUG: Response data:', response.data);
      if (response.data.frontends && response.data.frontends.length > 0) {
        response.data.frontends.forEach(frontend => {
          if (frontend.ssl_enabled) {
            console.log(`🔍 SSL FRONTEND DEBUG: ${frontend.name}`, {
              ssl_enabled: frontend.ssl_enabled,
              ssl_certificate_id: frontend.ssl_certificate_id,
              ssl_port: frontend.ssl_port
            });
          }
        });
      }
      
      const fetchedFrontends = response.data.frontends;
      setFrontends(fetchedFrontends);
      // CRITICAL FIX: Apply status filters after fetching to maintain filter state
      // This prevents frontends from disappearing when updated (e.g., APPLIED → PENDING)
      setFilteredFrontends(applyStatusFilters(fetchedFrontends));
    } catch (error) {
      message.error('Failed to fetch frontends: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  // Search filter function
  const handleSearch = (value) => {
    setSearchText(value);
    if (!value) {
      setFilteredFrontends(applyStatusFilters(frontends));
    } else {
      const filtered = frontends.filter(frontend =>
        frontend.name.toLowerCase().includes(value.toLowerCase()) ||
        frontend.bind_address.toLowerCase().includes(value.toLowerCase()) ||
        frontend.default_backend?.toLowerCase().includes(value.toLowerCase()) ||
        frontend.mode.toLowerCase().includes(value.toLowerCase())
      );
      setFilteredFrontends(applyStatusFilters(filtered));
    }
  };

  // Version history modal handlers
  const handleShowVersionHistory = (record) => {
    setSelectedEntityForVersion({
      entityType: 'frontend',
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
    // Refresh frontends list to show updated data
    fetchFrontends();
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

  // Update filtered data when frontends change
  useEffect(() => {
    if (searchText) {
      handleSearch(searchText);
    } else {
      setFilteredFrontends(applyStatusFilters(frontends));
    }
  }, [frontends, showPending, showRejected]);

  const fetchBackends = async () => {
    try {
      const params = selectedCluster ? { cluster_id: selectedCluster.id } : {};
      const response = await axios.get('/api/backends', { 
        params,
        headers: {
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache'
        }
      });
      setBackends(response.data.backends);
    } catch (error) {
      console.error('Failed to fetch backends:', error);
    }
  };

  const fetchSSLCertificates = async () => {
    if (!selectedCluster) return;
    
    setSslLoading(true);
    try {
      console.log('🔍 SSL FETCH DEBUG: Fetching certificates for cluster:', selectedCluster.id);
      
      const token = localStorage.getItem('token');
      console.log('🔍 SSL FETCH DEBUG: Token exists:', token ? 'Yes' : 'No');
      
      const response = await axios.get(`/api/ssl/certificates?cluster_id=${selectedCluster.id}`, {
        headers: { 
          'Authorization': `Bearer ${token}`,
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache'
        }
      });
      
      console.log('🔍 SSL FETCH DEBUG: Response received:', response.data);
      
      // Handle different response formats and ensure we have the new fields
      const certs = response.data.certificates || response.data || [];
      console.log('🔍 SSL FETCH DEBUG: Certificates processed:', certs.length, certs);
      console.log('🔍 SSL FETCH DEBUG: Certificate details:', certs.map(cert => ({
        id: cert.id,
        name: cert.name,
        domain: cert.domain || cert.primary_domain,
        ssl_type: cert.ssl_type
      })));
      
      setSslCertificates(certs);
    } catch (error) {
      console.error('🔍 SSL FETCH DEBUG: Failed to fetch SSL certificates:', error);
      console.error('🔍 SSL FETCH DEBUG: Error response:', error.response?.data);
      console.error('🔍 SSL FETCH DEBUG: Error status:', error.response?.status);
      setSslCertificates([]);
    } finally {
      setSslLoading(false);
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

  // Check for pending configuration changes
  const checkPendingChanges = async () => {
    if (!selectedCluster) return;
    
    try {
      console.log('🎯 APPLY DEBUG: Checking pending changes for cluster:', selectedCluster.id);
      const response = await axios.get(`/api/clusters/${selectedCluster.id}/config-versions`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      
      const versions = response.data.versions || [];
      const hasPending = versions.some(version => version.status === 'PENDING');
      console.log('🎯 APPLY DEBUG: Config versions:', versions.length);
      console.log('🎯 APPLY DEBUG: Pending versions:', versions.filter(v => v.status === 'PENDING').length);
      console.log('🎯 APPLY DEBUG: Has pending changes:', hasPending);
      setPendingChanges(hasPending);
    } catch (error) {
      console.error('🎯 APPLY DEBUG: Failed to check pending changes:', error);
    }
  };

  // Apply pending configuration changes
  const handleApplyChanges = async () => {
    if (!selectedCluster) return;
    
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
      
      // Also refresh the frontends list to update Config Status column
      console.log('🎯 APPLY DEBUG: Refreshing frontends after apply...');
      await fetchFrontends();
      
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
                    onClick={() => window.location.href = '/backend-servers'}
                    style={{ marginRight: 8 }}
                  >
                    Manage Backends
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
              <p><strong>Backend validation failed!</strong></p>
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
              <p>✅ <strong>Solution:</strong> Go to Backend Management and add servers to these backends.</p>
              <br />
              <Button 
                type="primary" 
                onClick={() => window.location.href = '/backend-servers'}
                style={{ marginTop: 10 }}
              >
                Go to Backend Management
              </Button>
            </div>
          ),
          width: 600,
          okText: 'I Understand',
          okType: 'default'
        });
      } else {
        message.error(`Failed to apply changes: ${error.response?.data?.message || error.response?.data?.detail || error.message}`);
      }
    } finally {
      setApplyLoading(false);
    }
  };

  const handleAdd = () => {
    setEditingFrontend(null);
    form.resetFields();
    form.setFieldsValue({
      bind_address: '*',
      mode: 'http',
      ssl_enabled: false,
      ssl_certificate_ids: []
    });
    
    // Update SSL field visibility for new frontend
    setTimeout(() => {
      updateSSLVisibility(false);
    }, 100);
    
    setModalVisible(true);
  };

  const handleEdit = (frontend) => {
    setEditingFrontend(frontend);
    
    console.log('🔍 FRONTEND EDIT DEBUG: Raw frontend data:', frontend);
    console.log('🔍 FRONTEND EDIT DEBUG: SSL fields:', {
      ssl_enabled: frontend.ssl_enabled,
      ssl_certificate_ids: frontend.ssl_certificate_ids,
      ssl_certificate_id: frontend.ssl_certificate_id
    });
    
    // ENTERPRISE DUAL-MODE: Support both old and new SSL format
    let sslCertIds = [];
    if (frontend.ssl_certificate_ids && Array.isArray(frontend.ssl_certificate_ids)) {
      // NEW: Multiple SSL certificates
      sslCertIds = frontend.ssl_certificate_ids;
    } else if (frontend.ssl_certificate_id) {
      // OLD: Single SSL certificate - convert to array
      sslCertIds = [frontend.ssl_certificate_id];
    }
    
    // Format ACL rules for textarea (array to multi-line string)
    let formattedAclRules = frontend.acl_rules;
    if (Array.isArray(frontend.acl_rules)) {
      formattedAclRules = frontend.acl_rules.join('\n');
    }
    
    // Format redirect rules for textarea (array to multi-line string)
    let formattedRedirectRules = frontend.redirect_rules;
    if (Array.isArray(frontend.redirect_rules)) {
      formattedRedirectRules = frontend.redirect_rules.join('\n');
    }
    
    // Format use_backend rules for textarea (array to multi-line string)
    let formattedUseBackendRules = frontend.use_backend_rules;
    if (Array.isArray(frontend.use_backend_rules)) {
      formattedUseBackendRules = frontend.use_backend_rules.join('\n');
    }
    
    form.setFieldsValue({
      ...frontend,
      ssl_enabled: frontend.ssl_enabled || false,
      ssl_certificate_ids: sslCertIds,
      acl_rules: formattedAclRules,
      redirect_rules: formattedRedirectRules,
      use_backend_rules: formattedUseBackendRules
    });
    
    // Update SSL field visibility after setting values
    setTimeout(() => {
      updateSSLVisibility(frontend.ssl_enabled || false);
    }, 100);
    
    setModalVisible(true);
  };

  const handleDelete = async (frontendId) => {
    if (!selectedCluster) {
      message.warning('Please select a HAProxy cluster first');
      return;
    }

    // Find the frontend to get details for confirmation
    const frontend = frontends.find(f => f.id === frontendId);
    if (!frontend) {
      message.error('Frontend not found');
      return;
    }

    // Check if frontend uses a backend
    let confirmMessage = `Are you sure you want to delete frontend "${frontend.name}"?`;
    let warningDetails = [];
    
    if (frontend.default_backend) {
      // Check if the backend still exists
      const backendExists = backends.some(b => b.name === frontend.default_backend);
      if (backendExists) {
        // Show error - frontend uses an active backend
        Modal.error({
          title: 'Cannot Delete Frontend',
          content: (
            <div>
              <p>Cannot delete frontend "<strong>{frontend.name}</strong>"</p>
              <div style={{ marginTop: 16 }}>
                <p><strong>Reason:</strong> This frontend uses backend "<strong>{frontend.default_backend}</strong>"</p>
                <p><strong>Solution:</strong> Please delete the backend first, then the frontend will be automatically updated.</p>
              </div>
            </div>
          ),
          okText: 'Understood'
        });
        return;
      }
    }

    // Check WAF rules (just for info, they will be auto-removed)
    // Note: We don't have easy access to WAF rules here, so we'll rely on backend handling

    // Show confirmation modal
    Modal.confirm({
      title: 'Delete Frontend',
      content: (
        <div>
          <p>{confirmMessage}</p>
          {frontend.default_backend && (
            <div style={{ marginTop: 16 }}>
              <p><strong>Note:</strong> Any associated WAF rules will also be removed.</p>
            </div>
          )}
        </div>
      ),
      okText: 'Delete',
      okType: 'danger',
      cancelText: 'Cancel',
      onOk: async () => {
        try {
          const response = await axios.delete(`/api/frontends/${frontendId}`, {
            data: { cluster_id: selectedCluster.id }
          });
      
          // Show frontend deletion success with details
          const frontendMessage = response.data.message || 'Frontend deleted successfully';
          
          if (response.data.sync_results) {
            const syncResults = response.data.sync_results;
            const successCount = syncResults.filter(r => r.success).length;
            const totalNodes = syncResults.length;
            
            if (successCount === totalNodes) {
              message.success(
                <div>
                  <div><strong>{frontendMessage}</strong></div>
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
                  <div><strong>{frontendMessage}</strong></div>
                  <div style={{ marginTop: 4, fontSize: '12px' }}>
                    ⚠️ {successCount}/{totalNodes} cluster node(s) updated successfully
                    <br />📅 Completed: {new Date().toLocaleString()}
                  </div>
                </div>,
                10
              );
            }
          } else {
            message.success(frontendMessage, 6);
          }
          
          fetchFrontends();
          checkPendingChanges();
        } catch (error) {
          const errorMsg = error.response?.data?.detail || error.message;
          message.error(
            <div>
              <div><strong>Failed to delete frontend</strong></div>
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

  const handleSubmit = async (values) => {
    if (!selectedCluster) {
      message.warning('Please select a HAProxy cluster first');
      return;
    }

    setSubmitting(true);
    try {
      // DEBUG: Log form values to see what's being sent
      console.log('🎯 FORM VALUES:', values);
      console.log('🎯 SSL CERTIFICATE DEBUG:', {
        ssl_enabled: values.ssl_enabled,
        ssl_certificate_id: values.ssl_certificate_id,
        ssl_port: values.ssl_port,
        sslCertificatesCount: sslCertificates.length
      });
      
      // DEBUG: Log editing context
      if (editingFrontend) {
        console.log('🎯 EDITING FRONTEND:', {
          id: editingFrontend.id,
          name: editingFrontend.name,
          original_ssl_enabled: editingFrontend.ssl_enabled,
          original_ssl_certificate_id: editingFrontend.ssl_certificate_id,
          original_ssl_port: editingFrontend.ssl_port
        });
      }
      
      const requestData = {
        ...values,
        cluster_id: selectedCluster.id
      };
      
      // DEBUG: Log request data to see final payload
      console.log('🎯 REQUEST DATA:', requestData);

      let response;
      if (editingFrontend) {
        response = await axios.put(`/api/frontends/${editingFrontend.id}`, requestData);
        
        // Show agent sync results
        if (response.data.sync_results) {
          const syncResults = response.data.sync_results;
          const agentCount = syncResults.length;
          const successfulAgents = syncResults.filter(r => r.success).length;
          
          message.success(
            <div>
              <div><strong>Frontend updated successfully!</strong></div>
              <div style={{ marginTop: 4, fontSize: '12px' }}>
                📝 Changes created as PENDING
                <br />🔄 Click "Apply Changes" to activate configuration
                <br />📅 Updated: {new Date().toLocaleString()}
              </div>
            </div>,
            6
          );
        } else {
          message.success('Frontend updated successfully');
        }
      } else {
        response = await axios.post('/api/frontends', requestData);
        
        // Show agent sync results
        if (response.data.sync_results) {
          const syncResults = response.data.sync_results;
          const agentCount = syncResults.length;
          const successfulAgents = syncResults.filter(r => r.success).length;
          
          message.success(
            <div>
              <div><strong>Frontend created successfully!</strong></div>
              <div style={{ marginTop: 4, fontSize: '12px' }}>
                📝 Changes created as PENDING
                <br />🔄 Click "Apply Changes" to activate configuration
                <br />📅 Created: {new Date().toLocaleString()}
              </div>
            </div>,
            6
          );
        } else {
          message.success('Frontend created successfully');
        }
      }
      
      setModalVisible(false);
      fetchFrontends();
      fetchSSLCertificates(); // Refresh SSL certificates after frontend update
      checkPendingChanges();
    } catch (error) {
      const errorMsg = error.response?.data?.detail || error.message;
      message.error(
        <div>
          <div><strong>Failed to save frontend</strong></div>
          <div style={{ marginTop: 4, fontSize: '12px', color: '#ff4d4f' }}>
            {errorMsg}
          </div>
        </div>,
        8
      );
    } finally {
      setSubmitting(false);
    }
  };

  const columns = [
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
      render: (text, record) => (
        <Space>
          <GlobalOutlined style={{ color: '#1890ff' }} />
          <strong>{text}</strong>
          {!record.is_active && <Tag color="red">Inactive</Tag>}
        </Space>
      ),
    },
    {
      title: 'Sync Status',
      key: 'sync_status',
      render: (_, record) => (
        <EntitySyncStatus
          key={`${record.id}-${refreshKey}`}
          entityType="frontends"
          entityId={record.id}
          entityUpdatedAt={record.updated_at}
          lastConfigStatus={record.last_config_status}
          clusterId={selectedCluster?.id}
          selectedCluster={selectedCluster}
        />
      ),
    },
    {
      title: 'Bind Address',
      dataIndex: 'bind_address',
      key: 'bind_address',
      render: (text, record) => `${text}:${record.bind_port}`,
    },
    {
      title: 'Mode',
      dataIndex: 'mode',
      key: 'mode',
      render: (mode) => (
        <Tag color={mode === 'http' ? 'blue' : 'green'}>{mode.toUpperCase()}</Tag>
      ),
    },
    {
      title: 'Default Backend',
      dataIndex: 'default_backend',
      key: 'default_backend',
      render: (backend) => backend ? (
        <Tag color="cyan">{backend}</Tag>
      ) : <span style={{ color: '#999' }}>Not Set</span>,
    },
    {
      title: 'SSL/TLS',
      key: 'ssl_info',
      width: 200,
      render: (_, record) => {
        if (!record.ssl_enabled) {
          return <Tag color="default" size="small">No SSL</Tag>;
        }
        
        // ENTERPRISE DUAL-MODE: Support both ssl_certificate_ids (new) and ssl_certificate_id (old)
        let certIds = [];
        if (record.ssl_certificate_ids && Array.isArray(record.ssl_certificate_ids)) {
          certIds = record.ssl_certificate_ids;
        } else if (record.ssl_certificate_id) {
          certIds = [record.ssl_certificate_id];
        }
        
        if (sslLoading) {
          return (
            <div style={{ minWidth: '140px' }}>
              <Tag color="processing" icon={<LoadingOutlined />} size="small">
                Loading SSL
              </Tag>
              <div style={{ fontSize: '10px', color: '#1890ff', marginTop: '2px' }}>
                Fetching certificate info...
              </div>
            </div>
          );
        }
        
        if (certIds.length === 0) {
          return (
            <div style={{ minWidth: '140px' }}>
              <Tag color="orange" icon={<WarningOutlined />} size="small">
                SSL Enabled
              </Tag>
              <div style={{ fontSize: '10px', color: '#fa8c16', marginTop: '2px' }}>
                No certificates assigned
              </div>
            </div>
          );
        }
        
        // Find all SSL certificates
        const sslCerts = certIds.map(id => sslCertificates.find(cert => cert.id === id)).filter(Boolean);
        
        if (sslCerts.length === 0) {
          return (
            <div style={{ minWidth: '140px' }}>
              <Tag color="red" icon={<WarningOutlined />} size="small">
                SSL Error
              </Tag>
              <div style={{ fontSize: '10px', color: '#ff4d4f', marginTop: '2px' }}>
                Certificate(s) not found
              </div>
            </div>
          );
        }
        
        // Single certificate - show full details
        if (sslCerts.length === 1) {
          const sslCert = sslCerts[0];
          const expiryInfo = getSSLExpiryInfo(sslCert.expiry_date);
          const domain = sslCert.domain || sslCert.primary_domain || sslCert.name;
          
          return (
            <div style={{ minWidth: '140px' }}>
              <Tag 
                color={expiryInfo.tagColor} 
                icon={<SafetyCertificateOutlined />}
                size="small"
                style={{ marginBottom: '6px', fontSize: '11px' }}
              >
                {domain}
              </Tag>
              
              <div style={{ marginBottom: '4px' }}>
                <Tooltip 
                  title={
                    <div>
                      <div><strong>{domain}</strong></div>
                      <div>Status: {expiryInfo.status}</div>
                      {sslCert.expiry_date && (
                        <div>Expires: {new Date(sslCert.expiry_date).toLocaleDateString('tr-TR', {
                          day: '2-digit',
                          month: '2-digit',
                          year: 'numeric'
                        })}</div>
                      )}
                    </div>
                  }
                  placement="top"
                >
                  <Progress 
                    percent={expiryInfo.progress}
                    size="small"
                    strokeColor={expiryInfo.color}
                    trailColor="#f0f0f0"
                    showInfo={false}
                    style={{ 
                      fontSize: '10px',
                      lineHeight: '12px',
                      cursor: 'help'
                    }}
                    strokeWidth={4}
                  />
                </Tooltip>
              </div>
              
              <div style={{ fontSize: '9px', color: '#666', lineHeight: '12px' }}>
                <div style={{ 
                  color: expiryInfo.tagColor === 'red' ? '#ff4d4f' : 
                         expiryInfo.tagColor === 'orange' ? '#fa8c16' : '#52c41a',
                  fontWeight: '500'
                }}>
                  {expiryInfo.status}
                </div>
              </div>
            </div>
          );
        }
        
        // Multiple certificates - show compact list
        const allValid = sslCerts.every(cert => {
          const expiry = getSSLExpiryInfo(cert.expiry_date);
          return expiry.tagColor === 'green';
        });
        
        return (
          <div style={{ minWidth: '160px' }}>
            <Tag 
              color={allValid ? 'green' : 'orange'} 
              icon={<SafetyCertificateOutlined />}
              size="small"
              style={{ marginBottom: '4px' }}
            >
              {sslCerts.length} Certificates
            </Tag>
            
            <Tooltip
              title={
                <div>
                  <div><strong>SSL Certificates ({sslCerts.length}):</strong></div>
                  {sslCerts.map(cert => {
                    const expiryInfo = getSSLExpiryInfo(cert.expiry_date);
                    return (
                      <div key={cert.id} style={{ marginTop: 4 }}>
                        • {cert.domain || cert.name} - {expiryInfo.status}
                      </div>
                    );
                  })}
                </div>
              }
              placement="top"
            >
              <div style={{ fontSize: '10px', color: '#666', cursor: 'help' }}>
                {sslCerts.map(cert => (cert.domain || cert.name)).join(', ').substring(0, 40)}...
              </div>
            </Tooltip>
          </div>
        );
      },
    },
    {
      title: 'Status',
      dataIndex: 'is_active',
      key: 'status',
      render: (isActive) => (
        <Tag color={isActive ? 'green' : 'red'}>
          {isActive ? 'Active' : 'Inactive'}
        </Tag>
      ),
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
        <Space size="middle">
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

          <Tooltip title="Edit Frontend">
            <Button
              type="primary"
              size="small"
              icon={<EditOutlined />}
              onClick={() => handleEdit(record)}
            />
          </Tooltip>
          <Popconfirm
            title="Are you sure you want to delete this frontend?"
            onConfirm={() => handleDelete(record.id)}
            okText="Yes"
            cancelText="No"
          >
            <Tooltip title="Delete Frontend">
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
    },
  ];

  // Show empty state when no cluster is selected
  if (!selectedCluster) {
    return (
      <div>
        <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
          <Col span={12}>
            <h2 style={{ margin: 0 }}>
              <GlobalOutlined style={{ marginRight: 8, color: '#1890ff' }} />
              Frontend Management
            </h2>
          </Col>
        </Row>
        
        <Card style={{ textAlign: 'center', padding: '60px 20px' }}>
          <div style={{ fontSize: '48px', color: '#d9d9d9', marginBottom: '16px' }}>
            <GlobalOutlined />
          </div>
          <Title level={3} style={{ color: '#595959', marginBottom: '8px' }}>
            No HAProxy Cluster Selected
          </Title>
          <Text style={{ color: '#8c8c8c', fontSize: '16px' }}>
            Please create and select a HAProxy cluster to manage frontends.
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
          <h2 style={{ margin: 0 }}>
            <GlobalOutlined style={{ marginRight: 8, color: '#1890ff' }} />
            Frontend Management
          </h2>
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
              <input
                type="text"
                placeholder="Search frontends..."
                value={searchText}
                onChange={(e) => handleSearch(e.target.value)}
                style={{
                  width: '100%',
                  height: 32,
                  paddingLeft: 8,
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
                fetchFrontends();
                setRefreshKey(prev => prev + 1); // Force EntitySyncStatus refresh
              }}
              loading={loading}
            >
              Refresh
            </Button>
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={handleAdd}
            >
              Add Frontend
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
        <Table
          columns={columns}
          dataSource={filteredFrontends}
          rowKey="id"
          loading={loading}
          pagination={{
            total: filteredFrontends.length,
            showSizeChanger: true,
            showQuickJumper: true,
            showTotal: (total, range) =>
              `${range[0]}-${range[1]} of ${total} frontends`,
          }}
        />
      </Card>

      <Modal
        title={editingFrontend ? 'Edit Frontend' : 'Add New Frontend'}
        open={modalVisible}
        onCancel={() => setModalVisible(false)}
        footer={null}
        width={900}
      >
        <Alert
          message="HAProxy Frontend Configuration"
          description="Configure all aspects of your HAProxy frontend including binding, SSL, ACLs, and advanced options."
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
        />
        
        <Form
          form={form}
          layout="vertical"
          onFinish={handleSubmit}
          initialValues={{
            bind_address: '*',
            mode: 'http',
            ssl_verify: 'optional',
            compression: false,
            log_separate: false,
            capture_request_headers: [],
            capture_response_headers: []
          }}
        >
          <Collapse defaultActiveKey={['1']} ghost forceRender>
            {/* Basic Configuration */}
            <Panel header="Basic Configuration" key="1" forceRender>
              <Row gutter={16}>
                <Col span={12}>
                  <Form.Item
                    name="name"
                    label="Frontend Name"
                    extra="Unique identifier for this frontend"
                    rules={[
                      { required: true, message: 'Please enter frontend name' },
                      { pattern: /^[a-zA-Z0-9_-]+$/, message: 'Only alphanumeric, underscore and dash allowed' }
                    ]}
                  >
                    <Input placeholder="e.g., main_frontend" />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    name="mode"
                    label="Protocol Mode"
                    extra="Protocol for processing connections"
                    rules={[{ required: true, message: 'Please select mode' }]}
                  >
                    <Select>
                      <Option value="http">HTTP - Layer 7 processing with HTTP understanding</Option>
                      <Option value="tcp">TCP - Layer 4 processing for non-HTTP protocols</Option>
                      <Option value="health">Health - Health check endpoint</Option>
                    </Select>
                  </Form.Item>
                </Col>
              </Row>

              <Row gutter={16}>
                <Col span={12}>
                  <Form.Item
                    name="bind_address"
                    label="Bind Address"
                    extra="IP address to bind to (* for all interfaces)"
                    rules={[{ required: true, message: 'Please enter bind address' }]}
                  >
                    <Input placeholder="* or specific IP like 192.168.1.10" />
                  </Form.Item>
                </Col>
                <Col span={6}>
                  <Form.Item
                    name="bind_port"
                    label="HTTP Port"
                    extra="Port for HTTP connections"
                    rules={[
                      { required: true, message: 'Please enter HTTP port' },
                      { type: 'number', min: 1, max: 65535, message: 'Port must be between 1-65535' },
                      ({ getFieldValue }) => ({
                        validator(_, value) {
                          if (!value) return Promise.resolve();
                          
                          // Only check HTTP port conflicts, not SSL port conflicts for HTTP field
                          const conflicts = validatePortConflict(value, null, editingFrontend?.id);
                          
                          if (conflicts.length > 0) {
                            return Promise.reject(new Error(`Port conflict detected:\n• ${conflicts.join('\n• ')}`));
                          }
                          return Promise.resolve();
                        },
                      }),
                    ]}
                  >
                    <InputNumber style={{ width: '100%' }} placeholder="80" />
                  </Form.Item>
                </Col>
                <Col span={6}>
                  <Form.Item
                    name="maxconn"
                    label="Max Connections"
                    extra="Maximum concurrent connections"
                  >
                    <InputNumber style={{ width: '100%' }} min={1} placeholder="2000" />
                  </Form.Item>
                </Col>
              </Row>

              <Form.Item
                name="default_backend"
                label="Default Backend"
                extra="Backend that will handle requests not matched by any ACL rules"
              >
                <Select
                  placeholder="Select default backend"
                  allowClear
                  showSearch
                  filterOption={(input, option) =>
                    option.children.toLowerCase().indexOf(input.toLowerCase()) >= 0
                  }
                >
                  {backends.map(backend => (
                    <Option key={backend.name} value={backend.name}>
                      {backend.name} ({backend.servers?.length || 0} servers)
                    </Option>
                  ))}
                </Select>
              </Form.Item>
            </Panel>

            {/* SSL Configuration */}
            <Panel header="SSL/TLS Configuration" key="2" forceRender>
              <Form.Item
                name="ssl_enabled"
                label="Enable SSL/TLS"
                valuePropName="checked"
                extra="Enable HTTPS/SSL support for this frontend"
              >
                <Switch 
                  checkedChildren="SSL ON" 
                  unCheckedChildren="SSL OFF"
                  onChange={(checked) => {
                    updateSSLVisibility(checked);
                  }}
                />
              </Form.Item>

              {/* SSL Fields - Always registered in form, visibility controlled via state */}
              <Row gutter={16} className="ssl-fields">
                <Col span={24}>
                  <Form.Item
                    name="ssl_certificate_ids"
                    label="SSL Certificates"
                    extra="🆕 Select one or more SSL certificates - HAProxy will use SNI (Server Name Indication) to serve the correct certificate based on hostname"
                  >
                            <Select 
                              mode="multiple"
                              placeholder="Select SSL certificate(s)" 
                              allowClear
                              showSearch
                              filterOption={(input, option) =>
                                option.children.toLowerCase().includes(input.toLowerCase())
                              }
                            >
                              {sslCertificates.map(cert => {
                                const statusIcon = cert.status === 'valid' ? 'Valid' : 
                                                  cert.status === 'expiring_soon' ? 'Expiring' : 'Expired';
                                const expiryInfo = cert.days_until_expiry !== undefined ? 
                                  `(${cert.days_until_expiry} days)` : '';
                                const sslTypeTag = cert.ssl_type === 'Global' ? 'Global' : 'Cluster';
                                
                                return (
                                  <Option key={cert.id} value={cert.id}>
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
              <Row gutter={16} className="ssl-fields">
                <Col span={24}>
                  <Form.Item
                    name="ssl_verify"
                    label="Client Certificate Verification"
                    extra="Level of client certificate verification"
                  >
                            <Select defaultValue="optional">
                              <Option value="none">None - No client certificate required</Option>
                              <Option value="optional">Optional - Accept connections with or without client cert</Option>
                              <Option value="required">Required - Client certificate mandatory</Option>
                            </Select>
                  </Form.Item>
                </Col>
              </Row>
            </Panel>

            {/* Advanced Options */}
            <Panel header="Advanced Options" key="3" forceRender>
              <Row gutter={16}>
                <Col span={8}>
                  <Form.Item
                    name="timeout_client"
                    label="Client Timeout (ms)"
                    extra="Maximum time to wait for client data"
                  >
                    <InputNumber style={{ width: '100%' }} min={1000} max={300000} placeholder="30000" />
                  </Form.Item>
                </Col>
                <Col span={8}>
                  <Form.Item
                    name="timeout_http_request"
                    label="HTTP Request Timeout (ms)"
                    extra="Maximum time to wait for complete HTTP request"
                  >
                    <InputNumber style={{ width: '100%' }} min={1000} max={300000} placeholder="10000" />
                  </Form.Item>
                </Col>
                <Col span={8}>
                  <Form.Item
                    name="rate_limit"
                    label="Rate Limit (req/sec)"
                    extra="Maximum requests per second per client IP"
                  >
                    <InputNumber style={{ width: '100%' }} min={1} placeholder="100" />
                  </Form.Item>
                </Col>
              </Row>

              <Row gutter={16}>
                <Col span={8}>
                  <Form.Item
                    name="compression"
                    label="Enable Compression"
                    valuePropName="checked"
                    extra="Compress responses to reduce bandwidth"
                  >
                    <Switch />
                  </Form.Item>
                </Col>
                <Col span={8}>
                  <Form.Item
                    name="log_separate"
                    label="Separate Logging"
                    valuePropName="checked"
                    extra="Use separate log file for this frontend"
                  >
                    <Switch />
                  </Form.Item>
                </Col>
                <Col span={8}>
                  <Form.Item
                    name="monitor_uri"
                    label="Monitor URI"
                    extra="URI for health monitoring (e.g., /health)"
                  >
                    <Input placeholder="/health" />
                  </Form.Item>
                </Col>
              </Row>
            </Panel>

            {/* ACL Rules */}
            <Panel header="Access Control Lists (ACL)" key="4" forceRender>
              <Alert
                message="ACL Rules"
                description="Define rules to match requests and route them to specific backends. Each rule is evaluated in order."
                type="info"
                style={{ marginBottom: 16 }}
              />
              
              <Form.Item
                name="acl_rules"
                label="ACL Rules"
                extra="One rule per line. Format: acl_name condition value"
              >
                <TextArea
                  rows={6}
                  placeholder={`Examples:
acl is_api path_beg /api
acl is_static path_end .css .js .png .jpg
acl is_admin src 192.168.1.0/24
acl host_example hdr(host) -i example.com`}
                />
              </Form.Item>

              <Form.Item
                name="use_backend_rules"
                label="Backend Routing Rules"
                extra="Route requests to specific backends based on ACL conditions"
              >
                <TextArea
                  rows={4}
                  placeholder={`Examples:
use_backend api_servers if is_api
use_backend static_servers if is_static
use_backend admin_servers if is_admin`}
                />
              </Form.Item>
            </Panel>

            {/* Header Manipulation */}
            <Panel header="Header Manipulation" key="5" forceRender>
              <Row gutter={16}>
                <Col span={12}>
                  <Form.Item
                    name="request_headers"
                    label="Request Header Rules"
                    extra="Modify request headers sent to backend"
                  >
                    <TextArea
                      rows={4}
                      placeholder={`Examples:
http-request add-header X-Forwarded-Proto https
http-request set-header X-Real-IP %[src]
http-request del-header X-Powered-By`}
                    />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item
                    name="response_headers"
                    label="Response Header Rules"
                    extra="Modify response headers sent to client"
                  >
                    <TextArea
                      rows={4}
                      placeholder={`Examples:
http-response add-header X-Frame-Options SAMEORIGIN
http-response add-header X-Content-Type-Options nosniff
http-response del-header Server`}
                    />
                  </Form.Item>
                </Col>
              </Row>

              <Row gutter={16}>
                <Col span={24}>
                  <Form.Item
                    name="tcp_request_rules"
                    label="TCP Request Rules (TCP Mode Only)"
                    extra="TCP-level request inspection and filtering rules"
                    tooltip="Used for TCP mode frontends to inspect and filter connections"
                  >
                    <TextArea
                      rows={4}
                      placeholder={`Examples:
tcp-request inspect-delay 5s
tcp-request content accept if { req_ssl_hello_type 1 }
tcp-request connection reject if { src -f /etc/haproxy/blacklist.lst }`}
                    />
                  </Form.Item>
                </Col>
              </Row>
            </Panel>
          </Collapse>

          <Form.Item style={{ marginBottom: 0, textAlign: 'right', marginTop: 24 }}>
            <Space>
              <Button onClick={() => setModalVisible(false)}>
                Cancel
              </Button>
              <Button type="primary" htmlType="submit" loading={submitting}>
                {submitting 
                  ? (editingFrontend ? 'Updating...' : 'Creating...') 
                  : (editingFrontend ? 'Update' : 'Create')} Frontend
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

function FrontendManagementWithErrorBoundary() {
  return (
    <FrontendErrorBoundary>
      <FrontendManagement />
    </FrontendErrorBoundary>
  );
}

export { FrontendManagementWithErrorBoundary as FrontendManagement };
export default FrontendManagementWithErrorBoundary; 