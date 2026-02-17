import React, { useState, useEffect, useContext } from 'react';
import {
  Card, Table, Button, Modal, Form, Input, Space, message, 
  Popconfirm, Tag, Tooltip, Row, Col, Typography, Alert, Badge,
  Progress, Tabs, Select, Switch, Spin
} from 'antd';
import { getAgentSyncColor, getConfigStatusColor, getEntityStatusColor } from '../utils/colors';
import EntitySyncStatus from './EntitySyncStatus';
import {
  PlusOutlined, DeleteOutlined, ReloadOutlined,
  LockOutlined, EyeOutlined, WarningOutlined,
  SafetyCertificateOutlined, SearchOutlined,
  PlayCircleOutlined, EditOutlined,
  CloudServerOutlined, CheckCircleOutlined, SyncOutlined,
  ExclamationCircleOutlined, CloseCircleOutlined, ClockCircleOutlined
} from '@ant-design/icons';
import axios from 'axios';
import { useCluster } from '../contexts/ClusterContext';
import { useProgress } from '../contexts/ProgressContext';
import { formatEntityForSync } from '../utils/agentSync';

const { Title, Text } = Typography;
const { TextArea } = Input;
const { TabPane } = Tabs;

const SSLManagement = () => {
  const { selectedCluster, clusters } = useCluster();
  const [certificates, setCertificates] = useState([]);
  const [filteredCertificates, setFilteredCertificates] = useState([]);
  const [searchText, setSearchText] = useState('');
  const [loading, setLoading] = useState(false);
  const [modalVisible, setModalVisible] = useState(false);
  const [viewModalVisible, setViewModalVisible] = useState(false);
  const [selectedCertificate, setSelectedCertificate] = useState(null);
  const [pendingChanges, setPendingChanges] = useState(false);
  const [usageSearch, setUsageSearch] = useState('');
  const [deploymentData, setDeploymentData] = useState([]);
  const [deploymentLoading, setDeploymentLoading] = useState(false);
  const [form] = Form.useForm();
  
  // Filter states with localStorage persistence
  const [showGlobal, setShowGlobal] = useState(() => {
    const saved = localStorage.getItem('ssl_filter_global');
    return saved !== null ? JSON.parse(saved) : true;
  });
  const [showClusterSpecific, setShowClusterSpecific] = useState(() => {
    const saved = localStorage.getItem('ssl_filter_cluster');
    return saved !== null ? JSON.parse(saved) : true;
  });

  // Filter toggle handlers
  const toggleGlobalFilter = () => {
    const newValue = !showGlobal;
    setShowGlobal(newValue);
    localStorage.setItem('ssl_filter_global', JSON.stringify(newValue));
  };

  const toggleClusterFilter = () => {
    const newValue = !showClusterSpecific;
    setShowClusterSpecific(newValue);
    localStorage.setItem('ssl_filter_cluster', JSON.stringify(newValue));
  };

  // Apply filters whenever certificates or filter states change
  useEffect(() => {
    let filtered = certificates;
    
    // Apply SSL type filters
    if (!showGlobal || !showClusterSpecific) {
      filtered = filtered.filter(cert => {
        if (cert.ssl_type === 'Global' && !showGlobal) return false;
        if (cert.ssl_type === 'Cluster-specific' && !showClusterSpecific) return false;
        return true;
      });
    }
    
    // Apply search filter
    if (searchText) {
      filtered = filtered.filter(cert =>
        cert.name.toLowerCase().includes(searchText.toLowerCase()) ||
        cert.domain.toLowerCase().includes(searchText.toLowerCase()) ||
        (cert.issuer && cert.issuer.toLowerCase().includes(searchText.toLowerCase()))
      );
    }
    
    setFilteredCertificates(filtered);
  }, [certificates, showGlobal, showClusterSpecific, searchText]);

  useEffect(() => {
    if (selectedCluster) {
      fetchCertificates();
      checkPendingChanges();
    } else {
      // Clear certificates when no cluster is selected
      setCertificates([]);
      setFilteredCertificates([]);
      setPendingChanges(false);
    }
  }, [selectedCluster]);

  const fetchCertificates = async () => {
    if (!selectedCluster) return;
    
    setLoading(true);
    // Clear existing certificates immediately when fetching new cluster data
    setCertificates([]);
    setFilteredCertificates([]);
    
    try {
      const response = await axios.get(`/api/ssl/certificates?cluster_id=${selectedCluster.id}`, {
        headers: {
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache'
        }
      });
      // Handle different response formats
      const certs = response.data.certificates || response.data || [];
      console.log('SSL FETCH DEBUG: Response structure:', {
        'response.data': Object.keys(response.data),
        'certificates count': certs.length,
        'sample cert': certs[0] ? {
          name: certs[0].name,
          has_pending_config: certs[0].has_pending_config,
          last_config_status: certs[0].last_config_status
        } : null
      });
      setCertificates(certs);
      setFilteredCertificates(certs);
    } catch (error) {
      console.error('SSL certificates fetch error:', error);
      message.error('Failed to fetch SSL certificates: ' + error.message);
      setCertificates([]);
      setFilteredCertificates([]);
    } finally {
      setLoading(false);
    }
  };

  // Search filter function  
  const handleSearch = (value) => {
    setSearchText(value);
    if (!value) {
      setFilteredCertificates(certificates || []);
    } else {
      const filtered = certificates.filter(cert =>
        cert.name.toLowerCase().includes(value.toLowerCase()) ||
        cert.domain.toLowerCase().includes(value.toLowerCase())
      );
      setFilteredCertificates(filtered);
    }
  };

  // Update filtered data when certificates change
  useEffect(() => {
    if (searchText) {
      handleSearch(searchText);
    } else {
      setFilteredCertificates(certificates);
    }
  }, [certificates, searchText]);

  // Check for pending SSL configuration changes
  const checkPendingChanges = async () => {
    if (!selectedCluster) return;
    
    try {
      console.log('SSL APPLY DEBUG: Checking pending changes for cluster:', selectedCluster.id);
      const response = await axios.get(`/api/clusters/${selectedCluster.id}/config-versions`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      
      const versions = response.data.config_versions || response.data.versions || response.data || [];
      console.log('SSL APPLY DEBUG: Versions type:', typeof versions, 'Array?', Array.isArray(versions), 'Value:', versions);
      
      if (!Array.isArray(versions)) {
        console.error('SSL APPLY DEBUG: versions is not an array!', versions);
        setPendingChanges(false);
        return;
      }
      
      const pendingVersions = versions.filter(version => 
        version.status === 'PENDING' && 
        version.version_name.includes('ssl-')
      );
      
      console.log('SSL APPLY DEBUG: Total versions:', versions.length);
      console.log('SSL APPLY DEBUG: SSL pending versions:', pendingVersions.length);
      console.log('SSL APPLY DEBUG: Pending SSL versions:', pendingVersions.map(v => v.version_name));
      
      setPendingChanges(pendingVersions.length > 0);
      
    } catch (error) {
      console.error('SSL APPLY DEBUG: Failed to check pending changes:', error);
      setPendingChanges(false);
    }
  };

  // Fetch entity agent sync status (consistent with other pages)
  const fetchEntityAgentSync = async (entityType, entityId) => {
    if (!selectedCluster) return null;
    try {
      const token = localStorage.getItem('token');
      
      // SSL certificates use a special endpoint for agent sync
      let endpoint;
      if (entityType === 'ssl_certificates') {
        endpoint = `/api/clusters/${selectedCluster.id}/ssl_certificates/${entityId}/agent-sync`;
      } else {
        endpoint = `/api/clusters/${selectedCluster.id}/entity-sync/${entityType}/${entityId}`;
      }
      
      const response = await axios.get(endpoint, {
        headers: { Authorization: `Bearer ${token}` }
      });
      return response.data;
    } catch (error) {
      console.error(`Failed to fetch entity sync for ${entityType}/${entityId}:`, error);
      return null;
    }
  };

  const handleAdd = () => {
    form.resetFields();
    // Set default values for new certificate
    form.setFieldsValue({
      ssl_type: 'cluster',
      usage_type: 'frontend'  // Default to frontend SSL
    });
    setSelectedCertificate(null);
    setModalVisible(true);
  };

  const handleView = async (certificate) => {
    try {
      const response = await axios.get(`/api/ssl/certificates/${certificate.id}`);
      setSelectedCertificate(response.data);
      setUsageSearch('');
      setViewModalVisible(true);
    } catch (error) {
      message.error('Failed to load certificate details: ' + error.message);
    }
  };

  const handleEdit = async (certificate) => {
    try {
      const response = await axios.get(`/api/ssl/certificates/${certificate.id}`);
      const cert = response.data;
      
      // Pre-fill form with certificate data
      form.setFieldsValue({
        name: cert.name,
        certificate_content: cert.certificate_content,
        private_key_content: cert.private_key_content,
        chain_content: cert.chain_content,
        ssl_type: cert.is_global ? 'global' : 'cluster',
        cluster_ids: cert.is_global ? null : cert.cluster_ids,
        usage_type: cert.usage_type || 'frontend'
      });
      
      setSelectedCertificate(cert);
      setModalVisible(true);
    } catch (error) {
      message.error('Failed to load certificate for editing: ' + error.message);
    }
  };

  const handleDelete = async (certificateId) => {
    try {
      const response = await axios.delete(`/api/ssl/certificates/${certificateId}`);
      
      // Handle cluster sync results
      const syncResults = response.data.sync_results || [];
      const totalNodes = syncResults.length;
      const successCount = syncResults.filter(result => result.success).length;
      
      if (syncResults.length > 0) {
        if (successCount === totalNodes) {
          message.success(
            <div>
              <div><strong>SSL certificate deleted successfully</strong></div>
              <div style={{ marginTop: 4, fontSize: '12px' }}>
                {successCount}/{totalNodes} nodes updated successfully
              </div>
            </div>,
            6
          );
        } else {
          message.warning(
            <div>
              <div><strong>SSL certificate deleted with warnings</strong></div>
              <div style={{ marginTop: 4, fontSize: '12px' }}>
                {successCount}/{totalNodes} nodes updated successfully
                <br />Some nodes may need manual cleanup
              </div>
            </div>,
            8
          );
        }
      } else {
        message.success('SSL certificate deleted successfully');
      }
      
      fetchCertificates();
    } catch (error) {
      message.error('Failed to delete certificate: ' + error.response?.data?.detail);
    }
  };

  const handleSubmit = async (values) => {
    // Check if editing existing certificate (define at function scope)
    const isEditing = selectedCertificate && selectedCertificate.id;
    
    try {
      // Prepare payload with new SSL model
      const payload = {
        name: values.name,
        certificate_content: values.certificate_content,
        private_key_content: values.private_key_content,
        chain_content: values.chain_content,
        is_global: values.ssl_type === 'global',
        cluster_ids: values.ssl_type === 'global' ? null : values.cluster_ids,
        usage_type: values.usage_type || 'frontend'
      };
      const response = isEditing 
        ? await axios.put(`/api/ssl/certificates/${selectedCertificate.id}`, payload)
        : await axios.post('/api/ssl/certificates', payload);
      
      // Handle cluster sync results
      const syncResults = response.data.sync_results || [];
      const totalNodes = syncResults.length;
      const successCount = syncResults.filter(result => result.success).length;
      
      if (syncResults.length > 0) {
        if (successCount === totalNodes) {
          message.success(
            <div>
              <div><strong>SSL certificate {isEditing ? 'updated' : 'added'} successfully</strong></div>
              <div style={{ marginTop: 4, fontSize: '12px' }}>
                {successCount}/{totalNodes} nodes updated successfully
              </div>
            </div>,
            6
          );
        } else {
          message.warning(
            <div>
              <div><strong>SSL certificate {isEditing ? 'updated' : 'added'} with warnings</strong></div>
              <div style={{ marginTop: 4, fontSize: '12px' }}>
                {successCount}/{totalNodes} nodes updated successfully
                <br />Some nodes may need manual certificate deployment
              </div>
            </div>,
            8
          );
        }
      } else {
        message.success(`SSL certificate ${isEditing ? 'updated' : 'added'} successfully`);
      }
      
      setModalVisible(false);
      setSelectedCertificate(null);
      fetchCertificates();
      checkPendingChanges();
    } catch (error) {
      console.error('SSL certificate operation failed:', error);
      
      // Handle specific error cases with user-friendly messages
      if (error.response?.status === 400) {
        const errorDetail = error.response?.data?.detail || '';
        
        if (errorDetail.includes('already exists')) {
          // SSL name already exists error
          Modal.error({
            title: 'SSL Certificate Name Already Exists',
            content: (
              <div>
                <p>A certificate with the name <strong>"{form.getFieldValue('name')}"</strong> already exists.</p>
                <p>Please choose one of the following options:</p>
                <ul style={{ paddingLeft: 20, marginTop: 10 }}>
                  <li>Choose a different name for your certificate</li>
                  <li>Delete the existing certificate first if you want to replace it</li>
                  <li>Edit the existing certificate instead of creating a new one</li>
                </ul>
              </div>
            ),
            okText: 'Got it',
            width: 500
          });
        } else if (errorDetail.includes('Invalid SSL certificate')) {
          // Invalid certificate content error
          Modal.error({
            title: 'Invalid SSL Certificate',
            content: (
              <div>
                <p><strong>Certificate validation failed:</strong></p>
                <p style={{ color: '#ff4d4f', fontFamily: 'monospace', background: '#fff2f0', padding: 8, borderRadius: 4 }}>
                  {errorDetail}
                </p>
                <p style={{ marginTop: 10 }}>Please check your certificate content and try again.</p>
              </div>
            ),
            okText: 'Fix Certificate',
            width: 600
          });
        } else {
          // Other 400 errors
          message.error(`Certificate validation error: ${errorDetail}`);
        }
      } else if (error.response?.status === 401) {
        message.error('Authentication failed. Please login again.');
      } else if (error.response?.status === 403) {
        message.error('You do not have permission to perform this action.');
      } else {
        // Generic error
        message.error(`Failed to ${isEditing ? 'update' : 'add'} certificate: ${error.response?.data?.detail || error.message}`);
      }
    }
  };

  const getExpiryStatus = (expiryDate, expiresSoon) => {
    if (!expiryDate) return { status: 'default', text: 'No expiry set' };
    
    const days = Math.ceil((new Date(expiryDate) - new Date()) / (1000 * 60 * 60 * 24));
    
    if (days < 0) return { status: 'error', text: 'Expired' };
    if (days <= 7) return { status: 'error', text: `${days} days left` };
    if (days <= 30) return { status: 'warning', text: `${days} days left` };
    return { status: 'success', text: `${days} days left` };
  };

  const fetchDeploymentStatus = async (cert) => {
    if (!cert) return;
    setDeploymentLoading(true);
    setDeploymentData([]);
    
    try {
      const token = localStorage.getItem('token');
      const targetClusters = cert.cluster_names && cert.cluster_names.length > 0
        ? clusters.filter(c => cert.cluster_names.includes(c.name))
        : clusters;
      
      const results = await Promise.allSettled(
        targetClusters.map(async (cluster) => {
          try {
            const response = await axios.get(
              `/api/clusters/${cluster.id}/ssl_certificates/${cert.id}/agent-sync`,
              { headers: { Authorization: `Bearer ${token}` } }
            );
            return {
              cluster_id: cluster.id,
              cluster_name: cluster.name,
              ...response.data.sync_status,
              ssl_config_status: response.data.ssl_config_status,
              version_applied_at: response.data.version_applied_at,
              latest_applied_version: response.data.latest_applied_version,
              agents: response.data.agents || [],
              error: null
            };
          } catch (err) {
            return {
              cluster_id: cluster.id,
              cluster_name: cluster.name,
              error: err.response?.status === 404 ? 'No data' : err.message
            };
          }
        })
      );
      
      setDeploymentData(results.map(r => r.status === 'fulfilled' ? r.value : { error: 'Request failed' }));
    } catch (error) {
      console.error('Failed to fetch deployment status:', error);
    } finally {
      setDeploymentLoading(false);
    }
  };

  const columns = [
    {
      title: 'Certificate',
      dataIndex: 'name',
      key: 'name',
      render: (text, record) => (
        <Space>
          <SafetyCertificateOutlined style={{ color: '#52c41a' }} />
          <div>
            <strong>{text}</strong>
            <br />
            <Text type="secondary" style={{ fontSize: 12 }}>
              {record.domain}
            </Text>
          </div>
        </Space>
      ),
    },
    {
      title: 'Scope',
      dataIndex: 'ssl_type',
      key: 'ssl_type',
      render: (type, record) => {
        const isGlobal = type === 'Global';
        return (
          <Tag color={isGlobal ? 'blue' : 'green'}>
            {isGlobal ? 'Global' : 'Cluster-specific'}
          </Tag>
        );
      },
    },
    {
      title: 'Usage',
      dataIndex: 'usage_type',
      key: 'usage_type',
      render: (usage_type) => {
        const isFrontend = usage_type === 'frontend';
        return (
          <Tag color={isFrontend ? 'purple' : 'orange'}>
            {isFrontend ? 'Frontend SSL' : 'Server SSL'}
          </Tag>
        );
      },
    },
    {
      title: 'Sync Status',
      key: 'sync_status',
      render: (_, record) => (
        <EntitySyncStatus
          entityType="ssl_certificates"
          entityId={record.id}
          entityUpdatedAt={record.updated_at}
          lastConfigStatus={record.last_config_status}
          clusterId={selectedCluster?.id}
          selectedCluster={selectedCluster}
        />
      ),
    },
    {
      title: 'Expiry Status',
      dataIndex: 'expiry_date',
      key: 'expiry_status',
      render: (expiryDate, record) => {
        const status = getExpiryStatus(expiryDate, record.expires_soon);
        return (
          <Badge 
            status={status.status} 
            text={status.text}
          />
        );
      },
    },
    {
      title: 'Expiry Date',
      dataIndex: 'expiry_date',
      key: 'expiry_date',
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
      title: 'Config Status',
      key: 'config_status',
      render: (_, record) => {
        const status = record.last_config_status || 'APPLIED';
        const color = getConfigStatusColor(status);
        return (
          <Tag color={color}>{status}</Tag>
        );
      },
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
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Space size="small">
          {(record.last_config_status === 'PENDING') && (
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

          <Tooltip title="View Certificate">
            <Button
              size="small"
              icon={<EyeOutlined />}
              onClick={() => handleView(record)}
            />
          </Tooltip>
          <Tooltip title="Edit Certificate">
            <Button
              size="small"
              icon={<EditOutlined />}
              onClick={() => handleEdit(record)}
            />
          </Tooltip>
          <Popconfirm
            title="Are you sure you want to delete this certificate?"
            description="This action cannot be undone and may affect frontends using this certificate."
            onConfirm={() => handleDelete(record.id)}
            okText="Yes"
            cancelText="No"
          >
            <Tooltip title="Delete Certificate">
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

  const expiringSoon = certificates?.filter(cert => cert.expires_soon) || [];

  return (
    <div>
      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col span={12}>
          <Title level={2} style={{ margin: 0 }}>
            <LockOutlined style={{ marginRight: 8, color: '#52c41a' }} />
            SSL Certificate Management
            {selectedCluster && (
              <Text type="secondary" style={{ fontSize: '14px', fontWeight: 'normal', marginLeft: '8px' }}>
                - {selectedCluster.name}
              </Text>
            )}
          </Title>
        </Col>
        <Col span={12} style={{ textAlign: 'right' }}>
          <Space wrap size={[8, 8]}>
            <Space>
              <span style={{ fontSize: 12 }}>Global</span>
              <Switch
                checked={showGlobal}
                onChange={toggleGlobalFilter}
                size="small"
              />
            </Space>
            <Space>
              <span style={{ fontSize: 12 }}>Cluster-specific</span>
              <Switch
                checked={showClusterSpecific}
                onChange={toggleClusterFilter}
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
                placeholder="Search certificates..."
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
              onClick={fetchCertificates}
              loading={loading}
            >
              Refresh
            </Button>
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={handleAdd}
              disabled={!selectedCluster}
            >
              Add Certificate
            </Button>
          </Space>
        </Col>
      </Row>

      {expiringSoon.length > 0 && (
        <Alert
          message="Certificates Expiring Soon"
          description={
            <div>
              {expiringSoon.map(cert => (
                <div key={cert.id}>
                  <strong>{cert.name}</strong> ({cert.domain}) - 
                  {getExpiryStatus(cert.expiry_date, cert.expires_soon).text}
                </div>
              ))}
            </div>
          }
          type="warning"
          showIcon
          icon={<WarningOutlined />}
          style={{ marginBottom: 16 }}
        />
      )}

      {!selectedCluster && (
        <Alert
          message="No Cluster Selected"
          description="Please select a cluster from the top navigation to manage SSL certificates."
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
        />
      )}

      <Row gutter={16} style={{ marginBottom: 16 }}>
        <Col span={6}>
          <Card size="small" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 20, fontWeight: 'bold', color: '#52c41a' }}>
              {certificates.length}
            </div>
            <div>Total Certificates</div>
          </Card>
        </Col>
        <Col span={6}>
          <Card size="small" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 20, fontWeight: 'bold', color: '#1890ff' }}>
              {certificates.filter(c => c.usage_count > 0).length}
            </div>
            <div>In Use</div>
          </Card>
        </Col>
        <Col span={6}>
          <Card size="small" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 20, fontWeight: 'bold', color: '#faad14' }}>
              {expiringSoon.length}
            </div>
            <div>Expiring Soon</div>
          </Card>
        </Col>
        <Col span={6}>
          <Card size="small" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 20, fontWeight: 'bold', color: '#ff4d4f' }}>
              {certificates.filter(c => c.expiry_date && new Date(c.expiry_date) < new Date()).length}
            </div>
            <div>Expired</div>
          </Card>
        </Col>
      </Row>

      <Card>
        <Table
          columns={columns}
          dataSource={filteredCertificates}
          rowKey="id"
          loading={loading}
          pagination={{
            showSizeChanger: true,
            showQuickJumper: true,
            showTotal: (total, range) =>
              `${range[0]}-${range[1]} of ${total} certificates`,
          }}
        />
      </Card>

      {/* Add Certificate Modal */}
      <Modal
        title={selectedCertificate && selectedCertificate.id ? "Edit SSL Certificate" : "Add SSL Certificate"}
        open={modalVisible}
        onCancel={() => {
          setModalVisible(false);
          setSelectedCertificate(null);
        }}
        footer={null}
        width={800}
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={handleSubmit}
        >
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item
                name="name"
                label="Certificate Name"
                rules={[
                  { required: true, message: 'Please enter certificate name' },
                  { pattern: /^[a-zA-Z0-9_-]+$/, message: 'Only alphanumeric, underscore and dash allowed' }
                ]}
                extra={selectedCertificate && selectedCertificate.id ? "Certificate name cannot be changed (used as file path on servers)" : "Used as file path: /etc/ssl/haproxy/{name}.pem"}
                tooltip={selectedCertificate && selectedCertificate.id ? "Certificate name is immutable after creation to maintain file system references" : null}
              >
                <Input 
                  placeholder="e.g., my-domain-cert" 
                  disabled={selectedCertificate && selectedCertificate.id ? true : false}
                />
              </Form.Item>
            </Col>
          </Row>

          {/* SSL Type and Cluster Selection */}
          <Row gutter={16}>
            <Col span={8}>
              <Form.Item
                name="usage_type"
                label="SSL Usage Type"
                rules={[{ required: true, message: 'Please select usage type' }]}
                tooltip="Frontend SSL requires private key, Server SSL does not"
              >
                <Select placeholder="Select usage type">
                  <Select.Option value="frontend">Frontend SSL (HAProxy Listen)</Select.Option>
                  <Select.Option value="server">Server SSL (Backend Verification)</Select.Option>
                </Select>
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item
                name="ssl_type"
                label="SSL Certificate Scope"
                rules={[{ required: true, message: 'Please select SSL scope' }]}
              >
                <Select
                  placeholder="Select SSL scope"
                  onChange={(value) => {
                    form.setFieldsValue({ cluster_ids: undefined });
                  }}
                >
                  <Select.Option value="global">Global (All Clusters)</Select.Option>
                  <Select.Option value="cluster">Cluster-specific</Select.Option>
                </Select>
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item shouldUpdate={(prevValues, currentValues) => prevValues.ssl_type !== currentValues.ssl_type}>
                {({ getFieldValue }) => {
                  const sslType = getFieldValue('ssl_type');
                  return (
                    <Form.Item
                      name="cluster_ids"
                      label="Target Clusters"
                      rules={[
                        {
                          validator: (_, value) => {
                            if (sslType === 'cluster' && (!value || value.length === 0)) {
                              return Promise.reject('Please select at least one cluster');
                            }
                            return Promise.resolve();
                          }
                        }
                      ]}
                    >
                      <Select
                        mode="multiple"
                        placeholder="Select clusters for this SSL certificate"
                        disabled={sslType === 'global'}
                        showSearch
                        filterOption={(input, option) =>
                          option.children.toLowerCase().indexOf(input.toLowerCase()) >= 0
                        }
                      >
                        {(clusters || []).map(cluster => (
                          <Select.Option key={cluster.id} value={cluster.id}>
                            {cluster.name}
                          </Select.Option>
                        ))}
                      </Select>
                    </Form.Item>
                  );
                }}
              </Form.Item>
            </Col>
          </Row>

          <Alert
            message="🔐 Auto-parsing Enabled"
            description="Domain and expiry date will be automatically extracted from the certificate content. Just paste your PEM certificate, private key, and optional certificate chain."
            type="info"
            showIcon
            style={{ marginBottom: 16 }}
          />

          <Form.Item
            name="certificate_content"
            label="Certificate Content (PEM Format)"
            rules={[{ required: true, message: 'Please enter certificate content' }]}
            extra="Domain and expiry date will be automatically parsed from this certificate"
          >
            <TextArea
              rows={8}
              placeholder="-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKoK/OvD...
-----END CERTIFICATE-----"
            />
          </Form.Item>

          <Form.Item
            noStyle
            shouldUpdate={(prevValues, currentValues) => prevValues.usage_type !== currentValues.usage_type}
          >
            {({ getFieldValue }) => {
              const usageType = getFieldValue('usage_type');
              const isRequired = usageType === 'frontend';
              
              return (
                <Form.Item
                  name="private_key_content"
                  label={
                    <span>
                      Private Key Content (PEM Format)
                      {isRequired && <span style={{ color: 'red' }}> *</span>}
                      {usageType === 'server' && <span style={{ color: '#999', fontWeight: 'normal' }}> - Optional</span>}
                    </span>
                  }
                  rules={[
                    {
                      required: isRequired,
                      message: 'Private key is required for Frontend SSL'
                    },
                    {
                      validator: (_, value) => {
                        // If value provided, validate format
                        if (value && value.trim()) {
                          if (!value.includes('-----BEGIN') || !value.includes('-----END')) {
                            return Promise.reject('Private key must be in PEM format');
                          }
                        }
                        return Promise.resolve();
                      }
                    }
                  ]}
                  extra={isRequired ? 
                    <span style={{ color: '#ff4d4f' }}>Required for Frontend SSL</span> : 
                    <span style={{ color: '#52c41a' }}>Optional for Server SSL (used for backend verification)</span>
                  }
                >
                  <TextArea
                    rows={8}
                    placeholder="-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEF...
-----END PRIVATE KEY-----"
                  />
                </Form.Item>
              );
            }}
          </Form.Item>

          <Form.Item
            name="chain_content"
            label="Certificate Chain (Optional)"
            extra="Intermediate certificates for full chain validation"
          >
            <TextArea
              rows={4}
              placeholder="-----BEGIN CERTIFICATE-----
...intermediate certificate...
-----END CERTIFICATE-----"
            />
          </Form.Item>



          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space>
              <Button onClick={() => setModalVisible(false)}>
                Cancel
              </Button>
              <Button type="primary" htmlType="submit">
                {selectedCertificate && selectedCertificate.id ? 'Update Certificate' : 'Add Certificate'}
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* View Certificate Modal */}
      <Modal
        title={`Certificate Details: ${selectedCertificate?.name}`}
        open={viewModalVisible}
        onCancel={() => setViewModalVisible(false)}
        footer={[
          <Button key="close" onClick={() => setViewModalVisible(false)}>
            Close
          </Button>
        ]}
        width={900}
      >
        {selectedCertificate && (
          <Tabs defaultActiveKey="1">
            <TabPane tab="General Info" key="1">
              <Row gutter={16}>
                <Col span={12}>
                  <Card size="small" title="Certificate Info">
                    <p><strong>Name:</strong> {selectedCertificate.name}</p>
                    <p><strong>Domain:</strong> {selectedCertificate.domain}</p>
                    <p><strong>Usage:</strong> 
                      <Badge 
                        status={selectedCertificate.usage_count > 0 ? 'success' : 'warning'} 
                        text={selectedCertificate.usage_count > 0
                          ? `In Use (${selectedCertificate.usage_count})`
                          : 'Not In Use'} 
                        style={{ marginLeft: 8 }}
                      />
                    </p>
                    <p><strong>Created:</strong> {new Date(selectedCertificate.created_at).toLocaleString(undefined, {
                      year: 'numeric',
                      month: 'short',
                      day: 'numeric',
                      hour: '2-digit',
                      minute: '2-digit',
                      second: '2-digit'
                    })}</p>
                  </Card>
                </Col>
                <Col span={12}>
                  <Card size="small" title="Expiry Info">
                    <p><strong>Expiry Date:</strong> {selectedCertificate.expiry_date ? new Date(selectedCertificate.expiry_date).toLocaleString(undefined, {
                      year: 'numeric',
                      month: 'short',
                      day: 'numeric',
                      hour: '2-digit',
                      minute: '2-digit',
                      second: '2-digit'
                    }) : 'Not set'}</p>
                    {selectedCertificate.expiry_date && (
                      <>
                        <p><strong>Status:</strong> 
                          <Badge 
                            {...getExpiryStatus(selectedCertificate.expiry_date)}
                            style={{ marginLeft: 8 }}
                          />
                        </p>
                        <Progress 
                          percent={Math.max(0, Math.min(100, (
                            (new Date(selectedCertificate.expiry_date) - new Date()) / 
                            (365 * 24 * 60 * 60 * 1000) * 100
                          )))}
                          status={new Date(selectedCertificate.expiry_date) < new Date() ? 'exception' : 'active'}
                          format={() => getExpiryStatus(selectedCertificate.expiry_date).text}
                        />
                      </>
                    )}
                  </Card>
                </Col>
              </Row>
            </TabPane>
            <TabPane tab="Certificate Content" key="2">
              <div style={{ marginBottom: 16 }}>
                <Title level={5}>Certificate (PEM)</Title>
                <TextArea
                  value={selectedCertificate.certificate_content}
                  rows={10}
                  readOnly
                  style={{ fontFamily: 'monospace' }}
                />
              </div>
              {selectedCertificate.chain_content && (
                <div>
                  <Title level={5}>Certificate Chain</Title>
                  <TextArea
                    value={selectedCertificate.chain_content}
                    rows={6}
                    readOnly
                    style={{ fontFamily: 'monospace' }}
                  />
                </div>
              )}
            </TabPane>
            <TabPane tab="Private Key" key="3">
              <Alert
                message="Security Warning"
                description="Private key content is sensitive. Only view when necessary and ensure secure handling."
                type="warning"
                showIcon
                style={{ marginBottom: 16 }}
              />
              <TextArea
                value={selectedCertificate.private_key_content}
                rows={12}
                readOnly
                style={{ fontFamily: 'monospace' }}
              />
            </TabPane>
            <TabPane tab={
              <span>
                Usage {selectedCertificate.usage_count > 0 &&
                  <Badge count={selectedCertificate.usage_count} size="small"
                    style={{ marginLeft: 4, backgroundColor: '#1890ff' }} />
                }
              </span>
            } key="4">
              {selectedCertificate.usage_count > 0 ? (
                <div>
                  <Alert
                    message={`In Use — ${selectedCertificate.used_by_frontends?.length || 0} frontend(s), ${selectedCertificate.used_by_servers?.length || 0} server(s)`}
                    type="success"
                    showIcon
                    style={{ marginBottom: 16 }}
                  />
                  <Input
                    placeholder="Search by name, backend, or cluster..."
                    prefix={<SearchOutlined />}
                    allowClear
                    onChange={e => setUsageSearch(e.target.value)}
                    value={usageSearch}
                    style={{ marginBottom: 16 }}
                  />
                  {selectedCertificate.used_by_frontends?.length > 0 && (
                    <div style={{ marginBottom: 16 }}>
                      <Title level={5}>Frontends</Title>
                      <Table
                        dataSource={
                          (selectedCertificate.used_by_frontends || []).filter(f => {
                            if (!usageSearch) return true;
                            const s = usageSearch.toLowerCase();
                            return (f.name || '').toLowerCase().includes(s) ||
                                   (f.cluster_name || '').toLowerCase().includes(s);
                          })
                        }
                        columns={[
                          { title: 'Frontend Name', dataIndex: 'name', key: 'name' },
                          { title: 'Cluster', dataIndex: 'cluster_name', key: 'cluster_name',
                            render: v => v || <Tag color="blue">Global</Tag> }
                        ]}
                        rowKey="id"
                        size="small"
                        pagination={{ pageSize: 5, hideOnSinglePage: true }}
                        locale={{ emptyText: 'No matching frontends' }}
                      />
                    </div>
                  )}
                  {selectedCertificate.used_by_servers?.length > 0 && (
                    <div>
                      <Title level={5}>Backend Servers</Title>
                      <Table
                        dataSource={
                          (selectedCertificate.used_by_servers || []).filter(sv => {
                            if (!usageSearch) return true;
                            const s = usageSearch.toLowerCase();
                            return (sv.server_name || '').toLowerCase().includes(s) ||
                                   (sv.backend_name || '').toLowerCase().includes(s) ||
                                   (sv.cluster_name || '').toLowerCase().includes(s);
                          })
                        }
                        columns={[
                          { title: 'Server Name', dataIndex: 'server_name', key: 'server_name' },
                          { title: 'Backend', dataIndex: 'backend_name', key: 'backend_name' },
                          { title: 'Cluster', dataIndex: 'cluster_name', key: 'cluster_name',
                            render: v => v || <Tag color="blue">Global</Tag> }
                        ]}
                        rowKey="id"
                        size="small"
                        pagination={{ pageSize: 5, hideOnSinglePage: true }}
                        locale={{ emptyText: 'No matching servers' }}
                      />
                    </div>
                  )}
                </div>
              ) : (
                <Alert
                  message="Not In Use"
                  description="This certificate is not referenced by any frontend or backend server."
                  type="warning"
                  showIcon
                />
              )}
            </TabPane>
            <TabPane tab={
              <span>
                <CloudServerOutlined /> Deployment Status
              </span>
            } key="5">
              <div style={{ marginBottom: 16 }}>
                <Button
                  type="primary"
                  icon={<ReloadOutlined />}
                  onClick={() => fetchDeploymentStatus(selectedCertificate)}
                  loading={deploymentLoading}
                >
                  Refresh Deployment Status
                </Button>
              </div>
              {deploymentLoading ? (
                <div style={{ textAlign: 'center', padding: 40 }}>
                  <Spin size="large" />
                  <p style={{ marginTop: 16 }}>Fetching deployment status from all clusters...</p>
                </div>
              ) : deploymentData.length > 0 ? (
                <Table
                  dataSource={deploymentData.filter(d => !d.error)}
                  rowKey="cluster_id"
                  size="small"
                  pagination={false}
                  columns={[
                    {
                      title: 'Cluster',
                      dataIndex: 'cluster_name',
                      key: 'cluster_name',
                      render: (text) => <strong>{text}</strong>
                    },
                    {
                      title: 'Synced Agents',
                      key: 'sync',
                      render: (_, record) => (
                        <span>
                          {record.synced_agents ?? '-'}/{record.total_agents ?? '-'}
                        </span>
                      )
                    },
                    {
                      title: 'Sync %',
                      key: 'sync_pct',
                      render: (_, record) => {
                        const pct = record.sync_percentage ?? 0;
                        return (
                          <Progress
                            percent={pct}
                            size="small"
                            status={pct === 100 ? 'success' : 'active'}
                            style={{ width: 120 }}
                          />
                        );
                      }
                    },
                    {
                      title: 'Offline',
                      key: 'offline',
                      render: (_, record) => {
                        const offline = record.offline_agents || 0;
                        return offline > 0
                          ? <Tag color="orange" icon={<ExclamationCircleOutlined />}>{offline}</Tag>
                          : <Tag color="green">0</Tag>;
                      }
                    },
                    {
                      title: 'Status',
                      key: 'status',
                      render: (_, record) => {
                        if (record.error) return <Tag color="red">Error</Tag>;
                        if (record.ssl_config_status === 'PENDING') return <Tag color="orange" icon={<ClockCircleOutlined />}>NOT APPLIED</Tag>;
                        const pct = record.sync_percentage ?? 0;
                        if (pct === 100) return <Tag color="green" icon={<CheckCircleOutlined />}>SYNCED</Tag>;
                        if (record.synced_agents > 0) return <Tag color="blue" icon={<SyncOutlined spin />}>APPLYING</Tag>;
                        return <Tag color="orange" icon={<ExclamationCircleOutlined />}>PENDING</Tag>;
                      }
                    },
                    {
                      title: 'Applied At',
                      key: 'applied_at',
                      render: (_, record) => {
                        if (record.ssl_config_status === 'PENDING') return <Text type="secondary">-</Text>;
                        return record.version_applied_at
                          ? new Date(record.version_applied_at).toLocaleString()
                          : '-';
                      }
                    }
                  ]}
                  expandable={{
                    expandedRowRender: (record) => (
                      <Table
                        dataSource={record.agents || []}
                        rowKey="name"
                        size="small"
                        pagination={false}
                        columns={[
                          { title: 'Agent', dataIndex: 'name', key: 'name' },
                          {
                            title: 'Status',
                            dataIndex: 'status',
                            key: 'status',
                            render: (v) => (
                              <Tag color={v === 'online' ? 'green' : 'red'}>
                                {v?.toUpperCase() || 'UNKNOWN'}
                              </Tag>
                            )
                          },
                          {
                            title: 'HAProxy',
                            dataIndex: 'haproxy_status',
                            key: 'haproxy_status',
                            render: (v) => (
                              <Tag color={v === 'running' ? 'green' : v === 'stopped' ? 'red' : 'default'}>
                                {v?.toUpperCase() || 'UNKNOWN'}
                              </Tag>
                            )
                          },
                          {
                            title: 'SSL Deployed',
                            dataIndex: 'ssl_file_deployed',
                            key: 'ssl_file_deployed',
                            render: (v) => v === true
                              ? <CheckCircleOutlined style={{ color: '#52c41a' }} />
                              : v === false
                                ? <CloseCircleOutlined style={{ color: '#ff4d4f' }} />
                                : '-'
                          },
                          {
                            title: 'Config Version',
                            dataIndex: 'delivered_version',
                            key: 'delivered_version',
                            render: (v) => v ? <Text code style={{ fontSize: 11 }}>{v}</Text> : '-'
                          }
                        ]}
                      />
                    )
                  }}
                />
              ) : (
                <Alert
                  message="Click 'Refresh Deployment Status' to load per-cluster deployment information."
                  type="info"
                  showIcon
                />
              )}
              {deploymentData.length > 0 && deploymentData.some(d => d.error) && (
                <Alert
                  message={`${deploymentData.filter(d => d.error).length} cluster(s) could not be reached`}
                  type="warning"
                  showIcon
                  style={{ marginTop: 8 }}
                />
              )}
            </TabPane>
          </Tabs>
        )}
      </Modal>
    </div>
  );
};

export { SSLManagement }; 