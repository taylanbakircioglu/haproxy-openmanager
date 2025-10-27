import React, { useState, useEffect } from 'react';
import {
  Card, Button, Space, Row, Col, message, Table, Modal, Spin, 
  Typography, Tag, Descriptions, Alert, Divider, Timeline, Empty,
  Popconfirm, Badge
} from 'antd';
import {
  HistoryOutlined, ReloadOutlined, EyeOutlined, RollbackOutlined,
  CheckCircleOutlined, ClockCircleOutlined, ExclamationCircleOutlined,
  ArrowLeftOutlined, InfoCircleOutlined, UserOutlined, CalendarOutlined
} from '@ant-design/icons';
import MonacoEditor from '@monaco-editor/react';
import axios from 'axios';
import { useCluster } from '../contexts/ClusterContext';
import { useNavigate } from 'react-router-dom';

const { Title, Text, Paragraph } = Typography;

const BulkVersionHistory = () => {
  const { selectedCluster } = useCluster();
  const navigate = useNavigate();
  
  // State
  const [loading, setLoading] = useState(false);
  const [restoreLoading, setRestoreLoading] = useState(false);
  const [configVersions, setConfigVersions] = useState([]);
  const [selectedVersion, setSelectedVersion] = useState(null);
  const [viewConfigModalVisible, setViewConfigModalVisible] = useState(false);
  const [viewChangeModalVisible, setViewChangeModalVisible] = useState(false);
  const [diffData, setDiffData] = useState(null);
  const [diffLoading, setDiffLoading] = useState(false);

  useEffect(() => {
    if (selectedCluster) {
      fetchConfigVersions();
    } else {
      setConfigVersions([]);
    }
  }, [selectedCluster]);

  const fetchConfigVersions = async () => {
    if (!selectedCluster) return;
    
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      if (!token || token === 'null' || token.trim() === '') {
        message.error('Authentication required. Please login again.');
        return;
      }

      const response = await axios.get(
        `/api/clusters/${selectedCluster.id}/config-versions`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      
      setConfigVersions(response.data.config_versions || []);
    } catch (error) {
      console.error('Error fetching config versions:', error);
      message.error('Failed to fetch configuration versions');
    } finally {
      setLoading(false);
    }
  };

  const handleViewConfig = (version) => {
    setSelectedVersion(version);
    setViewConfigModalVisible(true);
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

  const handleRestoreVersion = async (version) => {
    setRestoreLoading(true);
    try {
      const token = localStorage.getItem('token');
      
      // Step 1: Get restore preview
      const previewResponse = await axios.get(
        `/api/clusters/${selectedCluster.id}/config-versions/${version.id}/restore/preview`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      
      const plan = previewResponse.data.restore_plan;
      const summary = plan.summary;
      
      // Step 2: Show confirmation modal with preview
      Modal.confirm({
        title: '🔄 Restore Configuration Preview',
        width: 700,
        content: (
          <div>
            <Alert
              message="This will restore the configuration to a previous state"
              description={`Version: ${version.version_name}`}
              type="warning"
              showIcon
              style={{ marginBottom: 16 }}
            />
            
            <div style={{ marginBottom: 16 }}>
              <Text strong>Summary of Changes:</Text>
              <div style={{ marginTop: 8, padding: 12, backgroundColor: '#f5f5f5', borderRadius: 4 }}>
                <div>✅ <strong>{summary.creates}</strong> entities will be created</div>
                <div>✏️ <strong>{summary.updates}</strong> entities will be updated</div>
                <div>🗑️ <strong>{summary.deletes}</strong> entities will be deleted</div>
                <Divider style={{ margin: '8px 0' }} />
                <div>📊 <strong>{summary.total_changes}</strong> total changes</div>
              </div>
            </div>
            
            {plan.frontends.to_create.length > 0 && (
              <div style={{ marginBottom: 12 }}>
                <Text strong>Frontends to Create ({plan.frontends.to_create.length}):</Text>
                <ul style={{ marginTop: 4, marginBottom: 0 }}>
                  {plan.frontends.to_create.slice(0, 5).map((fe, idx) => (
                    <li key={idx}>{fe.name} (port {fe.bind_port})</li>
                  ))}
                  {plan.frontends.to_create.length > 5 && (
                    <li>... and {plan.frontends.to_create.length - 5} more</li>
                  )}
                </ul>
              </div>
            )}
            
            {plan.frontends.to_update.length > 0 && (
              <div style={{ marginBottom: 12 }}>
                <Text strong>Frontends to Update ({plan.frontends.to_update.length}):</Text>
                <ul style={{ marginTop: 4, marginBottom: 0 }}>
                  {plan.frontends.to_update.slice(0, 5).map((fe, idx) => (
                    <li key={idx}>
                      <strong>{fe.name}</strong>
                      {fe.changes && (
                        <ul style={{ fontSize: '11px', color: '#666', marginTop: 4 }}>
                          {Object.entries(fe.changes).map(([field, change]) => {
                            if (change.from === change.to) return null;
                            return (
                              <li key={field} style={{ marginBottom: 2 }}>
                                <code style={{ backgroundColor: '#f5f5f5', padding: '2px 4px', borderRadius: 2 }}>
                                  {field}
                                </code>: {' '}
                                <span style={{ color: '#ff4d4f' }}>{JSON.stringify(change.from)}</span>
                                {' → '}
                                <span style={{ color: '#52c41a' }}>{JSON.stringify(change.to)}</span>
                              </li>
                            );
                          })}
                        </ul>
                      )}
                    </li>
                  ))}
                  {plan.frontends.to_update.length > 5 && (
                    <li>... and {plan.frontends.to_update.length - 5} more</li>
                  )}
                </ul>
              </div>
            )}
            
            {plan.frontends.to_delete.length > 0 && (
              <div style={{ marginBottom: 12 }}>
                <Text strong style={{ color: '#ff4d4f' }}>Frontends to Delete ({plan.frontends.to_delete.length}):</Text>
                <ul style={{ marginTop: 4, marginBottom: 0 }}>
                  {plan.frontends.to_delete.slice(0, 5).map((fe, idx) => (
                    <li key={idx} style={{ color: '#ff4d4f' }}>{fe.name} (port {fe.bind_port})</li>
                  ))}
                  {plan.frontends.to_delete.length > 5 && (
                    <li style={{ color: '#ff4d4f' }}>... and {plan.frontends.to_delete.length - 5} more</li>
                  )}
                </ul>
              </div>
            )}
            
            {plan.backends.to_create.length > 0 && (
              <div style={{ marginBottom: 12 }}>
                <Text strong>Backends to Create ({plan.backends.to_create.length}):</Text>
                <ul style={{ marginTop: 4, marginBottom: 0 }}>
                  {plan.backends.to_create.slice(0, 5).map((be, idx) => (
                    <li key={idx}>{be.name} ({be.server_count} servers)</li>
                  ))}
                  {plan.backends.to_create.length > 5 && (
                    <li>... and {plan.backends.to_create.length - 5} more</li>
                  )}
                </ul>
              </div>
            )}
            
            {plan.backends.to_update.length > 0 && (
              <div style={{ marginBottom: 12 }}>
                <Text strong>Backends to Update ({plan.backends.to_update.length}):</Text>
                <ul style={{ marginTop: 4, marginBottom: 0 }}>
                  {plan.backends.to_update.slice(0, 5).map((be, idx) => (
                    <li key={idx}>
                      <strong>{be.name}</strong>
                      {be.changes && (
                        <ul style={{ fontSize: '11px', color: '#666', marginTop: 4 }}>
                          {Object.entries(be.changes).map(([field, change]) => {
                            if (change.from === change.to) return null;
                            return (
                              <li key={field} style={{ marginBottom: 2 }}>
                                <code style={{ backgroundColor: '#f5f5f5', padding: '2px 4px', borderRadius: 2 }}>
                                  {field}
                                </code>: {' '}
                                <span style={{ color: '#ff4d4f' }}>{JSON.stringify(change.from)}</span>
                                {' → '}
                                <span style={{ color: '#52c41a' }}>{JSON.stringify(change.to)}</span>
                              </li>
                            );
                          })}
                        </ul>
                      )}
                    </li>
                  ))}
                  {plan.backends.to_update.length > 5 && (
                    <li>... and {plan.backends.to_update.length - 5} more</li>
                  )}
                </ul>
              </div>
            )}
            
            {plan.backends.to_delete.length > 0 && (
              <div style={{ marginBottom: 12 }}>
                <Text strong style={{ color: '#ff4d4f' }}>Backends to Delete ({plan.backends.to_delete.length}):</Text>
                <ul style={{ marginTop: 4, marginBottom: 0 }}>
                  {plan.backends.to_delete.slice(0, 5).map((be, idx) => (
                    <li key={idx} style={{ color: '#ff4d4f' }}>{be.name}</li>
                  ))}
                  {plan.backends.to_delete.length > 5 && (
                    <li style={{ color: '#ff4d4f' }}>... and {plan.backends.to_delete.length - 5} more</li>
                  )}
                </ul>
              </div>
            )}
            
            {plan.servers && plan.servers.to_create.length > 0 && (
              <div style={{ marginBottom: 12 }}>
                <Text strong>Backend Servers to Create ({plan.servers.to_create.length}):</Text>
                <ul style={{ marginTop: 4, marginBottom: 0 }}>
                  {plan.servers.to_create.slice(0, 5).map((srv, idx) => (
                    <li key={idx}>📦 {srv.backend_name} / <strong>{srv.server_name}</strong> ({srv.server_address}:{srv.server_port})</li>
                  ))}
                  {plan.servers.to_create.length > 5 && (
                    <li>... and {plan.servers.to_create.length - 5} more</li>
                  )}
                </ul>
              </div>
            )}
            
            {plan.servers && plan.servers.to_update.length > 0 && (
              <div style={{ marginBottom: 12 }}>
                <Text strong>Backend Servers to Update ({plan.servers.to_update.length}):</Text>
                <ul style={{ marginTop: 4, marginBottom: 0 }}>
                  {plan.servers.to_update.slice(0, 5).map((srv, idx) => (
                    <li key={idx}>
                      📦 {srv.backend_name} / <strong>{srv.server_name}</strong>
                      {srv.changes && (
                        <ul style={{ fontSize: '11px', color: '#666', marginTop: 4 }}>
                          {Object.entries(srv.changes).map(([field, change]) => {
                            if (change.from === change.to) return null;
                            return (
                              <li key={field} style={{ marginBottom: 2 }}>
                                <code style={{ backgroundColor: '#f5f5f5', padding: '2px 4px', borderRadius: 2 }}>
                                  {field}
                                </code>: {' '}
                                <span style={{ color: '#ff4d4f' }}>{JSON.stringify(change.from)}</span>
                                {' → '}
                                <span style={{ color: '#52c41a' }}>{JSON.stringify(change.to)}</span>
                              </li>
                            );
                          })}
                        </ul>
                      )}
                    </li>
                  ))}
                  {plan.servers.to_update.length > 5 && (
                    <li>... and {plan.servers.to_update.length - 5} more</li>
                  )}
                </ul>
              </div>
            )}
            
            {plan.servers && plan.servers.to_delete.length > 0 && (
              <div style={{ marginBottom: 12 }}>
                <Text strong style={{ color: '#ff4d4f' }}>Backend Servers to Delete ({plan.servers.to_delete.length}):</Text>
                <ul style={{ marginTop: 4, marginBottom: 0 }}>
                  {plan.servers.to_delete.slice(0, 5).map((srv, idx) => (
                    <li key={idx} style={{ color: '#ff4d4f' }}>📦 {srv.backend_name} / <strong>{srv.server_name}</strong> ({srv.server_address}:{srv.server_port})</li>
                  ))}
                  {plan.servers.to_delete.length > 5 && (
                    <li style={{ color: '#ff4d4f' }}>... and {plan.servers.to_delete.length - 5} more</li>
                  )}
                </ul>
              </div>
            )}
            
            {plan.waf_rules && plan.waf_rules.to_update && plan.waf_rules.to_update.length > 0 && (
              <div style={{ marginBottom: 12 }}>
                <Text strong style={{ color: '#1890ff' }}>WAF Rules to Update ({plan.waf_rules.to_update.length}):</Text>
                <ul style={{ marginTop: 4, marginBottom: 0 }}>
                  {plan.waf_rules.to_update.slice(0, 5).map((waf, idx) => (
                    <li key={idx} style={{ color: '#1890ff' }}>
                      🛡️ <strong>{waf.name}</strong> ({waf.rule_type})
                      {waf.changes && waf.changes.length > 0 && (
                        <span style={{ marginLeft: 8, fontSize: '0.9em', color: '#666' }}>
                          ({waf.changes.join(', ')})
                        </span>
                      )}
                    </li>
                  ))}
                  {plan.waf_rules.to_update.length > 5 && (
                    <li style={{ color: '#1890ff' }}>... and {plan.waf_rules.to_update.length - 5} more</li>
                  )}
                </ul>
              </div>
            )}
            
            {plan.waf_rules && plan.waf_rules.to_activate && plan.waf_rules.to_activate.length > 0 && (
              <div style={{ marginBottom: 12 }}>
                <Text strong style={{ color: '#52c41a' }}>WAF Rules to Activate ({plan.waf_rules.to_activate.length}):</Text>
                <ul style={{ marginTop: 4, marginBottom: 0 }}>
                  {plan.waf_rules.to_activate.slice(0, 5).map((waf, idx) => (
                    <li key={idx} style={{ color: '#52c41a' }}>🛡️ <strong>{waf.name}</strong> ({waf.rule_type}) - currently {waf.current_status}</li>
                  ))}
                  {plan.waf_rules.to_activate.length > 5 && (
                    <li style={{ color: '#52c41a' }}>... and {plan.waf_rules.to_activate.length - 5} more</li>
                  )}
                </ul>
              </div>
            )}
            
            {plan.waf_rules && plan.waf_rules.to_deactivate && plan.waf_rules.to_deactivate.length > 0 && (
              <div style={{ marginBottom: 12 }}>
                <Text strong style={{ color: '#ff4d4f' }}>WAF Rules to Deactivate ({plan.waf_rules.to_deactivate.length}):</Text>
                <ul style={{ marginTop: 4, marginBottom: 0 }}>
                  {plan.waf_rules.to_deactivate.slice(0, 5).map((waf, idx) => (
                    <li key={idx} style={{ color: '#ff4d4f' }}>🛡️ <strong>{waf.name}</strong> ({waf.rule_type}) - currently {waf.current_status}</li>
                  ))}
                  {plan.waf_rules.to_deactivate.length > 5 && (
                    <li style={{ color: '#ff4d4f' }}>... and {plan.waf_rules.to_deactivate.length - 5} more</li>
                  )}
                </ul>
              </div>
            )}
            
            <Alert
              message="After confirmation, entities will be synced to database and marked as PENDING. Click 'Apply Changes' in Apply Management to activate."
              type="info"
              showIcon
              style={{ marginTop: 16 }}
            />
          </div>
        ),
        okText: 'Confirm Restore',
        okType: 'primary',
        cancelText: 'Cancel',
        onOk: async () => {
          try {
            // Step 3: Confirm restore
            const confirmResponse = await axios.post(
              `/api/clusters/${selectedCluster.id}/config-versions/${version.id}/restore/confirm`,
              {},
              { headers: { Authorization: `Bearer ${token}` } }
            );
            
            message.success(
              <div>
                <div><strong>Configuration Restored Successfully!</strong></div>
                <div style={{ marginTop: 4, fontSize: '12px' }}>
                  📋 {confirmResponse.data.changes.frontends_created}F+, {confirmResponse.data.changes.backends_created}B+ created
                  <br />✏️ {confirmResponse.data.changes.frontends_updated}F, {confirmResponse.data.changes.backends_updated}B updated
                  <br />🗑️ {confirmResponse.data.changes.frontends_deleted}F, {confirmResponse.data.changes.backends_deleted}B deleted
                  <br />⏳ Status: PENDING - Go to Apply Management
                </div>
              </div>,
              8
            );
            
            // Refresh versions
            await fetchConfigVersions();
            
            // Auto-redirect to Apply Management after successful restore
            setTimeout(() => {
              window.location.href = '/apply-management';
            }, 3000);
            
          } catch (confirmError) {
            console.error('Error confirming restore:', confirmError);
            const errorMsg = confirmError.response?.data?.detail || 'Failed to confirm restore';
            message.error(`Restore confirmation failed: ${errorMsg}`);
          }
        }
      });
      
    } catch (error) {
      console.error('Restore preview failed:', error);
      if (error.response?.status === 401) {
        message.error('Authentication failed. Please login again.');
      } else {
        message.error(`Failed to get restore preview: ${error.response?.data?.message || error.response?.data?.detail || error.message}`);
      }
    } finally {
      setRestoreLoading(false);
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'APPLIED': return 'green';
      case 'PENDING': return 'orange';
      case 'RESTORED': return 'blue';
      default: return 'default';
    }
  };

  const getStatusIcon = (status, isActive) => {
    if (isActive) return <CheckCircleOutlined style={{ color: '#52c41a' }} />;
    switch (status) {
      case 'APPLIED': return <CheckCircleOutlined style={{ color: '#52c41a' }} />;
      case 'PENDING': return <ClockCircleOutlined style={{ color: '#fa8c16' }} />;
      case 'RESTORED': return <RollbackOutlined style={{ color: '#1890ff' }} />;
      default: return <ExclamationCircleOutlined style={{ color: '#d9d9d9' }} />;
    }
  };

  const formatVersionName = (versionName) => {
    // Parse version name to extract meaningful information
    if (versionName.includes('frontend-')) return `Frontend Change - ${versionName}`;
    if (versionName.includes('backend-')) return `Backend Change - ${versionName}`;  
    if (versionName.includes('waf-')) return `WAF Change - ${versionName}`;
    if (versionName.includes('ssl-')) return `SSL Change - ${versionName}`;
    if (versionName.includes('bulk-apply-')) return `Bulk Apply - ${versionName}`;
    return versionName;
  };

  const columns = [
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 120,
      render: (status, record) => (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {getStatusIcon(status, record.is_active)}
          <Tag color={getStatusColor(status)}>
            {record.is_active ? 'ACTIVE' : status}
          </Tag>
        </div>
      ),
    },
    {
      title: 'Version Name',
      dataIndex: 'version_name',
      key: 'version_name',
      render: (text, record) => (
        <div>
          <div style={{ fontWeight: record.is_active ? 'bold' : 'normal' }}>
            {formatVersionName(text)}
          </div>
          {record.description && (
            <div style={{ fontSize: 12, color: '#666', marginTop: 4 }}>
              {record.description}
            </div>
          )}
        </div>
      ),
    },
    {
      title: 'Created At',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 180,
      render: (text) => (
        <div>
          <div>{new Date(text).toLocaleDateString()}</div>
          <div style={{ fontSize: 12, color: '#666' }}>
            {new Date(text).toLocaleTimeString()}
          </div>
        </div>
      ),
    },
    {
      title: 'Created By',
      dataIndex: 'created_by',
      key: 'created_by',
      width: 120,
      render: (userId) => (
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <UserOutlined style={{ color: '#666' }} />
          <span>User {userId}</span>
        </div>
      ),
    },
    {
      title: 'Actions',
      key: 'actions',
      width: 200,
      render: (_, record) => (
        <Space>
          <Button
            type="primary"
            size="small"
            icon={<EyeOutlined />}
            onClick={() => handleViewChange(record)}
          >
            View Change
          </Button>
          {!record.is_active && record.version_name.includes('apply-consolidated') && (
            <Popconfirm
              title="Restore Configuration Version"
              description={`Are you sure you want to restore to version "${record.version_name}"?`}
              onConfirm={() => handleRestoreVersion(record)}
              okText="Restore"
              cancelText="Cancel"
              okType="primary"
            >
              <Button
                type="default"
                size="small"
                icon={<RollbackOutlined />}
                loading={restoreLoading}
              >
                Restore
              </Button>
            </Popconfirm>
          )}
        </Space>
      ),
    },
  ];

  if (!selectedCluster) {
    return (
      <Card>
        <Empty 
          description="Please select a cluster to view version history"
          image={Empty.PRESENTED_IMAGE_SIMPLE}
        />
      </Card>
    );
  }

  return (
    <div style={{ padding: 24 }}>
      <div style={{ marginBottom: 24, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <Button 
            icon={<ArrowLeftOutlined />} 
            onClick={() => navigate('/apply-management')}
            style={{ marginRight: 16 }}
          >
            Back to Apply Management
          </Button>
          <Title level={3} style={{ display: 'inline', margin: 0 }}>
            <HistoryOutlined style={{ marginRight: 8 }} />
            Configuration Version History
          </Title>
        </div>
        <Button 
          icon={<ReloadOutlined />} 
          onClick={fetchConfigVersions}
          loading={loading}
        >
          Refresh
        </Button>
      </div>

      <Card
        title={
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span>
              <CalendarOutlined style={{ marginRight: 8 }} />
              Version History for Cluster: {selectedCluster.name}
            </span>
            <Badge count={configVersions.filter(v => v.status === 'PENDING').length} showZero>
              <span style={{ marginRight: 8 }}>Pending Versions</span>
            </Badge>
          </div>
        }
      >
        <Alert
          message="Configuration Version Management"
          description={
            <div>
              <p>• <strong>ACTIVE</strong> versions are currently deployed to agents</p>
              <p>• <strong>APPLIED</strong> versions are ready to be deployed</p>
              <p>• <strong>PENDING</strong> versions are waiting to be applied</p>
              <p>• Use <strong>Restore</strong> to revert to a previous configuration</p>
            </div>
          }
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
        />

        <Table
          columns={columns}
          dataSource={configVersions}
          rowKey="id"
          loading={loading}
          pagination={{
            pageSize: 20,
            showSizeChanger: false,
            showQuickJumper: true,
            showTotal: (total, range) => 
              `${range[0]}-${range[1]} of ${total} versions`,
          }}
          rowClassName={(record) => record.is_active ? 'active-version-row' : ''}
        />
      </Card>

      {/* View Config Modal */}
      <Modal
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <EyeOutlined />
            <span>Configuration Version: {selectedVersion?.version_name}</span>
          </div>
        }
        open={viewConfigModalVisible}
        onCancel={() => setViewConfigModalVisible(false)}
        width={1000}
        footer={[
          <Button key="close" onClick={() => setViewConfigModalVisible(false)}>
            Close
          </Button>
        ]}
      >
        {selectedVersion && (
          <div>
            <Descriptions bordered column={2} style={{ marginBottom: 16 }}>
              <Descriptions.Item label="Version Name">
                {formatVersionName(selectedVersion.version_name)}
              </Descriptions.Item>
              <Descriptions.Item label="Status">
                <Tag color={getStatusColor(selectedVersion.status)}>
                  {selectedVersion.is_active ? 'ACTIVE' : selectedVersion.status}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="Created At">
                {new Date(selectedVersion.created_at).toLocaleString()}
              </Descriptions.Item>
              <Descriptions.Item label="Created By">
                User {selectedVersion.created_by}
              </Descriptions.Item>
              {selectedVersion.description && (
                <Descriptions.Item label="Description" span={2}>
                  {selectedVersion.description}
                </Descriptions.Item>
              )}
            </Descriptions>

            <div style={{ marginBottom: 16 }}>
              <Title level={5}>HAProxy Configuration Content:</Title>
            </div>

            <div style={{ border: '1px solid #d9d9d9', borderRadius: 6 }}>
              <MonacoEditor
                height="400px"
                language="apache"
                value={selectedVersion.config_content || '# Configuration content not available'}
                options={{
                  readOnly: true,
                  minimap: { enabled: false },
                  scrollBeyondLastLine: false,
                  wordWrap: 'on',
                  theme: 'vs-light'
                }}
              />
            </div>
          </div>
        )}
      </Modal>

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
                  <div style={{ padding: '16px', fontFamily: 'monospace', fontSize: '12px', lineHeight: '1.4' }}>
                    {diffData.changes && diffData.changes.length > 0 ? (
                      diffData.changes.map((change, index) => (
                        <div key={index} style={{ marginBottom: '8px' }}>
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

      <style jsx global>{`
        .active-version-row {
          background-color: #f6ffed !important;
        }
        .active-version-row:hover {
          background-color: #f6ffed !important;
        }
      `}</style>
    </div>
  );
};

export default BulkVersionHistory;