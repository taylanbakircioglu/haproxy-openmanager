import React, { useState, useEffect } from 'react';
import {
  Modal, Table, Button, message, Tag, Space, Tooltip, Typography,
  Alert, Divider, Card, Descriptions
} from 'antd';
import {
  HistoryOutlined, RollbackOutlined, CheckCircleOutlined,
  ClockCircleOutlined, FileTextOutlined, UserOutlined
} from '@ant-design/icons';
import axios from 'axios';

const { Text, Title } = Typography;

const VersionHistory = ({ 
  visible, 
  onCancel, 
  entityType,  // 'frontend' or 'backend'
  entityId,    // frontend ID or backend ID
  onRestoreSuccess 
}) => {
  const [loading, setLoading] = useState(false);
  const [versions, setVersions] = useState([]);
  const [restoreLoading, setRestoreLoading] = useState({});
  const [entityInfo, setEntityInfo] = useState(null); // Store entity info including cluster ID

  useEffect(() => {
    if (visible && entityType && entityId) {
      fetchVersionHistory();
    }
  }, [visible, entityType, entityId]);

  const fetchVersionHistory = async () => {
    setLoading(true);
    try {
      // Use entity-specific endpoint
      const endpoint = entityType === 'frontend' 
        ? `/api/frontends/${entityId}/config-versions`
        : entityType === 'backend'
        ? `/api/backends/${entityId}/config-versions`
        : entityType === 'waf'
        ? `/api/waf/${entityId}/config-versions`
        : `/api/clusters/${entityId}/config-versions`; // fallback for cluster
      
      const response = await axios.get(endpoint);
      setVersions(response.data.versions || []);
      
      // Store entity info for restore operations
      if (entityType === 'frontend') {
        setEntityInfo({
          clusterId: response.data.cluster_id || null,
          clusterName: response.data.cluster_name,
          entityName: response.data.frontend_name
        });
      } else if (entityType === 'backend') {
        setEntityInfo({
          clusterId: response.data.cluster_id || null,
          clusterName: response.data.cluster_name,
          entityName: response.data.backend_name
        });
      } else if (entityType === 'waf') {
        setEntityInfo({
          clusterId: response.data.cluster_id || null,
          clusterName: response.data.cluster_name,
          entityName: response.data.waf_rule_name
        });
      } else {
        // Cluster fallback
        setEntityInfo({
          clusterId: response.data.cluster_id || entityId,
          clusterName: response.data.cluster_name || 'Unknown Cluster',
          entityName: 'Cluster Configuration'
        });
      }
    } catch (error) {
      console.error('Error fetching version history:', error);
      message.error(`Failed to load ${entityType} version history`);
    } finally {
      setLoading(false);
    }
  };

  const handleRestore = async (versionId, versionName) => {
    if (!entityInfo?.clusterId) {
      message.error('Cannot restore: Cluster information not available');
      return;
    }
    
    setRestoreLoading(prev => ({ ...prev, [versionId]: true }));
    try {
      // Step 1: Get restore preview
      const previewResponse = await axios.get(
        `/api/clusters/${entityInfo.clusterId}/config-versions/${versionId}/restore/preview`
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
              description={`Version: ${versionName}`}
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
              `/api/clusters/${entityInfo.clusterId}/config-versions/${versionId}/restore/confirm`
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
            
            // Refresh version history
            fetchVersionHistory();
            
            // Notify parent component about successful restore
            if (onRestoreSuccess) {
              onRestoreSuccess(confirmResponse.data);
            }
            
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
      console.error('Error getting restore preview:', error);
      const errorMsg = error.response?.data?.detail || 'Failed to get restore preview';
      message.error(`Restore preview failed: ${errorMsg}`);
    } finally {
      setRestoreLoading(prev => ({ ...prev, [versionId]: false }));
    }
  };

  const getVersionTypeColor = (type) => {
    const colors = {
      'Frontend': 'blue',
      'Backend': 'green',
      'Backend Server': 'orange',
      'WAF Rule': 'purple',
      'Configuration': 'default'
    };
    return colors[type] || 'default';
  };

  const formatFileSize = (bytes) => {
    if (!bytes) return '-';
    const kb = bytes / 1024;
    return `${kb.toFixed(1)} KB`;
  };

  const columns = [
    {
      title: 'Version Info',
      dataIndex: 'version_name',
      key: 'version_info',
      width: '35%',
      render: (version_name, record) => (
        <div>
          <div style={{ fontWeight: 'bold', marginBottom: 4 }}>
            <FileTextOutlined style={{ marginRight: 4, color: '#1890ff' }} />
            {version_name}
          </div>
          <Tag color={getVersionTypeColor(record.type)} style={{ marginBottom: 4 }}>
            {record.type}
          </Tag>
          <div style={{ fontSize: '12px', color: '#666' }}>
            {record.description}
          </div>
        </div>
      ),
    },
    {
      title: 'Details',
      key: 'details',
      width: '25%',
      render: (_, record) => (
        <div style={{ fontSize: '12px' }}>
          <div style={{ marginBottom: 2 }}>
            <UserOutlined style={{ marginRight: 4 }} />
            <strong>By:</strong> {record.created_by}
          </div>
          <div style={{ marginBottom: 2 }}>
            <ClockCircleOutlined style={{ marginRight: 4 }} />
            <strong>Date:</strong> {new Date(record.created_at).toLocaleString('tr-TR', {
              day: '2-digit',
              month: '2-digit', 
              year: 'numeric',
              hour: '2-digit',
              minute: '2-digit',
              second: '2-digit'
            })}
          </div>
          <div>
            <FileTextOutlined style={{ marginRight: 4 }} />
            <strong>Size:</strong> {formatFileSize(record.file_size)}
          </div>
        </div>
      ),
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: '15%',
      render: (status, record) => (
        <div>
          <Tag
            color={status === 'APPLIED' ? 'green' : 'orange'}
            icon={status === 'APPLIED' ? <CheckCircleOutlined /> : <ClockCircleOutlined />}
          >
            {status}
          </Tag>
          {record.is_active && (
            <div style={{ marginTop: 4 }}>
              <Tag color="blue" size="small">ACTIVE</Tag>
            </div>
          )}
        </div>
      ),
    },
    {
      title: 'Actions',
      key: 'actions',
      width: '25%',
      render: (_, record) => (
        <Space direction="vertical" size="small" style={{ width: '100%' }}>
          <Button
            type="primary"
            size="small"
            icon={<RollbackOutlined />}
            loading={restoreLoading[record.id]}
            onClick={() => handleRestore(record.id, record.version_name)}
            disabled={record.is_active || !record.version_name.includes('apply-consolidated')}
            style={{ width: '100%' }}
          >
            {record.is_active ? 'Current Version' : 'Restore'}
          </Button>
          <Tooltip title={`Checksum: ${record.checksum?.substring(0, 8)}...`}>
            <Text code style={{ fontSize: '10px' }}>
              {record.checksum?.substring(0, 12)}...
            </Text>
          </Tooltip>
        </Space>
      ),
    },
  ];

  return (
    <Modal
      title={
        <div>
          <HistoryOutlined style={{ marginRight: 8, color: '#1890ff' }} />
          {entityType === 'frontend' ? 'Frontend' : entityType === 'backend' ? 'Backend' : entityType === 'waf' ? 'WAF Rule' : 'Configuration'} Version History
          {entityInfo && (
            <div style={{ fontSize: '12px', color: '#666', fontWeight: 'normal', marginTop: 4 }}>
              {entityInfo.entityName} ({entityInfo.clusterName})
            </div>
          )}
        </div>
      }
      open={visible}
      onCancel={onCancel}
      footer={[
        <Button key="refresh" onClick={fetchVersionHistory} loading={loading}>
          Refresh
        </Button>,
        <Button key="close" type="primary" onClick={onCancel}>
          Close
        </Button>,
      ]}
      width={1000}
      bodyStyle={{ padding: '16px' }}
    >
      <Alert
        message={`${entityType === 'frontend' ? 'Frontend' : entityType === 'backend' ? 'Backend' : entityType === 'waf' ? 'WAF Rule' : 'Configuration'} Version Management`}
        description={
          <div>
            <div>• View all applied configuration versions for this {entityType}</div>
            <div>• Restore any previous version - it will be created as PENDING</div>
            <div>• Use "Apply Changes" button to activate restored configurations</div>
            <div>• Current active version cannot be restored</div>
          </div>
        }
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
      />

      <Table
        columns={columns}
        dataSource={versions}
        rowKey="id"
        loading={loading}
        pagination={{
          pageSize: 10,
          showSizeChanger: true,
          showQuickJumper: true,
          showTotal: (total, range) =>
            `${range[0]}-${range[1]} of ${total} versions`,
        }}
        scroll={{ y: 400 }}
        size="small"
      />

      {versions.length === 0 && !loading && (
        <div style={{ textAlign: 'center', padding: '40px 0', color: '#666' }}>
          <HistoryOutlined style={{ fontSize: '48px', marginBottom: '16px' }} />
          <div>No version history found for this cluster</div>
        </div>
      )}
    </Modal>
  );
};

export { VersionHistory }; 