import React, { useState, useEffect } from 'react';
import {
  Table, Button, Space, Modal, Form, Input, Select, Tag, message, 
  Tooltip, Popconfirm, Row, Col, Divider, Typography, Badge, Card, Alert
} from 'antd';
import {
  PlusOutlined, EditOutlined, DeleteOutlined,
  LoadingOutlined, CloudServerOutlined, DownloadOutlined, SettingOutlined,
  SafetyCertificateOutlined, UsergroupAddOutlined, SearchOutlined
} from '@ant-design/icons';
import { useCluster } from '../contexts/ClusterContext';

const { Option } = Select;
const { TextArea } = Input;
const { Title, Text } = Typography;

const ClusterManagement = () => {
  const {
    clusters,
    loading,
    addCluster,
    updateCluster,
    deleteCluster,
    fetchClusters
  } = useCluster();

  const [modalVisible, setModalVisible] = useState(false);
  const [editingCluster, setEditingCluster] = useState(null);
  const [form] = Form.useForm();
  const [searchText, setSearchText] = useState('');
  const [filteredClusters, setFilteredClusters] = useState([]);
  
  // Agent Management Integration
  const [agentPools, setAgentPools] = useState([]);
  const [loadingPools, setLoadingPools] = useState(false);
  
  // Path Discovery
  const [pathDiscoveryVisible, setPathDiscoveryVisible] = useState(false);

  const showPathDiscovery = () => {
    setPathDiscoveryVisible(true);
  };

  useEffect(() => {
    fetchClusters();
    fetchAgentPools();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    setFilteredClusters(clusters);
  }, [clusters]);

  // Fetch Agent Pools for Agent connection type
  const fetchAgentPools = async () => {
    setLoadingPools(true);
    try {
      const response = await fetch('/api/haproxy-cluster-pools', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('authToken') || ''}`,
        },
      });
      if (response.ok) {
        const data = await response.json();
        setAgentPools(data.pools || []); // Extract pools array from response
      } else {
        console.error('Failed to fetch agent pools:', response.status, response.statusText);
        setAgentPools([]);
      }
    } catch (error) {
      console.error('Error fetching agent pools:', error);
      setAgentPools([]);
    } finally {
      setLoadingPools(false);
    }
  };

  const handleAddCluster = () => {
    setEditingCluster(null);
    form.resetFields();
    form.setFieldsValue({
      connection_type: 'agent'
      // ✅ FIXED: No default values - let user enter their own paths
    });
    setModalVisible(true);
  };

  const handleEditCluster = (cluster) => {
    setEditingCluster(cluster);
    
    // 🔍 DEBUG: Log cluster data to see what we're getting from backend
    console.log('🔍 CLUSTER EDIT DEBUG - Raw cluster data:', cluster);
    console.log('🔍 CLUSTER EDIT DEBUG - haproxy_bin_path:', cluster.haproxy_bin_path);
    
    const formValues = {
      name: cluster.name,
      description: cluster.description,
      connection_type: cluster.connection_type,
      stats_socket_path: cluster.stats_socket_path || '/run/haproxy/admin.sock',
      haproxy_config_path: cluster.haproxy_config_path || '/etc/haproxy/haproxy.cfg',
      haproxy_bin_path: cluster.haproxy_bin_path,  // ✅ FIXED: Use actual value, no default override
      agent_pool_id: cluster.pool_id || undefined,
      haproxy_user: cluster.haproxy_user || '',
      haproxy_group: cluster.haproxy_group || ''
    };
    
    console.log('🔍 CLUSTER EDIT DEBUG - Form values being set:', formValues);
    
    form.setFieldsValue(formValues);
    setModalVisible(true);
  };

  const handleDeleteCluster = async (clusterId) => {
    try {
      await deleteCluster(clusterId);
      message.success('Cluster deleted successfully');
    } catch (error) {
      message.error('Failed to delete cluster: ' + (error.response?.data?.detail || error.message));
    }
  };

  const handleModalCancel = () => {
    setModalVisible(false);
    setEditingCluster(null);
    form.resetFields();
  };

  // Removed handleTestModalConnection

  const handleModalOk = async () => {
    try {
      const values = await form.validateFields();
      
      // Transform form values to match simplified backend API (agent-based only)
      const transformedValues = {
        name: values.name,
        description: values.description,
        connection_type: values.connection_type || 'agent',
        stats_socket_path: values.stats_socket_path,
        haproxy_config_path: values.haproxy_config_path,
        haproxy_bin_path: values.haproxy_bin_path,
        pool_id: values.agent_pool_id || null,
        haproxy_user: values.haproxy_user || null,
        haproxy_group: values.haproxy_group || null
      };
      
      // For new clusters, explicitly set is_active to true
      // For existing clusters (edit), don't send is_active so backend keeps the current value
      if (!editingCluster) {
        transformedValues.is_active = true;
      }
      
            const response = await fetch(editingCluster ? 
        `/api/clusters/${editingCluster.id}` :
        '/api/clusters', {
        method: editingCluster ? 'PUT' : 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('authToken') || localStorage.getItem('token') || ''}`,
        },
        body: JSON.stringify(transformedValues),
      });
      
      const result = await response.json();
      
      if (response.ok) {
        message.success(editingCluster ? 'Cluster updated successfully' : 'Cluster created successfully');
        setModalVisible(false);
        setEditingCluster(null);
        form.resetFields();
        await fetchClusters();
      } else {
        message.error(result.detail || result.message || 'An error occurred');
      }
    } catch (error) {
      message.error('Error: ' + error.message);
    }
  };

  const handleSearch = (value) => {
    const filtered = clusters.filter(cluster => 
      cluster.name.toLowerCase().includes(value.toLowerCase()) ||
      (cluster.description && cluster.description.toLowerCase().includes(value.toLowerCase()))
    );
    setFilteredClusters(filtered);
    setSearchText(value);
  };

  const getStatusBadge = (cluster) => {
    const status = cluster.agent_status || cluster.connection_status || 'unknown';
    const statusConfig = {
      'healthy': { status: 'success', text: 'Healthy' },
      'warning': { status: 'warning', text: 'Warning' }, 
      'offline': { status: 'error', text: 'Offline' },
      'no-agents': { status: 'default', text: 'No Agents' },
      'connected': { status: 'success', text: 'Connected' },
      'unknown': { status: 'default', text: 'Unknown' },
      'error': { status: 'error', text: 'Error' }
    };
    
    const config = statusConfig[status] || statusConfig['unknown'];
    return <Badge status={config.status} text={config.text} />;
  };

  const columns = [
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
      render: (text, record) => (
        <div>
          <strong>{text}</strong>
          {record.is_default && (
            <Tag color="gold" style={{ marginLeft: 8 }}>
              Default
            </Tag>
          )}
        </div>
      ),
    },
    {
      title: 'Description',
      dataIndex: 'description',
      key: 'description',
      render: (text) => text || <Text type="secondary">No description</Text>,
    },
    {
      title: 'Agent Pool',
      dataIndex: 'pool_name',
      key: 'pool_name',
      render: (poolName, record) => {
        if (!poolName) {
          return <Text type="secondary">No pool assigned</Text>;
        }
        return (
          <Tag color="blue" icon={<UsergroupAddOutlined />}>
            {poolName}
          </Tag>
        );
      },
    },
    {
      title: 'Connection Type',
      dataIndex: 'connection_type',
      key: 'connection_type',
      render: (type) => (
        <Tag color={type === 'agent' ? 'green' : 'purple'}>
          {type === 'agent' ? 'Agent Connection' : 'Sidecar Agent'}
        </Tag>
      ),
    },
    {
      title: 'Status',
      key: 'status',
      render: (_, record) => (
        <div>
          {getStatusBadge(record)}
          {(record.total_agents > 0) && (
            <div style={{ fontSize: '12px', color: '#666', marginTop: '4px' }}>
              {record.healthy_agents}/{record.total_agents} agents healthy
            </div>
          )}
        </div>
      ),
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Space>
          <Tooltip title="Edit Cluster">
            <Button
              type="text"
              icon={<EditOutlined />}
              onClick={() => handleEditCluster(record)}
            />
          </Tooltip>
          
          {!record.is_default && (
            <Popconfirm
              title="Delete Cluster"
              description="Are you sure you want to delete this cluster?"
              onConfirm={() => handleDeleteCluster(record.id)}
              okText="Delete"
              cancelText="Cancel"
              okType="danger"
            >
              <Tooltip title="Delete Cluster">
                <Button
                  type="text"
                  danger
                  icon={<DeleteOutlined />}
                />
              </Tooltip>
            </Popconfirm>
          )}
        </Space>
      ),
    },
  ];

  return (
    <div>
      <Card>
        <div style={{ marginBottom: '24px' }}>
          <Title level={2} style={{ margin: 0 }}>
            HAProxy Cluster Management
          </Title>
          <Text type="secondary">
            Manage remote HAProxy clusters through agent connections
          </Text>
        </div>

        <div style={{ marginBottom: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ 
            position: 'relative', 
            display: 'inline-block',
            width: 300
          }}>
            <input
              type="text"
              placeholder="Search clusters..."
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
            type="primary"
            icon={<PlusOutlined />}
            onClick={handleAddCluster}
          >
            Add New Cluster
          </Button>
        </div>

        <Table
          columns={columns}
          dataSource={filteredClusters}
          rowKey="id"
          loading={loading}
          pagination={{
            pageSize: 10,
            showSizeChanger: true,
            showQuickJumper: true,
            showTotal: (total) => `Total ${total} clusters`,
          }}
        />
      </Card>

      <Modal
        title={editingCluster ? 'Edit HAProxy Cluster' : 'Add New HAProxy Cluster'}
        open={modalVisible}
        onCancel={handleModalCancel}
        width={600}
        destroyOnClose
        footer={[
          <Button key="cancel" onClick={handleModalCancel}>
            Cancel
          </Button>,
          <Button key="submit" type="primary" onClick={handleModalOk}>
            {editingCluster ? 'Update' : 'Create'} Cluster
          </Button>,
        ]}
      >
        <Form
          form={form}
          layout="vertical"
          initialValues={{
            connection_type: 'agent'
            // ✅ FIXED: No default paths - user must enter their own values
          }}
        >
          <Form.Item
            label="Cluster Name"
            name="name"
            rules={[
              { required: true, message: 'Please enter cluster name' },
              { min: 2, message: 'Name must be at least 2 characters' }
            ]}
          >
            <Input placeholder="e.g., Production HAProxy" />
          </Form.Item>

          <Form.Item
            label="Description"
            name="description"
          >
            <TextArea 
              rows={2} 
              placeholder="Optional description for this cluster"
            />
          </Form.Item>

          <Form.Item
            label="Connection Type"
            name="connection_type"
            rules={[{ required: true, message: 'Please select connection type' }]}
          >
            <Select>
              <Option value="agent">Agent Connection</Option>
            </Select>
          </Form.Item>

          <Form.Item
            label="Agent Pool"
            name="agent_pool_id"
            tooltip="Select the pool where agents will connect to this cluster"
          >
            <Select
              placeholder="Choose an agent pool (optional)"
              loading={loadingPools}
              allowClear
              optionLabelProp="label"
            >
              {agentPools.map(pool => (
                <Option 
                  key={pool.id} 
                  value={pool.id} 
                  title={pool.description || `${pool.name} - ${pool.environment} environment`}
                  label={
                    <Space>
                      <Text strong>{pool.name}</Text>
                      <Tag color={pool.environment === 'production' ? 'red' : pool.environment === 'staging' ? 'orange' : 'blue'} size="small">
                        {pool.environment}
                      </Tag>
                    </Space>
                  }
                >
                  <Space style={{ width: '100%', justifyContent: 'space-between' }}>
                    <Space>
                      <Text strong>{pool.name}</Text>
                      {pool.location && (
                        <Text type="secondary" style={{ fontSize: '11px' }}>
                          📍 {pool.location}
                        </Text>
                      )}
                    </Space>
                    <Tag color={pool.environment === 'production' ? 'red' : pool.environment === 'staging' ? 'orange' : 'blue'}>
                      {pool.environment}
                    </Tag>
                  </Space>
                </Option>
              ))}
            </Select>
          </Form.Item>

          <Row>
            <Col span={20}>
              <Typography.Title level={5} style={{ marginBottom: 16 }}>
                HAProxy Paths Configuration
              </Typography.Title>
            </Col>
            <Col span={4} style={{ textAlign: 'right' }}>
              <Button 
                type="link" 
                size="small" 
                icon={<SearchOutlined />} 
                onClick={showPathDiscovery}
                style={{ padding: 0 }}
              >
                Path Helper
              </Button>
            </Col>
          </Row>

          <Form.Item
            label="Stats Socket Path"
            name="stats_socket_path"
            rules={[{ required: true, message: 'Please enter stats socket path' }]}
            tooltip="HAProxy stats socket path - agent will use this to communicate with HAProxy"
          >
            <Input placeholder="/run/haproxy/admin.sock" />
          </Form.Item>

          <Form.Item
            label="HAProxy Config Path"
            name="haproxy_config_path"
            rules={[{ required: true, message: 'Please enter HAProxy config path' }]}
            tooltip="HAProxy configuration file path - agent will manage this file"
          >
            <Input placeholder="/etc/haproxy/haproxy.cfg" />
          </Form.Item>

          <Form.Item
            label="HAProxy Binary Path"
            name="haproxy_bin_path"
            rules={[{ required: true, message: 'Please enter HAProxy binary path' }]}
            tooltip="HAProxy binary executable path - used for config validation and service management"
          >
            <Input placeholder="/usr/sbin/haproxy" />
          </Form.Item>

        </Form>
      </Modal>

      {/* Path Discovery Helper Modal */}
      <Modal
        title="HAProxy Path Discovery Helper"
        open={pathDiscoveryVisible}
        onCancel={() => setPathDiscoveryVisible(false)}
        footer={[
          <Button key="close" onClick={() => setPathDiscoveryVisible(false)}>
            Close
          </Button>
        ]}
        width={800}
      >
        <Alert
          message="HAProxy Path Discovery"
          description="Run this single command on your HAProxy server to discover all required paths at once."
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
        />
        
        <Row gutter={16}>
          <Col span={12}>
            <Card 
              title={
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span>🐧 Linux</span>
                  <Typography.Text 
                    copyable={{ 
                      text: `echo "=== HAProxy Paths ===" && HAPROXY_PID=$(pgrep -f 'haproxy.*-f' | head -1) && if [ ! -z "$HAPROXY_PID" ]; then HAPROXY_CMDLINE=$(cat /proc/$HAPROXY_PID/cmdline 2>/dev/null | tr '\\0' ' ') && CONFIG_FROM_CMDLINE=$(echo "$HAPROXY_CMDLINE" | grep -oE '\\-f[[:space:]]+[^[:space:]]+' | awk '{print $2}' | head -1) && SOCKET_PATH="" && if [ -f "$CONFIG_FROM_CMDLINE" ]; then SOCKET_PATH=$(grep -v '^[[:space:]]*#' "$CONFIG_FROM_CMDLINE" | grep 'stats socket' | sed 's/.*stats socket[[:space:]]*\\([^[:space:]]*\\).*/\\1/' | head -1); fi && echo "Socket: \${SOCKET_PATH:-'Not configured (HTTP stats may be used instead)'}" && echo "Config: \${CONFIG_FROM_CMDLINE:-'Not found'}" && echo "Binary: $(readlink -f /proc/$HAPROXY_PID/exe 2>/dev/null || which haproxy)"; else echo "HAProxy process not found"; fi`,
                      tooltips: ['Copy command', 'Copied!']
                    }}
                    style={{ fontSize: '12px' }}
                  >
                    Copy Script
                  </Typography.Text>
                </div>
              }
              size="small"
            >
              <pre 
                style={{ 
                  background: '#f6f8fa', 
                  padding: '12px', 
                  borderRadius: '6px', 
                  fontSize: '12px',
                  lineHeight: '1.4',
                  margin: 0,
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word'
                }}
              >
                <Typography.Text>
{`echo "=== HAProxy Paths ===" && \\
HAPROXY_PID=$(pgrep -f 'haproxy.*-f' | head -1) && \\
if [ ! -z "$HAPROXY_PID" ]; then \\
  HAPROXY_CMDLINE=$(cat /proc/$HAPROXY_PID/cmdline 2>/dev/null | tr '\\0' ' ') && \\
  CONFIG_FROM_CMDLINE=$(echo "$HAPROXY_CMDLINE" | grep -oE '\\-f[[:space:]]+[^[:space:]]+' | awk '{print $2}' | head -1) && \\
  SOCKET_PATH="" && \\
  if [ -f "$CONFIG_FROM_CMDLINE" ]; then \\
    SOCKET_PATH=$(grep -v '^[[:space:]]*#' "$CONFIG_FROM_CMDLINE" | grep 'stats socket' | sed 's/.*stats socket[[:space:]]*\\([^[:space:]]*\\).*/\\1/' | head -1); \\
  fi && \\
  echo "Socket: \${SOCKET_PATH:-'Not configured (HTTP stats may be used instead)'}" && \\
  echo "Config: \${CONFIG_FROM_CMDLINE:-'Not found'}" && \\
  echo "Binary: $(readlink -f /proc/$HAPROXY_PID/exe 2>/dev/null || which haproxy)"; \\
else \\
  echo "HAProxy process not found"; \\
fi`}
                </Typography.Text>
              </pre>
            </Card>
          </Col>
          <Col span={12}>
            <Card 
              title={
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span>🍎 macOS</span>
                  <Typography.Text 
                    copyable={{ 
                      text: `echo "=== HAProxy Paths ===" && HAPROXY_PID=$(pgrep -f 'haproxy.*-f' | head -1) && if [ ! -z "$HAPROXY_PID" ]; then HAPROXY_CMDLINE=$(ps -p $HAPROXY_PID -o args= 2>/dev/null) && CONFIG_FROM_CMDLINE=$(echo "$HAPROXY_CMDLINE" | grep -oE '\\-f[[:space:]]+[^[:space:]]+' | awk '{print $2}' | head -1) && SOCKET_PATH="" && if [ -f "$CONFIG_FROM_CMDLINE" ]; then SOCKET_PATH=$(grep 'stats socket' "$CONFIG_FROM_CMDLINE" | grep -v '^#' | sed 's/.*stats socket *//' | awk '{print $1}' | head -1); fi && echo "Socket: \${SOCKET_PATH:-'Not configured (HTTP stats may be used instead)'}" && echo "Config: \${CONFIG_FROM_CMDLINE:-'Not found'}" && echo "Binary: $(ps -p $HAPROXY_PID -o comm= 2>/dev/null || which haproxy)"; else echo "HAProxy process not found"; fi`,
                      tooltips: ['Copy command', 'Copied!']
                    }}
                    style={{ fontSize: '12px' }}
                  >
                    Copy Script
                  </Typography.Text>
                </div>
              }
              size="small"
            >
              <pre 
                style={{ 
                  background: '#f6f8fa', 
                  padding: '12px', 
                  borderRadius: '6px', 
                  fontSize: '12px',
                  lineHeight: '1.4',
                  margin: 0,
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word'
                }}
              >
                <Typography.Text>
{`echo "=== HAProxy Paths ===" && \\
HAPROXY_PID=$(pgrep -f 'haproxy.*-f' | head -1) && \\
if [ ! -z "$HAPROXY_PID" ]; then \\
  HAPROXY_CMDLINE=$(ps -p $HAPROXY_PID -o args= 2>/dev/null) && \\
  CONFIG_FROM_CMDLINE=$(echo "$HAPROXY_CMDLINE" | grep -oE '\\-f[[:space:]]+[^[:space:]]+' | awk '{print $2}' | head -1) && \\
  SOCKET_PATH="" && \\
  if [ -f "$CONFIG_FROM_CMDLINE" ]; then \\
    SOCKET_PATH=$(grep -v '^[[:space:]]*#' "$CONFIG_FROM_CMDLINE" | grep 'stats socket' | sed 's/.*stats socket[[:space:]]*\\([^[:space:]]*\\).*/\\1/' | head -1); \\
  fi && \\
  echo "Socket: \${SOCKET_PATH:-'Not configured (HTTP stats may be used instead)'}" && \\
  echo "Config: \${CONFIG_FROM_CMDLINE:-'Not found'}" && \\
  echo "Binary: $(ps -p $HAPROXY_PID -o comm= 2>/dev/null || which haproxy)"; \\
else \\
  echo "HAProxy process not found"; \\
fi`}
                </Typography.Text>
              </pre>
            </Card>
          </Col>
        </Row>
      </Modal>
    </div>
  );
};

export default ClusterManagement; 