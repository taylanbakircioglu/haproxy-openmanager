import React, { useState, useEffect, useCallback, useContext } from 'react';
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
  Typography,
  Alert,
  Tooltip,
  Row,
  Col,
  Statistic,
  Progress,
  List,
  Avatar
} from 'antd';
import {
  PlusOutlined,
  DeleteOutlined,
  EditOutlined,
  EyeOutlined,
  SettingOutlined,
  TeamOutlined,
  DesktopOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  WarningOutlined,
  EnvironmentOutlined,
  HistoryOutlined,
  ReloadOutlined
} from '@ant-design/icons';
import axios from 'axios';
import AuthContext from '../contexts/AuthContext';

const { Option } = Select;
const { Text, Title, Paragraph } = Typography;
const { TextArea } = Input;

const PoolManagement = () => {
  const { loading: userIsLoading } = useContext(AuthContext);
  const [pools, setPools] = useState([]);
  const [filteredPools, setFilteredPools] = useState([]);
  const [searchText, setSearchText] = useState('');
  const [statusFilter, setStatusFilter] = useState('active');
  const [loading, setLoading] = useState(false);
  const [poolModalVisible, setPoolModalVisible] = useState(false);
  const [editingPool, setEditingPool] = useState(null);
  const [poolDetailModalVisible, setPoolDetailModalVisible] = useState(false);
  const [selectedPool, setSelectedPool] = useState(null);
  const [poolAgents, setPoolAgents] = useState([]);
  const [agentsLoading, setAgentsLoading] = useState(false);
  
  const [poolForm] = Form.useForm();

  // Environment options
  const environmentOptions = [
    { value: 'production', label: 'Production', color: '#f50' },
    { value: 'staging', label: 'Staging', color: '#2db7f5' },
    { value: 'test', label: 'Test', color: '#87d068' },
    { value: 'development', label: 'Development', color: '#108ee9' }
  ];

  // Fetch pools from API
  const fetchPools = useCallback(async () => {
    const token = localStorage.getItem('authToken');
    if (!token) {
      console.log("PoolManagement - Aborting fetch, no token.");
      return;
    }
    setLoading(true);
    try {
      console.log('PoolManagement - Token status:', token ? 'Token exists' : 'No token');
      console.log('PoolManagement - Token length:', token ? token.length : 0);
      
      const response = await axios.get('/api/haproxy-cluster-pools', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache'
        },
      });
      const poolsData = response.data.pools || [];
      setPools(poolsData);
      setFilteredPools(poolsData); // Always update filtered list with fresh data
      console.log('PoolManagement - Pools fetched successfully:', poolsData.length);
    } catch (error) {
      console.error('PoolManagement - Failed to fetch pools:', error);
      console.error('PoolManagement - Error response:', error.response?.data);
      console.error('PoolManagement - Error status:', error.response?.status);
      message.error('Failed to fetch pools: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  }, []);

  // Search/filter pools
  const handleSearch = (value) => {
    setSearchText(value);
  };
  
  const handleFilterChange = (key, value) => {
    if (key === 'status') {
      setStatusFilter(value);
    }
  };

  useEffect(() => {
    let filtered = [...pools];

    if (statusFilter !== 'all') {
      filtered = filtered.filter(pool => pool.is_active === (statusFilter === 'active'));
    }

    if (searchText) {
      filtered = filtered.filter(pool =>
        pool.name.toLowerCase().includes(searchText.toLowerCase()) ||
        pool.description?.toLowerCase().includes(searchText.toLowerCase()) ||
        pool.environment.toLowerCase().includes(searchText.toLowerCase())
      );
    }
    
    setFilteredPools(filtered);
  }, [pools, searchText, statusFilter]);

  useEffect(() => {
    if (!userIsLoading) {
      fetchPools();
    }
  }, [fetchPools, userIsLoading]);

  // Fetch agents for a specific pool
  const fetchPoolAgents = useCallback(async (poolId) => {
    const token = localStorage.getItem('authToken');
    if (!token) return;
    setAgentsLoading(true);
    try {
      const response = await axios.get(`/api/haproxy-cluster-pools/${poolId}/agents`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache'
        },
      });
      setPoolAgents(response.data.agents || []);
    } catch (error) {
      console.error('Failed to fetch pool agents:', error);
      message.error('Failed to fetch pool agents: ' + (error.response?.data?.detail || error.message));
    } finally {
      setAgentsLoading(false);
    }
  }, []);

  // Create or update pool
  const handlePoolSubmit = async (values) => {
    const token = localStorage.getItem('authToken');
    if (!token) {
      message.error("Authentication error. Please log in again.");
      return;
    }
    try {
      const config = {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      };

      if (editingPool) {
        // Update existing pool
        await axios.put(`/api/haproxy-cluster-pools/${editingPool.id}`, values, config);
        message.success('Pool updated successfully');
      } else {
        // Create new pool
        await axios.post('/api/pools', values, config);
        message.success('Pool created successfully');
      }
      
      setPoolModalVisible(false);
      setEditingPool(null);
      poolForm.resetFields();
      fetchPools();
    } catch (error) {
      const errorMessage = error.response?.data?.detail || error.message;
      message.error(`Failed to ${editingPool ? 'update' : 'create'} pool: ${errorMessage}`);
    }
  };

  // Delete pool
  const deletePool = async (poolId, poolName) => {
    const token = localStorage.getItem('authToken');
    if (!token) {
      message.error("Authentication error. Please log in again.");
      return;
    }
    try {
      await axios.delete(`/api/haproxy-cluster-pools/${poolId}`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      message.success(`Pool "${poolName}" deleted successfully`);
      fetchPools();
    } catch (error) {
      const errorMessage = error.response?.data?.detail || error.message;
      message.error(`Failed to delete pool "${poolName}": ${errorMessage}`);
    }
  };

  // Show pool details
  const showPoolDetails = (pool) => {
    setSelectedPool(pool);
    setPoolDetailModalVisible(true);
    fetchPoolAgents(pool.id);
  };

  // Open create/edit modal
  const openPoolModal = (pool = null) => {
    setEditingPool(pool);
    setPoolModalVisible(true);
    
    if (pool) {
      poolForm.setFieldsValue({
        name: pool.name,
        description: pool.description,
        environment: pool.environment,
        is_active: pool.is_active
      });
    } else {
      poolForm.resetFields();
    }
  };

  // Get environment tag
  const getEnvironmentTag = (environment) => {
    const envConfig = environmentOptions.find(env => env.value === environment);
    return (
      <Tag color={envConfig?.color || 'default'}>
        {envConfig?.label || environment}
      </Tag>
    );
  };

  // Get agent health badge
  const getAgentHealthBadge = (health) => {
    const healthConfig = {
      healthy: { status: 'success', icon: <CheckCircleOutlined />, text: 'Online' },
      warning: { status: 'warning', icon: <WarningOutlined />, text: 'Warning' },
      offline: { status: 'error', icon: <CloseCircleOutlined />, text: 'Offline' },
      unknown: { status: 'default', icon: <DesktopOutlined />, text: 'Unknown' }
    };
    
    const config = healthConfig[health] || healthConfig.unknown;
    return <Badge {...config} text={config.text} />;
  };

  // Table columns for pools
  const poolColumns = [
    {
      title: 'Pool Name',
      dataIndex: 'name',
      key: 'name',
      render: (text, record) => (
        <Space direction="vertical" size="small">
          <Text strong>{text}</Text>
          <Text type="secondary" style={{ fontSize: '12px' }}>
            {record.description}
          </Text>
        </Space>
      ),
    },
    {
      title: 'Environment',
      dataIndex: 'environment',
      key: 'environment',
      render: (environment) => getEnvironmentTag(environment),
      width: 120,
    },
    {
      title: 'Agents',
      key: 'agents',
      render: (_, record) => (
        <Space direction="vertical" size="small">
          <Text>
            <Text strong>{record.agent_count || 0}</Text> total
          </Text>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', marginBottom: '2px' }}>
              <Badge status="success" />
              <Text style={{ fontSize: '12px', marginLeft: '4px' }}>{record.online_agents || record.healthy_agents || 0} online</Text>
            </div>
            {(record.warning_agents || 0) > 0 && (
              <div style={{ display: 'flex', alignItems: 'center', marginBottom: '2px' }}>
                <Badge status="warning" />
                <Text style={{ fontSize: '12px', marginLeft: '4px' }}>{record.warning_agents || 0} warning</Text>
              </div>
            )}
            <div style={{ display: 'flex', alignItems: 'center' }}>
              <Badge status="error" />
              <Text style={{ fontSize: '12px', marginLeft: '4px' }}>{record.offline_agents || 0} offline</Text>
            </div>
          </div>
        </Space>
      ),
      width: 140,
    },
    {
      title: 'Status',
      dataIndex: 'is_active',
      key: 'is_active',
      render: (isActive) => (
        <Tag color={isActive ? 'green' : 'red'}>
          {isActive ? 'active' : 'inactive'}
        </Tag>
      ),
      width: 100,
    },
    {
      title: 'Created',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (createdAt) => {
        if (!createdAt) return '-';
        const date = new Date(createdAt);
        return (
          <Tooltip title={date.toLocaleString()}>
            <Text type="secondary" style={{ fontSize: '12px' }}>
              {date.toLocaleDateString()}
            </Text>
          </Tooltip>
        );
      },
      width: 100,
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Space>
          <Tooltip title="View Details">
            <Button
              type="primary"
              size="small"
              icon={<EyeOutlined />}
              onClick={() => showPoolDetails(record)}
            />
          </Tooltip>
          <Tooltip title="Edit Pool">
            <Button
              type="default"
              size="small"
              icon={<EditOutlined />}
              onClick={() => openPoolModal(record)}
            />
          </Tooltip>
          <Popconfirm
            title={`Delete Pool "${record.name}"?`}
            description="This will also remove all associated agents. This action cannot be undone."
            onConfirm={() => deletePool(record.id, record.name)}
            okText="Delete"
            cancelText="Cancel"
            okButtonProps={{ danger: true }}
          >
            <Tooltip title="Delete Pool">
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
      width: 140,
      fixed: 'right',
    },
  ];

  // Calculate pool statistics
  const getPoolStats = () => {
    const total = pools.length;
    const active = pools.filter(p => p.is_active).length;
    const totalAgents = pools.reduce((sum, p) => sum + (p.agent_count || 0), 0);
    const healthyAgents = pools.reduce((sum, p) => sum + (p.online_agents || p.healthy_agents || 0), 0);
    const warningAgents = pools.reduce((sum, p) => sum + (p.warning_agents || 0), 0);
    const offlineAgents = pools.reduce((sum, p) => sum + (p.offline_agents || 0), 0);
    
    return { total, active, totalAgents, healthyAgents, warningAgents, offlineAgents };
  };

  const stats = getPoolStats();

  return (
    <div style={{ padding: '24px' }}>
      <div style={{ marginBottom: '24px' }}>
        <Title level={2}>
          <Space>
            <EnvironmentOutlined />
            HAProxy Agent Pool Management
          </Space>
        </Title>
        <Paragraph>
          Manage HAProxy agent pools for organized agent deployment and configuration management.
          Each pool represents a logical grouping of HAProxy agents in the same environment or data center.
        </Paragraph>
      </div>

      {/* Statistics Cards */}
      <Row gutter={16} style={{ marginBottom: '24px' }}>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic
              title="Total Pools"
              value={stats.total}
              prefix={<EnvironmentOutlined />}
              valueStyle={{ color: '#1890ff' }}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic
              title="Active Pools"
              value={stats.active}
              prefix={<CheckCircleOutlined />}
              valueStyle={{ color: '#3f8600' }}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic
              title="Total Agents"
              value={stats.totalAgents}
              prefix={<TeamOutlined />}
              valueStyle={{ color: '#722ed1' }}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card>
            <Statistic
              title="Healthy Agents"
              value={stats.healthyAgents}
              prefix={<CheckCircleOutlined />}
              valueStyle={{ color: '#3f8600' }}
            />
          </Card>
        </Col>
      </Row>

      {/* Pools Table */}
      <Card
        title={
          <Space>
            <EnvironmentOutlined />
            <span>HAProxy Agent Pools</span>
          </Space>
        }
        extra={
          <Space>
            <div style={{ 
              position: 'relative', 
              display: 'inline-block',
              width: 200
            }}>
              <input
                type="text"
                placeholder="Search pools..."
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
            <Select
              defaultValue="active"
              style={{ width: 120 }}
              onChange={(value) => handleFilterChange('status', value)}
            >
              <Option value="all">All Statuses</Option>
              <Option value="active">Active</Option>
              <Option value="inactive">Inactive</Option>
            </Select>
            <Button
              icon={<ReloadOutlined />}
              onClick={fetchPools}
              loading={loading}
            >
              Refresh
            </Button>
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={() => openPoolModal()}
            >
              Create Agent Pool
            </Button>
          </Space>
        }
      >
        <Table
          columns={poolColumns}
          dataSource={filteredPools}
          rowKey="id"
          loading={loading}
          pagination={{
            pageSize: 10,
            showSizeChanger: true,
            showQuickJumper: true,
            showTotal: (total, range) => 
              `${range[0]}-${range[1]} of ${total} pools`,
          }}
          scroll={{ x: 800 }}
        />
      </Card>

      {/* Create/Edit Pool Modal */}
      <Modal
        title={editingPool ? 'Edit Agent Pool' : 'Create New Agent Pool'}
        visible={poolModalVisible}
        onCancel={() => {
          setPoolModalVisible(false);
          setEditingPool(null);
          poolForm.resetFields();
        }}
        footer={null}
        width={600}
      >
        <Form
          form={poolForm}
          layout="vertical"
          onFinish={handlePoolSubmit}
          initialValues={{
            is_active: true
          }}
        >
          <Form.Item
            name="name"
            label="Pool Name"
            rules={[
              { required: true, message: 'Please enter pool name' },
              { min: 3, message: 'Pool name must be at least 3 characters' },
              { max: 100, message: 'Pool name must be less than 100 characters' }
            ]}
          >
            <Input placeholder="Production Agent Pool" showCount maxLength={100} />
          </Form.Item>

          <Form.Item
            name="description"
            label="Description"
            rules={[
              { max: 500, message: 'Description must be less than 500 characters' }
            ]}
          >
            <TextArea
              rows={3}
              placeholder="Main production agent pool for web services"
              maxLength={500}
            />
          </Form.Item>

          <Form.Item
            name="environment"
            label="Environment"
            rules={[{ required: true, message: 'Please select an environment' }]}
          >
            <Select placeholder="Select environment">
              {environmentOptions.map(env => (
                <Option key={env.value} value={env.value}>
                  <Space>
                    <Badge color={env.color} />
                    {env.label}
                  </Space>
                </Option>
              ))}
            </Select>
          </Form.Item>

          <Form.Item
            name="is_active"
            label="Status"
            rules={[{ required: true, message: 'Please select status' }]}
          >
            <Select>
              <Option value={true}>
                <Space>
                  <Badge status="success" />
                  Active
                </Space>
              </Option>
              <Option value={false}>
                <Space>
                  <Badge status="error" />
                  Inactive
                </Space>
              </Option>
            </Select>
          </Form.Item>

          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space>
              <Button onClick={() => {
                setPoolModalVisible(false);
                setEditingPool(null);
                poolForm.resetFields();
              }}>
                Cancel
              </Button>
              <Button type="primary" htmlType="submit">
                {editingPool ? 'Update' : 'Create'} Pool
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* Pool Details Modal */}
      <Modal
        title={
          <Space>
            <EnvironmentOutlined />
            <span>Agent Pool Details: {selectedPool?.name}</span>
          </Space>
        }
        visible={poolDetailModalVisible}
        onCancel={() => setPoolDetailModalVisible(false)}
        width={900}
        footer={[
          <Button key="close" onClick={() => setPoolDetailModalVisible(false)}>
            Close
          </Button>
        ]}
      >
        {selectedPool && (
          <div>
            <Row gutter={16} style={{ marginBottom: '24px' }}>
              <Col span={12}>
                <Card size="small">
                  <Descriptions title="Agent Pool Information" column={1} size="small">
                    <Descriptions.Item label="Name">{selectedPool.name}</Descriptions.Item>
                    <Descriptions.Item label="Environment">
                      {getEnvironmentTag(selectedPool.environment)}
                    </Descriptions.Item>
                    <Descriptions.Item label="Status">
                      <Tag color={selectedPool.is_active ? 'green' : 'red'}>
                        {selectedPool.is_active ? 'active' : 'inactive'}
                      </Tag>
                    </Descriptions.Item>
                    <Descriptions.Item label="Description">
                      {selectedPool.description || 'No description'}
                    </Descriptions.Item>
                  </Descriptions>
                </Card>
              </Col>
              <Col span={12}>
                <Card size="small">
                  <Statistic
                    title="Agents in Pool"
                    value={selectedPool.agent_count}
                    prefix={<TeamOutlined />}
                    suffix={
                      <div style={{ fontSize: '14px', marginTop: '8px' }}>
                        <div>
                          <Badge status="success" />
                          {selectedPool.healthy_agents} online
                        </div>
                        {selectedPool.warning_agents > 0 && (
                          <div>
                            <Badge status="warning" />
                            {selectedPool.warning_agents} warning
                          </div>
                        )}
                        <div>
                          <Badge status="error" />
                          {selectedPool.offline_agents} offline
                        </div>
                      </div>
                    }
                  />
                </Card>
              </Col>
            </Row>

            <Card
              title="Pool Agents"
              size="small"
              loading={agentsLoading}
              extra={
                <Button
                  size="small"
                  icon={<ReloadOutlined />}
                  onClick={() => fetchPoolAgents(selectedPool.id)}
                />
              }
            >
              {poolAgents.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '40px' }}>
                  <TeamOutlined style={{ fontSize: '48px', color: '#d9d9d9' }} />
                  <Paragraph type="secondary" style={{ marginTop: '16px' }}>
                    No agents registered in this pool yet.
                  </Paragraph>
                </div>
              ) : (
                <List
                  itemLayout="horizontal"
                  dataSource={poolAgents}
                  renderItem={agent => (
                    <List.Item
                      actions={[
                        getAgentHealthBadge(agent.health)
                      ]}
                    >
                      <List.Item.Meta
                        avatar={
                          <Avatar 
                            icon={<DesktopOutlined />} 
                            style={{ backgroundColor: agent.health === 'healthy' ? '#52c41a' : '#ff4d4f' }}
                          />
                        }
                        title={
                          <Space>
                            <Text strong>{agent.name}</Text>
                            <Tag>{agent.platform}</Tag>
                          </Space>
                        }
                        description={
                          <Space direction="vertical" size="small">
                            <Text type="secondary">
                              {agent.hostname} {agent.ip_address && `(${agent.ip_address})`}
                            </Text>
                            <Text type="secondary" style={{ fontSize: '12px' }}>
                              HAProxy: {agent.haproxy_version || 'Unknown'} | 
                              Last seen: {agent.last_seen ? new Date(agent.last_seen).toLocaleString() : 'Never'}
                            </Text>
                          </Space>
                        }
                      />
                    </List.Item>
                  )}
                />
              )}
            </Card>
          </div>
        )}
      </Modal>
    </div>
  );
};

export default PoolManagement; 