import React, { useState, useEffect } from 'react';
import {
  Card, Table, Button, Modal, Form, Input, Select, message, 
  Space, Tag, Typography, Divider, Alert, Tooltip, 
  Popconfirm, Row, Col, Statistic, Badge, Copy
} from 'antd';
import {
  SecurityScanOutlined, KeyOutlined, PlusOutlined, DeleteOutlined,
  ExclamationCircleOutlined, InfoCircleOutlined, CopyOutlined,
  ClockCircleOutlined, CheckCircleOutlined, WarningOutlined
} from '@ant-design/icons';
import axios from 'axios';
import { useCluster } from '../contexts/ClusterContext';

const { Title, Text, Paragraph } = Typography;
const { Option } = Select;
const { TextArea } = Input;

const Security = () => {
  const { selectedCluster } = useCluster();
  const [tokens, setTokens] = useState([]);
  const [loading, setLoading] = useState(false);
  const [modalVisible, setModalVisible] = useState(false);
  const [tokenModalVisible, setTokenModalVisible] = useState(false);
  const [newToken, setNewToken] = useState(null);
  const [form] = Form.useForm();

  useEffect(() => {
    fetchTokens();
  }, []);

  const fetchTokens = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get('/api/security/agent-tokens', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setTokens(response.data.tokens || []);
    } catch (error) {
      console.error('Failed to fetch agent tokens:', error);
      message.error('Failed to fetch agent tokens');
    } finally {
      setLoading(false);
    }
  };


  const handleCreateToken = async (values) => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.post('/api/security/agent-tokens', values, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      setNewToken(response.data);
      setTokenModalVisible(true);
      setModalVisible(false);
      form.resetFields();
      
      await fetchTokens();
      
      message.success('Agent API token created successfully!');
    } catch (error) {
      console.error('Failed to create agent token:', error);
      message.error(error.response?.data?.detail || 'Failed to create agent token');
    }
  };

  const handleRevokeToken = async (tokenName, agentCount) => {
    try {
      const token = localStorage.getItem('token');
      const response = await axios.delete(`/api/security/agent-tokens/by-name/${encodeURIComponent(tokenName)}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      await fetchTokens();
      
      message.success(response.data.message || `API token '${tokenName}' revoked successfully`);
    } catch (error) {
      console.error('Failed to revoke agent token:', error);
      message.error(error.response?.data?.detail || 'Failed to revoke agent token');
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    message.success('API token copied to clipboard!');
  };

  const getTokenStatus = (token) => {
    if (token.is_expired) {
      return <Tag color="red" icon={<WarningOutlined />}>Expired</Tag>;
    }
    if (token.expires_at) {
      const daysLeft = Math.ceil((new Date(token.expires_at) - new Date()) / (1000 * 60 * 60 * 24));
      if (daysLeft <= 7) {
        return <Tag color="orange" icon={<ClockCircleOutlined />}>Expires in {daysLeft}d</Tag>;
      }
      return <Tag color="green" icon={<CheckCircleOutlined />}>Active</Tag>;
    }
    return <Tag color="blue" icon={<CheckCircleOutlined />}>No Expiration</Tag>;
  };

  const columns = [
    {
      title: 'Token Name',
      dataIndex: 'name',
      key: 'name',
      render: (name) => <Text code>{name}</Text>
    },
    {
      title: 'Agents',
      key: 'agents',
      render: (_, record) => {
        const { agent_count, agent_names } = record;
        
        if (agent_count === 0) {
          return (
            <Space>
              <ClockCircleOutlined style={{ color: '#faad14' }} />
              <Text type="secondary">Awaiting first agent</Text>
            </Space>
          );
        } else if (agent_count === 1) {
          return (
            <Space>
              <SecurityScanOutlined style={{ color: '#52c41a' }} />
              <Text strong>{agent_names[0]}</Text>
            </Space>
          );
        } else {
          return (
            <Space>
              <Badge count={agent_count} size="small">
                <SecurityScanOutlined style={{ color: '#1890ff', fontSize: '16px' }} />
              </Badge>
              <Tooltip title={`Agents: ${agent_names?.join(', ')}`}>
                <Text strong style={{ cursor: 'pointer' }}>
                  {agent_count} agents
                </Text>
              </Tooltip>
            </Space>
          );
        }
      },
      width: 200
    },
    {
      title: 'Status',
      key: 'status',
      render: (_, record) => getTokenStatus(record)
    },
    {
      title: 'Created',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (date) => new Date(date).toLocaleDateString()
    },
    {
      title: 'Created By',
      dataIndex: 'created_by_username',
      key: 'created_by_username'
    },
    {
      title: 'Last Used',
      dataIndex: 'last_used',
      key: 'last_used',
      render: (date) => date ? new Date(date).toLocaleDateString() : <Text type="secondary">Never</Text>
    },
    {
      title: 'Expires',
      dataIndex: 'expires_at',
      key: 'expires_at',
      render: (date) => date ? new Date(date).toLocaleDateString() : <Text type="secondary">No expiration</Text>
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Popconfirm
          title="Revoke API Token"
          description={
            record.agent_count === 0 
              ? "Are you sure you want to revoke this unused token?"
              : `Are you sure you want to revoke this token? This will immediately stop ${record.agent_count} agent(s) from accessing the API: ${record.agent_names?.join(', ')}`
          }
          onConfirm={() => handleRevokeToken(record.name, record.agent_count)}
          okText="Revoke"
          cancelText="Cancel"
          okButtonProps={{ danger: true }}
        >
          <Button 
            type="text" 
            danger 
            icon={<DeleteOutlined />}
            size="small"
          >
            Revoke
          </Button>
        </Popconfirm>
      )
    }
  ];

  return (
    <div style={{ padding: '24px' }}>
      <Title level={2}>
        <Space>
          <SecurityScanOutlined />
          Security Management
        </Space>
      </Title>
      
      <Paragraph>
        Manage API tokens for secure agent authentication. Each agent requires a unique API token to communicate with the HAProxy management system.
      </Paragraph>

      {/* Statistics Cards */}
      <Row gutter={16} style={{ marginBottom: '24px' }}>
        <Col span={6}>
          <Card>
            <Statistic
              title="Active Tokens"
              value={tokens.filter(t => !t.is_expired).length}
              prefix={<KeyOutlined style={{ color: '#52c41a' }} />}
              valueStyle={{ color: '#52c41a' }}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="Expired Tokens"
              value={tokens.filter(t => t.is_expired).length}
              prefix={<WarningOutlined style={{ color: '#ff4d4f' }} />}
              valueStyle={{ color: '#ff4d4f' }}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="Pending Tokens"
              value={tokens.filter(token => token.agent_count === 0).length}
              prefix={<ClockCircleOutlined style={{ color: '#fa8c16' }} />}
              valueStyle={{ color: '#fa8c16' }}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic
              title="Active Agents"
              value={tokens.reduce((total, token) => total + (token.agent_count || 0), 0)}
              prefix={<SecurityScanOutlined style={{ color: '#1890ff' }} />}
              valueStyle={{ color: '#1890ff' }}
            />
          </Card>
        </Col>
      </Row>

      {/* Info Alert */}
      <Alert
        message="Agent Token Management"
        description="Create standalone tokens for agent registration. Agents will automatically associate with tokens during their first connection."
        type="info"
        showIcon
        style={{ marginBottom: '24px' }}
      />

      {/* Main Content */}
      <Card
        title={
          <Space>
            <KeyOutlined />
            Agent API Tokens
          </Space>
        }
        extra={
          <Space>
            <Button 
              type="primary" 
              icon={<PlusOutlined />}
              onClick={() => {
                console.log('🔍 SECURITY DEBUG: Create Token clicked');
                setModalVisible(true);
              }}
              disabled={false} // Always enable token creation
              title="Create standalone token for agent registration"
            >
              Create Token
            </Button>
          </Space>
        }
      >
        <Table
          columns={columns}
          dataSource={tokens}
          rowKey="primary_agent_id"
          loading={loading}
          pagination={{ pageSize: 10 }}
          locale={{
            emptyText: 'No agent API tokens created yet'
          }}
        />
      </Card>

      {/* Create Token Modal */}
      <Modal
        title={
          <Space>
            <KeyOutlined />
            Create Agent API Token
          </Space>
        }
        open={modalVisible}
        onCancel={() => {
          setModalVisible(false);
          form.resetFields();
        }}
        footer={null}
        width={600}
      >
        <Alert
          message="Standalone Token"
          description="This token can be used by any agent during registration. The token will be shown only once after creation."
          type="info"
          showIcon
          style={{ marginBottom: '24px' }}
        />

        <Form
          form={form}
          layout="vertical"
          onFinish={handleCreateToken}
        >
          <Form.Item
            name="name"
            label="Token Name"
            rules={[{ required: true, message: 'Please enter a token name' }]}
          >
            <Input placeholder="e.g., Production Agent Token" />
          </Form.Item>

          <Form.Item
            name="description"
            label="Description (Optional)"
          >
            <TextArea 
              rows={3} 
              placeholder="Optional description for this token..."
            />
          </Form.Item>

          <Form.Item
            name="expires_in_days"
            label="Expiration"
            extra="Leave empty for no expiration (recommended for production agents)"
          >
            <Select placeholder="Select expiration period" allowClear>
              <Option value={30}>30 days</Option>
              <Option value={90}>90 days</Option>
              <Option value={180}>180 days</Option>
              <Option value={365}>1 year</Option>
            </Select>
          </Form.Item>

          <Form.Item style={{ marginBottom: 0 }}>
            <Space>
              <Button type="primary" htmlType="submit">
                Create Token
              </Button>
              <Button onClick={() => {
                setModalVisible(false);
                form.resetFields();
              }}>
                Cancel
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* Token Display Modal */}
      <Modal
        title={
          <Space>
            <KeyOutlined style={{ color: '#52c41a' }} />
            API Token Created Successfully
          </Space>
        }
        open={tokenModalVisible}
        onCancel={() => {
          setTokenModalVisible(false);
          setNewToken(null);
        }}
        footer={[
          <Button 
            key="copy" 
            type="primary" 
            icon={<CopyOutlined />}
            onClick={() => copyToClipboard(newToken?.api_key)}
          >
            Copy Token
          </Button>,
          <Button 
            key="close" 
            onClick={() => {
              setTokenModalVisible(false);
              setNewToken(null);
            }}
          >
            Close
          </Button>
        ]}
        width={700}
      >
        {newToken && (
          <div>
            <Alert
              message="⚠️ Important: Save this token securely!"
              description="This API token will not be shown again. Copy it now and store it in a secure location."
              type="warning"
              showIcon
              style={{ marginBottom: '24px' }}
            />

            <div style={{ marginBottom: '16px' }}>
              <Text strong>Agent:</Text> <Tag color="blue">{newToken.agent_name}</Tag>
            </div>
            
            <div style={{ marginBottom: '16px' }}>
              <Text strong>Token Name:</Text> <Text code>{newToken.token_name}</Text>
            </div>

            <div style={{ marginBottom: '16px' }}>
              <Text strong>API Token:</Text>
              <div style={{ 
                background: '#f5f5f5', 
                padding: '12px', 
                borderRadius: '6px', 
                marginTop: '8px',
                fontFamily: 'monospace',
                fontSize: '13px',
                wordBreak: 'break-all',
                border: '1px solid #d9d9d9'
              }}>
                {newToken.api_key}
              </div>
            </div>

            {newToken.expires_at && (
              <div style={{ marginBottom: '16px' }}>
                <Text strong>Expires:</Text> <Text>{new Date(newToken.expires_at).toLocaleDateString()}</Text>
              </div>
            )}

            <Divider />
            
            <Alert
              message="Next Steps"
              description={
                <div>
                  <p>1. Copy the API token above</p>
                  <p>2. Configure your agent script with this token</p>
                  <p>3. Set the token as <Text code>X-API-Key</Text> header in agent requests</p>
                </div>
              }
              type="info"
              showIcon
            />
          </div>
        )}
      </Modal>
    </div>
  );
};

export default Security;
