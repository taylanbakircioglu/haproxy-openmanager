// Configuration Management Component - Agent haproxy.cfg viewer
import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Card,
  Table,
  Button,
  Space,
  Tag,
  message,
  Badge,
  Typography,
  Alert,
  Tooltip,
  Spin,
  Modal,
  Input,
  Progress
} from 'antd';
import {
  DesktopOutlined,
  EyeOutlined,
  DownloadOutlined,
  ReloadOutlined,
  HeartTwoTone,
  WarningOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  ClockCircleOutlined,
  LinuxOutlined,
  AppleOutlined,
  WifiOutlined,
  DisconnectOutlined,
  InfoCircleOutlined,
  FileTextOutlined,
  SyncOutlined
} from '@ant-design/icons';
import axios from 'axios';
import { useCluster } from '../contexts/ClusterContext';

const { Text, Title, Paragraph } = Typography;
const { TextArea } = Input;

const Configuration = () => {
  // === State Management ===
  const [agents, setAgents] = useState([]);
  const [filteredAgents, setFilteredAgents] = useState([]);
  const [searchText, setSearchText] = useState('');
  const [loading, setLoading] = useState(false);
  const [configModalVisible, setConfigModalVisible] = useState(false);
  const [selectedAgent, setSelectedAgent] = useState(null);
  const [configContent, setConfigContent] = useState('');
  const [configLoading, setConfigLoading] = useState(false);
  const [requestId, setRequestId] = useState(null);
  const [progressPercent, setProgressPercent] = useState(0);
  const [timeRemaining, setTimeRemaining] = useState(60);
  
  // Use refs to store interval and timeout IDs to avoid stale closures
  const pollingIntervalRef = useRef(null);
  const timeoutRef = useRef(null);
  const pollCountRef = useRef(0);
  
  const { selectedCluster } = useCluster();

  // Platform configuration
  const platformConfig = {
    linux: {
      name: 'Linux',
      icon: <LinuxOutlined style={{ fontSize: '24px', color: '#1890ff' }} />,
      color: '#1890ff'
    },
    darwin: {
      name: 'macOS',
      icon: <AppleOutlined style={{ fontSize: '24px', color: '#722ed1' }} />,
      color: '#722ed1'
    }
  };

  // Fetch agents from API
  const fetchAgents = useCallback(async () => {
    if (!selectedCluster) {
      setAgents([]);
      setFilteredAgents([]);
        return;
      }

    setLoading(true);
    try {
      const params = { pool_id: selectedCluster.pool_id };
      const response = await axios.get('/api/agents', { 
        params, 
        timeout: 10000,
        headers: {
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache'
        }
      });
      const agentsData = response.data.agents || [];
      
      setAgents(agentsData);
      setFilteredAgents(agentsData);
    } catch (error) {
      console.error('Failed to fetch agents:', error);
      message.error('Failed to fetch agents: ' + (error.response?.data?.detail || error.message));
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
        agent.hostname?.toLowerCase().includes(value.toLowerCase()) ||
        agent.pool_name?.toLowerCase().includes(value.toLowerCase()) ||
        agent.platform?.toLowerCase().includes(value.toLowerCase()) ||
        agent.ip_address?.toLowerCase().includes(value.toLowerCase())
      );
      setFilteredAgents(filtered);
    }
  };

  // Update filteredAgents when agents change
  useEffect(() => {
    handleSearch(searchText);
  }, [agents, searchText]);

  // CRITICAL FIX: Clear agents immediately when cluster changes (prevent cache/mixing)
  useEffect(() => {
    if (selectedCluster) {
      console.log(`🔄 CLUSTER CHANGED: ${selectedCluster.name} (ID: ${selectedCluster.id}) - Clearing agents to prevent mixing...`);
      setAgents([]);
      setFilteredAgents([]);
    }
  }, [selectedCluster?.id]); // Trigger on cluster ID change only

  // Initial load
  useEffect(() => {
    fetchAgents();
  }, [fetchAgents, selectedCluster]);

  // Get platform icon
  const getPlatformIcon = (platform) => {
    return platformConfig[platform]?.icon || <DesktopOutlined style={{ fontSize: '16px' }} />;
  };

  // Enhanced status badge
  const getStatusBadge = (health, status, lastSeen) => {
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
      unknown: { 
        status: 'default', 
        icon: <ClockCircleOutlined />, 
        text: 'Unknown',
        color: '#d9d9d9'
      }
    };
    
    const config = statusConfig[health] || statusConfig.unknown;
    
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

  // Cancel config request
  const cancelConfigRequest = () => {
    if (pollingIntervalRef.current) {
      clearInterval(pollingIntervalRef.current);
      pollingIntervalRef.current = null;
    }
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
      timeoutRef.current = null;
    }
    setConfigLoading(false);
    setProgressPercent(0);
    setTimeRemaining(60);
    pollCountRef.current = 0;
    message.info('Configuration request cancelled');
  };

  // Poll for config response
  const pollConfigResponse = useCallback(async (reqId) => {
    try {
      pollCountRef.current += 1;
      
      const response = await axios.get(`/api/configuration/response/${reqId}`);
      const data = response.data;
      
      if (data.status === 'completed' && data.config_content) {
        // Success - got the config
        if (pollingIntervalRef.current) {
          clearInterval(pollingIntervalRef.current);
          pollingIntervalRef.current = null;
        }
        if (timeoutRef.current) {
          clearTimeout(timeoutRef.current);
          timeoutRef.current = null;
        }
        setConfigLoading(false);
        setProgressPercent(100);
        setConfigContent(data.config_content);
        setConfigModalVisible(true);
        message.success('Configuration retrieved successfully');
      } else if (data.status === 'expired') {
        // Request expired
        if (pollingIntervalRef.current) {
          clearInterval(pollingIntervalRef.current);
          pollingIntervalRef.current = null;
        }
        if (timeoutRef.current) {
          clearTimeout(timeoutRef.current);
          timeoutRef.current = null;
        }
        setConfigLoading(false);
        setProgressPercent(0);
        message.error('Request expired. Agent did not respond in time.');
      } else {
        // Still pending - update progress
        const elapsed = pollCountRef.current * 2; // 2 seconds per poll
        const progress = Math.min((elapsed / 90) * 100, 95); // Cap at 95% until complete (90s timeout)
        setProgressPercent(progress);
      }
    } catch (error) {
      if (pollingIntervalRef.current) {
        clearInterval(pollingIntervalRef.current);
        pollingIntervalRef.current = null;
      }
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
        timeoutRef.current = null;
      }
      setConfigLoading(false);
      setProgressPercent(0);
      message.error('Failed to get configuration: ' + (error.response?.data?.detail || error.message));
    }
  }, []);

  // View configuration
  const viewConfig = async (agent) => {
    if (agent.status !== 'online') {
      message.warning(`Agent '${agent.name}' is not online. Cannot retrieve configuration.`);
        return;
      }
    
    if (!selectedCluster) {
      message.error('No cluster selected. Please select a cluster first.');
      return;
    }
      
    setSelectedAgent(agent);
    setConfigLoading(true);
    setConfigContent('');
    setProgressPercent(0);
    setTimeRemaining(90);
    pollCountRef.current = 0;
    
    try {
      // Create config request with cluster_id
      const response = await axios.post('/api/configuration/request', null, {
        params: {
          agent_name: agent.name,
          cluster_id: selectedCluster.id,
          request_type: 'view'
        }
      });
      
      const reqId = response.data.request_id;
      setRequestId(reqId);
      
      message.info('Configuration request sent. Waiting for agent response...');
      
      // Start polling for response
      pollingIntervalRef.current = setInterval(() => {
        pollConfigResponse(reqId);
      }, 2000); // Poll every 2 seconds
      
      // Timeout after 90 seconds (agent checks every 30 seconds, worst case ~60s with restart)
      timeoutRef.current = setTimeout(() => {
        if (pollingIntervalRef.current) {
          clearInterval(pollingIntervalRef.current);
          pollingIntervalRef.current = null;
        }
        setConfigLoading(false);
        setProgressPercent(0);
        message.error('Request timeout. Agent did not respond in time. Please try again.');
      }, 90000); // 90 seconds
      
    } catch (error) {
      setConfigLoading(false);
      setProgressPercent(0);
      message.error('Failed to create configuration request: ' + (error.response?.data?.detail || error.message));
    }
  };

  // Download configuration
  const downloadConfig = async (agent) => {
    if (agent.status !== 'online') {
      message.warning(`Agent '${agent.name}' is not online. Cannot retrieve configuration.`);
      return;
    }

    if (!selectedCluster) {
      message.error('No cluster selected. Please select a cluster first.');
      return;
    }

    setSelectedAgent(agent);
    setConfigLoading(true);
    setProgressPercent(0);
    pollCountRef.current = 0;
    
    try {
      // Create config request with cluster_id
      const response = await axios.post('/api/configuration/request', null, {
        params: {
          agent_name: agent.name,
          cluster_id: selectedCluster.id,
          request_type: 'download'
        }
      });
      
      const reqId = response.data.request_id;
      
      message.info('Configuration request sent. Waiting for agent response...');
      
      // Start polling for response
      const pollForDownload = async () => {
        try {
          pollCountRef.current += 1;
          const elapsed = pollCountRef.current * 2;
          const progress = Math.min((elapsed / 90) * 100, 95); // 90s timeout
          setProgressPercent(progress);
          
          const pollResponse = await axios.get(`/api/configuration/response/${reqId}`);
          const data = pollResponse.data;
          
          if (data.status === 'completed' && data.config_content) {
            // Success - download the config
            setProgressPercent(100);
            if (pollingIntervalRef.current) {
              clearInterval(pollingIntervalRef.current);
              pollingIntervalRef.current = null;
            }
            if (timeoutRef.current) {
              clearTimeout(timeoutRef.current);
              timeoutRef.current = null;
            }
            
            const element = document.createElement('a');
            const file = new Blob([data.config_content], { type: 'text/plain' });
            element.href = URL.createObjectURL(file);
            element.download = `${agent.name}-haproxy.cfg`;
            document.body.appendChild(element);
            element.click();
            document.body.removeChild(element);
            
            setConfigLoading(false);
            setProgressPercent(0);
            message.success('Configuration downloaded successfully');
            return true;
          } else if (data.status === 'expired') {
            if (pollingIntervalRef.current) {
              clearInterval(pollingIntervalRef.current);
              pollingIntervalRef.current = null;
            }
            if (timeoutRef.current) {
              clearTimeout(timeoutRef.current);
              timeoutRef.current = null;
            }
            setConfigLoading(false);
            setProgressPercent(0);
            message.error('Request expired. Agent did not respond in time.');
            return true;
          }
          return false;
    } catch (error) {
          if (pollingIntervalRef.current) {
            clearInterval(pollingIntervalRef.current);
            pollingIntervalRef.current = null;
          }
          if (timeoutRef.current) {
            clearTimeout(timeoutRef.current);
            timeoutRef.current = null;
          }
          setConfigLoading(false);
          setProgressPercent(0);
          message.error('Failed to download configuration: ' + (error.response?.data?.detail || error.message));
          return true;
        }
      };
      
      // Poll every 2 seconds
      pollingIntervalRef.current = setInterval(async () => {
        await pollForDownload();
      }, 2000);
      
      // Timeout after 90 seconds (agent checks every 30 seconds, worst case ~60s with restart)
      timeoutRef.current = setTimeout(() => {
        if (pollingIntervalRef.current) {
          clearInterval(pollingIntervalRef.current);
          pollingIntervalRef.current = null;
        }
        setConfigLoading(false);
        setProgressPercent(0);
        message.error('Request timeout. Agent did not respond in time. Please try again.');
      }, 90000); // 90 seconds
      
    } catch (error) {
      setConfigLoading(false);
      setProgressPercent(0);
      message.error('Failed to create configuration request: ' + (error.response?.data?.detail || error.message));
    }
  };

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      if (pollingIntervalRef.current) {
        clearInterval(pollingIntervalRef.current);
        pollingIntervalRef.current = null;
      }
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
        timeoutRef.current = null;
      }
    };
  }, []);

  // Table columns
  const columns = [
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
      title: 'Platform',
      key: 'platform',
      render: (_, record) => (
        <Space>
          <Tag color="blue" style={{ textTransform: 'capitalize' }}>
            {record.platform}
          </Tag>
          <Tag color="cyan" size="small">
            {record.architecture}
          </Tag>
        </Space>
      ),
      width: 150,
    },
    {
      title: 'HAProxy Status',
      key: 'haproxy_status',
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
      render: (_, record) => getStatusBadge(record.health, record.status, record.last_seen),
      width: 120,
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => {
        const isLoading = configLoading && selectedAgent?.id === record.id;
        
        if (isLoading) {
          return (
            <Space direction="vertical" style={{ width: '100%' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <SyncOutlined spin style={{ color: '#1890ff' }} />
                <Text type="secondary" style={{ fontSize: '12px' }}>
                  Waiting for agent...
                </Text>
              </div>
              <Progress 
                percent={progressPercent} 
            size="small"
                status="active"
                showInfo={false}
              />
          <Button
            size="small"
                danger 
                onClick={cancelConfigRequest}
                style={{ width: '100%' }}
          >
                Cancel
          </Button>
              </Space>
          );
        }
        
        return (
                  <Space>
            <Tooltip title={record.status !== 'online' ? 'Agent must be online' : 'View configuration'}>
                      <Button
                type="primary"
                        size="small"
            icon={<EyeOutlined />}
                onClick={() => viewConfig(record)}
                disabled={record.status !== 'online'}
          >
            View
          </Button>
            </Tooltip>
            <Tooltip title={record.status !== 'online' ? 'Agent must be online' : 'Download configuration'}>
                          <Button
                            size="small"
                icon={<DownloadOutlined />}
                onClick={() => downloadConfig(record)}
                disabled={record.status !== 'online'}
              >
                Download
              </Button>
            </Tooltip>
                  </Space>
        );
      },
      width: 220,
      fixed: 'right',
              },
  ];

    return (
    <div style={{ padding: '24px' }}>
      <div style={{ marginBottom: '24px' }}>
        <Title level={2}>
          <Space>
            <FileTextOutlined />
            Configuration Management
          </Space>
        </Title>
        <Paragraph>
          View and download active haproxy.cfg files from agents. 
          Configuration files are retrieved directly from agents in real-time.
        </Paragraph>
        
        {/* Info Alert */}
        <Alert
          message="How it works"
          description={
            <div>
              <ul style={{ marginBottom: 0, paddingLeft: '20px' }}>
                <li>Click "View" or "Download" to request the configuration file from an agent</li>
                <li>The agent will retrieve its current haproxy.cfg file on the next heartbeat</li>
                <li>The configuration will be displayed or downloaded once available</li>
                <li>Agents must be online to process configuration requests</li>
              </ul>
            </div>
          }
          type="info"
          showIcon
          style={{ marginTop: '16px' }}
        />
      </div>

          <Card
        title={<Space><DesktopOutlined /> Agents - {selectedCluster?.name || 'No cluster selected'}</Space>}
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
                    fontSize: 14
                  }}
                />
              )}
            </div>
                <Button
                  icon={<ReloadOutlined />}
              onClick={fetchAgents}
              loading={loading}
              type="primary"
              ghost
                >
                  Refresh
                </Button>
              </Space>
            }
          >
        {!selectedCluster ? (
            <Alert
            message="No Cluster Selected"
            description="Please select a cluster from the cluster selector above to view its agents."
            type="warning"
              showIcon
          />
        ) : agents.length === 0 && !loading ? (
          <div style={{ 
            textAlign: 'center', 
            padding: '60px 20px',
            background: '#fafafa',
            borderRadius: '6px'
          }}>
            <DesktopOutlined style={{ fontSize: '64px', color: '#d9d9d9', marginBottom: '16px' }} />
            <Title level={3} type="secondary">No Agents Found</Title>
            <Paragraph type="secondary">
              No agents are registered in this cluster yet.
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
              }}
              scroll={{ x: 1000 }}
              size="middle"
            />
          </Spin>
        )}
          </Card>

      {/* Configuration Modal */}
      <Modal
        title={
            <Space>
            <FileTextOutlined />
            <span>Configuration - {selectedAgent?.name}</span>
            </Space>
        }
        open={configModalVisible}
        onCancel={() => {
          setConfigModalVisible(false);
          setConfigContent('');
        }}
        width="90%"
        footer={[
            <Button
              key="download"
              icon={<DownloadOutlined />}
            onClick={() => {
              const element = document.createElement('a');
              const file = new Blob([configContent], { type: 'text/plain' });
              element.href = URL.createObjectURL(file);
              element.download = `${selectedAgent?.name}-haproxy.cfg`;
              document.body.appendChild(element);
              element.click();
              document.body.removeChild(element);
              message.success('Configuration downloaded');
            }}
            >
              Download
          </Button>,
          <Button key="close" onClick={() => setConfigModalVisible(false)}>
            Close
            </Button>
        ]}
      >
        <Alert
          message="Read-Only Configuration"
          description="This is the current active configuration from the agent. Use the Download button to save it locally."
          type="info"
          showIcon
          style={{ marginBottom: '16px' }}
        />
        
        <div style={{ border: '1px solid #d9d9d9', borderRadius: '6px' }}>
          <div style={{ 
            background: '#001529', 
            color: 'white', 
            padding: '8px 12px', 
            fontSize: '12px',
            borderBottom: '1px solid #434343'
          }}>
            {selectedAgent?.config_path || 'haproxy.cfg'}
              </div>
          <TextArea
            value={configContent}
            readOnly
            rows={25}
            style={{
              fontFamily: 'Monaco, Menlo, "Ubuntu Mono", monospace',
              fontSize: '12px',
              border: 'none',
              borderRadius: '0 0 6px 6px'
                }}
              />
            </div>
      </Modal>
    </div>
  );
};

export default Configuration;
