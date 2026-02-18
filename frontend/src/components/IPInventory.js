import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Card,
  Table,
  Input,
  Tag,
  Badge,
  Tabs,
  Typography,
  Row,
  Col,
  Statistic,
  Space,
  Select,
  Spin,
  Empty,
  Tooltip,
  message
} from 'antd';
import {
  SearchOutlined,
  SyncOutlined,
  CloudServerOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  LinuxOutlined,
  AppleOutlined,
  GlobalOutlined,
  HeartTwoTone,
  ClockCircleOutlined,
  DesktopOutlined
} from '@ant-design/icons';
import axios from 'axios';
import { useTheme } from '../contexts/ThemeContext';

const { Text, Title } = Typography;

const CLUSTER_COLORS = ['blue', 'green', 'orange', 'purple', 'cyan', 'magenta', 'red', 'gold', 'lime', 'geekblue', 'volcano'];

function getClusterColor(clusterName, clusterNames) {
  if (!clusterName || clusterName === '-') return 'default';
  const sorted = [...clusterNames].sort();
  const idx = sorted.indexOf(clusterName);
  if (idx === -1) return 'default';
  return CLUSTER_COLORS[idx % CLUSTER_COLORS.length];
}

function timeAgo(dateStr) {
  if (!dateStr) return '-';
  const now = new Date();
  const date = new Date(dateStr);
  const seconds = Math.floor((now - date) / 1000);
  if (seconds < 0) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function highlightMatch(text, search) {
  if (!search || !text) return text || '-';
  const str = String(text);
  const idx = str.toLowerCase().indexOf(search.toLowerCase());
  if (idx === -1) return str;
  return (
    <span>
      {str.substring(0, idx)}
      <span style={{
        backgroundColor: 'rgba(24, 144, 255, 0.15)',
        borderRadius: 2,
        padding: '0 2px',
        fontWeight: 600
      }}>
        {str.substring(idx, idx + search.length)}
      </span>
      {str.substring(idx + search.length)}
    </span>
  );
}

const IPInventory = () => {
  const { isDarkMode } = useTheme();

  const [agents, setAgents] = useState([]);
  const [clusters, setClusters] = useState([]);
  const [backendServers, setBackendServers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [searchText, setSearchText] = useState('');
  const [activeSearch, setActiveSearch] = useState('');
  const [activeTab, setActiveTab] = useState('agents');
  const [agentClusterFilter, setAgentClusterFilter] = useState(null);
  const [agentStatusFilter, setAgentStatusFilter] = useState(null);
  const [serverClusterFilter, setServerClusterFilter] = useState(null);
  const [serverStatusFilter, setServerStatusFilter] = useState(null);

  const fetchData = useCallback(async (isInitial = false) => {
    if (!isInitial) setRefreshing(true);
    try {
      const [agentsRes, clustersRes, backendsRes] = await Promise.all([
        axios.get('/api/agents'),
        axios.get('/api/clusters'),
        axios.get('/api/backends')
      ]);

      const clustersData = clustersRes.data.clusters || clustersRes.data || [];
      setClusters(clustersData);

      const clusterByPoolId = {};
      clustersData.forEach(c => {
        if (c.pool_id) {
          clusterByPoolId[c.pool_id] = c;
        }
      });

      const clusterById = {};
      clustersData.forEach(c => {
        clusterById[c.id] = c;
      });

      const agentsData = (agentsRes.data.agents || []).map(agent => {
        const cluster = clusterByPoolId[agent.pool_id];
        return {
          ...agent,
          cluster_name: cluster?.name || '-',
          cluster_id: cluster?.id || null
        };
      });
      setAgents(agentsData);

      const servers = [];
      const backends = backendsRes.data.backends || [];
      backends.forEach(backend => {
        (backend.servers || []).forEach(server => {
          const clusterId = backend.cluster_id || server.cluster_id;
          const cluster = clusterById[clusterId];
          servers.push({
            ...server,
            backend_name: backend.name || server.backend_name,
            cluster_id: clusterId,
            cluster_name: cluster?.name || '-'
          });
        });
      });
      setBackendServers(servers);
    } catch (error) {
      console.error('Failed to fetch IP inventory data:', error);
      if (isInitial) {
        message.error('Failed to load IP inventory data');
      }
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchData(true);
    const interval = setInterval(() => fetchData(false), 30000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const clusterNames = useMemo(() => {
    const names = new Set();
    agents.forEach(a => { if (a.cluster_name && a.cluster_name !== '-') names.add(a.cluster_name); });
    backendServers.forEach(s => { if (s.cluster_name && s.cluster_name !== '-') names.add(s.cluster_name); });
    return [...names].sort();
  }, [agents, backendServers]);

  const handleSearch = (value) => {
    const trimmed = (value || '').trim();
    setActiveSearch(trimmed);
  };

  const handleInputChange = (e) => {
    const val = e.target.value || '';
    setSearchText(val);
    if (!val) {
      setActiveSearch('');
    }
  };

  const MAX_SEARCH_RESULTS_DISPLAY = 50;

  const searchResults = useMemo(() => {
    if (!activeSearch) return [];
    const results = [];
    const q = activeSearch.toLowerCase();

    agents.forEach(agent => {
      const ipMatch = agent.ip_address && agent.ip_address.toLowerCase().includes(q);
      const vipMatch = agent.keepalive_ip && agent.keepalive_ip.toLowerCase().includes(q);
      if (ipMatch) {
        results.push({
          type: 'Agent IP',
          color: 'blue',
          name: agent.name,
          ip: agent.ip_address,
          cluster: agent.cluster_name,
          detail: `${agent.status || 'unknown'}${agent.keepalive_state ? '  ·  ' + agent.keepalive_state : ''}`,
          status: agent.status
        });
      }
      if (vipMatch) {
        results.push({
          type: 'VIP',
          color: 'green',
          name: agent.name,
          ip: agent.keepalive_ip,
          cluster: agent.cluster_name,
          detail: `${agent.status || 'unknown'}${agent.keepalive_state ? '  ·  ' + agent.keepalive_state : ''}`,
          status: agent.status
        });
      }
    });

    backendServers.forEach(server => {
      const addr = server.address || '';
      if (addr.toLowerCase().includes(q)) {
        results.push({
          type: 'Backend Server',
          color: 'purple',
          name: server.name || server.server_name,
          ip: addr,
          cluster: server.cluster_name,
          detail: `${server.backend_name || '-'}  ·  ${server.status || 'unknown'}`,
          status: server.status
        });
      }
    });

    return results;
  }, [activeSearch, agents, backendServers]);

  const filteredAgents = useMemo(() => {
    let data = agents;
    if (activeSearch) {
      const q = activeSearch.toLowerCase();
      data = data.filter(a =>
        (a.ip_address && a.ip_address.toLowerCase().includes(q)) ||
        (a.keepalive_ip && a.keepalive_ip.toLowerCase().includes(q))
      );
    }
    if (agentClusterFilter) {
      data = data.filter(a => a.cluster_name === agentClusterFilter);
    }
    if (agentStatusFilter) {
      data = data.filter(a => a.status === agentStatusFilter);
    }
    return data;
  }, [agents, activeSearch, agentClusterFilter, agentStatusFilter]);

  const filteredServers = useMemo(() => {
    let data = backendServers;
    if (activeSearch) {
      const q = activeSearch.toLowerCase();
      data = data.filter(s => {
        const addr = s.address || '';
        return addr.toLowerCase().includes(q);
      });
    }
    if (serverClusterFilter) {
      data = data.filter(s => s.cluster_name === serverClusterFilter);
    }
    if (serverStatusFilter) {
      data = data.filter(s => {
        const baseStatus = (s.status || '').split(' ')[0].toUpperCase();
        return baseStatus === serverStatusFilter.toUpperCase();
      });
    }
    return data;
  }, [backendServers, activeSearch, serverClusterFilter, serverStatusFilter]);

  const stats = useMemo(() => {
    const onlineAgents = agents.filter(a => a.status === 'online').length;
    const vipCount = agents.filter(a => a.keepalive_ip).length;
    return {
      totalAgents: agents.length,
      onlineAgents,
      vipCount,
      totalServers: backendServers.length
    };
  }, [agents, backendServers]);

  const agentColumns = [
    {
      title: 'Cluster',
      dataIndex: 'cluster_name',
      key: 'cluster_name',
      width: 150,
      sorter: (a, b) => (a.cluster_name || '').localeCompare(b.cluster_name || ''),
      render: (name) => (
        <Tag color={getClusterColor(name, clusterNames)} style={{ fontWeight: 500 }}>
          {name}
        </Tag>
      )
    },
    {
      title: 'Agent Name',
      dataIndex: 'name',
      key: 'name',
      width: 180,
      sorter: (a, b) => (a.name || '').localeCompare(b.name || ''),
      render: (name) => <Text strong>{name}</Text>
    },
    {
      title: 'Hostname',
      dataIndex: 'hostname',
      key: 'hostname',
      width: 160,
      sorter: (a, b) => (a.hostname || '').localeCompare(b.hostname || ''),
      render: (val) => val || '-'
    },
    {
      title: 'Agent IP',
      dataIndex: 'ip_address',
      key: 'ip_address',
      width: 150,
      sorter: (a, b) => (a.ip_address || '').localeCompare(b.ip_address || ''),
      render: (ip) => ip ? (
        <Text code style={{ fontSize: 13 }}>
          {highlightMatch(ip, activeSearch)}
        </Text>
      ) : '-'
    },
    {
      title: 'VIP (Keepalive)',
      dataIndex: 'keepalive_ip',
      key: 'keepalive_ip',
      width: 150,
      sorter: (a, b) => (a.keepalive_ip || '').localeCompare(b.keepalive_ip || ''),
      render: (ip) => ip ? (
        <Text code style={{ fontSize: 13, color: '#52c41a' }}>
          {highlightMatch(ip, activeSearch)}
        </Text>
      ) : <Text type="secondary">-</Text>
    },
    {
      title: 'Keepalive State',
      dataIndex: 'keepalive_state',
      key: 'keepalive_state',
      width: 130,
      sorter: (a, b) => (a.keepalive_state || '').localeCompare(b.keepalive_state || ''),
      render: (state) => {
        if (!state) return <Text type="secondary">-</Text>;
        return state === 'MASTER'
          ? <Tag color="green">MASTER</Tag>
          : <Tag color="orange">BACKUP</Tag>;
      }
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      sorter: (a, b) => (a.status || '').localeCompare(b.status || ''),
      render: (status) => (
        <Badge
          status={status === 'online' ? 'success' : 'error'}
          text={<Text style={{ fontSize: 13 }}>{status || 'unknown'}</Text>}
        />
      )
    },
    {
      title: 'Platform',
      dataIndex: 'platform',
      key: 'platform',
      width: 100,
      render: (platform) => {
        const icon = platform === 'linux' ? <LinuxOutlined /> :
                     platform === 'darwin' ? <AppleOutlined /> :
                     <DesktopOutlined />;
        return <Space size={4}>{icon}<Text style={{ fontSize: 13 }}>{platform || '-'}</Text></Space>;
      }
    },
    {
      title: 'Last Seen',
      dataIndex: 'last_seen',
      key: 'last_seen',
      width: 110,
      sorter: (a, b) => new Date(a.last_seen || 0) - new Date(b.last_seen || 0),
      render: (val) => (
        <Tooltip title={val ? new Date(val).toLocaleString() : '-'}>
          <Space size={4}>
            <ClockCircleOutlined style={{ fontSize: 12, color: '#8c8c8c' }} />
            <Text type="secondary" style={{ fontSize: 13 }}>{timeAgo(val)}</Text>
          </Space>
        </Tooltip>
      )
    }
  ];

  const serverColumns = [
    {
      title: 'Cluster',
      dataIndex: 'cluster_name',
      key: 'cluster_name',
      width: 150,
      sorter: (a, b) => (a.cluster_name || '').localeCompare(b.cluster_name || ''),
      render: (name) => (
        <Tag color={getClusterColor(name, clusterNames)} style={{ fontWeight: 500 }}>
          {name}
        </Tag>
      )
    },
    {
      title: 'Server Name',
      key: 'server_name',
      width: 160,
      sorter: (a, b) => (a.name || a.server_name || '').localeCompare(b.name || b.server_name || ''),
      render: (_, record) => <Text strong>{record.name || record.server_name || '-'}</Text>
    },
    {
      title: 'Address',
      dataIndex: 'address',
      key: 'address',
      width: 180,
      sorter: (a, b) => (a.address || '').localeCompare(b.address || ''),
      render: (addr) => addr ? (
        <Text code style={{ fontSize: 13 }}>
          {highlightMatch(addr, activeSearch)}
        </Text>
      ) : '-'
    },
    {
      title: 'Backend Name',
      dataIndex: 'backend_name',
      key: 'backend_name',
      width: 180,
      sorter: (a, b) => (a.backend_name || '').localeCompare(b.backend_name || ''),
      render: (val) => val || '-'
    },
    {
      title: 'Weight',
      dataIndex: 'weight',
      key: 'weight',
      width: 80,
      sorter: (a, b) => (a.weight || 0) - (b.weight || 0),
      render: (val) => val !== undefined && val !== null ? val : '-'
    },
    {
      title: 'Health Check',
      dataIndex: 'check_enabled',
      key: 'check_enabled',
      width: 110,
      render: (enabled) => enabled
        ? <CheckCircleOutlined style={{ color: '#52c41a', fontSize: 16 }} />
        : <CloseCircleOutlined style={{ color: '#ff4d4f', fontSize: 16 }} />
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      sorter: (a, b) => (a.status || '').localeCompare(b.status || ''),
      render: (status) => {
        const full = (status || '').toUpperCase();
        const base = full.split(' ')[0];
        const colorMap = { UP: 'green', DOWN: 'red', DRAIN: 'orange', MAINT: 'default', NOLB: 'gold' };
        return <Tag color={colorMap[base] || 'default'}>{full || 'UNKNOWN'}</Tag>;
      }
    },
    {
      title: 'Backup',
      dataIndex: 'backup_server',
      key: 'backup_server',
      width: 80,
      render: (val) => val ? <Tag color="warning">Backup</Tag> : null
    }
  ];

  const cardStyle = {
    borderRadius: 8,
    height: '100%'
  };

  const statCards = [
    { title: 'Total Agents', value: stats.totalAgents, icon: <CloudServerOutlined style={{ fontSize: 24, color: '#1890ff' }} /> },
    { title: 'Online Agents', value: stats.onlineAgents, icon: <CheckCircleOutlined style={{ fontSize: 24, color: '#52c41a' }} /> },
    { title: 'Keepalive (VIP)', value: stats.vipCount, icon: <HeartTwoTone twoToneColor="#eb2f96" style={{ fontSize: 24 }} /> },
    { title: 'Backend Servers', value: stats.totalServers, icon: <GlobalOutlined style={{ fontSize: 24, color: '#722ed1' }} /> }
  ];

  const clusterFilterOptions = clusterNames.map(name => ({ label: name, value: name }));

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh', flexDirection: 'column', gap: 16 }}>
        <Spin size="large" />
        <Text type="secondary">Loading IP inventory...</Text>
      </div>
    );
  }

  return (
    <div>
      <div style={{ marginBottom: 24, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <Title level={3} style={{ margin: 0 }}>
            <SearchOutlined style={{ marginRight: 8 }} />
            IP Inventory
          </Title>
          <Text type="secondary">Unified view of all IPs across all clusters</Text>
        </div>
        {refreshing && (
          <SyncOutlined spin style={{ fontSize: 16, color: '#1890ff' }} />
        )}
      </div>

      {/* Search Bar */}
      <Card style={{ marginBottom: 16, borderRadius: 8 }} bodyStyle={{ padding: '12px 16px' }}>
        <Input.Search
          placeholder="Enter IP address to search across all agents and backend servers..."
          allowClear
          enterButton="Search"
          size="large"
          prefix={<SearchOutlined style={{ color: '#bfbfbf' }} />}
          value={searchText}
          onChange={handleInputChange}
          onSearch={handleSearch}
          style={{ maxWidth: 700 }}
        />
      </Card>

      {/* Summary Cards */}
      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        {statCards.map((card, idx) => (
          <Col xs={12} sm={12} md={6} key={idx}>
            <Card style={cardStyle} bodyStyle={{ padding: '16px 20px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                {card.icon}
                <Statistic title={card.title} value={card.value} />
              </div>
            </Card>
          </Col>
        ))}
      </Row>

      {/* Search Results Card */}
      {activeSearch && (
        <Card
          style={{ marginBottom: 16, borderRadius: 8, borderLeft: '3px solid #1890ff' }}
          bodyStyle={{ padding: '12px 16px' }}
        >
          <Text strong style={{ fontSize: 14 }}>
            Found {searchResults.length} match{searchResults.length !== 1 ? 'es' : ''} for "{activeSearch}"
          </Text>
          {searchResults.length === 0 ? (
            <div style={{ marginTop: 8 }}>
              <Empty description="No IP matches found" image={Empty.PRESENTED_IMAGE_SIMPLE} />
            </div>
          ) : (
            <div style={{ marginTop: 12, display: 'flex', flexDirection: 'column', gap: 8 }}>
              {searchResults.slice(0, MAX_SEARCH_RESULTS_DISPLAY).map((result, idx) => (
                <div
                  key={idx}
                  style={{
                    padding: '8px 12px',
                    borderRadius: 6,
                    background: isDarkMode ? 'rgba(255,255,255,0.04)' : 'rgba(0,0,0,0.02)',
                    border: `1px solid ${isDarkMode ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.06)'}`,
                    display: 'flex',
                    alignItems: 'center',
                    gap: 12,
                    flexWrap: 'wrap'
                  }}
                >
                  <Tag color={result.color} style={{ margin: 0, minWidth: 110, textAlign: 'center' }}>
                    {result.type}
                  </Tag>
                  <Text strong style={{ minWidth: 140 }}>{result.name}</Text>
                  <Text code style={{ fontSize: 13 }}>
                    {highlightMatch(result.ip, activeSearch)}
                  </Text>
                  <Tag color={getClusterColor(result.cluster, clusterNames)} style={{ margin: 0 }}>
                    {result.cluster}
                  </Tag>
                  <Text type="secondary" style={{ fontSize: 12 }}>{result.detail}</Text>
                </div>
              ))}
              {searchResults.length > MAX_SEARCH_RESULTS_DISPLAY && (
                <Text type="secondary" style={{ fontSize: 12, marginTop: 4 }}>
                  Showing {MAX_SEARCH_RESULTS_DISPLAY} of {searchResults.length} matches. Use the tabs below to browse all results.
                </Text>
              )}
            </div>
          )}
        </Card>
      )}

      {/* Tabs */}
      <Card style={{ borderRadius: 8 }}>
        <Tabs
          activeKey={activeTab}
          onChange={setActiveTab}
          items={[
            {
              key: 'agents',
              label: (
                <span>
                  <CloudServerOutlined style={{ marginRight: 6 }} />
                  Agents
                  <Badge
                    count={activeSearch ? filteredAgents.length : agents.length}
                    style={{ marginLeft: 8, backgroundColor: activeSearch ? '#1890ff' : '#d9d9d9', color: activeSearch ? '#fff' : '#595959' }}
                    overflowCount={9999}
                    showZero
                  />
                </span>
              ),
              children: (
                <div>
                  <Space style={{ marginBottom: 16 }} wrap>
                    <Select
                      placeholder="All Clusters"
                      allowClear
                      style={{ width: 200 }}
                      options={clusterFilterOptions}
                      value={agentClusterFilter}
                      onChange={setAgentClusterFilter}
                    />
                    <Select
                      placeholder="All Status"
                      allowClear
                      style={{ width: 140 }}
                      options={[
                        { label: 'Online', value: 'online' },
                        { label: 'Offline', value: 'offline' }
                      ]}
                      value={agentStatusFilter}
                      onChange={setAgentStatusFilter}
                    />
                  </Space>
                  <Table
                    columns={agentColumns}
                    dataSource={filteredAgents}
                    rowKey={(record) => record.id || record.name}
                    pagination={{
                      defaultPageSize: 20,
                      showSizeChanger: true,
                      pageSizeOptions: ['10', '20', '50', '100'],
                      showTotal: (total, range) => `${range[0]}-${range[1]} of ${total} agents`
                    }}
                    scroll={{ x: 1200 }}
                    size="middle"
                    locale={{ emptyText: activeSearch ? 'No agents match this IP' : 'No agents found' }}
                  />
                </div>
              )
            },
            {
              key: 'servers',
              label: (
                <span>
                  <GlobalOutlined style={{ marginRight: 6 }} />
                  Backend Servers
                  <Badge
                    count={activeSearch ? filteredServers.length : backendServers.length}
                    style={{ marginLeft: 8, backgroundColor: activeSearch ? '#722ed1' : '#d9d9d9', color: activeSearch ? '#fff' : '#595959' }}
                    overflowCount={9999}
                    showZero
                  />
                </span>
              ),
              children: (
                <div>
                  <Space style={{ marginBottom: 16 }} wrap>
                    <Select
                      placeholder="All Clusters"
                      allowClear
                      style={{ width: 200 }}
                      options={clusterFilterOptions}
                      value={serverClusterFilter}
                      onChange={setServerClusterFilter}
                    />
                    <Select
                      placeholder="All Status"
                      allowClear
                      style={{ width: 140 }}
                      options={[
                        { label: 'UP', value: 'UP' },
                        { label: 'DOWN', value: 'DOWN' },
                        { label: 'DRAIN', value: 'DRAIN' },
                        { label: 'MAINT', value: 'MAINT' }
                      ]}
                      value={serverStatusFilter}
                      onChange={setServerStatusFilter}
                    />
                  </Space>
                  <Table
                    columns={serverColumns}
                    dataSource={filteredServers}
                    rowKey={(record) => `${record.id || record.name}-${record.backend_name}-${record.address}`}
                    pagination={{
                      defaultPageSize: 20,
                      showSizeChanger: true,
                      pageSizeOptions: ['10', '20', '50', '100'],
                      showTotal: (total, range) => `${range[0]}-${range[1]} of ${total} servers`
                    }}
                    scroll={{ x: 1100 }}
                    size="middle"
                    locale={{ emptyText: activeSearch ? 'No backend servers match this IP' : 'No backend servers found' }}
                  />
                </div>
              )
            }
          ]}
        />
      </Card>
    </div>
  );
};

export default IPInventory;
