import React, { useState, useMemo, memo } from 'react';
import { 
  Card, Table, Badge, Tag, Input, Space, Button, Switch, 
  Tooltip, Typography, Progress, Collapse, Select, Row, Col, Statistic
} from 'antd';
import {
  SearchOutlined,
  EyeOutlined,
  EyeInvisibleOutlined,
  FilterOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  WarningOutlined,
  AppstoreOutlined,
  BarsOutlined,
  ClockCircleOutlined
} from '@ant-design/icons';
import { FixedSizeList as List } from 'react-window';

const { Text } = Typography;
const { Panel } = Collapse;

const CompactBackendList = ({ data, loading, onSelect, selectedItems = [] }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [compactView, setCompactView] = useState(true);
  const [statusFilter, setStatusFilter] = useState('all');
  const [showAll, setShowAll] = useState(false);
  const [viewMode, setViewMode] = useState('grouped');
  const defaultShowCount = 10;

  // Filter and search
  const filteredData = useMemo(() => {
    let filtered = data || [];
    
    if (searchTerm) {
      filtered = filtered.filter(item =>
        item.name.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }
    
    if (statusFilter !== 'all') {
      filtered = filtered.filter(item => {
        const status = (item.status || '').toUpperCase();
        const healthPct = item.health_percentage || 0;
        switch (statusFilter) {
          case 'up':
            return status === 'UP' && healthPct >= 80;
          case 'degraded':
            return healthPct > 0 && healthPct < 80;
          case 'down':
            return status === 'DOWN' || healthPct === 0;
          default:
            return true;
        }
      });
    }
    
    return filtered;
  }, [data, searchTerm, statusFilter]);

  // Group by health status
  const groupedData = useMemo(() => {
    const groups = {
      healthy: [],
      degraded: [],
      down: [],
      unknown: []
    };
    
    filteredData.forEach(item => {
      const status = (item.status || '').toUpperCase();
      const healthPct = item.health_percentage || 0;
      
      if (status === 'UP' && healthPct >= 80) {
        groups.healthy.push(item);
      } else if (healthPct > 0 && healthPct < 80) {
        groups.degraded.push(item);
      } else if (status === 'DOWN' || healthPct === 0) {
        groups.down.push(item);
      } else {
        groups.unknown.push(item);
      }
    });
    
    return groups;
  }, [filteredData]);

  const visibleData = useMemo(() => {
    return showAll ? filteredData : filteredData.slice(0, defaultShowCount);
  }, [filteredData, showAll]);

  // Calculate stats
  const stats = useMemo(() => {
    const total = data.length;
    const healthy = groupedData.healthy.length;
    const degraded = groupedData.degraded.length;
    const down = groupedData.down.length;
    const totalQueue = data.reduce((sum, b) => sum + (b.queue_current || 0), 0);
    const avgResponseTime = data.length > 0 ?
      Math.round(data.reduce((sum, b) => sum + (b.response_time_avg || 0), 0) / data.length) : 0;
    
    return { total, healthy, degraded, down, totalQueue, avgResponseTime };
  }, [data, groupedData]);

  const getHealthColor = (healthPct) => {
    if (healthPct >= 80) return '#52c41a';
    if (healthPct >= 50) return '#faad14';
    return '#ff4d4f';
  };

  const getStatusBadge = (status, healthPct) => {
    if (status === 'UP' && healthPct >= 80) {
      return { status: 'success', icon: <CheckCircleOutlined />, color: 'green' };
    }
    if (healthPct > 0 && healthPct < 80) {
      return { status: 'warning', icon: <WarningOutlined />, color: 'orange' };
    }
    return { status: 'error', icon: <CloseCircleOutlined />, color: 'red' };
  };

  const compactColumns = [
    {
      title: 'Backend',
      dataIndex: 'name',
      key: 'name',
      width: '20%',
      sorter: (a, b) => a.name.localeCompare(b.name),
      render: (name, record) => {
        const badge = getStatusBadge(record.status, record.health_percentage);
        return (
          <Space>
            <Badge {...badge} />
            <Text strong>{name}</Text>
          </Space>
        );
      }
    },
    {
      title: 'Health',
      key: 'health',
      width: '15%',
      sorter: (a, b) => (a.health_percentage || 0) - (b.health_percentage || 0),
      render: (_, record) => (
        <Space direction="vertical" size={0} style={{ width: '100%' }}>
          <Text style={{ fontSize: 11 }}>
            {record.servers_active}/{record.servers_total}
          </Text>
          <Progress
            percent={record.health_percentage || 0}
            size="small"
            showInfo={false}
            strokeColor={getHealthColor(record.health_percentage)}
          />
        </Space>
      )
    },
    {
      title: 'Response',
      dataIndex: 'response_time_avg',
      key: 'response_time',
      width: '12%',
      align: 'right',
      sorter: (a, b) => (a.response_time_avg || 0) - (b.response_time_avg || 0),
      render: (val) => {
        const color = val > 500 ? '#ff4d4f' : val > 200 ? '#faad14' : '#52c41a';
        return <Text style={{ color }}>{val || 0}ms</Text>;
      }
    },
    {
      title: 'Queue',
      key: 'queue',
      width: '12%',
      align: 'right',
      sorter: (a, b) => (a.queue_current || 0) - (b.queue_current || 0),
      render: (_, record) => {
        const queuePct = record.queue_max > 0 ?
          Math.round((record.queue_current / record.queue_max) * 100) : 0;
        const color = queuePct > 80 ? '#ff4d4f' : queuePct > 50 ? '#faad14' : '#52c41a';
        return (
          <Text style={{ color }}>
            {record.queue_current}/{record.queue_max || '∞'}
          </Text>
        );
      }
    },
    {
      title: 'Sessions',
      dataIndex: 'current_sessions',
      key: 'sessions',
      width: '12%',
      align: 'right',
      sorter: (a, b) => (a.current_sessions || 0) - (b.current_sessions || 0),
      render: (val) => <Text>{val || 0}</Text>
    },
    {
      title: 'Errors',
      key: 'errors',
      width: '12%',
      align: 'right',
      sorter: (a, b) => {
        const errorsA = (a.connection_errors || 0) + (a.response_errors || 0);
        const errorsB = (b.connection_errors || 0) + (b.response_errors || 0);
        return errorsA - errorsB;
      },
      render: (_, record) => {
        const errors = (record.connection_errors || 0) + (record.response_errors || 0);
        return <Text type={errors > 0 ? 'danger' : 'secondary'}>{errors}</Text>;
      }
    },
    {
      title: 'Action',
      key: 'action',
      width: '12%',
      render: (_, record) => (
        <Button
          size="small"
          type={selectedItems.includes(record.name) ? 'primary' : 'default'}
          onClick={() => onSelect && onSelect(record.name)}
        >
          {selectedItems.includes(record.name) ? 'Selected' : 'Select'}
        </Button>
      )
    }
  ];

  const detailedColumns = [
    ...compactColumns,
    {
      title: 'Requests',
      dataIndex: 'requests_total',
      key: 'requests',
      render: (val) => (val || 0).toLocaleString()
    },
    {
      title: 'Retries',
      dataIndex: 'retry_warnings',
      key: 'retries',
      render: (val) => val || 0
    }
  ];

  const VirtualRow = ({ index, style }) => {
    const item = visibleData[index];
    const badge = getStatusBadge(item.status, item.health_percentage);
    
    return (
      <div style={{ ...style, padding: '8px 16px', borderBottom: '1px solid #f0f0f0' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <Badge {...badge} />
          <Text strong style={{ flex: 1 }}>{item.name}</Text>
          <Text type="secondary">{item.servers_active}/{item.servers_total}</Text>
          <Text type="secondary">{item.response_time_avg || 0}ms</Text>
          <Text type="secondary">Q:{item.queue_current || 0}</Text>
          <Button
            size="small"
            type={selectedItems.includes(item.name) ? 'primary' : 'default'}
            onClick={() => onSelect && onSelect(item.name)}
          >
            {selectedItems.includes(item.name) ? '✓' : '+'}
          </Button>
        </div>
      </div>
    );
  };

  const renderGroupedView = () => (
    <Collapse defaultActiveKey={['healthy']} ghost>
      {groupedData.healthy.length > 0 && (
        <Panel
          key="healthy"
          header={
            <Space>
              <CheckCircleOutlined style={{ color: '#52c41a' }} />
              <Text strong>Healthy ({groupedData.healthy.length})</Text>
            </Space>
          }
        >
          <Table
            columns={compactView ? compactColumns : detailedColumns}
            dataSource={groupedData.healthy}
            rowKey="name"
            size="small"
            pagination={false}
            scroll={{ y: 300 }}
          />
        </Panel>
      )}

      {groupedData.degraded.length > 0 && (
        <Panel
          key="degraded"
          header={
            <Space>
              <WarningOutlined style={{ color: '#faad14' }} />
              <Text strong>Degraded ({groupedData.degraded.length})</Text>
            </Space>
          }
        >
          <Table
            columns={compactView ? compactColumns : detailedColumns}
            dataSource={groupedData.degraded}
            rowKey="name"
            size="small"
            pagination={false}
            scroll={{ y: 300 }}
          />
        </Panel>
      )}

      {groupedData.down.length > 0 && (
        <Panel
          key="down"
          header={
            <Space>
              <CloseCircleOutlined style={{ color: '#ff4d4f' }} />
              <Text strong>Down ({groupedData.down.length})</Text>
            </Space>
          }
        >
          <Table
            columns={compactView ? compactColumns : detailedColumns}
            dataSource={groupedData.down}
            rowKey="name"
            size="small"
            pagination={false}
            scroll={{ y: 300 }}
          />
        </Panel>
      )}
    </Collapse>
  );

  const renderListView = () => {
    if (visibleData.length > 20) {
      return (
        <List
          height={600}
          itemCount={visibleData.length}
          itemSize={50}
          width="100%"
        >
          {VirtualRow}
        </List>
      );
    }
    
    return (
      <Table
        columns={compactView ? compactColumns : detailedColumns}
        dataSource={visibleData}
        rowKey="name"
        size="small"
        pagination={false}
        scroll={{ y: 600 }}
        loading={loading}
      />
    );
  };

  const renderGridView = () => (
    <Row gutter={[16, 16]}>
      {visibleData.map(item => {
        const badge = getStatusBadge(item.status, item.health_percentage);
        return (
          <Col xs={24} sm={12} md={8} lg={6} key={item.name}>
            <Card
              size="small"
              title={
                <Space>
                  <Badge {...badge} />
                  <Text strong ellipsis style={{ maxWidth: 120 }}>
                    {item.name}
                  </Text>
                </Space>
              }
              extra={
                <Button
                  size="small"
                  type={selectedItems.includes(item.name) ? 'primary' : 'default'}
                  onClick={() => onSelect && onSelect(item.name)}
                >
                  {selectedItems.includes(item.name) ? '✓' : '+'}
                </Button>
              }
            >
              <Space direction="vertical" size="small" style={{ width: '100%' }}>
                <div>
                  <Text type="secondary" style={{ fontSize: 11 }}>Health</Text>
                  <Progress
                    percent={item.health_percentage || 0}
                    size="small"
                    strokeColor={getHealthColor(item.health_percentage)}
                    format={() => `${item.servers_active}/${item.servers_total}`}
                  />
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <Text type="secondary" style={{ fontSize: 11 }}>Response:</Text>
                  <Text strong style={{ fontSize: 11 }}>{item.response_time_avg || 0}ms</Text>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <Text type="secondary" style={{ fontSize: 11 }}>Queue:</Text>
                  <Text strong style={{ fontSize: 11 }}>{item.queue_current || 0}</Text>
                </div>
              </Space>
            </Card>
          </Col>
        );
      })}
    </Row>
  );

  return (
    <Card
      title={
        <Space>
          <span>Backends</span>
          <Tag color="blue">{stats.total}</Tag>
          <Badge count={stats.healthy} style={{ backgroundColor: '#52c41a' }} />
          {stats.degraded > 0 && <Badge count={stats.degraded} style={{ backgroundColor: '#faad14' }} />}
          {stats.down > 0 && <Badge count={stats.down} style={{ backgroundColor: '#ff4d4f' }} />}
        </Space>
      }
      extra={
        <Space wrap>
          <Select
            value={viewMode}
            onChange={setViewMode}
            style={{ width: 120 }}
            size="small"
            options={[
              { label: <><BarsOutlined /> Grouped</>, value: 'grouped' },
              { label: <><BarsOutlined /> List</>, value: 'list' },
              { label: <><AppstoreOutlined /> Grid</>, value: 'grid' }
            ]}
          />
          
          <Tooltip title={compactView ? 'Detailed view' : 'Compact view'}>
            <Switch
              checked={compactView}
              onChange={setCompactView}
              checkedChildren={<EyeInvisibleOutlined />}
              unCheckedChildren={<EyeOutlined />}
              size="small"
            />
          </Tooltip>
        </Space>
      }
    >
      {/* Summary Stats */}
      <Row gutter={16} style={{ marginBottom: 16 }}>
        <Col span={8}>
          <Statistic
            title="Avg Response Time"
            value={stats.avgResponseTime}
            suffix="ms"
            valueStyle={{ fontSize: 16 }}
            prefix={<ClockCircleOutlined />}
          />
        </Col>
        <Col span={8}>
          <Statistic
            title="Total Queue"
            value={stats.totalQueue}
            valueStyle={{ fontSize: 16 }}
          />
        </Col>
        <Col span={8}>
          <Statistic
            title="Health Rate"
            value={stats.total > 0 ? Math.round((stats.healthy / stats.total) * 100) : 0}
            suffix="%"
            valueStyle={{ fontSize: 16, color: stats.healthy === stats.total ? '#52c41a' : '#faad14' }}
          />
        </Col>
      </Row>

      {/* Search and Filter */}
      <Space style={{ marginBottom: 16, width: '100%', justifyContent: 'space-between' }} wrap>
        <Space>
          <Input
            placeholder="Search backends..."
            prefix={<SearchOutlined />}
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{ width: 250 }}
            allowClear
          />
          
          <Select
            value={statusFilter}
            onChange={setStatusFilter}
            style={{ width: 150 }}
            options={[
              { label: <><FilterOutlined /> All</>, value: 'all' },
              { label: <><CheckCircleOutlined style={{ color: '#52c41a' }} /> Healthy</>, value: 'up' },
              { label: <><WarningOutlined style={{ color: '#faad14' }} /> Degraded</>, value: 'degraded' },
              { label: <><CloseCircleOutlined style={{ color: '#ff4d4f' }} /> Down</>, value: 'down' }
            ]}
          />
        </Space>

        {filteredData.length > defaultShowCount && (
          <Button
            size="small"
            onClick={() => setShowAll(!showAll)}
          >
            {showAll ? `Show Top ${defaultShowCount}` : `Show All (${filteredData.length})`}
          </Button>
        )}
      </Space>

      <div style={{ marginBottom: 12 }}>
        <Text type="secondary" style={{ fontSize: 12 }}>
          Showing {visibleData.length} of {filteredData.length} backends
          {searchTerm && ` (filtered from ${data.length})`}
        </Text>
      </div>

      {viewMode === 'grouped' && renderGroupedView()}
      {viewMode === 'list' && renderListView()}
      {viewMode === 'grid' && renderGridView()}
    </Card>
  );
};

// Memoized export for performance
export default memo(CompactBackendList);

