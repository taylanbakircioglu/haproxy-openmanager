import React, { useState, useMemo, memo } from 'react';
import { 
  Card, Table, Badge, Tag, Input, Space, Button, Switch, 
  Tooltip, Typography, Statistic, Collapse, Select, Row, Col 
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
  BarsOutlined
} from '@ant-design/icons';
import { FixedSizeList as List } from 'react-window';

const { Text } = Typography;
const { Panel } = Collapse;

const CompactFrontendList = ({ data, loading, onSelect, selectedItems = [] }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [compactView, setCompactView] = useState(true);
  const [statusFilter, setStatusFilter] = useState('all');
  const [showAll, setShowAll] = useState(false);
  const [viewMode, setViewMode] = useState('grouped'); // 'grouped', 'list', 'grid'
  const defaultShowCount = 10;

  // Filter and search
  const filteredData = useMemo(() => {
    let filtered = data || [];
    
    // Search filter
    if (searchTerm) {
      filtered = filtered.filter(item =>
        item.name.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }
    
    // Status filter
    if (statusFilter !== 'all') {
      filtered = filtered.filter(item => {
        const status = (item.status || '').toUpperCase();
        switch (statusFilter) {
          case 'up':
            return status === 'OPEN' || status === 'UP';
          case 'down':
            return status === 'DOWN' || status === 'CLOSED';
          case 'warning':
            return status.includes('WARN') || status.includes('MAINT');
          default:
            return true;
        }
      });
    }
    
    return filtered;
  }, [data, searchTerm, statusFilter]);

  // Group by status
  const groupedData = useMemo(() => {
    const groups = {
      healthy: [],
      warning: [],
      down: [],
      unknown: []
    };
    
    filteredData.forEach(item => {
      const status = (item.status || '').toUpperCase();
      if (status === 'OPEN' || status === 'UP') {
        groups.healthy.push(item);
      } else if (status === 'DOWN' || status === 'CLOSED') {
        groups.down.push(item);
      } else if (status.includes('WARN') || status.includes('MAINT')) {
        groups.warning.push(item);
      } else {
        groups.unknown.push(item);
      }
    });
    
    return groups;
  }, [filteredData]);

  // Visible data (with show all toggle)
  const visibleData = useMemo(() => {
    return showAll ? filteredData : filteredData.slice(0, defaultShowCount);
  }, [filteredData, showAll]);

  // Calculate stats
  const stats = useMemo(() => {
    const total = data.length;
    const healthy = groupedData.healthy.length;
    const warning = groupedData.warning.length;
    const down = groupedData.down.length;
    const totalRequests = data.reduce((sum, f) => sum + (f.requests_total || 0), 0);
    const totalSessions = data.reduce((sum, f) => sum + (f.current_sessions || 0), 0);
    
    return { total, healthy, warning, down, totalRequests, totalSessions };
  }, [data, groupedData]);

  const getStatusBadge = (status) => {
    const statusUpper = (status || '').toUpperCase();
    if (statusUpper === 'OPEN' || statusUpper === 'UP') {
      return { status: 'success', icon: <CheckCircleOutlined />, color: 'green' };
    }
    if (statusUpper === 'DOWN' || statusUpper === 'CLOSED') {
      return { status: 'error', icon: <CloseCircleOutlined />, color: 'red' };
    }
    return { status: 'warning', icon: <WarningOutlined />, color: 'orange' };
  };

  // Compact table columns
  const compactColumns = [
    {
      title: 'Frontend',
      dataIndex: 'name',
      key: 'name',
      width: '25%',
      sorter: (a, b) => a.name.localeCompare(b.name),
      render: (name, record) => (
        <Space>
          <Badge {...getStatusBadge(record.status)} />
          <Text strong>{name}</Text>
        </Space>
      )
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: '10%',
      sorter: (a, b) => (a.status || '').localeCompare(b.status || ''),
      render: (status) => {
        const badge = getStatusBadge(status);
        return <Tag color={badge.color} icon={badge.icon}>{status}</Tag>;
      }
    },
    {
      title: 'Requests',
      dataIndex: 'requests_total',
      key: 'requests_total',
      width: '15%',
      align: 'right',
      sorter: (a, b) => (a.requests_total || 0) - (b.requests_total || 0),
      render: (val) => <Text>{(val || 0).toLocaleString()}</Text>
    },
    {
      title: 'Rate',
      dataIndex: 'requests_rate',
      key: 'requests_rate',
      width: '12%',
      sorter: (a, b) => (a.requests_rate || 0) - (b.requests_rate || 0),
      align: 'right',
      render: (val) => <Text>{val || 0} req/s</Text>
    },
    {
      title: 'Sessions',
      dataIndex: 'current_sessions',
      key: 'current_sessions',
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
        const errorsA = (a.request_errors || 0) + (a.connection_errors || 0);
        const errorsB = (b.request_errors || 0) + (b.connection_errors || 0);
        return errorsA - errorsB;
      },
      render: (_, record) => {
        const errors = (record.request_errors || 0) + (record.connection_errors || 0);
        return <Text type={errors > 0 ? 'danger' : 'secondary'}>{errors}</Text>;
      }
    },
    {
      title: 'Action',
      key: 'action',
      width: '14%',
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

  // Detailed table columns
  const detailedColumns = [
    ...compactColumns,
    {
      title: 'Bytes In',
      dataIndex: 'bytes_in',
      key: 'bytes_in',
      render: (val) => `${((val || 0) / 1024 / 1024).toFixed(2)} MB`
    },
    {
      title: 'Bytes Out',
      dataIndex: 'bytes_out',
      key: 'bytes_out',
      render: (val) => `${((val || 0) / 1024 / 1024).toFixed(2)} MB`
    }
  ];

  // Virtualized row renderer
  const VirtualRow = ({ index, style }) => {
    const item = visibleData[index];
    const badge = getStatusBadge(item.status);
    
    return (
      <div style={{ ...style, padding: '8px 16px', borderBottom: '1px solid #f0f0f0' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <Badge {...badge} />
          <Text strong style={{ flex: 1 }}>{item.name}</Text>
          <Tag color={badge.color}>{item.status}</Tag>
          <Text type="secondary">{(item.requests_total || 0).toLocaleString()} req</Text>
          <Text type="secondary">{item.current_sessions || 0} sess</Text>
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
      {/* Healthy Group */}
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

      {/* Warning Group */}
      {groupedData.warning.length > 0 && (
        <Panel
          key="warning"
          header={
            <Space>
              <WarningOutlined style={{ color: '#faad14' }} />
              <Text strong>Warning ({groupedData.warning.length})</Text>
            </Space>
          }
        >
          <Table
            columns={compactView ? compactColumns : detailedColumns}
            dataSource={groupedData.warning}
            rowKey="name"
            size="small"
            pagination={false}
            scroll={{ y: 300 }}
          />
        </Panel>
      )}

      {/* Down Group */}
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
      // Use virtualized list for performance
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
        const badge = getStatusBadge(item.status);
        return (
          <Col xs={24} sm={12} md={8} lg={6} key={item.name}>
            <Card
              size="small"
              title={
                <Space>
                  <Badge {...badge} />
                  <Text strong ellipsis style={{ maxWidth: 150 }}>
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
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <Text type="secondary" style={{ fontSize: 11 }}>Requests:</Text>
                  <Text strong style={{ fontSize: 11 }}>{(item.requests_total || 0).toLocaleString()}</Text>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <Text type="secondary" style={{ fontSize: 11 }}>Rate:</Text>
                  <Text strong style={{ fontSize: 11 }}>{item.requests_rate || 0} req/s</Text>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <Text type="secondary" style={{ fontSize: 11 }}>Sessions:</Text>
                  <Text strong style={{ fontSize: 11 }}>{item.current_sessions || 0}</Text>
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
          <span>Frontends</span>
          <Tag color="blue">{stats.total}</Tag>
          <Badge count={stats.healthy} style={{ backgroundColor: '#52c41a' }} />
          {stats.warning > 0 && <Badge count={stats.warning} style={{ backgroundColor: '#faad14' }} />}
          {stats.down > 0 && <Badge count={stats.down} style={{ backgroundColor: '#ff4d4f' }} />}
        </Space>
      }
      extra={
        <Space wrap>
          {/* View Mode Toggle */}
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
          
          {/* Compact View Toggle */}
          <Tooltip title={compactView ? 'Switch to detailed view' : 'Switch to compact view'}>
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
            title="Total Requests"
            value={stats.totalRequests}
            valueStyle={{ fontSize: 16 }}
          />
        </Col>
        <Col span={8}>
          <Statistic
            title="Active Sessions"
            value={stats.totalSessions}
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

      {/* Search and Filter Bar */}
      <Space style={{ marginBottom: 16, width: '100%', justifyContent: 'space-between' }} wrap>
        <Space>
          <Input
            placeholder="Search frontends..."
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
            placeholder="Filter by status"
            options={[
              { label: <><FilterOutlined /> All</>, value: 'all' },
              { label: <><CheckCircleOutlined style={{ color: '#52c41a' }} /> Healthy</>, value: 'up' },
              { label: <><WarningOutlined style={{ color: '#faad14' }} /> Warning</>, value: 'warning' },
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

      {/* Results Info */}
      <div style={{ marginBottom: 12 }}>
        <Text type="secondary" style={{ fontSize: 12 }}>
          Showing {visibleData.length} of {filteredData.length} frontends
          {searchTerm && ` (filtered from ${data.length})`}
        </Text>
      </div>

      {/* Content based on view mode */}
      {viewMode === 'grouped' && renderGroupedView()}
      {viewMode === 'list' && renderListView()}
      {viewMode === 'grid' && renderGridView()}
    </Card>
  );
};

// Memoized export for performance
export default memo(CompactFrontendList);

