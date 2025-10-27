import React, { useState, useMemo, memo } from 'react';
import { 
  Card, Badge, Tag, Input, Space, Button, Switch, Table,
  Tooltip, Typography, Progress, Select, Statistic, Row, Col, Radio
} from 'antd';
import {
  SearchOutlined,
  EyeOutlined,
  EyeInvisibleOutlined,
  FilterOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  WarningOutlined,
  ThunderboltOutlined,
  ClockCircleOutlined,
  BarsOutlined,
  TableOutlined
} from '@ant-design/icons';
import { FixedSizeList as List } from 'react-window';

const { Text } = Typography;

const CompactServerList = ({ data, loading }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [backendFilter, setBackendFilter] = useState('all');
  const [showAll, setShowAll] = useState(false);
  const [compactView, setCompactView] = useState(true);
  const [viewMode, setViewMode] = useState('table'); // 'list' or 'table' - default: table
  const defaultShowCount = 20;

  // Get unique backends for filtering
  const backends = useMemo(() => {
    return [...new Set((data || []).map(s => s.backend))].sort();
  }, [data]);

  // Filter data
  const filteredData = useMemo(() => {
    let filtered = data || [];
    
    // Search filter
    if (searchTerm) {
      filtered = filtered.filter(item =>
        item.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.backend.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }
    
    // Status filter
    if (statusFilter !== 'all') {
      filtered = filtered.filter(item => {
        const status = (item.status || '').toUpperCase();
        switch (statusFilter) {
          case 'up':
            return status === 'UP';
          case 'down':
            return status === 'DOWN';
          case 'maint':
            return status.includes('MAINT');
          case 'drain':
            return status.includes('DRAIN');
          default:
            return true;
        }
      });
    }
    
    // Backend filter
    if (backendFilter !== 'all') {
      filtered = filtered.filter(item => item.backend === backendFilter);
    }
    
    return filtered;
  }, [data, searchTerm, statusFilter, backendFilter]);

  // Sort by status (DOWN first, then others)
  const sortedData = useMemo(() => {
    return [...filteredData].sort((a, b) => {
      const statusA = (a.status || '').toUpperCase();
      const statusB = (b.status || '').toUpperCase();
      
      if (statusA === 'DOWN' && statusB !== 'DOWN') return -1;
      if (statusA !== 'DOWN' && statusB === 'DOWN') return 1;
      if (statusA === 'UP' && statusB !== 'UP') return -1;
      if (statusA !== 'UP' && statusB === 'UP') return 1;
      
      return a.backend.localeCompare(b.backend);
    });
  }, [filteredData]);

  const visibleData = useMemo(() => {
    return showAll ? sortedData : sortedData.slice(0, defaultShowCount);
  }, [sortedData, showAll]);

  // Calculate stats
  const stats = useMemo(() => {
    const total = data.length;
    const up = data.filter(s => (s.status || '').toUpperCase() === 'UP').length;
    const down = data.filter(s => (s.status || '').toUpperCase() === 'DOWN').length;
    const maint = data.filter(s => (s.status || '').toUpperCase().includes('MAINT')).length;
    const totalWeight = data.reduce((sum, s) => sum + (s.weight || 0), 0);
    const avgWeight = total > 0 ? Math.round(totalWeight / total) : 0;
    const totalSessions = data.reduce((sum, s) => sum + (s.current_sessions || 0), 0);
    const avgResponseTime = up > 0 ? 
      Math.round(data.filter(s => s.status === 'UP').reduce((sum, s) => sum + (s.response_time || 0), 0) / up) : 0;
    
    return { total, up, down, maint, avgWeight, totalSessions, avgResponseTime };
  }, [data]);

  const getStatusColor = (status) => {
    const statusUpper = (status || '').toUpperCase();
    if (statusUpper === 'UP') return '#52c41a';
    if (statusUpper === 'DOWN') return '#ff4d4f';
    if (statusUpper.includes('MAINT')) return '#faad14';
    if (statusUpper.includes('DRAIN')) return '#1890ff';
    return '#8c8c8c';
  };

  const getStatusIcon = (status) => {
    const statusUpper = (status || '').toUpperCase();
    if (statusUpper === 'UP') return <CheckCircleOutlined />;
    if (statusUpper === 'DOWN') return <CloseCircleOutlined />;
    return <WarningOutlined />;
  };

  // Table columns with sorting
  const tableColumns = [
    {
      title: 'Server',
      dataIndex: 'name',
      key: 'name',
      width: '20%',
      sorter: (a, b) => a.name.localeCompare(b.name),
      render: (name, record) => (
        <Space>
          <Badge status={record.status === 'UP' ? 'success' : record.status === 'DOWN' ? 'error' : 'default'} />
          <Text strong>{name}</Text>
        </Space>
      )
    },
    {
      title: 'Backend',
      dataIndex: 'backend',
      key: 'backend',
      width: '15%',
      sorter: (a, b) => a.backend.localeCompare(b.backend),
      render: (backend) => <Tag color="blue">{backend}</Tag>
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: '10%',
      sorter: (a, b) => (a.status || '').localeCompare(b.status || ''),
      render: (status) => {
        const statusColor = getStatusColor(status);
        const statusIcon = getStatusIcon(status);
        return <Tag color={statusColor} icon={statusIcon}>{status}</Tag>;
      }
    },
    {
      title: 'Weight',
      dataIndex: 'weight',
      key: 'weight',
      width: '8%',
      align: 'right',
      sorter: (a, b) => (a.weight || 0) - (b.weight || 0),
      render: (weight) => <Text>{weight || 0}</Text>
    },
    {
      title: 'Sessions',
      dataIndex: 'current_sessions',
      key: 'current_sessions',
      width: '10%',
      align: 'right',
      sorter: (a, b) => (a.current_sessions || 0) - (b.current_sessions || 0),
      render: (current, record) => (
        <Text>{current || 0}/{record.max_sessions || '-'}</Text>
      )
    },
    {
      title: 'Response Time',
      dataIndex: 'response_time',
      key: 'response_time',
      width: '12%',
      align: 'right',
      sorter: (a, b) => (a.response_time || 0) - (b.response_time || 0),
      render: (time) => <Text>{time ? `${time}ms` : '-'}</Text>
    },
    {
      title: 'Requests',
      dataIndex: 'requests_total',
      key: 'requests_total',
      width: '10%',
      align: 'right',
      sorter: (a, b) => (a.requests_total || 0) - (b.requests_total || 0),
      render: (requests) => <Text>{(requests || 0).toLocaleString()}</Text>
    },
    {
      title: 'Health Check',
      dataIndex: 'check_status',
      key: 'check_status',
      width: '15%',
      ellipsis: {
        showTitle: false
      },
      render: (check_status) => (
        check_status ? (
          <Tooltip title={check_status}>
            <Text type="secondary" style={{ fontSize: '12px' }}>{check_status}</Text>
          </Tooltip>
        ) : '-'
      )
    }
  ];

  // Virtualized row component
  const ServerRow = ({ index, style }) => {
    const server = visibleData[index];
    const statusColor = getStatusColor(server.status);
    const statusIcon = getStatusIcon(server.status);
    
    if (compactView) {
      // Compact view - single line
      return (
        <div 
          style={{ 
            ...style, 
            display: 'flex', 
            alignItems: 'center', 
            padding: '8px 16px',
            borderBottom: '1px solid #f0f0f0',
            gap: '12px',
            fontSize: '13px'
          }}
        >
          <div style={{ width: '24px' }}>
            <Badge status={server.status === 'UP' ? 'success' : server.status === 'DOWN' ? 'error' : 'default'} />
          </div>
          <div style={{ flex: '0 0 200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            <Text strong>{server.name}</Text>
          </div>
          <div style={{ flex: '0 0 150px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            <Tag color="blue" style={{ fontSize: '11px' }}>{server.backend}</Tag>
          </div>
          <div style={{ flex: '0 0 80px' }}>
            <Tag color={statusColor} icon={statusIcon} style={{ fontSize: '11px' }}>
              {server.status}
            </Tag>
          </div>
          <div style={{ flex: '0 0 60px', textAlign: 'right' }}>
            <Text type="secondary" style={{ fontSize: '12px' }}>W: {server.weight || 0}</Text>
          </div>
          <div style={{ flex: '0 0 80px', textAlign: 'right' }}>
            <Text type="secondary" style={{ fontSize: '12px' }}>
              {server.response_time ? `${server.response_time}ms` : '-'}
            </Text>
          </div>
          <div style={{ flex: '0 0 70px', textAlign: 'right' }}>
            <Text type="secondary" style={{ fontSize: '12px' }}>
              {server.current_sessions || 0} sess
            </Text>
          </div>
          <div style={{ flex: 1, minWidth: '120px' }}>
            {server.check_status && (
              <Tooltip title={server.check_status}>
                <Text 
                  type="secondary" 
                  ellipsis 
                  style={{ fontSize: '11px', maxWidth: '120px', display: 'block' }}
                >
                  {server.check_status}
                </Text>
              </Tooltip>
            )}
          </div>
        </div>
      );
    } else {
      // Detailed view - two lines
      return (
        <div 
          style={{ 
            ...style, 
            padding: '12px 16px',
            borderBottom: '1px solid #f0f0f0'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: '8px', gap: '12px' }}>
            <Badge status={server.status === 'UP' ? 'success' : server.status === 'DOWN' ? 'error' : 'default'} />
            <Text strong style={{ fontSize: '14px' }}>{server.name}</Text>
            <Tag color="blue">{server.backend}</Tag>
            <Tag color={statusColor} icon={statusIcon}>{server.status}</Tag>
          </div>
          <div style={{ 
            display: 'flex', 
            gap: '16px', 
            fontSize: '12px',
            color: '#8c8c8c',
            paddingLeft: '32px'
          }}>
            <span>Weight: {server.weight || 0}</span>
            <span>Sessions: {server.current_sessions || 0}/{server.max_sessions || '-'}</span>
            <span>Response: {server.response_time ? `${server.response_time}ms` : '-'}</span>
            <span>Requests: {(server.requests_total || 0).toLocaleString()}</span>
            {server.check_status && (
              <Tooltip title={server.check_status}>
                <span style={{ maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  Check: {server.check_status}
                </span>
              </Tooltip>
            )}
            {server.check_duration && <span>Duration: {server.check_duration}ms</span>}
          </div>
        </div>
      );
    }
  };

  // Group servers by backend for summary
  const backendGroups = useMemo(() => {
    const groups = {};
    (data || []).forEach(server => {
      if (!groups[server.backend]) {
        groups[server.backend] = { total: 0, up: 0, down: 0 };
      }
      groups[server.backend].total++;
      if (server.status === 'UP') groups[server.backend].up++;
      if (server.status === 'DOWN') groups[server.backend].down++;
    });
    return groups;
  }, [data]);

  return (
    <Card
      title={
        <Space>
          <ThunderboltOutlined />
          <span>Servers</span>
          <Tag color="blue">{stats.total}</Tag>
          <Badge count={stats.up} style={{ backgroundColor: '#52c41a' }} />
          {stats.down > 0 && <Badge count={stats.down} style={{ backgroundColor: '#ff4d4f' }} />}
          {stats.maint > 0 && <Badge count={stats.maint} style={{ backgroundColor: '#faad14' }} />}
        </Space>
      }
      extra={
        <Space>
          <Radio.Group
            size="small"
            value={viewMode}
            onChange={(e) => setViewMode(e.target.value)}
            optionType="button"
            buttonStyle="solid"
          >
            <Radio.Button value="list">
              <Tooltip title="List View (Fast, Virtualized)">
                <BarsOutlined />
              </Tooltip>
            </Radio.Button>
            <Radio.Button value="table">
              <Tooltip title="Table View (Sortable Columns)">
                <TableOutlined />
              </Tooltip>
            </Radio.Button>
          </Radio.Group>
          {viewMode === 'list' && (
            <Tooltip title={compactView ? 'Switch to detailed view' : 'Switch to compact view'}>
              <Switch
                checked={compactView}
                onChange={setCompactView}
                checkedChildren={<EyeInvisibleOutlined />}
                unCheckedChildren={<EyeOutlined />}
                size="small"
              />
            </Tooltip>
          )}
        </Space>
      }
      loading={loading}
    >
      {/* Summary Stats */}
      <Row gutter={16} style={{ marginBottom: 16 }}>
        <Col span={6}>
          <Statistic
            title="Active Servers"
            value={`${stats.up}/${stats.total}`}
            valueStyle={{ fontSize: 16 }}
            prefix={<CheckCircleOutlined style={{ color: '#52c41a' }} />}
          />
          <Progress
            percent={stats.total > 0 ? Math.round((stats.up / stats.total) * 100) : 0}
            size="small"
            showInfo={false}
            strokeColor="#52c41a"
            style={{ marginTop: 4 }}
          />
        </Col>
        <Col span={6}>
          <Statistic
            title="Total Sessions"
            value={stats.totalSessions}
            valueStyle={{ fontSize: 16 }}
          />
        </Col>
        <Col span={6}>
          <Statistic
            title="Avg Response"
            value={stats.avgResponseTime}
            suffix="ms"
            valueStyle={{ fontSize: 16 }}
            prefix={<ClockCircleOutlined />}
          />
        </Col>
        <Col span={6}>
          <Statistic
            title="Avg Weight"
            value={stats.avgWeight}
            valueStyle={{ fontSize: 16 }}
          />
        </Col>
      </Row>

      {/* Backend Summary Chips */}
      <div style={{ marginBottom: 16 }}>
        <Text type="secondary" style={{ fontSize: 12, display: 'block', marginBottom: 8 }}>
          Backends Summary:
        </Text>
        <Space wrap size="small">
          {Object.entries(backendGroups).map(([backend, stats]) => (
            <Tooltip 
              key={backend} 
              title={`${stats.up} UP / ${stats.down} DOWN / ${stats.total} Total`}
            >
              <Tag 
                color={stats.down > 0 ? 'red' : stats.up === stats.total ? 'green' : 'orange'}
                style={{ cursor: 'pointer', fontSize: '11px' }}
                onClick={() => setBackendFilter(backend)}
              >
                {backend}: {stats.up}/{stats.total}
              </Tag>
            </Tooltip>
          ))}
        </Space>
      </div>

      {/* Filters */}
      <Space style={{ marginBottom: 16, width: '100%' }} wrap>
        <Input
          placeholder="Search servers or backends..."
          prefix={<SearchOutlined />}
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          style={{ width: 300 }}
          allowClear
          size="small"
        />
        
        <Select
          value={statusFilter}
          onChange={setStatusFilter}
          style={{ width: 140 }}
          size="small"
          options={[
            { label: <><FilterOutlined /> All Status</>, value: 'all' },
            { label: <><CheckCircleOutlined style={{ color: '#52c41a' }} /> UP</>, value: 'up' },
            { label: <><CloseCircleOutlined style={{ color: '#ff4d4f' }} /> DOWN</>, value: 'down' },
            { label: <><WarningOutlined style={{ color: '#faad14' }} /> MAINT</>, value: 'maint' },
            { label: 'DRAIN', value: 'drain' }
          ]}
        />
        
        <Select
          value={backendFilter}
          onChange={setBackendFilter}
          style={{ width: 180 }}
          size="small"
          showSearch
          placeholder="Filter by backend"
          options={[
            { label: 'All Backends', value: 'all' },
            ...backends.map(b => ({ label: b, value: b }))
          ]}
        />

        {sortedData.length > defaultShowCount && (
          <Button
            size="small"
            onClick={() => setShowAll(!showAll)}
          >
            {showAll ? `Show Top ${defaultShowCount}` : `Show All (${sortedData.length})`}
          </Button>
        )}
      </Space>

      {/* Results Info */}
      <div style={{ marginBottom: 12 }}>
        <Text type="secondary" style={{ fontSize: 12 }}>
          Showing {visibleData.length} of {filteredData.length} servers
          {(searchTerm || statusFilter !== 'all' || backendFilter !== 'all') && 
            ` (filtered from ${data.length})`}
        </Text>
      </div>

      {/* Render based on view mode */}
      {viewMode === 'table' ? (
        // Table View with Sortable Columns
        <Table
          columns={tableColumns}
          dataSource={sortedData}
          loading={loading}
          rowKey={(record) => `${record.backend}-${record.name}`}
          pagination={{
            defaultPageSize: 20,
            showSizeChanger: true,
            showTotal: (total) => `Total ${total} servers`,
            pageSizeOptions: ['10', '20', '50', '100']
          }}
          size="small"
          scroll={{ x: 1200 }}
        />
      ) : (
        <>
          {/* Header for compact view */}
          {compactView && visibleData.length > 0 && (
            <div style={{ 
              display: 'flex', 
              padding: '8px 16px',
              backgroundColor: '#fafafa',
              borderBottom: '2px solid #d9d9d9',
              fontWeight: 'bold',
              fontSize: '12px',
              gap: '12px'
            }}>
              <div style={{ width: '24px' }}></div>
              <div style={{ flex: '0 0 200px' }}>Server Name</div>
              <div style={{ flex: '0 0 150px' }}>Backend</div>
              <div style={{ flex: '0 0 80px' }}>Status</div>
              <div style={{ flex: '0 0 60px', textAlign: 'right' }}>Weight</div>
              <div style={{ flex: '0 0 80px', textAlign: 'right' }}>Response</div>
              <div style={{ flex: '0 0 70px', textAlign: 'right' }}>Sessions</div>
              <div style={{ flex: 1, minWidth: '120px' }}>Health Check</div>
            </div>
          )}

          {/* Virtualized List */}
          {visibleData.length > 0 ? (
            <List
              height={600}
              itemCount={visibleData.length}
              itemSize={compactView ? 50 : 72}
              width="100%"
              overscanCount={5}
            >
              {ServerRow}
            </List>
          ) : (
            <div style={{ textAlign: 'center', padding: '40px 0' }}>
              <Text type="secondary">No servers found matching the filters</Text>
            </div>
          )}
        </>
      )}

      {/* Status Legend */}
      <div style={{ 
        marginTop: 16, 
        padding: '12px', 
        backgroundColor: '#fafafa', 
        borderRadius: '4px',
        display: 'flex',
        gap: '24px',
        flexWrap: 'wrap',
        fontSize: '11px'
      }}>
        <Space size="small">
          <CheckCircleOutlined style={{ color: '#52c41a' }} />
          <Text type="secondary">UP - Server is healthy and active</Text>
        </Space>
        <Space size="small">
          <CloseCircleOutlined style={{ color: '#ff4d4f' }} />
          <Text type="secondary">DOWN - Server is not responding</Text>
        </Space>
        <Space size="small">
          <WarningOutlined style={{ color: '#faad14' }} />
          <Text type="secondary">MAINT - Server in maintenance mode</Text>
        </Space>
        <Space size="small">
          <WarningOutlined style={{ color: '#1890ff' }} />
          <Text type="secondary">DRAIN - Server draining connections</Text>
        </Space>
      </div>
    </Card>
  );
};

// Memoized export for performance - prevents unnecessary re-renders
export default memo(CompactServerList);

