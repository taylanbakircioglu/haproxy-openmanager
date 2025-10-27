import React from 'react';
import { Card, Empty, Spin, Table, Badge, Tag, Progress, Space, Typography, Tooltip } from 'antd';
import {
  CheckCircleOutlined,
  CloseCircleOutlined,
  QuestionCircleOutlined,
  ClockCircleOutlined,
  WarningOutlined
} from '@ant-design/icons';

const { Text } = Typography;

const HealthCheckStatus = ({ data, loading, title = "Health Check Status" }) => {
  if (loading) {
    return (
      <Card title={title}>
        <div style={{ textAlign: 'center', padding: 50 }}>
          <Spin size="large" tip="Loading health check data..." />
        </div>
      </Card>
    );
  }

  if (!data || data.length === 0) {
    return (
      <Card title={title}>
        <Empty description="No health check data available" image={Empty.PRESENTED_IMAGE_SIMPLE} />
      </Card>
    );
  }

  // Get status badge and color
  const getStatusBadge = (status) => {
    const statusUpper = (status || 'UNKNOWN').toUpperCase();
    if (statusUpper.includes('UP') || statusUpper.includes('OK')) {
      return { status: 'success', icon: <CheckCircleOutlined />, color: '#52c41a' };
    }
    if (statusUpper.includes('DOWN') || statusUpper.includes('FAIL')) {
      return { status: 'error', icon: <CloseCircleOutlined />, color: '#ff4d4f' };
    }
    if (statusUpper.includes('WARN') || statusUpper.includes('MAINT')) {
      return { status: 'warning', icon: <WarningOutlined />, color: '#faad14' };
    }
    return { status: 'default', icon: <QuestionCircleOutlined />, color: '#8c8c8c' };
  };

  // Calculate statistics
  const totalServers = data.length;
  const healthyServers = data.filter(s => {
    const status = (s.status || '').toUpperCase();
    return status.includes('UP') || status.includes('OK');
  }).length;
  const unhealthyServers = data.filter(s => {
    const status = (s.status || '').toUpperCase();
    return status.includes('DOWN') || status.includes('FAIL');
  }).length;
  const warningServers = totalServers - healthyServers - unhealthyServers;

  // Get check duration color
  const getCheckDurationColor = (duration) => {
    if (!duration || duration === 0) return '#8c8c8c';
    if (duration < 100) return '#52c41a';
    if (duration < 300) return '#1890ff';
    if (duration < 500) return '#faad14';
    return '#ff4d4f';
  };

  // Format last check time
  const formatLastCheck = (lastCheck) => {
    if (!lastCheck || lastCheck === 'N/A' || lastCheck === '-') {
      return 'Never';
    }
    return lastCheck;
  };

  const columns = [
    {
      title: 'Server',
      key: 'server',
      width: '25%',
      sorter: (a, b) => a.name.localeCompare(b.name),
      render: (_, record) => (
        <Space direction="vertical" size={0}>
          <Text strong>{record.name}</Text>
          <Text type="secondary" style={{ fontSize: 11 }}>
            {record.backend}
          </Text>
        </Space>
      )
    },
    {
      title: 'Status',
      key: 'status',
      width: '15%',
      sorter: (a, b) => (a.status || '').localeCompare(b.status || ''),
      render: (_, record) => {
        const badge = getStatusBadge(record.status);
        return (
          <Space>
            <Badge status={badge.status} />
            <Tag color={badge.color} icon={badge.icon}>
              {record.status || 'UNKNOWN'}
            </Tag>
          </Space>
        );
      }
    },
    {
      title: 'Check Status',
      dataIndex: 'check_status',
      sorter: (a, b) => (a.check_status || '').localeCompare(b.check_status || ''),
      key: 'check_status',
      width: '20%',
      render: (checkStatus) => {
        if (!checkStatus || checkStatus === '-' || checkStatus === '') {
          return <Text type="secondary">-</Text>;
        }
        const isHealthy = checkStatus.toUpperCase().includes('OK') || 
                         checkStatus.toUpperCase().includes('UP') ||
                         checkStatus.toUpperCase().includes('PASS');
        return (
          <Tooltip title={checkStatus}>
            <Tag color={isHealthy ? 'green' : 'red'} style={{ fontSize: 11 }}>
              {checkStatus.length > 20 ? checkStatus.substring(0, 20) + '...' : checkStatus}
            </Tag>
          </Tooltip>
        );
      }
    },
    {
      title: 'Check Duration',
      dataIndex: 'check_duration',
      key: 'check_duration',
      width: '15%',
      sorter: (a, b) => (a.check_duration || 0) - (b.check_duration || 0),
      render: (duration) => {
        if (!duration || duration === 0) {
          return <Text type="secondary">-</Text>;
        }
        return (
          <Tooltip title={`Health check took ${duration}ms`}>
            <Text strong style={{ color: getCheckDurationColor(duration) }}>
              {duration}ms
            </Text>
          </Tooltip>
        );
      }
    },
    {
      title: 'Last Check',
      dataIndex: 'last_check',
      key: 'last_check',
      width: '15%',
      sorter: (a, b) => (a.last_check || '').localeCompare(b.last_check || ''),
      render: (lastCheck) => (
        <Tooltip title={lastCheck}>
          <Space size={4}>
            <ClockCircleOutlined style={{ fontSize: 12, color: '#8c8c8c' }} />
            <Text type="secondary" style={{ fontSize: 11 }}>
              {formatLastCheck(lastCheck)}
            </Text>
          </Space>
        </Tooltip>
      )
    },
    {
      title: 'Failures',
      key: 'failures',
      width: '10%',
      sorter: (a, b) => {
        const totalA = (a.check_fail || 0) + (a.check_down || 0);
        const totalB = (b.check_fail || 0) + (b.check_down || 0);
        return totalA - totalB;
      },
      render: (_, record) => {
        const failures = record.check_fail || 0;
        const downs = record.check_down || 0;
        const total = failures + downs;
        
        if (total === 0) {
          return <Tag color="success">0</Tag>;
        }
        return (
          <Tooltip title={`${failures} check failures, ${downs} down events`}>
            <Tag color={total > 5 ? 'error' : 'warning'}>
              {total}
            </Tag>
          </Tooltip>
        );
      }
    }
  ];

  // Calculate health percentage
  const healthPercentage = totalServers > 0 ? 
    Math.round((healthyServers / totalServers) * 100) : 0;

  return (
    <Card 
      title={
        <Space>
          <span>{title}</span>
          <Tag color={healthPercentage >= 90 ? 'green' : healthPercentage >= 70 ? 'orange' : 'red'}>
            {healthyServers}/{totalServers} Healthy
          </Tag>
        </Space>
      }
    >
      {/* Health Summary */}
      <div style={{ 
        padding: '12px', 
        backgroundColor: '#f5f5f5', 
        borderRadius: '4px', 
        marginBottom: '16px'
      }}>
        <div style={{ display: 'flex', gap: '16px' }}>
          <div style={{ flex: 1 }}>
            <Space direction="vertical" style={{ width: '100%' }} size="small">
              <Text type="secondary" style={{ fontSize: 12 }}>Overall Health</Text>
              <Progress
                percent={healthPercentage}
                strokeColor={{
                  '0%': '#ff4d4f',
                  '50%': '#faad14',
                  '70%': '#1890ff',
                  '90%': '#52c41a'
                }}
                format={(percent) => (
                  <span style={{ fontSize: 14, fontWeight: 'bold' }}>
                    {percent}%
                  </span>
                )}
              />
            </Space>
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', justifyContent: 'space-around', paddingTop: 8 }}>
              <div style={{ textAlign: 'center' }}>
                <CheckCircleOutlined style={{ fontSize: 20, color: '#52c41a' }} />
                <div style={{ fontSize: 18, fontWeight: 'bold', color: '#52c41a' }}>
                  {healthyServers}
                </div>
                <Text type="secondary" style={{ fontSize: 11 }}>Healthy</Text>
              </div>
              <div style={{ textAlign: 'center' }}>
                <WarningOutlined style={{ fontSize: 20, color: '#faad14' }} />
                <div style={{ fontSize: 18, fontWeight: 'bold', color: '#faad14' }}>
                  {warningServers}
                </div>
                <Text type="secondary" style={{ fontSize: 11 }}>Warning</Text>
              </div>
              <div style={{ textAlign: 'center' }}>
                <CloseCircleOutlined style={{ fontSize: 20, color: '#ff4d4f' }} />
                <div style={{ fontSize: 18, fontWeight: 'bold', color: '#ff4d4f' }}>
                  {unhealthyServers}
                </div>
                <Text type="secondary" style={{ fontSize: 11 }}>Down</Text>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Server Health Table */}
      <Table
        columns={columns}
        dataSource={data}
        rowKey={(record) => `${record.backend}_${record.name}`}
        pagination={{ pageSize: 10 }}
        size="small"
        scroll={{ x: 'max-content' }}
      />
    </Card>
  );
};

export default HealthCheckStatus;

