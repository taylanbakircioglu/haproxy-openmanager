import React from 'react';
import { Card, Empty, Spin, Table, Tag, Progress, Space, Typography, Tooltip } from 'antd';
import {
  WarningOutlined,
  CheckCircleOutlined,
  ExclamationCircleOutlined
} from '@ant-design/icons';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  Cell,
  Legend
} from 'recharts';

const { Text } = Typography;

const QueueMonitor = ({ data, loading, title = "Backend Queue Status" }) => {
  if (loading) {
    return (
      <Card title={title}>
        <div style={{ textAlign: 'center', padding: 50 }}>
          <Spin size="large" tip="Loading queue data..." />
        </div>
      </Card>
    );
  }

  if (!data || data.length === 0) {
    return (
      <Card title={title}>
        <Empty 
          description={
            <div style={{ textAlign: 'center' }}>
              <Text type="secondary">No backend queue data available</Text>
              <br />
              <Text type="secondary" style={{ fontSize: 12 }}>
                Queue data will appear when backends start receiving traffic
              </Text>
            </div>
          } 
          image={Empty.PRESENTED_IMAGE_SIMPLE} 
        />
      </Card>
    );
  }

  // Prepare chart data
  const chartData = data.map(backend => ({
    name: backend.name,
    current: backend.queue_current || 0,
    max: backend.queue_max || 0,
    percentage: backend.queue_max > 0 ? 
      Math.round((backend.queue_current / backend.queue_max) * 100) : 0
  }));

  // Get color based on queue status
  const getQueueColor = (current, max) => {
    if (max === 0) return '#52c41a'; // No limit
    const percentage = (current / max) * 100;
    if (percentage === 0) return '#52c41a'; // Empty queue
    if (percentage < 50) return '#1890ff'; // Low
    if (percentage < 80) return '#faad14'; // Medium
    return '#ff4d4f'; // High/Critical
  };

  const getQueueStatus = (current, max) => {
    if (current === 0) return { text: 'Empty', color: 'success' };
    if (max === 0) return { text: 'Active', color: 'processing' };
    const percentage = (current / max) * 100;
    if (percentage < 50) return { text: 'Normal', color: 'success' };
    if (percentage < 80) return { text: 'Moderate', color: 'warning' };
    return { text: 'Critical', color: 'error' };
  };

  // Calculate statistics
  const totalQueuedRequests = chartData.reduce((sum, b) => sum + b.current, 0);
  const backendsWithQueue = chartData.filter(b => b.current > 0).length;
  const criticalBackends = chartData.filter(b => {
    return b.max > 0 && (b.current / b.max) >= 0.8;
  }).length;

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload;
      return (
        <div style={{ 
          backgroundColor: 'rgba(255, 255, 255, 0.96)', 
          padding: '10px', 
          border: '1px solid #d9d9d9',
          borderRadius: '4px',
          boxShadow: '0 2px 8px rgba(0,0,0,0.15)'
        }}>
          <p style={{ margin: 0, fontWeight: 'bold' }}>{label}</p>
          <p style={{ margin: '4px 0', color: '#1890ff' }}>
            Current Queue: <strong>{data.current}</strong>
          </p>
          <p style={{ margin: '4px 0', color: '#8c8c8c' }}>
            Max Queue: <strong>{data.max > 0 ? data.max : 'Unlimited'}</strong>
          </p>
          <p style={{ margin: '4px 0', color: '#faad14' }}>
            Usage: <strong>{data.percentage}%</strong>
          </p>
        </div>
      );
    }
    return null;
  };

  const columns = [
    {
      title: 'Backend',
      dataIndex: 'name',
      key: 'name',
      width: '30%',
      sorter: (a, b) => a.name.localeCompare(b.name),
      render: (name) => <Text strong>{name}</Text>
    },
    {
      title: 'Queue Status',
      key: 'status',
      width: '20%',
      sorter: (a, b) => {
        const statusA = getQueueStatus(a.queue_current, a.queue_max);
        const statusB = getQueueStatus(b.queue_current, b.queue_max);
        return statusA.text.localeCompare(statusB.text);
      },
      render: (_, record) => {
        const status = getQueueStatus(record.queue_current, record.queue_max);
        return (
          <Tag color={status.color} icon={
            status.text === 'Critical' ? <ExclamationCircleOutlined /> :
            status.text === 'Empty' ? <CheckCircleOutlined /> :
            <WarningOutlined />
          }>
            {status.text}
          </Tag>
        );
      }
    },
    {
      title: 'Current / Max',
      key: 'queue',
      width: '30%',
      sorter: (a, b) => (a.queue_current || 0) - (b.queue_current || 0),
      render: (_, record) => (
        <Space direction="vertical" style={{ width: '100%' }} size="small">
          <Text>
            {record.queue_current} / {record.queue_max > 0 ? record.queue_max : '∞'}
          </Text>
          <Progress
            percent={record.queue_max > 0 ? 
              Math.round((record.queue_current / record.queue_max) * 100) : 
              (record.queue_current > 0 ? 100 : 0)
            }
            size="small"
            strokeColor={getQueueColor(record.queue_current, record.queue_max)}
            showInfo={false}
          />
        </Space>
      )
    },
    {
      title: 'Usage',
      key: 'usage',
      width: '20%',
      align: 'right',
      sorter: (a, b) => {
        const pctA = a.queue_max > 0 ? (a.queue_current / a.queue_max) * 100 : 0;
        const pctB = b.queue_max > 0 ? (b.queue_current / b.queue_max) * 100 : 0;
        return pctA - pctB;
      },
      render: (_, record) => {
        if (record.queue_max === 0) {
          return <Text type="secondary">N/A</Text>;
        }
        const percentage = Math.round((record.queue_current / record.queue_max) * 100);
        return (
          <Text strong style={{ 
            color: getQueueColor(record.queue_current, record.queue_max)
          }}>
            {percentage}%
          </Text>
        );
      }
    }
  ];

  return (
    <Card 
      title={
        <Space>
          <span>{title}</span>
          <Tooltip title="Backends with active queue">
            <Tag color={backendsWithQueue > 0 ? 'orange' : 'green'}>
              {backendsWithQueue} queued
            </Tag>
          </Tooltip>
          {criticalBackends > 0 && (
            <Tooltip title="Backends with critical queue (>80%)">
              <Tag color="red" icon={<ExclamationCircleOutlined />}>
                {criticalBackends} critical
              </Tag>
            </Tooltip>
          )}
        </Space>
      }
    >
      {/* Summary Stats */}
      <div style={{ 
        padding: '12px', 
        backgroundColor: '#f5f5f5', 
        borderRadius: '4px', 
        marginBottom: '16px',
        display: 'flex',
        justifyContent: 'space-around'
      }}>
        <div style={{ textAlign: 'center' }}>
          <Text type="secondary" style={{ fontSize: 12 }}>Total Queued</Text>
          <div style={{ fontSize: 24, fontWeight: 'bold', color: '#1890ff' }}>
            {totalQueuedRequests}
          </div>
        </div>
        <div style={{ textAlign: 'center' }}>
          <Text type="secondary" style={{ fontSize: 12 }}>Backends</Text>
          <div style={{ fontSize: 24, fontWeight: 'bold' }}>
            {data.length}
          </div>
        </div>
        <div style={{ textAlign: 'center' }}>
          <Text type="secondary" style={{ fontSize: 12 }}>With Queue</Text>
          <div style={{ fontSize: 24, fontWeight: 'bold', color: '#faad14' }}>
            {backendsWithQueue}
          </div>
        </div>
      </div>

      {/* Bar Chart */}
      {chartData.some(d => d.current > 0) && (
        <div style={{ marginBottom: 16 }}>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
              <XAxis 
                dataKey="name" 
                stroke="#8c8c8c"
                style={{ fontSize: 11 }}
                angle={-45}
                textAnchor="end"
                height={80}
              />
              <YAxis 
                stroke="#8c8c8c"
                style={{ fontSize: 12 }}
                label={{ value: 'Queue Depth', angle: -90, position: 'insideLeft', style: { fill: '#8c8c8c' } }}
              />
              <RechartsTooltip content={<CustomTooltip />} />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              <Bar dataKey="current" name="Current Queue" radius={[4, 4, 0, 0]}>
                {chartData.map((entry, index) => (
                  <Cell 
                    key={`cell-${index}`} 
                    fill={getQueueColor(entry.current, entry.max)} 
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Detailed Table */}
      <Table
        columns={columns}
        dataSource={data}
        rowKey="name"
        pagination={false}
        size="small"
        scroll={{ y: 300 }}
      />
    </Card>
  );
};

export default QueueMonitor;

