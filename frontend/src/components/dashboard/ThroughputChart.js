import React from 'react';
import { Card, Empty, Spin, Statistic, Row, Col, Typography, Alert } from 'antd';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend
} from 'recharts';
import { ArrowUpOutlined, ArrowDownOutlined } from '@ant-design/icons';

const { Text } = Typography;

const ThroughputChart = ({ data, realtimeData, loading, title = "Network Throughput (24h)" }) => {
  if (loading) {
    return (
      <Card title={title}>
        <div style={{ textAlign: 'center', padding: 50 }}>
          <Spin size="large" tip="Loading throughput data..." />
        </div>
      </Card>
    );
  }

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
  };

  // Format data for charting (if historical data is provided)
  const chartData = data && data.length > 0 ? data.map(point => ({
    time: new Date(point.timestamp).toLocaleTimeString([], { 
      hour: '2-digit', 
      minute: '2-digit' 
    }),
    'Bytes In': Math.round(point.bytes_in / (1024 * 1024)), // Convert to MB
    'Bytes Out': Math.round(point.bytes_out / (1024 * 1024))
  })) : [];

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div style={{ 
          backgroundColor: 'rgba(255, 255, 255, 0.96)', 
          padding: '10px', 
          border: '1px solid #d9d9d9',
          borderRadius: '4px',
          boxShadow: '0 2px 8px rgba(0,0,0,0.15)'
        }}>
          <p style={{ margin: 0, fontWeight: 'bold' }}>{label}</p>
          {payload.map((entry, index) => (
            <p key={index} style={{ margin: '4px 0', color: entry.color }}>
              {entry.name}: <strong>{entry.value} MB</strong>
            </p>
          ))}
        </div>
      );
    }
    return null;
  };

  // Check if all data is zero/empty
  const hasRealtimeData = realtimeData && (
    realtimeData.bytes_in_mb > 0 || 
    realtimeData.bytes_out_mb > 0 || 
    realtimeData.bytes_in_gb > 0 || 
    realtimeData.bytes_out_gb > 0 || 
    realtimeData.rate_in_mbps > 0 || 
    realtimeData.rate_out_mbps > 0
  );
  const hasHistoricalData = chartData.length > 0;
  
  // If no data at all, show empty state
  if (!realtimeData || (!hasRealtimeData && !hasHistoricalData)) {
    return (
      <Card title={title}>
        <Empty 
          description={
            <div style={{ textAlign: 'center' }}>
              <Text type="secondary">No network throughput data available</Text>
              <br />
              <Text type="secondary" style={{ fontSize: 12 }}>
                This usually means no traffic is currently flowing through HAProxy,<br />
                or historical throughput data collection is not yet implemented.
              </Text>
            </div>
          } 
          image={Empty.PRESENTED_IMAGE_SIMPLE} 
        />
      </Card>
    );
  }

  return (
    <Card title={title}>
      {/* Info Alert for Zero Values */}
      {realtimeData && !hasRealtimeData && (
        <Alert
          message="Network throughput counters are currently at 0"
          description={
            <div>
              <Text>This is normal after HAProxy restart or reload. HAProxy uses cumulative counters (bin/bout) that reset to zero on restart.</Text>
              <br />
              <Text type="secondary" style={{ fontSize: 12 }}>
                Data will appear automatically as traffic flows through HAProxy. The counters accumulate over time until the next HAProxy restart/reload.
              </Text>
            </div>
          }
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
        />
      )}

      {/* Real-time Statistics */}
      {realtimeData && (
        <Row gutter={16} style={{ marginBottom: 16 }}>
          <Col span={6}>
            <Statistic
              title="Total Bytes In"
              value={realtimeData.bytes_in_mb}
              precision={2}
              suffix="MB"
              prefix={<ArrowDownOutlined style={{ color: '#1890ff' }} />}
              valueStyle={{ fontSize: 16, color: '#1890ff' }}
            />
          </Col>
          <Col span={6}>
            <Statistic
              title="Total Bytes Out"
              value={realtimeData.bytes_out_mb}
              precision={2}
              suffix="MB"
              prefix={<ArrowUpOutlined style={{ color: '#52c41a' }} />}
              valueStyle={{ fontSize: 16, color: '#52c41a' }}
            />
          </Col>
          <Col span={6}>
            <Statistic
              title="Approx Rate In"
              value={realtimeData.rate_in_mbps}
              precision={2}
              suffix="MB/min"
              valueStyle={{ fontSize: 16 }}
            />
          </Col>
          <Col span={6}>
            <Statistic
              title="Approx Rate Out"
              value={realtimeData.rate_out_mbps}
              precision={2}
              suffix="MB/min"
              valueStyle={{ fontSize: 16 }}
            />
          </Col>
        </Row>
      )}

      {/* Historical Chart */}
      {chartData.length > 0 ? (
        <ResponsiveContainer width="100%" height={250}>
          <LineChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
            <XAxis 
              dataKey="time" 
              stroke="#8c8c8c"
              style={{ fontSize: 12 }}
              tick={{ fill: '#8c8c8c' }}
            />
            <YAxis 
              stroke="#8c8c8c"
              style={{ fontSize: 12 }}
              tick={{ fill: '#8c8c8c' }}
              label={{ value: 'MB', angle: -90, position: 'insideLeft', style: { fill: '#8c8c8c' } }}
            />
          <Tooltip 
            content={<CustomTooltip />} 
            cursor={{ strokeDasharray: '3 3' }}
            position={({ x, y }) => {
              // Tooltip is small (only throughput metrics), fixed height
              const tooltipHeight = 180;
              return { x: x - 150, y: y - tooltipHeight };
            }}
            allowEscapeViewBox={{ x: true, y: true }}
            wrapperStyle={{ 
              pointerEvents: 'none',
              zIndex: 9999
            }}
          />
            <Legend 
              wrapperStyle={{ fontSize: 12 }}
              iconType="line"
            />
            <Line
              type="monotone"
              dataKey="Bytes In"
              stroke="#1890ff"
              strokeWidth={2}
              dot={false}
            />
            <Line
              type="monotone"
              dataKey="Bytes Out"
              stroke="#52c41a"
              strokeWidth={2}
              dot={false}
            />
          </LineChart>
        </ResponsiveContainer>
      ) : (
        <Empty description="No historical throughput data available" image={Empty.PRESENTED_IMAGE_SIMPLE} />
      )}
    </Card>
  );
};

export default ThroughputChart;

