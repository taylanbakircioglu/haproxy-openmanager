import React from 'react';
import { Card, Spin, Empty, Statistic, Row, Col, Progress, Typography, Tag, Space } from 'antd';
import { 
  ArrowUpOutlined, 
  ArrowDownOutlined,
  DashboardOutlined,
  ThunderboltOutlined
} from '@ant-design/icons';
import {
  ResponsiveContainer,
  RadialBarChart,
  RadialBar,
  Legend,
  Tooltip as RechartsTooltip,
  PolarAngleAxis
} from 'recharts';

const { Text, Title } = Typography;

const ConnectionRateGauge = ({ data, loading, title = "Connection Rate Monitor" }) => {
  if (loading) {
    return (
      <Card title={title}>
        <div style={{ textAlign: 'center', padding: 50 }}>
          <Spin size="large" tip="Loading connection data..." />
        </div>
      </Card>
    );
  }

  const currentRate = data?.current_rate || 0;
  const maxRate = data?.max_rate || 0;
  const rateLimit = data?.rate_limit || 1000;
  const avgRate = data?.avg_rate || 0;

  // If no data or all values are zero, show empty state
  if (!data || (currentRate === 0 && maxRate === 0 && avgRate === 0)) {
    return (
      <Card title={title}>
        <Empty 
          description={
            <div style={{ textAlign: 'center' }}>
              <Text type="secondary">No connection rate data available</Text>
              <br />
              <Text type="secondary" style={{ fontSize: 12 }}>
                This usually means no traffic is currently flowing through HAProxy
              </Text>
            </div>
          } 
          image={Empty.PRESENTED_IMAGE_SIMPLE} 
        />
      </Card>
    );
  }
  
  // Calculate percentage
  const percentage = Math.min(Math.round((currentRate / rateLimit) * 100), 100);
  
  // Determine status and color
  const getStatus = () => {
    if (percentage >= 90) return { text: 'Critical', color: '#ff4d4f' };
    if (percentage >= 75) return { text: 'High', color: '#faad14' };
    if (percentage >= 50) return { text: 'Moderate', color: '#1890ff' };
    return { text: 'Normal', color: '#52c41a' };
  };

  const status = getStatus();

  // Prepare gauge data
  const gaugeData = [
    {
      name: 'Current',
      value: percentage,
      fill: status.color
    }
  ];

  // Calculate trend (comparing current vs average)
  const trend = currentRate > avgRate ? 'up' : 'down';
  const trendPercentage = avgRate > 0 ? 
    Math.abs(Math.round(((currentRate - avgRate) / avgRate) * 100)) : 0;

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      return (
        <div style={{ 
          backgroundColor: 'rgba(255, 255, 255, 0.96)', 
          padding: '10px', 
          border: '1px solid #d9d9d9',
          borderRadius: '4px',
          boxShadow: '0 2px 8px rgba(0,0,0,0.15)'
        }}>
          <p style={{ margin: '4px 0', fontWeight: 'bold' }}>
            Connection Rate
          </p>
          <p style={{ margin: '4px 0' }}>
            Usage: <strong>{payload[0].value}%</strong>
          </p>
          <p style={{ margin: '4px 0' }}>
            Current: <strong>{currentRate} conn/s</strong>
          </p>
          <p style={{ margin: '4px 0' }}>
            Limit: <strong>{rateLimit} conn/s</strong>
          </p>
        </div>
      );
    }
    return null;
  };

  return (
    <Card 
      title={
        <Space>
          <ThunderboltOutlined />
          <span>{title}</span>
          <Tag color={status.color}>{status.text}</Tag>
        </Space>
      }
    >
      <Row gutter={16}>
        {/* Gauge Chart */}
        <Col span={12}>
          <div style={{ textAlign: 'center' }}>
            <ResponsiveContainer width="100%" height={200}>
              <RadialBarChart
                cx="50%"
                cy="50%"
                innerRadius="60%"
                outerRadius="90%"
                data={gaugeData}
                startAngle={180}
                endAngle={0}
              >
                <PolarAngleAxis
                  type="number"
                  domain={[0, 100]}
                  angleAxisId={0}
                  tick={false}
                />
                <RadialBar
                  background
                  dataKey="value"
                  cornerRadius={10}
                  fill={status.color}
                />
                <RechartsTooltip content={<CustomTooltip />} />
              </RadialBarChart>
            </ResponsiveContainer>
            
            {/* Center Display */}
            <div style={{ 
              marginTop: -110, 
              position: 'relative',
              zIndex: 10
            }}>
              <Title level={2} style={{ margin: 0, color: status.color }}>
                {currentRate}
              </Title>
              <Text type="secondary" style={{ fontSize: 12 }}>
                connections/sec
              </Text>
            </div>
          </div>

          {/* Progress Bar */}
          <div style={{ marginTop: 20 }}>
            <Text type="secondary" style={{ fontSize: 11 }}>
              Capacity Usage
            </Text>
            <Progress
              percent={percentage}
              strokeColor={{
                '0%': '#52c41a',
                '50%': '#1890ff',
                '75%': '#faad14',
                '90%': '#ff4d4f'
              }}
              format={(percent) => `${percent}%`}
            />
          </div>
        </Col>

        {/* Statistics */}
        <Col span={12}>
          <Space direction="vertical" style={{ width: '100%' }} size="middle">
            {/* Current Rate */}
            <Card size="small" style={{ backgroundColor: '#f5f5f5' }}>
              <Statistic
                title="Current Rate"
                value={currentRate}
                suffix="conn/s"
                valueStyle={{ fontSize: 20, color: status.color }}
                prefix={<DashboardOutlined />}
              />
            </Card>

            {/* Max Rate */}
            <Card size="small">
              <Statistic
                title="Peak Rate (24h)"
                value={maxRate}
                suffix="conn/s"
                valueStyle={{ fontSize: 16 }}
                prefix={
                  trend === 'up' ? 
                    <ArrowUpOutlined style={{ color: '#ff4d4f' }} /> : 
                    <ArrowDownOutlined style={{ color: '#52c41a' }} />
                }
              />
              {trendPercentage > 0 && (
                <Text type="secondary" style={{ fontSize: 11 }}>
                  {trend === 'up' ? '+' : '-'}{trendPercentage}% vs avg
                </Text>
              )}
            </Card>

            {/* Average Rate */}
            <Card size="small">
              <Statistic
                title="Average Rate (24h)"
                value={avgRate}
                suffix="conn/s"
                valueStyle={{ fontSize: 16 }}
              />
            </Card>

            {/* Rate Limit */}
            <Card size="small">
              <Statistic
                title="Rate Limit"
                value={rateLimit}
                suffix="conn/s"
                valueStyle={{ fontSize: 16, color: '#8c8c8c' }}
              />
              <Text type="secondary" style={{ fontSize: 11 }}>
                {Math.round((rateLimit - currentRate))} conn/s available
              </Text>
            </Card>
          </Space>
        </Col>
      </Row>

      {/* Warning Messages */}
      {percentage >= 90 && (
        <div style={{ 
          marginTop: 16, 
          padding: '8px 12px', 
          backgroundColor: '#fff2e8', 
          border: '1px solid #ffbb96',
          borderRadius: '4px'
        }}>
          <Text type="warning">
            <ThunderboltOutlined /> Connection rate is critical! Consider scaling or throttling.
          </Text>
        </div>
      )}
    </Card>
  );
};

export default ConnectionRateGauge;

