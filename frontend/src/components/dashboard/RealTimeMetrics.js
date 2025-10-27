import React, { useState, useEffect } from 'react';
import { Card, Statistic, Row, Col, Badge, Space, Typography, Tooltip } from 'antd';
import {
  DashboardOutlined,
  ThunderboltOutlined,
  ClockCircleOutlined,
  WarningOutlined,
  ArrowUpOutlined,
  ArrowDownOutlined,
  SyncOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined
} from '@ant-design/icons';

const { Text } = Typography;

// CSS animations for card updates
const animationStyles = `
  @keyframes pulse {
    0% { transform: scale(1); }
    50% { transform: scale(1.02); }
    100% { transform: scale(1); }
  }
  
  @keyframes highlight {
    0% { background-color: #ffffff; }
    50% { background-color: #e6f7ff; }
    100% { background-color: #ffffff; }
  }
  
  .animated-card {
    height: 100%;
    transition: all 0.3s ease;
  }
  
  .animated-card.pulse {
    animation: pulse 0.5s ease, highlight 0.5s ease;
  }
`;

// Inject styles
if (typeof document !== 'undefined' && !document.getElementById('realtime-metrics-styles')) {
  const styleSheet = document.createElement('style');
  styleSheet.id = 'realtime-metrics-styles';
  styleSheet.textContent = animationStyles;
  document.head.appendChild(styleSheet);
}

const RealTimeMetrics = ({ data, loading }) => {
  const [previousData, setPreviousData] = useState(null);
  const [changes, setChanges] = useState({});

  useEffect(() => {
    if (data && previousData) {
      const newChanges = {};
      
      // Detect changes
      if (data.requests_total !== previousData.requests_total) {
        newChanges.requests = data.requests_total > previousData.requests_total ? 'up' : 'down';
      }
      if (data.avg_response_time !== previousData.avg_response_time) {
        newChanges.response_time = data.avg_response_time > previousData.avg_response_time ? 'up' : 'down';
      }
      if (data.error_rate !== previousData.error_rate) {
        newChanges.error_rate = data.error_rate > previousData.error_rate ? 'up' : 'down';
      }
      if (data.active_sessions !== previousData.active_sessions) {
        newChanges.sessions = data.active_sessions > previousData.active_sessions ? 'up' : 'down';
      }
      
      setChanges(newChanges);
      
      // Clear change indicators after 2 seconds
      setTimeout(() => setChanges({}), 2000);
    }
    
    setPreviousData(data);
  }, [data]);

  if (!data) {
    return null;
  }

  const getValueColor = (value, thresholds) => {
    if (!thresholds) return '#1890ff';
    if (value >= thresholds.critical) return '#ff4d4f';
    if (value >= thresholds.warning) return '#faad14';
    return '#52c41a';
  };

  const AnimatedCard = ({ children, change }) => {
    const [animating, setAnimating] = useState(false);
    
    useEffect(() => {
      if (change) {
        setAnimating(true);
        const timer = setTimeout(() => setAnimating(false), 500);
        return () => clearTimeout(timer);
      }
    }, [change]);
    
    return (
      <div className={`animated-card ${animating ? 'pulse' : ''}`}>
        {children}
      </div>
    );
  };

  return (
    <div style={{ marginBottom: 16 }}>
      <Row gutter={[16, 16]}>
        {/* Total Requests */}
        <Col xs={24} sm={12} md={6}>
          <AnimatedCard change={changes.requests}>
            <Card>
              <Statistic
                title={
                  <Space>
                    <DashboardOutlined />
                    <span>Total Requests</span>
                    {loading && <SyncOutlined spin style={{ fontSize: 12 }} />}
                  </Space>
                }
                value={data.requests_total || 0}
                valueStyle={{ fontSize: 24 }}
                prefix={
                  changes.requests === 'up' ? (
                    <ArrowUpOutlined style={{ color: '#52c41a' }} />
                  ) : changes.requests === 'down' ? (
                    <ArrowDownOutlined style={{ color: '#ff4d4f' }} />
                  ) : null
                }
              />
              {data.requests_rate && (
                <Text type="secondary" style={{ fontSize: 12 }}>
                  {data.requests_rate} req/s
                </Text>
              )}
            </Card>
          </AnimatedCard>
        </Col>

        {/* Active Sessions */}
        <Col xs={24} sm={12} md={6}>
          <AnimatedCard change={changes.sessions}>
            <Card>
              <Statistic
                title={
                  <Space>
                    <ThunderboltOutlined />
                    <span>Active Sessions</span>
                  </Space>
                }
                value={data.active_sessions || 0}
                valueStyle={{ 
                  fontSize: 24,
                  color: getValueColor(
                    data.active_sessions || 0,
                    { warning: 1000, critical: 5000 }
                  )
                }}
                prefix={
                  changes.sessions === 'up' ? (
                    <ArrowUpOutlined />
                  ) : changes.sessions === 'down' ? (
                    <ArrowDownOutlined />
                  ) : null
                }
              />
              {data.max_sessions && (
                <Text type="secondary" style={{ fontSize: 12 }}>
                  Max: {data.max_sessions}
                </Text>
              )}
            </Card>
          </AnimatedCard>
        </Col>

        {/* Average Response Time */}
        <Col xs={24} sm={12} md={6}>
          <AnimatedCard change={changes.response_time}>
            <Card>
              <Statistic
                title={
                  <Space>
                    <ClockCircleOutlined />
                    <span>Avg Response</span>
                  </Space>
                }
                value={data.avg_response_time || 0}
                suffix="ms"
                valueStyle={{ 
                  fontSize: 24,
                  color: getValueColor(
                    data.avg_response_time || 0,
                    { warning: 200, critical: 500 }
                  )
                }}
                prefix={
                  changes.response_time === 'up' ? (
                    <ArrowUpOutlined style={{ color: '#ff4d4f' }} />
                  ) : changes.response_time === 'down' ? (
                    <ArrowDownOutlined style={{ color: '#52c41a' }} />
                  ) : null
                }
              />
              {data.p95_response_time && (
                <Tooltip title="95th percentile">
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    P95: {data.p95_response_time}ms
                  </Text>
                </Tooltip>
              )}
            </Card>
          </AnimatedCard>
        </Col>

        {/* Error Rate */}
        <Col xs={24} sm={12} md={6}>
          <AnimatedCard change={changes.error_rate}>
            <Card>
              <Statistic
                title={
                  <Space>
                    <WarningOutlined />
                    <span>Error Rate</span>
                  </Space>
                }
                value={data.error_rate || 0}
                precision={2}
                suffix="%"
                valueStyle={{ 
                  fontSize: 24,
                  color: getValueColor(
                    data.error_rate || 0,
                    { warning: 1, critical: 5 }
                  )
                }}
                prefix={
                  (data.error_rate || 0) < 1 ? (
                    <CheckCircleOutlined style={{ color: '#52c41a' }} />
                  ) : (data.error_rate || 0) < 5 ? (
                    <WarningOutlined style={{ color: '#faad14' }} />
                  ) : (
                    <CloseCircleOutlined style={{ color: '#ff4d4f' }} />
                  )
                }
              />
              {data.total_errors !== undefined && (
                <Text type="secondary" style={{ fontSize: 12 }}>
                  {data.total_errors} errors
                </Text>
              )}
            </Card>
          </AnimatedCard>
        </Col>
      </Row>

      {/* Secondary Metrics */}
      <Row gutter={[16, 16]} style={{ marginTop: 16 }}>
        {/* Throughput In */}
        {data.throughput_in !== undefined && (
          <Col xs={12} sm={8} md={4}>
            <Card size="small">
              <Statistic
                title="Throughput In"
                value={(data.throughput_in / 1024 / 1024).toFixed(2)}
                suffix="MB/s"
                valueStyle={{ fontSize: 16 }}
              />
            </Card>
          </Col>
        )}

        {/* Throughput Out */}
        {data.throughput_out !== undefined && (
          <Col xs={12} sm={8} md={4}>
            <Card size="small">
              <Statistic
                title="Throughput Out"
                value={(data.throughput_out / 1024 / 1024).toFixed(2)}
                suffix="MB/s"
                valueStyle={{ fontSize: 16 }}
              />
            </Card>
          </Col>
        )}

        {/* Queue Depth */}
        {data.queue_depth !== undefined && (
          <Col xs={12} sm={8} md={4}>
            <Card size="small">
              <Statistic
                title="Queue Depth"
                value={data.queue_depth}
                valueStyle={{ 
                  fontSize: 16,
                  color: data.queue_depth > 50 ? '#faad14' : '#52c41a'
                }}
              />
            </Card>
          </Col>
        )}

        {/* Active Backends */}
        {data.backends_active !== undefined && data.backends_total !== undefined && (
          <Col xs={12} sm={8} md={4}>
            <Card size="small">
              <Statistic
                title="Backends"
                value={`${data.backends_active}/${data.backends_total}`}
                valueStyle={{ fontSize: 16 }}
                prefix={
                  data.backends_active === data.backends_total ? (
                    <CheckCircleOutlined style={{ color: '#52c41a' }} />
                  ) : (
                    <WarningOutlined style={{ color: '#faad14' }} />
                  )
                }
              />
            </Card>
          </Col>
        )}

        {/* Active Servers */}
        {data.servers_up !== undefined && data.servers_total !== undefined && (
          <Col xs={12} sm={8} md={4}>
            <Card size="small">
              <Statistic
                title="Servers UP"
                value={`${data.servers_up}/${data.servers_total}`}
                valueStyle={{ fontSize: 16 }}
                prefix={
                  data.servers_up === data.servers_total ? (
                    <CheckCircleOutlined style={{ color: '#52c41a' }} />
                  ) : (
                    <WarningOutlined style={{ color: '#faad14' }} />
                  )
                }
              />
            </Card>
          </Col>
        )}

        {/* Connection Rate */}
        {data.connection_rate !== undefined && (
          <Col xs={12} sm={8} md={4}>
            <Card size="small">
              <Statistic
                title="Conn Rate"
                value={data.connection_rate}
                suffix="c/s"
                valueStyle={{ fontSize: 16 }}
              />
            </Card>
          </Col>
        )}
      </Row>
    </div>
  );
};

export default RealTimeMetrics;

