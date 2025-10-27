/**
 * Capacity & Load Tab - Queue, Connection Rate, HTTP Codes
 * Shows current capacity and load metrics
 */

import React from 'react';
import { Row, Col, Card, Statistic, Divider, Typography, Alert } from 'antd';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RechartsTooltip, Legend } from 'recharts';

import QueueMonitor from '../QueueMonitor';
import ConnectionRateGauge from '../ConnectionRateGauge';

const { Text } = Typography;

const COLORS = {
  success: '#52c41a',
  cyan: '#13c2c2',
  warning: '#faad14',
  error: '#f5222d'
};

const CapacityLoadTab = React.memo(({
  loading,
  initialLoad,
  queueData,
  connectionRateData,
  responseCodeData,
  responseTimeData,
  httpResponses
}) => {
  return (
    <div style={{ marginTop: 24 }}>
      {/* Queue Monitor & Connection Rate */}
      <Row gutter={[24, 24]}>
        <Col xs={24} lg={16}>
          <QueueMonitor data={queueData} loading={loading && initialLoad} />
        </Col>
        <Col xs={24} lg={8}>
          <ConnectionRateGauge data={connectionRateData} loading={loading && initialLoad} />
        </Col>
      </Row>

      {/* HTTP Response Codes & Response Time Stats */}
      <Row gutter={[24, 24]} style={{ marginTop: 24 }}>
        {/* HTTP Response Codes Distribution */}
        {responseCodeData && responseCodeData.length > 0 && (
          <Col xs={24} lg={12}>
            <Card
              title="HTTP Response Codes (24h)"
              style={{ boxShadow: '0 2px 8px rgba(0,0,0,0.06)', borderRadius: 8 }}
            >
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={responseCodeData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={(entry) => `${entry.name}: ${entry.value}`}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {responseCodeData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <RechartsTooltip />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
              <Divider style={{ margin: '16px 0' }} />
              <Row gutter={8}>
                <Col span={12}>
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    Success: {httpResponses?.distribution?.['2xx_pct'] || 0}%
                  </Text>
                </Col>
                <Col span={12}>
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    Errors: {((httpResponses?.distribution?.['4xx_pct'] || 0) + (httpResponses?.distribution?.['5xx_pct'] || 0)).toFixed(1)}%
                  </Text>
                </Col>
              </Row>
            </Card>
          </Col>
        )}

        {/* Response Time Distribution */}
        <Col xs={24} lg={12}>
          <Card
            title="Response Time Distribution"
            style={{ boxShadow: '0 2px 8px rgba(0,0,0,0.06)', borderRadius: 8 }}
          >
            {/* Info if all values are zero */}
            {(responseTimeData?.avg || 0) === 0 && (responseTimeData?.p95 || 0) === 0 && (
              <Alert
                message="All Response Times are 0ms"
                description="This is normal if HAProxy is responding extremely fast (< 1ms), or if there is very little traffic being processed."
                type="info"
                showIcon
                style={{ marginBottom: 16 }}
                closable
              />
            )}
            <Row gutter={16}>
              <Col span={12}>
                <Statistic
                  title="Average"
                  value={responseTimeData?.avg || 0}
                  suffix="ms"
                  valueStyle={{ color: (responseTimeData?.avg || 0) > 200 ? COLORS.warning : COLORS.success }}
                />
              </Col>
              <Col span={12}>
                <Statistic
                  title="P95"
                  value={responseTimeData?.p95 || 0}
                  suffix="ms"
                  valueStyle={{ color: (responseTimeData?.p95 || 0) > 500 ? COLORS.error : COLORS.success }}
                />
              </Col>
            </Row>
            <Divider />
            <Row gutter={16}>
              <Col span={12}>
                <Statistic
                  title="P50 (Median)"
                  value={responseTimeData?.p50 || 0}
                  suffix="ms"
                />
              </Col>
              <Col span={12}>
                <Statistic
                  title="P99"
                  value={responseTimeData?.p99 || 0}
                  suffix="ms"
                />
              </Col>
            </Row>
          </Card>
        </Col>
      </Row>
    </div>
  );
});

CapacityLoadTab.displayName = 'CapacityLoadTab';

export default CapacityLoadTab;

