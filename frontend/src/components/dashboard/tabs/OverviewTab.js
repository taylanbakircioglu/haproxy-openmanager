/**
 * Overview Tab - Critical Metrics Dashboard
 * Always visible, auto-refreshes every 60s
 */

import React from 'react';
import { Row, Col, Card, Statistic, Progress, Skeleton } from 'antd';
import {
  GlobalOutlined, CloudServerOutlined, CheckCircleOutlined,
  SafetyCertificateOutlined, SecurityScanOutlined, WarningOutlined
} from '@ant-design/icons';

import RealTimeMetrics from '../RealTimeMetrics';
import AgentStatusCard from '../AgentStatusCard';

const COLORS = {
  primary: '#1890ff',
  success: '#52c41a',
  warning: '#faad14',
  error: '#f5222d',
  purple: '#722ed1',
  orange: '#fa8c16'
};

const CardSkeleton = ({ rows = 1 }) => (
  <Card>
    <Skeleton active paragraph={{ rows }} />
  </Card>
);

const OverviewTab = React.memo(({
  loading,
  initialLoad,
  realTimeMetricsData,
  agentsStatus,
  overviewData,
  statsData
}) => {
  return (
    <div>
      {/* Overview Metrics Cards - PRIORITY: Shows at TOP */}
      <Row gutter={[24, 24]}>
        <Col xs={24} sm={12} md={8} lg={4}>
          {loading && initialLoad ? <CardSkeleton rows={1} /> : (
            <Card
              hoverable
              style={{
                boxShadow: '0 2px 8px rgba(0,0,0,0.06)',
                borderRadius: 8,
                transition: 'all 0.3s ease'
              }}
            >
              <Statistic
                title="Frontends"
                value={overviewData.frontends_count || 0}
                prefix={<GlobalOutlined style={{ color: COLORS.primary }} />}
              />
            </Card>
          )}
        </Col>

        <Col xs={24} sm={12} md={8} lg={4}>
          {loading && initialLoad ? <CardSkeleton rows={1} /> : (
            <Card
              hoverable
              style={{
                boxShadow: '0 2px 8px rgba(0,0,0,0.06)',
                borderRadius: 8,
                transition: 'all 0.3s ease'
              }}
            >
              <Statistic
                title="Backends"
                value={overviewData.backends_count || 0}
                prefix={<CloudServerOutlined style={{ color: COLORS.success }} />}
              />
            </Card>
          )}
        </Col>

        <Col xs={24} sm={12} md={8} lg={4}>
          {loading && initialLoad ? <CardSkeleton rows={1} /> : (
            <Card
              hoverable
              style={{
                boxShadow: '0 2px 8px rgba(0,0,0,0.06)',
                borderRadius: 8,
                transition: 'all 0.3s ease'
              }}
            >
              <Statistic
                title="Active Servers"
                value={`${overviewData.servers_up || 0}/${overviewData.servers_total || 0}`}
                prefix={<CheckCircleOutlined style={{ color: COLORS.success }} />}
              />
              {overviewData.servers_total > 0 && (
                <Progress
                  percent={Math.round((overviewData.servers_up / overviewData.servers_total) * 100)}
                  size="small"
                  showInfo={false}
                  strokeColor={COLORS.success}
                  style={{ marginTop: 8 }}
                />
              )}
            </Card>
          )}
        </Col>

        <Col xs={24} sm={12} md={8} lg={4}>
          {loading && initialLoad ? <CardSkeleton rows={1} /> : (
            <Card
              hoverable
              style={{
                boxShadow: '0 2px 8px rgba(0,0,0,0.06)',
                borderRadius: 8,
                transition: 'all 0.3s ease'
              }}
            >
              <Statistic
                title="SSL Certificates"
                value={overviewData.ssl_certificates || 0}
                prefix={<SafetyCertificateOutlined style={{ color: COLORS.purple }} />}
              />
            </Card>
          )}
        </Col>

        <Col xs={24} sm={12} md={8} lg={4}>
          {loading && initialLoad ? <CardSkeleton rows={1} /> : (
            <Card
              hoverable
              style={{
                boxShadow: '0 2px 8px rgba(0,0,0,0.06)',
                borderRadius: 8,
                transition: 'all 0.3s ease'
              }}
            >
              <Statistic
                title="WAF Rules"
                value={overviewData.waf_rules || 0}
                prefix={<SecurityScanOutlined style={{ color: COLORS.orange }} />}
              />
            </Card>
          )}
        </Col>

        <Col xs={24} sm={12} md={8} lg={4}>
          {loading && initialLoad ? <CardSkeleton rows={1} /> : (
            <Card
              hoverable
              style={{
                boxShadow: '0 2px 8px rgba(0,0,0,0.06)',
                borderRadius: 8,
                transition: 'all 0.3s ease'
              }}
            >
              <Statistic
                title="Error Rate"
                value={statsData.metrics?.error_rate || 0}
                suffix="%"
                precision={2}
                prefix={<WarningOutlined />}
                valueStyle={{
                  color: (statsData.metrics?.error_rate || 0) > 5 ? COLORS.error : COLORS.success
                }}
              />
            </Card>
          )}
        </Col>
      </Row>

      {/* Real-Time Metrics Cards with Animation */}
      {realTimeMetricsData && (
        <div style={{ marginTop: 24 }}>
          <RealTimeMetrics data={realTimeMetricsData} loading={loading} />
        </div>
      )}

      {/* Agent Status Cards - Shows at BOTTOM */}
      {agentsStatus && agentsStatus.length > 0 && (
        <Row gutter={[24, 24]} style={{ marginTop: 24 }}>
          <Col span={24}>
            <Card
              title="Cluster Agents"
              extra={
                <span style={{ fontSize: 12, color: '#8c8c8c' }}>
                  {agentsStatus.filter(a => a.health === 'healthy').length} Healthy / {agentsStatus.length} Total
                </span>
              }
              style={{
                boxShadow: '0 2px 8px rgba(0,0,0,0.06)',
                borderRadius: 8
              }}
            >
              <Row gutter={[16, 16]}>
                {agentsStatus.map(agent => (
                  <Col xs={24} sm={12} md={8} lg={6} xl={4} key={agent.id}>
                    <AgentStatusCard agent={agent} />
                  </Col>
                ))}
              </Row>
            </Card>
          </Col>
        </Row>
      )}
    </div>
  );
});

OverviewTab.displayName = 'OverviewTab';

export default OverviewTab;

