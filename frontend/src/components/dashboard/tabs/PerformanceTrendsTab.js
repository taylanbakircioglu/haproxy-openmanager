/**
 * Performance Trends Tab - Time Series Charts
 * Auto-refreshes when active
 */

import React, { useMemo } from 'react';
import { Row, Col, Card, Empty, Select, Space, Spin, Typography } from 'antd';
import { LineChartOutlined, FilterOutlined } from '@ant-design/icons';

import RequestRateTrend from '../RequestRateTrend';
import ResponseTimeTrend from '../ResponseTimeTrend';
import ErrorRateTrend from '../ErrorRateTrend';
import SessionsTrend from '../SessionsTrend';
import ThroughputChart from '../ThroughputChart';
import ResponseTimeHeatmap from '../ResponseTimeHeatmap';

const { Text } = Typography;

const PerformanceTrendsTab = React.memo(({
  loading,
  initialLoad,
  requestsTimeseries,
  responseTimeTimeseries,
  errorsTimeseries,
  sessionsTimeseries,
  throughputData,
  responseTimeHeatmapData,
  // Filter props
  frontendOptions,
  selectedFrontends,
  onFrontendChange,
  cacheLoading
}) => {
  // Memoize filter options to prevent re-computation
  const filterOptions = useMemo(() => [
    { label: '📊 All Frontends', value: 'all' },
    ...frontendOptions.map(f => ({ label: f, value: f }))
  ], [frontendOptions]);

  return (
    <div style={{ marginTop: 24 }}>
      {/* Filter Section */}
      <Card
        size="small"
        style={{
          marginBottom: 24,
          backgroundColor: '#fafafa',
          borderRadius: 8
        }}
      >
        <Space wrap>
          <FilterOutlined style={{ color: '#1890ff' }} />
          <Text strong>Filter by Frontend:</Text>
          <Select
            mode="multiple"
            style={{ minWidth: 300 }}
            placeholder="Select Frontends (affects Request & Session charts)"
            value={selectedFrontends}
            onChange={onFrontendChange}
            loading={cacheLoading}
            options={filterOptions}
            maxTagCount={3}
            showSearch
            virtual
            listHeight={256}
            optionFilterProp="label"
            autoClearSearchValue={false}
            dropdownMatchSelectWidth={400}
            filterOption={(input, option) =>
              (option?.label ?? '').toLowerCase().includes(input.toLowerCase())
            }
            notFoundContent={cacheLoading ? <Spin size="small" /> : <Empty description="No frontends" image={Empty.PRESENTED_IMAGE_SIMPLE} />}
          />
          {selectedFrontends && selectedFrontends.length >= 10 && !selectedFrontends.includes('all') && (
            <Text type="warning" style={{ fontSize: 11 }}>
              Max 10 selections
            </Text>
          )}
        </Space>
      </Card>
      {/* Time Series Charts Row 1 */}
      <Row gutter={[24, 24]}>
        <Col xs={24} lg={12}>
          <RequestRateTrend data={requestsTimeseries} loading={loading && initialLoad} />
        </Col>
        <Col xs={24} lg={12}>
          <ResponseTimeTrend data={responseTimeTimeseries} loading={loading && initialLoad} />
        </Col>
      </Row>

      {/* Time Series Charts Row 2 */}
      <Row gutter={[24, 24]} style={{ marginTop: 24 }}>
        <Col xs={24} lg={12}>
          <ErrorRateTrend data={errorsTimeseries} loading={loading && initialLoad} />
        </Col>
        <Col xs={24} lg={12}>
          <SessionsTrend data={sessionsTimeseries} loading={loading && initialLoad} />
        </Col>
      </Row>

      {/* Throughput Chart */}
      <Row gutter={[24, 24]} style={{ marginTop: 24 }}>
        <Col span={24}>
          <ThroughputChart
            data={[]}
            realtimeData={throughputData}
            loading={loading && initialLoad}
          />
        </Col>
      </Row>

      {/* Response Time Heatmap (24h) */}
      {responseTimeHeatmapData && responseTimeHeatmapData.length > 0 ? (
        <Row gutter={[24, 24]} style={{ marginTop: 24 }}>
          <Col span={24}>
            <ResponseTimeHeatmap data={responseTimeHeatmapData} loading={loading && initialLoad} />
          </Col>
        </Row>
      ) : (
        !loading && (
          <Row gutter={[24, 24]} style={{ marginTop: 24 }}>
            <Col span={24}>
              <Card
                title="Response Time Heatmap (24h)"
                style={{ boxShadow: '0 2px 8px rgba(0,0,0,0.06)', borderRadius: 8 }}
              >
                <Empty
                  image={Empty.PRESENTED_IMAGE_SIMPLE}
                  description="No heatmap data available yet. Data will appear as agents send statistics."
                />
              </Card>
            </Col>
          </Row>
        )
      )}
    </div>
  );
});

PerformanceTrendsTab.displayName = 'PerformanceTrendsTab';

export default PerformanceTrendsTab;

