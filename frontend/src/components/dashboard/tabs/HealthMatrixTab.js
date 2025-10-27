/**
 * Health Matrix Tab - Backend & Server Health Status
 * Shows health check details and backend health matrix
 */

import React, { useMemo } from 'react';
import { Row, Col, Card, Empty, Select, Space, Spin, Typography } from 'antd';
import { BarChart, Bar, CartesianGrid, XAxis, YAxis, ResponsiveContainer, Tooltip as RechartsTooltip } from 'recharts';
import { FilterOutlined } from '@ant-design/icons';

import HealthCheckStatus from '../HealthCheckStatus';
import CompactBackendList from '../CompactBackendList';

const { Text } = Typography;

const COLORS = {
  warning: '#faad14'
};

const HealthMatrixTab = React.memo(({
  loading,
  initialLoad,
  healthCheckData,
  backendHealth,
  slowestBackends,
  selectedBackends,
  setSelectedBackends,
  // Filter props
  backendOptions,
  onBackendChange,
  cacheLoading
}) => {
  // Memoize filter options
  const filterOptions = useMemo(() => [
    { label: '📊 All Backends', value: 'all' },
    ...backendOptions.map(b => ({ label: b, value: b }))
  ], [backendOptions]);

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
          <Text strong>Filter by Backend:</Text>
          <Select
            mode="multiple"
            style={{ minWidth: 300 }}
            placeholder="Select Backends (affects health & response time)"
            value={selectedBackends}
            onChange={onBackendChange}
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
            notFoundContent={cacheLoading ? <Spin size="small" /> : <Empty description="No backends" image={Empty.PRESENTED_IMAGE_SIMPLE} />}
          />
          {selectedBackends && selectedBackends.length >= 10 && !selectedBackends.includes('all') && (
            <Text type="warning" style={{ fontSize: 11 }}>
              Max 10 selections
            </Text>
          )}
        </Space>
      </Card>
      {/* Health Check Status */}
      {healthCheckData && healthCheckData.length > 0 ? (
        <Row gutter={[24, 24]}>
          <Col span={24}>
            <HealthCheckStatus data={healthCheckData} loading={loading && initialLoad} />
          </Col>
        </Row>
      ) : (
        !loading && (
          <Row gutter={[24, 24]}>
            <Col span={24}>
              <Card
                title="Health Check Status"
                style={{ boxShadow: '0 2px 8px rgba(0,0,0,0.06)', borderRadius: 8 }}
              >
                <Empty
                  image={Empty.PRESENTED_IMAGE_SIMPLE}
                  description="No health check data available yet"
                />
              </Card>
            </Col>
          </Row>
        )
      )}

      {/* Backend Health Matrix */}
      {backendHealth && backendHealth.length > 0 ? (
        <Row gutter={[24, 24]} style={{ marginTop: 24 }}>
          <Col span={24}>
            <CompactBackendList
              data={backendHealth}
              loading={loading && initialLoad}
              onSelect={(backendName) => {
                // Toggle selection
                if (selectedBackends.includes(backendName)) {
                  setSelectedBackends(selectedBackends.filter(b => b !== backendName));
                } else if (selectedBackends.includes('all')) {
                  setSelectedBackends([backendName]);
                } else if (selectedBackends.length < 10) {
                  setSelectedBackends([...selectedBackends, backendName]);
                }
              }}
              selectedItems={selectedBackends}
            />
          </Col>
        </Row>
      ) : null}

      {/* Slowest Backends */}
      {slowestBackends && slowestBackends.length > 0 && (
        <Row gutter={[24, 24]} style={{ marginTop: 24 }}>
          <Col xs={24} lg={16}>
            <Card
              title="Top 5 Slowest Backends"
              style={{ boxShadow: '0 2px 8px rgba(0,0,0,0.06)', borderRadius: 8 }}
            >
              <ResponsiveContainer width="100%" height={250}>
                <BarChart data={slowestBackends} layout="vertical" margin={{ left: 10 }}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis type="number" />
                  <YAxis
                    dataKey="name"
                    type="category"
                    width={200}
                    style={{ fontSize: 11 }}
                    tick={{ fill: '#595959' }}
                  />
                  <RechartsTooltip />
                  <Bar dataKey="response_time" fill={COLORS.warning} />
                </BarChart>
              </ResponsiveContainer>
            </Card>
          </Col>
        </Row>
      )}
    </div>
  );
});

HealthMatrixTab.displayName = 'HealthMatrixTab';

export default HealthMatrixTab;

