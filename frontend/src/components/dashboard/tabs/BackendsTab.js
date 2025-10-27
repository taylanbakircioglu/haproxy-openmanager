/**
 * Backends & Servers Tab - Backend and Server Details
 * Comprehensive backend/server information with virtualized server list
 */

import React, { useMemo } from 'react';
import { Row, Col, Card, Statistic, Divider, Empty, Select, Space, Spin, Typography } from 'antd';
import { GlobalOutlined, CloudServerOutlined, FilterOutlined } from '@ant-design/icons';

import CompactServerList from '../CompactServerList';

const { Text } = Typography;

const BackendsTab = React.memo(({
  loading,
  initialLoad,
  serversData,
  statsData,
  // Filter props
  backendOptions,
  selectedBackends,
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
            placeholder="Select specific backends to view servers"
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
      {/* Aggregated Metrics Summary */}
      {statsData && statsData.frontends && (
        <Row gutter={[24, 24]}>
          <Col xs={24} lg={12}>
            <Card
              title="Aggregated Metrics"
              style={{ boxShadow: '0 2px 8px rgba(0,0,0,0.06)', borderRadius: 8 }}
            >
              <Row gutter={16}>
                <Col span={12}>
                  <Statistic
                    title="Total Requests"
                    value={statsData.frontends?.aggregated?.total_requests || 0}
                    prefix={<GlobalOutlined />}
                  />
                </Col>
                <Col span={12}>
                  <Statistic
                    title="Total Sessions"
                    value={statsData.frontends?.aggregated?.total_sessions || 0}
                    prefix={<CloudServerOutlined />}
                  />
                </Col>
              </Row>
              <Divider />
              <Row gutter={16}>
                <Col span={12}>
                  <Statistic
                    title="Bytes In"
                    value={(statsData.frontends?.aggregated?.total_bytes_in || 0) / 1024 / 1024}
                    suffix="MB"
                    precision={2}
                  />
                </Col>
                <Col span={12}>
                  <Statistic
                    title="Bytes Out"
                    value={(statsData.frontends?.aggregated?.total_bytes_out || 0) / 1024 / 1024}
                    suffix="MB"
                    precision={2}
                  />
                </Col>
              </Row>
            </Card>
          </Col>
        </Row>
      )}

      {/* Server Details - Compact List with Virtualization */}
      {serversData && serversData.length > 0 ? (
        <Row gutter={[24, 24]} style={{ marginTop: 24 }}>
          <Col span={24}>
            <CompactServerList
              data={serversData}
              loading={loading && initialLoad}
            />
          </Col>
        </Row>
      ) : (
        !loading && (
          <Row gutter={[24, 24]} style={{ marginTop: 24 }}>
            <Col span={24}>
              <Card
                title="Server Details"
                style={{ boxShadow: '0 2px 8px rgba(0,0,0,0.06)', borderRadius: 8 }}
              >
                <Empty
                  image={Empty.PRESENTED_IMAGE_SIMPLE}
                  description="No server data available. Waiting for agent statistics..."
                />
              </Card>
            </Col>
          </Row>
        )
      )}
    </div>
  );
});

BackendsTab.displayName = 'BackendsTab';

export default BackendsTab;

