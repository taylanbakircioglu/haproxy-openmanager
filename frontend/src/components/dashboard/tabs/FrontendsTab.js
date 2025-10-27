/**
 * Frontends Tab - Frontend Performance Details
 * Interactive frontend list with selection
 */

import React, { useMemo } from 'react';
import { Row, Col, Card, Empty, Select, Space, Spin, Typography } from 'antd';
import { FilterOutlined } from '@ant-design/icons';

import CompactFrontendList from '../CompactFrontendList';

const { Text } = Typography;

const FrontendsTab = React.memo(({
  loading,
  initialLoad,
  frontendsData,
  selectedFrontends,
  setSelectedFrontends,
  // Filter props
  frontendOptions,
  onFrontendChange,
  cacheLoading
}) => {
  // Memoize filter options
  const filterOptions = useMemo(() => [
    { label: '📊 All Frontends', value: 'all' },
    ...frontendOptions.map(f => ({ label: f, value: f }))
  ], [frontendOptions]);

  return (
    <div style={{ marginTop: 24 }}>
      {/* Quick Filter Section */}
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
          <Text strong>Quick Filter:</Text>
          <Select
            mode="multiple"
            style={{ minWidth: 300 }}
            placeholder="Select specific frontends to view"
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
          <Text type="secondary" style={{ fontSize: 12 }}>
            (You can also click rows below to toggle selection)
          </Text>
        </Space>
      </Card>
      {/* Frontend Performance - Compact List */}
      {frontendsData && frontendsData.length > 0 ? (
        <Row gutter={[24, 24]}>
          <Col span={24}>
            <CompactFrontendList
              data={frontendsData}
              loading={loading && initialLoad}
              onSelect={(frontendName) => {
                // Toggle selection
                if (selectedFrontends.includes(frontendName)) {
                  setSelectedFrontends(selectedFrontends.filter(f => f !== frontendName));
                } else if (selectedFrontends.includes('all')) {
                  setSelectedFrontends([frontendName]);
                } else if (selectedFrontends.length < 10) {
                  setSelectedFrontends([...selectedFrontends, frontendName]);
                }
              }}
              selectedItems={selectedFrontends}
            />
          </Col>
        </Row>
      ) : (
        !loading && (
          <Row gutter={[24, 24]}>
            <Col span={24}>
              <Card
                title="Frontend Performance"
                style={{ boxShadow: '0 2px 8px rgba(0,0,0,0.06)', borderRadius: 8 }}
              >
                <Empty
                  image={Empty.PRESENTED_IMAGE_SIMPLE}
                  description="No frontend data available. Waiting for agent statistics..."
                />
              </Card>
            </Col>
          </Row>
        )
      )}
    </div>
  );
});

FrontendsTab.displayName = 'FrontendsTab';

export default FrontendsTab;

