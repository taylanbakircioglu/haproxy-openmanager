import React, { useMemo, memo } from 'react';
import { Card, Empty, Spin, Typography, Tooltip, Tag, Space, Alert } from 'antd';
import { ClockCircleOutlined, InfoCircleOutlined } from '@ant-design/icons';

const { Text } = Typography;

const ResponseTimeHeatmap = memo(({ data, loading, title = "Response Time Heatmap (24h)" }) => {
  // Memoize heavy computation - only recalculate when data changes
  // MUST be before any early returns (React Hooks rule)
  const { backends, matrix, hourBuckets, maxValue, minValue, avgValue, totalBackends } = useMemo(() => {
    // Return empty state if no data
    if (!data || data.length === 0) {
      return {
        backends: [],
        matrix: [],
        hourBuckets: [],
        maxValue: 0,
        minValue: 0,
        avgValue: 0,
        totalBackends: 0
      };
    }
    const hours = 24;
    
    // Calculate the time window: last 24 hours
    const now = new Date();
    const startTime = new Date(now.getTime() - 24 * 60 * 60 * 1000); // 24 hours ago
    
    // Only log once when data changes
    if (process.env.NODE_ENV === 'development') {
      console.log('🔥 Heatmap Processing:', {
        total_data_points: data?.length || 0,
        time_range: `${startTime.toISOString()} to ${now.toISOString()}`
      });
    }
    
    // Create hour buckets for the last 24 hours
    const hourBuckets = [];
    for (let i = 0; i < hours; i++) {
      const bucketTime = new Date(startTime.getTime() + i * 60 * 60 * 1000);
      hourBuckets.push({
        hour: i,
        startTime: bucketTime,
        endTime: new Date(bucketTime.getTime() + 60 * 60 * 1000),
        label: bucketTime.getHours() + 'h'
      });
    }
    
    // Calculate average response time per backend to find slowest ones
    const backendAvgs = {};
    data.forEach(point => {
      if (!backendAvgs[point.backend]) {
        backendAvgs[point.backend] = { sum: 0, count: 0 };
      }
      backendAvgs[point.backend].sum += point.value || 0;
      backendAvgs[point.backend].count += 1;
    });
    
    // Sort by average response time (slowest first) and take top 10
    const backends = Object.entries(backendAvgs)
      .map(([name, stats]) => ({ 
        name, 
        avg: stats.sum / stats.count 
      }))
      .sort((a, b) => b.avg - a.avg) // Sort descending (slowest first)
      .slice(0, 10)
      .map(b => b.name);
    
    // Create a grid matrix
    const matrix = Array(backends.length).fill(null).map(() => Array(hours).fill(null));
    
    // Fill the matrix with data based on time buckets
    let matched = 0;
    data.forEach(point => {
      const backendIndex = backends.indexOf(point.backend);
      if (backendIndex === -1) return;
      
      const timestamp = new Date(point.timestamp);
      
      // Find which hour bucket this timestamp belongs to
      for (let hourIndex = 0; hourIndex < hourBuckets.length; hourIndex++) {
        const bucket = hourBuckets[hourIndex];
        if (timestamp >= bucket.startTime && timestamp < bucket.endTime) {
          // Use max value for this bucket (or could use average)
          if (!matrix[backendIndex][hourIndex] || matrix[backendIndex][hourIndex] < point.value) {
            matrix[backendIndex][hourIndex] = point.value;
          }
          matched++;
          break;
        }
      }
    });
    
    // Calculate statistics
    const allValues = matrix.flat().filter(v => v !== null);
    const avgValue = allValues.length > 0 ?
      Math.round(allValues.reduce((sum, v) => sum + v, 0) / allValues.length) : 0;
    const maxValue = allValues.length > 0 ? Math.max(...allValues) : 0;
    const minValue = allValues.length > 0 ? Math.min(...allValues) : 0;
    
    if (process.env.NODE_ENV === 'development') {
      console.log('🔥 Matrix Fill:', {
        matched_points: matched,
        filled_cells: allValues.length,
        total_cells: matrix.length * hours
      });
    }
    
    return {
      backends,
      matrix,
      hourBuckets,
      maxValue,
      minValue,
      avgValue,
      totalBackends: Object.keys(backendAvgs).length
    };
  }, [data]); // Only recalculate when data changes!

  // Early returns AFTER hooks
  if (loading) {
    return (
      <Card title={title}>
        <div style={{ textAlign: 'center', padding: 50 }}>
          <Spin size="large" tip="Loading heatmap data..." />
        </div>
      </Card>
    );
  }

  if (!data || data.length === 0 || backends.length === 0) {
    return (
      <Card title={title}>
        <Empty 
          description={
            <div>
              <Text type="secondary">No response time data available</Text>
              <br />
              <Text type="secondary" style={{ fontSize: 12 }}>
                This usually means no traffic has been processed yet
              </Text>
            </div>
          } 
          image={Empty.PRESENTED_IMAGE_SIMPLE} 
        />
      </Card>
    );
  }

  // Helper functions for colors and labels
  const getColor = (value) => {
    if (value === null) return '#f5f5f5';
    if (value < 50) return '#d9f7be'; // Excellent
    if (value < 100) return '#95de64'; // Good
    if (value < 200) return '#ffe58f'; // Fair
    if (value < 300) return '#ffc069'; // Moderate
    if (value < 500) return '#ff9c6e'; // Slow
    return '#ff4d4f'; // Critical
  };

  const getLabel = (value) => {
    if (value === null) return 'No data';
    if (value < 50) return 'Excellent';
    if (value < 100) return 'Good';
    if (value < 200) return 'Fair';
    if (value < 300) return 'Moderate';
    if (value < 500) return 'Slow';
    return 'Critical';
  };

  return (
    <Card 
      title={
        <Space>
          <ClockCircleOutlined />
          <span>{title}</span>
          {totalBackends > 10 && (
            <Tag color="purple">Showing top 10 slowest of {totalBackends} backends</Tag>
          )}
          <Tag color="blue">Avg: {avgValue}ms</Tag>
          <Tag color="orange">Max: {maxValue}ms</Tag>
        </Space>
      }
    >
      {/* Info alert if all values are zero */}
      {maxValue === 0 && (
        <Alert
          message="All Response Times are 0ms"
          description="This is normal if there is very little traffic, or if HAProxy is responding extremely fast (< 1ms). The response times may be too small to measure accurately."
          type="info"
          icon={<InfoCircleOutlined />}
          showIcon
          style={{ marginBottom: 16 }}
          closable
        />
      )}
      
      {/* Legend */}
      <div style={{ 
        display: 'flex', 
        justifyContent: 'center', 
        marginBottom: 16,
        gap: '8px',
        flexWrap: 'wrap'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
          <div style={{ width: 20, height: 20, backgroundColor: '#d9f7be', border: '1px solid #ccc' }} />
          <Text style={{ fontSize: 11 }}>{'<50ms'}</Text>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
          <div style={{ width: 20, height: 20, backgroundColor: '#95de64', border: '1px solid #ccc' }} />
          <Text style={{ fontSize: 11 }}>{'<100ms'}</Text>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
          <div style={{ width: 20, height: 20, backgroundColor: '#ffe58f', border: '1px solid #ccc' }} />
          <Text style={{ fontSize: 11 }}>{'<200ms'}</Text>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
          <div style={{ width: 20, height: 20, backgroundColor: '#ffc069', border: '1px solid #ccc' }} />
          <Text style={{ fontSize: 11 }}>{'<300ms'}</Text>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
          <div style={{ width: 20, height: 20, backgroundColor: '#ff9c6e', border: '1px solid #ccc' }} />
          <Text style={{ fontSize: 11 }}>{'<500ms'}</Text>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
          <div style={{ width: 20, height: 20, backgroundColor: '#ff4d4f', border: '1px solid #ccc' }} />
          <Text style={{ fontSize: 11 }}>{'>500ms'}</Text>
        </div>
      </div>

      {/* Scroll hint */}
      {hourBuckets.length > 0 && (
        <div style={{ 
          textAlign: 'center', 
          marginBottom: '8px',
          color: '#8c8c8c',
          fontSize: '12px'
        }}>
          ← Scroll horizontally to view all 24 hours →
        </div>
      )}

      {/* Heatmap Grid with scroll for many backends */}
      <div style={{ 
        overflowX: 'auto', 
        overflowY: 'auto', 
        maxHeight: '600px',
        border: '1px solid #d9d9d9',
        borderRadius: '4px',
        marginBottom: '8px'
      }}>
        <table style={{ 
          borderCollapse: 'collapse', 
          width: 'max-content', // Force table to take minimum width needed for all columns
          minWidth: '100%',
          fontSize: 11
        }}>
          <thead>
            <tr>
              <th style={{ 
                padding: '8px', 
                backgroundColor: '#fafafa',
                border: '1px solid #d9d9d9',
                fontWeight: 'bold',
                position: 'sticky',
                left: 0,
                zIndex: 1,
                minWidth: '120px'
              }}>
                Backend
              </th>
              {hourBuckets.map((bucket, i) => (
                <th key={i} style={{ 
                  padding: '8px', 
                  backgroundColor: '#fafafa',
                  border: '1px solid #d9d9d9',
                  minWidth: '40px',
                  textAlign: 'center'
                }}>
                  {bucket.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {backends.map((backend, backendIndex) => (
              <tr key={backend}>
                <td style={{ 
                  padding: '8px', 
                  backgroundColor: '#fafafa',
                  border: '1px solid #d9d9d9',
                  fontWeight: 'bold',
                  position: 'sticky',
                  left: 0,
                  zIndex: 1
                }}>
                  <Text 
                    strong 
                    style={{ fontSize: 11 }} 
                    ellipsis={{ tooltip: backend }}
                  >
                    {backend.length > 15 ? backend.substring(0, 15) + '...' : backend}
                  </Text>
                </td>
                {matrix[backendIndex].map((value, hourIndex) => (
                  <Tooltip
                    key={hourIndex}
                    title={
                      value !== null ? (
                        <div>
                          <div><strong>{backend}</strong></div>
                          <div>Time: {hourBuckets[hourIndex].startTime.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</div>
                          <div>Response: {value}ms</div>
                          <div>Status: {getLabel(value)}</div>
                        </div>
                      ) : (
                        <div>
                          <div><strong>{backend}</strong></div>
                          <div>Time: {hourBuckets[hourIndex].startTime.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</div>
                          <div>No data</div>
                        </div>
                      )
                    }
                  >
                    <td style={{ 
                      padding: '8px', 
                      backgroundColor: getColor(value),
                      border: '1px solid #d9d9d9',
                      cursor: 'pointer',
                      textAlign: 'center',
                      transition: 'all 0.2s'
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.transform = 'scale(1.1)';
                      e.currentTarget.style.zIndex = '10';
                      e.currentTarget.style.boxShadow = '0 2px 8px rgba(0,0,0,0.2)';
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.transform = 'scale(1)';
                      e.currentTarget.style.zIndex = '1';
                      e.currentTarget.style.boxShadow = 'none';
                    }}
                    >
                      {value !== null && (
                        <span style={{ 
                          fontSize: 10, 
                          fontWeight: value > 300 ? 'bold' : 'normal',
                          color: value > 300 ? '#fff' : '#000'
                        }}>
                          {value}
                        </span>
                      )}
                    </td>
                  </Tooltip>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Summary Stats */}
      <div style={{ 
        marginTop: 16, 
        padding: '12px', 
        backgroundColor: '#f5f5f5', 
        borderRadius: '4px',
        display: 'flex',
        justifyContent: 'space-around',
        flexWrap: 'wrap',
        gap: '16px'
      }}>
        <div style={{ textAlign: 'center' }}>
          <Text type="secondary" style={{ fontSize: 11 }}>Min Response</Text>
          <div style={{ fontSize: 16, fontWeight: 'bold', color: '#52c41a' }}>
            {minValue}ms
          </div>
        </div>
        <div style={{ textAlign: 'center' }}>
          <Text type="secondary" style={{ fontSize: 11 }}>Avg Response</Text>
          <div style={{ fontSize: 16, fontWeight: 'bold', color: '#1890ff' }}>
            {avgValue}ms
          </div>
        </div>
        <div style={{ textAlign: 'center' }}>
          <Text type="secondary" style={{ fontSize: 11 }}>Max Response</Text>
          <div style={{ fontSize: 16, fontWeight: 'bold', color: '#ff4d4f' }}>
            {maxValue}ms
          </div>
        </div>
        <div style={{ textAlign: 'center' }}>
          <Text type="secondary" style={{ fontSize: 11 }}>Backends</Text>
          <div style={{ fontSize: 16, fontWeight: 'bold' }}>
            {backends.length}
          </div>
        </div>
        <div style={{ textAlign: 'center' }}>
          <Text type="secondary" style={{ fontSize: 11 }}>Data Points</Text>
          <div style={{ fontSize: 16, fontWeight: 'bold' }}>
            {matrix.flat().filter(v => v !== null).length}
          </div>
        </div>
      </div>
    </Card>
  );
});

export default ResponseTimeHeatmap;

