import React from 'react';
import { Card, Empty, Spin } from 'antd';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
  ReferenceLine
} from 'recharts';

const COLORS = {
  p50: '#52c41a',
  p95: '#1890ff',
  p99: '#faad14'
};

const ResponseTimeTrend = ({ data, loading, title = "Response Time Trend (24h)" }) => {
  if (loading) {
    return (
      <Card title={title}>
        <div style={{ textAlign: 'center', padding: 50 }}>
          <Spin size="large" tip="Loading response time data..." />
        </div>
      </Card>
    );
  }

  if (!data || data.length === 0) {
    return (
      <Card title={title}>
        <Empty description="No response time data available" image={Empty.PRESENTED_IMAGE_SIMPLE} />
      </Card>
    );
  }

  // Format data for charting
  const chartData = data.map(point => ({
    time: new Date(point.timestamp).toLocaleTimeString([], { 
      hour: '2-digit', 
      minute: '2-digit' 
    }),
    value: point.value,
    backend: point.backend
  }));

  // Get top 10 backends by average response time
  const backendTotals = {};
  const backendCounts = {};
  data.forEach(point => {
    if (!backendTotals[point.backend]) {
      backendTotals[point.backend] = 0;
      backendCounts[point.backend] = 0;
    }
    backendTotals[point.backend] += point.value || 0;
    backendCounts[point.backend] += 1;
  });
  
  // Sort by average response time (slowest first) and take top 10
  const sortedBackends = Object.entries(backendTotals)
    .map(([name, total]) => [name, total / backendCounts[name]])
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([name]) => name);
  
  const backends = sortedBackends.length > 0 ? sortedBackends : [...new Set(data.map(d => d.backend))].slice(0, 10);
  
  const groupedData = {};
  
  chartData.forEach(point => {
    if (!groupedData[point.time]) {
      groupedData[point.time] = { time: point.time };
    }
    groupedData[point.time][point.backend] = point.value;
  });

  const finalData = Object.values(groupedData);

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
              {entry.name}: <strong>{entry.value}ms</strong>
            </p>
          ))}
        </div>
      );
    }
    return null;
  };

  const totalBackends = [...new Set(data.map(d => d.backend))].length;
  const showingTop = backends.length < totalBackends;

  return (
    <Card 
      title={title}
      extra={showingTop && (
        <span style={{ fontSize: 12, color: '#8c8c8c' }}>
          Showing top {backends.length} slowest of {totalBackends} backends
        </span>
      )}
    >
      <ResponsiveContainer width="100%" height={300}>
        <LineChart data={finalData}>
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
            label={{ value: 'Response Time (ms)', angle: -90, position: 'insideLeft', style: { fill: '#8c8c8c' } }}
          />
          <Tooltip 
            content={<CustomTooltip />} 
            cursor={{ strokeDasharray: '3 3' }}
            position={({ x, y }) => {
              // Tooltip should appear well above the cursor
              // Estimate tooltip height: ~30px per line + padding
              // With many backends, tooltip can be 400-500px tall
              const tooltipHeight = Math.max(500, backends.length * 30);
              return { x: x - 150, y: y - tooltipHeight - 20 };
            }}
            allowEscapeViewBox={{ x: true, y: true }}
            wrapperStyle={{ 
              pointerEvents: 'none',
              zIndex: 9999
            }}
          />
          {/* Legend disabled for better readability with many backends */}
          
          {/* Reference lines for thresholds */}
          <ReferenceLine y={100} stroke="#52c41a" strokeDasharray="3 3" label="Good (100ms)" />
          <ReferenceLine y={300} stroke="#faad14" strokeDasharray="3 3" label="Warning (300ms)" />
          <ReferenceLine y={500} stroke="#ff4d4f" strokeDasharray="3 3" label="Critical (500ms)" />
          
          {backends.map((backend, index) => (
            <Line
              key={backend}
              type="monotone"
              dataKey={backend}
              stroke={['#1890ff', '#52c41a', '#faad14', '#f5222d', '#722ed1'][index % 5]}
              strokeWidth={2}
              dot={false}
              name={backend}
              connectNulls
            />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </Card>
  );
};

export default ResponseTimeTrend;

