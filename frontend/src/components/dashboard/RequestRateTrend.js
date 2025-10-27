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
  Legend
} from 'recharts';

const COLORS = ['#1890ff', '#52c41a', '#faad14', '#f5222d', '#722ed1', '#13c2c2'];

const RequestRateTrend = ({ data, loading, title = "Request Rate Trend (24h)" }) => {
  if (loading) {
    return (
      <Card title={title}>
        <div style={{ textAlign: 'center', padding: 50 }}>
          <Spin size="large" tip="Loading request data..." />
        </div>
      </Card>
    );
  }

  if (!data || data.length === 0) {
    return (
      <Card title={title}>
        <Empty description="No request data available" image={Empty.PRESENTED_IMAGE_SIMPLE} />
      </Card>
    );
  }

  // Format data for charting - group by timestamp
  const groupedData = {};
  data.forEach(point => {
    const timestamp = new Date(point.timestamp).toLocaleTimeString([], { 
      hour: '2-digit', 
      minute: '2-digit' 
    });
    
    if (!groupedData[timestamp]) {
      groupedData[timestamp] = { time: timestamp };
    }
    
    groupedData[timestamp][point.frontend] = point.value;
  });

  const chartData = Object.values(groupedData);

  // Get unique frontends for lines - limit to top 10 by request volume
  const frontendTotals = {};
  data.forEach(point => {
    if (!frontendTotals[point.frontend]) {
      frontendTotals[point.frontend] = 0;
    }
    frontendTotals[point.frontend] += point.value || 0;
  });
  
  // Sort by total and take top 10
  const sortedFrontends = Object.entries(frontendTotals)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([name]) => name);
  
  const frontends = sortedFrontends.length > 0 ? sortedFrontends : [...new Set(data.map(d => d.frontend))].slice(0, 10);

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
              {entry.name}: <strong>{entry.value.toLocaleString()} req</strong>
            </p>
          ))}
        </div>
      );
    }
    return null;
  };

  const totalFrontends = [...new Set(data.map(d => d.frontend))].length;
  const showingTop = frontends.length < totalFrontends;

  return (
    <Card 
      title={title}
      extra={showingTop && (
        <span style={{ fontSize: 12, color: '#8c8c8c' }}>
          Showing top {frontends.length} of {totalFrontends} frontends
        </span>
      )}
    >
      <ResponsiveContainer width="100%" height={300}>
        <LineChart data={chartData}>
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
            label={{ value: 'Requests', angle: -90, position: 'insideLeft', style: { fill: '#8c8c8c' } }}
          />
          <Tooltip 
            content={<CustomTooltip />} 
            cursor={{ strokeDasharray: '3 3' }}
            position={({ x, y }) => {
              // Tooltip should appear well above the cursor
              // Estimate tooltip height: ~30px per line + padding
              // With many frontends, tooltip can be 400-500px tall
              const tooltipHeight = Math.max(500, frontends.length * 30);
              return { x: x - 150, y: y - tooltipHeight - 20 };
            }}
            allowEscapeViewBox={{ x: true, y: true }}
            wrapperStyle={{ 
              pointerEvents: 'none',
              zIndex: 9999
            }}
          />
          {/* Legend disabled for better readability with many frontends - use tooltip instead */}
          {frontends.map((frontend, index) => (
            <Line
              key={frontend}
              type="monotone"
              dataKey={frontend}
              stroke={COLORS[index % COLORS.length]}
              strokeWidth={2}
              dot={false}
              name={frontend}
              connectNulls
            />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </Card>
  );
};

export default RequestRateTrend;

