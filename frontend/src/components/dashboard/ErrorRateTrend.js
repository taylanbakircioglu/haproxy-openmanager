import React from 'react';
import { Card, Empty, Spin } from 'antd';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend
} from 'recharts';

const ErrorRateTrend = ({ data, loading, title = "Error Rate Trend (24h)" }) => {
  if (loading) {
    return (
      <Card title={title}>
        <div style={{ textAlign: 'center', padding: 50 }}>
          <Spin size="large" tip="Loading error data..." />
        </div>
      </Card>
    );
  }

  if (!data || data.length === 0) {
    return (
      <Card title={title}>
        <Empty description="No error data available" image={Empty.PRESENTED_IMAGE_SIMPLE} />
      </Card>
    );
  }

  // Format data for charting
  const chartData = data.map(point => ({
    time: new Date(point.timestamp).toLocaleTimeString([], { 
      hour: '2-digit', 
      minute: '2-digit' 
    }),
    '4xx Errors': point.errors_4xx || 0,
    '5xx Errors': point.errors_5xx || 0,
    total: (point.errors_4xx || 0) + (point.errors_5xx || 0)
  }));

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      const total = payload.reduce((sum, entry) => sum + entry.value, 0);
      return (
        <div style={{ 
          backgroundColor: 'rgba(255, 255, 255, 0.96)', 
          padding: '10px', 
          border: '1px solid #d9d9d9',
          borderRadius: '4px',
          boxShadow: '0 2px 8px rgba(0,0,0,0.15)'
        }}>
          <p style={{ margin: 0, fontWeight: 'bold' }}>{label}</p>
          <p style={{ margin: '4px 0', color: '#faad14' }}>
            4xx Errors: <strong>{payload[0]?.value || 0}</strong>
          </p>
          <p style={{ margin: '4px 0', color: '#ff4d4f' }}>
            5xx Errors: <strong>{payload[1]?.value || 0}</strong>
          </p>
          <p style={{ margin: '4px 0', fontWeight: 'bold' }}>
            Total Errors: <strong>{total}</strong>
          </p>
        </div>
      );
    }
    return null;
  };

  return (
    <Card title={title}>
      <ResponsiveContainer width="100%" height={300}>
        <AreaChart data={chartData}>
          <defs>
            <linearGradient id="color4xx" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#faad14" stopOpacity={0.8}/>
              <stop offset="95%" stopColor="#faad14" stopOpacity={0.1}/>
            </linearGradient>
            <linearGradient id="color5xx" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#ff4d4f" stopOpacity={0.8}/>
              <stop offset="95%" stopColor="#ff4d4f" stopOpacity={0.1}/>
            </linearGradient>
          </defs>
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
            label={{ value: 'Errors', angle: -90, position: 'insideLeft', style: { fill: '#8c8c8c' } }}
          />
          <Tooltip 
            content={<CustomTooltip />} 
            cursor={{ strokeDasharray: '3 3' }}
            position={({ x, y }) => {
              // Tooltip is small (only 2 error types), fixed height
              const tooltipHeight = 180;
              return { x: x - 150, y: y - tooltipHeight };
            }}
            allowEscapeViewBox={{ x: true, y: true }}
            wrapperStyle={{ 
              pointerEvents: 'none',
              zIndex: 9999
            }}
          />
          <Legend 
            wrapperStyle={{ fontSize: 12 }}
            iconType="square"
          />
          <Area
            type="monotone"
            dataKey="4xx Errors"
            stackId="1"
            stroke="#faad14"
            strokeWidth={2}
            fill="url(#color4xx)"
          />
          <Area
            type="monotone"
            dataKey="5xx Errors"
            stackId="1"
            stroke="#ff4d4f"
            strokeWidth={2}
            fill="url(#color5xx)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </Card>
  );
};

export default ErrorRateTrend;

