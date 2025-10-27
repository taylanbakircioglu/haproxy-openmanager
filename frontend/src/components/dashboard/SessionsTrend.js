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

const SessionsTrend = ({ data, loading, title = "Active Sessions (24h)" }) => {
  if (loading) {
    return (
      <Card title={title}>
        <div style={{ textAlign: 'center', padding: 50 }}>
          <Spin size="large" tip="Loading session data..." />
        </div>
      </Card>
    );
  }

  if (!data || data.length === 0) {
    return (
      <Card title={title}>
        <Empty description="No session data available" image={Empty.PRESENTED_IMAGE_SIMPLE} />
      </Card>
    );
  }

  // Format data for charting
  const chartData = data.map(point => ({
    time: new Date(point.timestamp).toLocaleTimeString([], { 
      hour: '2-digit', 
      minute: '2-digit' 
    }),
    Sessions: point.sessions || 0,
    'Avg Sessions': point.avg_sessions || 0
  }));

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
          <p style={{ margin: '4px 0', color: '#1890ff' }}>
            Sessions: <strong>{payload[0]?.value || 0}</strong>
          </p>
          <p style={{ margin: '4px 0', color: '#52c41a' }}>
            Avg: <strong>{payload[1]?.value || 0}</strong>
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
            <linearGradient id="colorSessions" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#1890ff" stopOpacity={0.8}/>
              <stop offset="95%" stopColor="#1890ff" stopOpacity={0.1}/>
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
            label={{ value: 'Sessions', angle: -90, position: 'insideLeft', style: { fill: '#8c8c8c' } }}
          />
          <Tooltip 
            content={<CustomTooltip />} 
            cursor={{ strokeDasharray: '3 3' }}
            position={({ x, y }) => {
              // Tooltip is small (only 2 session metrics), fixed height
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
            dataKey="Sessions"
            stroke="#1890ff"
            strokeWidth={2}
            fill="url(#colorSessions)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </Card>
  );
};

export default SessionsTrend;

