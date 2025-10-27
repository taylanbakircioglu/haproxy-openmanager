import React from 'react';
import { Card, Badge, Tooltip, Typography, Progress, Space, Tag } from 'antd';
import {
  CheckCircleOutlined,
  WarningOutlined,
  CloseCircleOutlined,
  QuestionCircleOutlined,
  ClockCircleOutlined
} from '@ant-design/icons';

const { Text } = Typography;

const AgentStatusCard = ({ agent }) => {
  // Determine status icon and color
  const getStatusIcon = () => {
    switch (agent.health) {
      case 'healthy':
        return <CheckCircleOutlined style={{ fontSize: 24, color: '#52c41a' }} />;
      case 'warning':
        return <WarningOutlined style={{ fontSize: 24, color: '#faad14' }} />;
      case 'degraded':
        return <WarningOutlined style={{ fontSize: 24, color: '#ff7875' }} />;
      case 'offline':
        return <CloseCircleOutlined style={{ fontSize: 24, color: '#ff4d4f' }} />;
      default:
        return <QuestionCircleOutlined style={{ fontSize: 24, color: '#8c8c8c' }} />;
    }
  };

  const getStatusBadge = () => {
    switch (agent.health) {
      case 'healthy':
        return 'success';
      case 'warning':
        return 'warning';
      case 'degraded':
        return 'warning';
      case 'offline':
        return 'error';
      default:
        return 'default';
    }
  };

  const getStatusColor = () => {
    switch (agent.health) {
      case 'healthy':
        return '#52c41a';
      case 'warning':
        return '#faad14';
      case 'degraded':
        return '#ff7875';
      case 'offline':
        return '#ff4d4f';
      default:
        return '#8c8c8c';
    }
  };

  const formatLastSeen = (secondsAgo) => {
    if (secondsAgo === null || secondsAgo === undefined) {
      return 'Never';
    }
    
    if (secondsAgo < 60) {
      return `${secondsAgo}s ago`;
    } else if (secondsAgo < 3600) {
      return `${Math.floor(secondsAgo / 60)}m ago`;
    } else {
      return `${Math.floor(secondsAgo / 3600)}h ago`;
    }
  };

  return (
    <Card
      size="small"
      style={{ 
        borderLeft: `4px solid ${getStatusColor()}`,
        height: '100%'
      }}
      hoverable
    >
      <Space direction="vertical" style={{ width: '100%' }} size="small">
        {/* Agent Name and Status Icon */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Space>
            {getStatusIcon()}
            <Text strong style={{ fontSize: 16 }}>
              {agent.name}
            </Text>
          </Space>
          <Badge status={getStatusBadge()} />
        </div>

        {/* Health Progress */}
        <Progress
          percent={agent.health_percentage}
          size="small"
          status={agent.health === 'healthy' ? 'success' : agent.health === 'offline' ? 'exception' : 'active'}
          showInfo={false}
          strokeColor={getStatusColor()}
        />

        {/* Agent Details */}
        <div style={{ fontSize: 12 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
            <Text type="secondary">Health:</Text>
            <Tag color={getStatusColor()} style={{ margin: 0, fontSize: 11 }}>
              {agent.health_percentage}%
            </Tag>
          </div>
          
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
            <Text type="secondary">
              <ClockCircleOutlined style={{ marginRight: 4 }} />
              Last Seen:
            </Text>
            <Tooltip title={agent.last_seen}>
              <Text style={{ fontSize: 11 }}>
                {formatLastSeen(agent.seconds_ago)}
              </Text>
            </Tooltip>
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
            <Text type="secondary">Platform:</Text>
            <Text style={{ fontSize: 11 }}>{agent.platform || 'Unknown'}</Text>
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <Text type="secondary">Version:</Text>
            <Text style={{ fontSize: 11 }}>{agent.version || '-'}</Text>
          </div>
        </div>

        {/* Status Label */}
        <div style={{ textAlign: 'center', marginTop: 4 }}>
          <Tag 
            color={agent.enabled ? getStatusColor() : 'default'}
            style={{ fontSize: 11, fontWeight: 'bold' }}
          >
            {agent.enabled ? agent.health.toUpperCase() : 'DISABLED'}
          </Tag>
        </div>
      </Space>
    </Card>
  );
};

export default AgentStatusCard;

