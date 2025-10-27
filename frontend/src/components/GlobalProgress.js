import React from 'react';
import { Progress, Card, Typography } from 'antd';
import { useProgress } from '../contexts/ProgressContext';
import { COLORS } from '../utils/colors';

const { Text } = Typography;

const GlobalProgress = () => {
  const { progress, getElapsedTime } = useProgress();

  if (!progress.visible) {
    return null;
  }

  const getProgressColor = () => {
    if (progress.progress === 100) return COLORS.PROGRESS.SUCCESS;
    if (progress.progress >= 80) return COLORS.PROGRESS.ACTIVE;
    return COLORS.PROGRESS.ACTIVE;
  };

  const getProgressStatus = () => {
    if (progress.progress === 100) return 'success';
    if (progress.progress > 0) return 'active';
    return 'normal';
  };

  return (
    <div style={{
      position: 'fixed',
      bottom: '24px',
      right: '24px',
      width: '400px',
      zIndex: 1000,
      boxShadow: '0 4px 12px rgba(0, 0, 0, 0.15)',
      borderRadius: '8px'
    }}>
      <Card
        size="small"
        style={{
          backgroundColor: '#fff',
          border: `1px solid ${getProgressColor()}`,
        }}
      >
        <div style={{ marginBottom: 8 }}>
          <Text strong style={{ color: getProgressColor() }}>
            {progress.type?.toUpperCase() || 'PROGRESS'}: {progress.step}
          </Text>
        </div>
        
        <Progress
          percent={progress.progress}
          status={getProgressStatus()}
          strokeColor={getProgressColor()}
          size="small"
          showInfo={true}
        />
        
        <div style={{ 
          marginTop: 8, 
          display: 'flex', 
          justifyContent: 'space-between',
          fontSize: '12px',
          color: '#666'
        }}>
          <span>
            {getElapsedTime()}s elapsed
          </span>
          <span>
            Synced Entities: {progress.entityCounts.synced}/{progress.entityCounts.total}
          </span>
        </div>
        
        {progress.agentCounts.total > 0 && (
          <div style={{ 
            marginTop: 4, 
            fontSize: '12px',
            color: '#666',
            textAlign: 'center',
            display: 'flex',
            justifyContent: 'space-between'
          }}>
            <span>Agents: {progress.agentCounts.synced}/{progress.agentCounts.total}</span>
            <span>Cluster: {progress.agentCounts.synced === progress.agentCounts.total ? '✓ Synced' : '⏳ Syncing'}</span>
          </div>
        )}
        
        {Object.keys(progress.details).length > 0 && (
          <div style={{ 
            marginTop: 8, 
            padding: '4px 8px', 
            backgroundColor: '#f5f5f5', 
            borderRadius: '4px',
            fontSize: '11px'
          }}>
            {Object.entries(progress.details).map(([key, value]) => (
              <div key={key}>
                <Text type="secondary">{key}:</Text> <Text>{value}</Text>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
};

export default GlobalProgress;
