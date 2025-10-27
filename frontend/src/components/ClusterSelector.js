import React from 'react';
import { Select, Badge, Tooltip } from 'antd';
import { CloudServerOutlined, CheckCircleOutlined, ExclamationCircleOutlined, CloseCircleOutlined, LoadingOutlined } from '@ant-design/icons';
import { useCluster } from '../contexts/ClusterContext';

const { Option } = Select;

const ClusterSelector = () => {
  const { clusters, selectedCluster, selectCluster, loading, agentHealthByPool } = useCluster();

  const getAgentStatusIcon = (agentStatus, totalAgents) => {
    if (totalAgents === 0) {
      return <ExclamationCircleOutlined style={{ color: '#ff4d4f' }} />;
    }
    
    switch (agentStatus) {
      case 'healthy':
        return <CheckCircleOutlined style={{ color: '#52c41a' }} />;
      case 'warning':
        return <ExclamationCircleOutlined style={{ color: '#faad14' }} />;
      case 'offline':
        return <CloseCircleOutlined style={{ color: '#ff4d4f' }} />;
      default:
        return <LoadingOutlined style={{ color: '#1890ff' }} />;
    }
  };

  const getAgentStatusColor = (agentStatus, totalAgents) => {
    if (totalAgents === 0) {
      return '#ff4d4f'; // Red for no agents
    }
    
    switch (agentStatus) {
      case 'healthy':
        return '#52c41a'; // Green
      case 'warning':
        return '#faad14'; // Orange/Yellow
      case 'offline':
        return '#ff4d4f'; // Red
      default:
        return '#d9d9d9'; // Gray for unknown
    }
  };

  const getAgentStatusText = (cluster) => {
    const { total_agents, healthy_agents, warning_agents, offline_agents, agent_status } = cluster;
    
    if (total_agents === 0) {
      return 'No Agents';
    }
    
    const statusParts = [];
    if (healthy_agents > 0) statusParts.push(`${healthy_agents} online`);
    if (warning_agents > 0) statusParts.push(`${warning_agents} warning`);
    if (offline_agents > 0) statusParts.push(`${offline_agents} offline`);
    
    return statusParts.join(', ') || `${total_agents} ${agent_status}`;
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <LoadingOutlined />
        <span>Loading clusters...</span>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
      <CloudServerOutlined style={{ color: '#1890ff' }} />
      <Select
        value={selectedCluster?.id}
        style={{ 
          minWidth: 250, 
          maxWidth: 350 
        }}
        placeholder="Select HAProxy Cluster"
        onChange={(clusterId) => {
          const cluster = clusters.find(c => c.id === clusterId);
          if (cluster) {
            selectCluster(cluster);
          }
        }}
        optionLabelProp="label"
        size="middle"
      >
        {clusters.map(cluster => (
          <Option 
            key={cluster.id} 
            value={cluster.id}
            label={
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Badge 
                  dot 
                  color={getAgentStatusColor(cluster.agent_status, cluster.total_agents)} 
                />
                <span>{cluster.name}</span>
                <span style={{ 
                  fontSize: '11px', 
                  color: '#666',
                  marginLeft: 'auto'
                }}>
                  ({cluster.connection_type})
                </span>
              </div>
            }
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: 1 }}>
                <Badge 
                  dot 
                  color={getAgentStatusColor(cluster.agent_status, cluster.total_agents)} 
                />
                <div>
                  <div style={{ fontWeight: 500 }}>
                    {cluster.name}
                    {cluster.is_default && (
                      <span style={{ 
                        marginLeft: '6px',
                        fontSize: '10px', 
                        background: '#1890ff', 
                        color: 'white', 
                        padding: '1px 4px', 
                        borderRadius: '2px' 
                      }}>
                        DEFAULT
                      </span>
                    )}
                  </div>
                  <div style={{ 
                    fontSize: '12px', 
                    color: '#666',
                    marginTop: '2px'
                  }}>
                    Pool: {cluster.pool_name} ({cluster.connection_type})
                  </div>
                  <div style={{ 
                    fontSize: '11px', 
                    color: cluster.total_agents === 0 ? '#ff4d4f' : '#52c41a',
                    marginTop: '1px',
                    fontWeight: 500
                  }}>
                    Agents: {getAgentStatusText(cluster)}
                  </div>
                  {cluster.description && (
                    <div style={{ 
                      fontSize: '11px', 
                      color: '#999',
                      marginTop: '1px'
                    }}>
                      {cluster.description}
                    </div>
                  )}
                </div>
              </div>
              <Tooltip title={`Agents: ${getAgentStatusText(cluster)}`}>
                {getAgentStatusIcon(cluster.agent_status, cluster.total_agents)}
              </Tooltip>
            </div>
          </Option>
        ))}
      </Select>
      {selectedCluster && (
        <Tooltip title={`${selectedCluster.name} - Agents: ${getAgentStatusText(selectedCluster)}`}>
          <Badge 
            dot 
            color={getAgentStatusColor(
              agentHealthByPool[selectedCluster.pool_id] || selectedCluster.agent_status,
              selectedCluster.total_agents
            )} 
          />
        </Tooltip>
      )}
    </div>
  );
};

export default ClusterSelector; 