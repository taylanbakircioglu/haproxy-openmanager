import React, { createContext, useContext, useState, useEffect } from 'react';
import axios from 'axios';

const ClusterContext = createContext();

export { ClusterContext };

export const useCluster = () => {
  const context = useContext(ClusterContext);
  if (!context) {
    throw new Error('useCluster must be used within a ClusterProvider');
  }
  return context;
};

export const ClusterProvider = ({ children }) => {
  const [clusters, setClusters] = useState([]);
  const [selectedCluster, setSelectedCluster] = useState(null);
  const [agentHealthByPool, setAgentHealthByPool] = useState({});
  const [loading, setLoading] = useState(true);

  // Fetch all clusters
  const fetchClusters = async () => {
    try {
      const response = await axios.get('/api/clusters');
      const clustersData = response.data.clusters || [];
      setClusters(clustersData);
      // Precompute health by pool to avoid flicker when switching clusters
      const healthMap = {};
      clustersData.forEach(c => {
        const total = c.total_agents || 0;
        const healthy = c.healthy_agents || 0;
        healthMap[c.pool_id] = total === 0 ? 'no-agents' : (healthy === total ? 'healthy' : (healthy > 0 ? 'warning' : 'offline'));
      });
      setAgentHealthByPool(healthMap);
      
      // Set selected cluster - handle empty clusters list gracefully
      if (response.data.clusters.length > 0) {
        const defaultCluster = response.data.clusters.find(c => c.is_default);
        const savedClusterId = localStorage.getItem('selectedClusterId');
        
        if (savedClusterId) {
          const savedCluster = response.data.clusters.find(c => c.id === parseInt(savedClusterId));
          if (savedCluster) {
            setSelectedCluster(savedCluster);
          } else {
            setSelectedCluster(defaultCluster || response.data.clusters[0]);
          }
        } else {
          setSelectedCluster(defaultCluster || response.data.clusters[0]);
        }
      } else {
        // No clusters available - clear selection
        setSelectedCluster(null);
        localStorage.removeItem('selectedClusterId');
      }
    } catch (error) {
      console.error('Failed to fetch clusters:', error);
      // On error, set empty state - no fallback cluster
      setClusters([]);
      setSelectedCluster(null);
      localStorage.removeItem('selectedClusterId');
    } finally {
      setLoading(false);
    }
  };

  // Select cluster
  const selectCluster = (cluster) => {
    setSelectedCluster(cluster);
    localStorage.setItem('selectedClusterId', cluster.id.toString());
  };

  // Add new cluster
  const addCluster = async (clusterData) => {
    try {
      const response = await axios.post('/api/clusters', clusterData);
      await fetchClusters(); // Refresh clusters list
      return response.data;
    } catch (error) {
      console.error('Failed to add cluster:', error);
      throw error;
    }
  };

  // Update cluster
  const updateCluster = async (clusterId, updateData) => {
    try {
      const response = await axios.put(`/api/clusters/${clusterId}`, updateData);
      await fetchClusters(); // Refresh clusters list
      return response.data;
    } catch (error) {
      console.error('Failed to update cluster:', error);
      throw error;
    }
  };

  // Delete cluster
  const deleteCluster = async (clusterId) => {
    try {
      const response = await axios.delete(`/api/clusters/${clusterId}`);
      await fetchClusters(); // Refresh clusters list
      
      // If deleted cluster was selected, switch to default
      if (selectedCluster && selectedCluster.id === clusterId) {
        const defaultCluster = clusters.find(c => c.is_default && c.id !== clusterId);
        if (defaultCluster) {
          selectCluster(defaultCluster);
        }
      }
      
      return response.data;
    } catch (error) {
      console.error('Failed to delete cluster:', error);
      throw error;
    }
  };

  // Test cluster connection
  const testConnection = async (clusterId) => {
    try {
      const response = await axios.post(`/api/clusters/${clusterId}/test-connection`);
      await fetchClusters(); // Refresh to get updated connection status
      return response.data;
    } catch (error) {
      console.error('Failed to test connection:', error);
      throw error;
    }
  };

  // Set default cluster
  const setDefaultCluster = async (clusterId) => {
    try {
      const response = await axios.post(`/api/clusters/${clusterId}/set-default`);
      await fetchClusters(); // Refresh clusters list
      return response.data;
    } catch (error) {
      console.error('Failed to set default cluster:', error);
      throw error;
    }
  };

  useEffect(() => {
    fetchClusters();
  }, []);

  const value = {
    clusters,
    selectedCluster,
    loading,
    agentHealthByPool,
    selectCluster,
    addCluster,
    updateCluster,
    deleteCluster,
    testConnection,
    setDefaultCluster,
    fetchClusters
  };

  return (
    <ClusterContext.Provider value={value}>
      {children}
    </ClusterContext.Provider>
  );
}; 