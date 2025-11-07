import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { 
  Card, Row, Col, Statistic, Table, Badge, Typography, Alert, Space, Button, 
  Select, Spin, Empty, Tag, Progress, Divider, Tooltip, Skeleton, Tabs
} from 'antd';
import { 
  DashboardOutlined, SafetyCertificateOutlined, SecurityScanOutlined,
  CloudServerOutlined, GlobalOutlined, CheckCircleOutlined,
  ReloadOutlined, LoadingOutlined, ExclamationCircleOutlined,
  WarningOutlined, InfoCircleOutlined, ArrowUpOutlined, ArrowDownOutlined,
  ClockCircleOutlined, ClearOutlined,
  LineChartOutlined, FundOutlined, HeartOutlined, DatabaseOutlined
} from '@ant-design/icons';
import {
  LineChart, Line, AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer, Legend
} from 'recharts';
import axios from 'axios';
import { useCluster } from '../contexts/ClusterContext';
import { dashboardCache } from '../utils/dashboardCache';

// Import Tab Components
import OverviewTab from './dashboard/tabs/OverviewTab';
import PerformanceTrendsTab from './dashboard/tabs/PerformanceTrendsTab';
import CapacityLoadTab from './dashboard/tabs/CapacityLoadTab';
import HealthMatrixTab from './dashboard/tabs/HealthMatrixTab';
import FrontendsTab from './dashboard/tabs/FrontendsTab';
import BackendsTab from './dashboard/tabs/BackendsTab';

const { Title, Text } = Typography;

// Color schemes for charts
const COLORS = {
  primary: '#1890ff',
  success: '#52c41a',
  warning: '#faad14',
  error: '#f5222d',
  purple: '#722ed1',
  cyan: '#13c2c2',
  orange: '#fa8c16',
  green: '#52c41a',
  red: '#ff4d4f',
  blue: '#1890ff',
  gray: '#8c8c8c'
};

const RESPONSE_CODE_COLORS = ['#52c41a', '#1890ff', '#faad14', '#f5222d'];

// Skeleton loader component for cards
const CardSkeleton = ({ rows = 3 }) => (
  <Card>
    <Skeleton active paragraph={{ rows }} />
  </Card>
);

const DashboardV2 = () => {
  const { selectedCluster } = useCluster();
  
  // State management
  const [loading, setLoading] = useState(true);
  const [initialLoad, setInitialLoad] = useState(true);
  const [error, setError] = useState(null);
  const [overviewData, setOverviewData] = useState({});
  const [statsData, setStatsData] = useState({});
  const [selectedFrontends, setSelectedFrontends] = useState([]);
  const [selectedBackends, setSelectedBackends] = useState([]);
  const [frontendOptions, setFrontendOptions] = useState([]);
  const [backendOptions, setBackendOptions] = useState([]);
  const [backendHealth, setBackendHealth] = useState([]);
  const [slowestBackends, setSlowestBackends] = useState([]);
  
  // New state for advanced features
  const [agentsStatus, setAgentsStatus] = useState([]);
  const [requestsTimeseries, setRequestsTimeseries] = useState([]);
  const [responseTimeTimeseries, setResponseTimeTimeseries] = useState([]);
  const [responseTimeHeatmapData, setResponseTimeHeatmapData] = useState([]); // 24h data for heatmap
  const [errorsTimeseries, setErrorsTimeseries] = useState([]);
  const [sessionsTimeseries, setSessionsTimeseries] = useState([]);
  const [throughputData, setThroughputData] = useState(null);
  const [lastUpdate, setLastUpdate] = useState(null);
  const [autoRefreshCountdown, setAutoRefreshCountdown] = useState(30);
  const [cacheLoading, setCacheLoading] = useState(false);
  const [usingCache, setUsingCache] = useState({ frontends: false, backends: false });
  
  // Tab state management
  const [activeTab, setActiveTab] = useState('overview');
  const [tabsInitialized, setTabsInitialized] = useState({ overview: true });
  
  // Fetch overview metrics data
  const fetchOverviewData = useCallback(async () => {
    if (!selectedCluster) return;
    
    try {
      const response = await axios.get('/api/dashboard-stats/metrics/overview', {
        params: { cluster_id: selectedCluster.id }
      });
      setOverviewData(prevData => ({ ...prevData, ...response.data }));
    } catch (error) {
      console.error('Failed to fetch overview data:', error);
    }
  }, [selectedCluster]);
  
  // Fetch agents status
  const fetchAgentsStatus = useCallback(async () => {
    if (!selectedCluster) return;
    
    try {
      const response = await axios.get('/api/dashboard-stats/agents/status', {
        params: { cluster_id: selectedCluster.id }
      });
      setAgentsStatus(response.data.agents || []);
    } catch (error) {
      console.error('Failed to fetch agents status:', error);
      setAgentsStatus([]);
    }
  }, [selectedCluster]);
  
  // Fetch requests timeseries (optimized with limit)
  const fetchRequestsTimeseries = useCallback(async () => {
    if (!selectedCluster) return;
    
    try {
      const params = {
        cluster_id: selectedCluster.id,
        hours: 2, // Reduced from 24 to 2 hours for performance
        limit: 50 // Limit data points
      };
      
      if (selectedFrontends.length > 0 && !selectedFrontends.includes('all')) {
        params.frontends = selectedFrontends.join(',');
      }
      
      const response = await axios.get('/api/dashboard-stats/metrics/timeseries/requests', { params });
      setRequestsTimeseries(response.data.data || []);
    } catch (error) {
      console.error('Failed to fetch requests timeseries:', error);
      setRequestsTimeseries([]);
    }
  }, [selectedCluster, selectedFrontends]);
  
  // Fetch response time timeseries (optimized with limit) - for trend chart
  const fetchResponseTimeTimeseries = useCallback(async () => {
    if (!selectedCluster) return;
    
    try {
      const params = {
        cluster_id: selectedCluster.id,
        hours: 2, // 2 hours for detailed trend chart
        limit: 50 // Limit data points
      };
      
      if (selectedBackends.length > 0 && !selectedBackends.includes('all')) {
        params.backends = selectedBackends.join(',');
      }
      
      const response = await axios.get('/api/dashboard-stats/metrics/timeseries/response-time', { params });
      setResponseTimeTimeseries(response.data.data || []);
    } catch (error) {
      console.error('Failed to fetch response time timeseries:', error);
      setResponseTimeTimeseries([]);
    }
  }, [selectedCluster, selectedBackends]);
  
  // Fetch response time heatmap data (24 hours, aggregated by hour)
  const fetchResponseTimeHeatmap = useCallback(async () => {
    if (!selectedCluster) return;
    
    try {
      const params = {
        cluster_id: selectedCluster.id,
        hours: 24, // Full 24 hours for heatmap
        // Heatmap shows only top 10 backends, so we need enough data for all 24 hours
        // For 24 hours with data every 5-10 seconds: ~10,000 points per backend
        // But we only show top 10 backends, so: 10 backends * 24 hours * ~50 points/hour = ~12,000
        // Use 5000 as a reasonable limit to get ~200 points per hour for 10 backends
        limit: 5000 
      };
      
      if (selectedBackends.length > 0 && !selectedBackends.includes('all')) {
        params.backends = selectedBackends.join(',');
      }
      
      const response = await axios.get('/api/dashboard-stats/metrics/timeseries/response-time', { params });
      const responseData = response.data.data || [];
      
      // Only log in development mode
      if (process.env.NODE_ENV === 'development') {
        console.log('Heatmap API Response:', {
          total_points: responseData.length,
          backends: responseData.length > 0 ? [...new Set(responseData.map(d => d.backend))].length : 0,
          time_range: {
            first: responseData[0]?.timestamp || 'N/A',
            last: responseData[responseData.length - 1]?.timestamp || 'N/A'
          }
        });
      }
      
      setResponseTimeHeatmapData(responseData);
    } catch (error) {
      console.error('Failed to fetch response time heatmap:', error);
      setResponseTimeHeatmapData([]);
    }
  }, [selectedCluster, selectedBackends]);
  
  // Fetch errors timeseries (optimized with limit)
  const fetchErrorsTimeseries = useCallback(async () => {
    if (!selectedCluster) return;
    
    try {
      const response = await axios.get('/api/dashboard-stats/metrics/timeseries/errors', {
        params: { 
          cluster_id: selectedCluster.id, 
          hours: 2, // Reduced from 24 to 2 hours for performance
          limit: 50 // Limit data points
        }
      });
      setErrorsTimeseries(response.data.data || []);
    } catch (error) {
      console.error('Failed to fetch errors timeseries:', error);
      setErrorsTimeseries([]);
    }
  }, [selectedCluster]);
  
  // Fetch sessions timeseries (optimized with limit)
  const fetchSessionsTimeseries = useCallback(async () => {
    if (!selectedCluster) return;
    
    try {
      const response = await axios.get('/api/dashboard-stats/metrics/timeseries/sessions', {
        params: { 
          cluster_id: selectedCluster.id, 
          hours: 2, // Reduced from 24 to 2 hours for performance
          limit: 50 // Limit data points
        }
      });
      setSessionsTimeseries(response.data.data || []);
    } catch (error) {
      console.error('Failed to fetch sessions timeseries:', error);
      setSessionsTimeseries([]);
    }
  }, [selectedCluster]);
  
  // Fetch throughput data
  const fetchThroughputData = useCallback(async () => {
    if (!selectedCluster) return;
    
    try {
      const response = await axios.get('/api/dashboard-stats/metrics/realtime/throughput', {
        params: { cluster_id: selectedCluster.id }
      });
      setThroughputData(response.data.throughput || null);
    } catch (error) {
      console.error('Failed to fetch throughput data:', error);
      setThroughputData(null);
    }
  }, [selectedCluster]);
  
  // Fetch frontend options with browser cache
  const fetchFrontendOptions = useCallback(async (forceRefresh = false) => {
    if (!selectedCluster) return;
    
    try {
      // Try to get from cache first (unless force refresh)
      if (!forceRefresh) {
        const cachedFrontends = await dashboardCache.getFrontends(selectedCluster.id);
        if (cachedFrontends && cachedFrontends.length > 0) {
          setFrontendOptions(cachedFrontends);
          setUsingCache(prev => ({ ...prev, frontends: true }));
          return;
        }
      }
      
      // Cache miss or force refresh - fetch from API
      setCacheLoading(true);
      const response = await axios.get('/api/dashboard-stats/frontends', {
        params: { cluster_id: selectedCluster.id }
      });
      
      const frontends = response.data.frontends || [];
      setFrontendOptions(frontends);
      setUsingCache(prev => ({ ...prev, frontends: false }));
      
      // Store in cache for next time
      await dashboardCache.setFrontends(selectedCluster.id, frontends);
      
    } catch (error) {
      console.error('Failed to fetch frontend options:', error);
      setFrontendOptions([]);
      setUsingCache(prev => ({ ...prev, frontends: false }));
    } finally {
      setCacheLoading(false);
    }
  }, [selectedCluster]);
  
  // Fetch backend options with browser cache
  const fetchBackendOptions = useCallback(async (forceRefresh = false) => {
    if (!selectedCluster) return;
    
    try {
      // Try to get from cache first (unless force refresh)
      if (!forceRefresh) {
        const cachedBackends = await dashboardCache.getBackends(selectedCluster.id);
        if (cachedBackends && cachedBackends.length > 0) {
          setBackendOptions(cachedBackends);
          setUsingCache(prev => ({ ...prev, backends: true }));
          return;
        }
      }
      
      // Cache miss or force refresh - fetch from API
      setCacheLoading(true);
      const response = await axios.get('/api/dashboard-stats/backends', {
        params: { cluster_id: selectedCluster.id }
      });
      
      const backends = response.data.backends || [];
      setBackendOptions(backends);
      setUsingCache(prev => ({ ...prev, backends: false }));
      
      // Store in cache for next time
      await dashboardCache.setBackends(selectedCluster.id, backends);
      
    } catch (error) {
      console.error('Failed to fetch backend options:', error);
      setBackendOptions([]);
      setUsingCache(prev => ({ ...prev, backends: false }));
    } finally {
      setCacheLoading(false);
    }
  }, [selectedCluster]);
  
  // Fetch main stats data
  const fetchStatsData = useCallback(async () => {
    if (!selectedCluster) return;
    
    // Don't show loading spinner on refresh, only on initial load
    if (initialLoad) {
      setLoading(true);
    }
    setError(null);
    
    try {
      const params = {
        cluster_id: selectedCluster.id
      };
      
      if (selectedFrontends.length > 0 && !selectedFrontends.includes('all')) {
        params.frontends = selectedFrontends.join(',');
      }
      
      if (selectedBackends.length > 0 && !selectedBackends.includes('all')) {
        params.backends = selectedBackends.join(',');
      }
      
      const response = await axios.get('/api/dashboard-stats/stats', { params });
      setStatsData(prevData => ({ ...prevData, ...response.data }));
    } catch (error) {
      console.error('Failed to fetch stats data:', error);
      setError(error.response?.data?.detail || error.message);
    } finally {
      if (initialLoad) {
        setLoading(false);
        setInitialLoad(false);
      }
    }
  }, [selectedCluster, selectedFrontends, selectedBackends, initialLoad]);
  
  // Fetch backend health
  const fetchBackendHealth = useCallback(async () => {
    if (!selectedCluster) return;
    
    try {
      const response = await axios.get('/api/dashboard-stats/backend-health', {
        params: { cluster_id: selectedCluster.id }
      });
      setBackendHealth(response.data.backends || []);
    } catch (error) {
      console.error('Failed to fetch backend health:', error);
      setBackendHealth([]);
    }
  }, [selectedCluster]);
  
  // Fetch slowest backends
  const fetchSlowestBackends = useCallback(async () => {
    if (!selectedCluster) return;
    
    try {
      const response = await axios.get('/api/dashboard-stats/slowest-backends', {
        params: { cluster_id: selectedCluster.id, limit: 5 }
      });
      setSlowestBackends(response.data.slowest_backends || []);
    } catch (error) {
      console.error('Failed to fetch slowest backends:', error);
      setSlowestBackends([]);
    }
  }, [selectedCluster]);
  
  // Load all data on cluster change
  useEffect(() => {
    if (!selectedCluster) return;
    
    // CRITICAL FIX: Clear all dashboard state when cluster changes
    setStatsData({});
    setFrontendOptions([]);
    setBackendOptions([]);
    setBackendHealth([]);
    setSlowestBackends([]);
    
    let isMounted = true;
    
    const loadInitialData = async () => {
      setSelectedFrontends(['all']);
      setSelectedBackends(['all']);
      setLastUpdate(new Date());
      setInitialLoad(true);
      
      try {
        // Fetch data sequentially to avoid race conditions
        await fetchOverviewData();
        if (!isMounted) return;
        
        await fetchAgentsStatus();
        if (!isMounted) return;
        
        await fetchFrontendOptions();
        if (!isMounted) return;
        
        await fetchBackendOptions();
        if (!isMounted) return;
        
        await fetchStatsData();
        if (!isMounted) return;
        
        await fetchBackendHealth();
        if (!isMounted) return;
        
        await fetchSlowestBackends();
        if (!isMounted) return;
        
        // Load timeseries data in parallel
        await Promise.all([
          fetchRequestsTimeseries(),
          fetchResponseTimeTimeseries(),
          fetchErrorsTimeseries(),
          fetchSessionsTimeseries(),
          fetchThroughputData()
        ]);
        
        if (!isMounted) return;
        
        // Fetch heatmap data separately (24h data, won't block other data)
        fetchResponseTimeHeatmap();
        
        setInitialLoad(false);
      } catch (error) {
        console.error('Initial data load failed:', error);
        if (isMounted) {
          setInitialLoad(false);
          setLoading(false);
        }
      }
    };
    
    loadInitialData();
    
    return () => {
      isMounted = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedCluster?.id]); // Only depend on cluster ID change
  
  // Refresh stats when filters change
  useEffect(() => {
    if (!selectedCluster || initialLoad) return;
    if (selectedFrontends.length === 0 && selectedBackends.length === 0) return;
    
    let isMounted = true;
    
    const refreshFilteredData = async () => {
      try {
        await Promise.all([
          fetchStatsData(),
          fetchRequestsTimeseries(),
          fetchResponseTimeTimeseries()
        ]);
        
        if (isMounted) {
          // Update heatmap with filtered backends (separate, heavy query)
          fetchResponseTimeHeatmap();
        }
      } catch (error) {
        console.error('Filter refresh failed:', error);
      }
    };
    
    refreshFilteredData();
    
    return () => {
      isMounted = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedCluster?.id, initialLoad, selectedFrontends, selectedBackends]);
  
  // Auto-refresh countdown (increased to 60 seconds for better performance)
  useEffect(() => {
    if (!selectedCluster) return;
    
    const countdownInterval = setInterval(() => {
      setAutoRefreshCountdown((prev) => {
        if (prev <= 1) {
          return 60; // Increased from 30 to 60 seconds
        }
        return prev - 1;
      });
    }, 1000);
    
    return () => clearInterval(countdownInterval);
  }, [selectedCluster]);
  
  // Tab-aware auto-refresh every 60 seconds (performance optimized)
  useEffect(() => {
    if (!selectedCluster || initialLoad) return;
    
    const interval = setInterval(() => {
      setLastUpdate(new Date());
      
      // Always refresh Overview data (lightweight)
      fetchOverviewData();
      fetchStatsData();
      fetchThroughputData();
      
      // Refresh active tab data
      switch(activeTab) {
        case 'trends':
          // Refresh time series data
          fetchRequestsTimeseries();
          fetchResponseTimeTimeseries();
          fetchErrorsTimeseries();
          fetchSessionsTimeseries();
          // Skip heatmap (24h data - too heavy for auto-refresh)
          break;
        
        case 'health':
          // Refresh health matrix
          fetchBackendHealth();
          fetchSlowestBackends();
          break;
        
        // 'overview', 'capacity', 'frontends', 'backends' use statsData (already refreshed above)
        default:
          break;
      }
    }, 60000); // 60 seconds
    
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedCluster?.id, initialLoad, activeTab]);
  
  // Handle frontend filter change (optimized with functional update)
  const handleFrontendChange = useCallback((values) => {
    // Limit selection to max 10 items for performance
    const maxSelection = 10;
    
    setSelectedFrontends(prev => {
      if (values.includes('all')) {
        if (!prev.includes('all')) {
          return ['all'];
        } else {
          const filtered = values.filter(v => v !== 'all');
          return filtered.length > 0 ? filtered : ['all'];
        }
      } else {
        // Enforce max selection limit
        if (values.length > maxSelection) {
          return values.slice(0, maxSelection);
        } else {
          return values.length > 0 ? values : ['all'];
        }
      }
    });
  }, []); // No dependencies - uses functional update
  
  // Handle backend filter change (optimized with functional update)
  const handleBackendChange = useCallback((values) => {
    // Limit selection to max 10 items for performance
    const maxSelection = 10;
    
    setSelectedBackends(prev => {
      if (values.includes('all')) {
        if (!prev.includes('all')) {
          return ['all'];
        } else {
          const filtered = values.filter(v => v !== 'all');
          return filtered.length > 0 ? filtered : ['all'];
        }
      } else {
        // Enforce max selection limit
        if (values.length > maxSelection) {
          return values.slice(0, maxSelection);
        } else {
          return values.length > 0 ? values : ['all'];
        }
      }
    });
  }, []); // No dependencies - uses functional update
  
  // Manual refresh - loads ALL data (force refresh cache)
  const handleRefresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    setLastUpdate(new Date());
    setAutoRefreshCountdown(60);
    
    try {
      // Fetch all data in parallel (force refresh cache for filters)
      await Promise.all([
        fetchOverviewData(),
        fetchAgentsStatus(),
        fetchFrontendOptions(true), // Force refresh cache
        fetchBackendOptions(true),  // Force refresh cache
        fetchStatsData(),
        fetchBackendHealth(),
        fetchSlowestBackends(),
        fetchRequestsTimeseries(),
        fetchResponseTimeTimeseries(),
        fetchErrorsTimeseries(),
        fetchSessionsTimeseries(),
        fetchThroughputData()
      ]);
      
      // Fetch heatmap data separately (24h data, won't block other data)
      fetchResponseTimeHeatmap();
    } catch (err) {
      console.error('Refresh failed:', err);
      setError('Failed to refresh dashboard data');
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // No dependencies - uses latest function references from closure
  
  // Clear cache and reload
  const handleClearCache = useCallback(async () => {
    if (!selectedCluster) return;
    
    try {
      await dashboardCache.invalidateCluster(selectedCluster.id);
      setUsingCache({ frontends: false, backends: false });
      
      // Reload filter options from API
      await Promise.all([
        fetchFrontendOptions(true),
        fetchBackendOptions(true)
      ]);
      
      console.log('✅ Cache cleared and filters reloaded');
    } catch (error) {
      console.error('Failed to clear cache:', error);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedCluster?.id]); // Only depend on cluster ID
  
  // Handle tab change with data loading and URL routing
  const handleTabChange = useCallback((key) => {
    setActiveTab(key);
    
    // Update URL hash for deep linking
    window.location.hash = key;
    
    // Save user preference
    localStorage.setItem('dashboard_active_tab', key);
    
    // Load tab data if not initialized yet
    if (!tabsInitialized[key]) {
      setTabsInitialized(prev => ({ ...prev, [key]: true }));
      
      // Fetch tab-specific data
      switch(key) {
        case 'trends':
          fetchRequestsTimeseries();
          fetchResponseTimeTimeseries();
          fetchErrorsTimeseries();
          fetchSessionsTimeseries();
          fetchResponseTimeHeatmap();
          break;
        case 'health':
          fetchBackendHealth();
          fetchSlowestBackends();
          break;
        // 'capacity', 'frontends', 'backends' tabs use already fetched statsData
        default:
          break;
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tabsInitialized]); // Only depend on tabs state, fetch functions use latest closure
  
  // Initialize tab from URL hash or localStorage on mount
  useEffect(() => {
    const validTabs = ['overview', 'trends', 'capacity', 'health', 'frontends', 'backends'];
    
    let initialTab = 'overview';
    
    // Check URL hash first
    const hash = window.location.hash.replace('#', '');
    if (hash && validTabs.includes(hash)) {
      initialTab = hash;
    } else {
      // Check localStorage preference
      const savedTab = localStorage.getItem('dashboard_active_tab');
      if (savedTab && validTabs.includes(savedTab)) {
        initialTab = savedTab;
        window.location.hash = savedTab;
      } else {
        window.location.hash = 'overview';
      }
    }
    
    // Set active tab and initialize it
    setActiveTab(initialTab);
    
    // Mark tab as initialized and load its data if needed
    setTabsInitialized(prev => ({ ...prev, [initialTab]: true }));
    
    // Load tab-specific data for lazy-loaded tabs
    if (initialTab === 'trends') {
      // Trends data will be loaded in initial data load useEffect
      // Just mark as initialized
    } else if (initialTab === 'health') {
      // Health data will be loaded in initial data load useEffect
      // Just mark as initialized
    }
  }, []);
  
  // Handle browser back/forward button
  useEffect(() => {
    const handleHashChange = () => {
      const hash = window.location.hash.replace('#', '');
      const validTabs = ['overview', 'trends', 'capacity', 'health', 'frontends', 'backends'];
      if (hash && validTabs.includes(hash)) {
        handleTabChange(hash);
      }
    };
    
    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, [handleTabChange]);
  
  // Format last update time
  const formatLastUpdate = useMemo(() => {
    if (!lastUpdate) return 'Never';
    const seconds = Math.floor((new Date() - lastUpdate) / 1000);
    if (seconds < 60) return `${seconds}s ago`;
    return lastUpdate.toLocaleTimeString();
  }, [lastUpdate]);
  
  // Memoized real-time metrics data
  const realTimeMetricsData = useMemo(() => {
    if (!statsData.frontends || !statsData.metrics) return null;
    
    return {
      requests_total: statsData.frontends?.aggregated?.total_requests || 0,
      requests_rate: statsData.frontends?.aggregated?.requests_rate || 0,
      active_sessions: statsData.frontends?.aggregated?.total_sessions || 0,
      max_sessions: statsData.frontends?.aggregated?.max_sessions || 0,
      avg_response_time: statsData.metrics?.response_time?.avg || 0,
      p95_response_time: statsData.metrics?.response_time?.p95 || 0,
      error_rate: statsData.metrics?.error_rate || 0,
      total_errors: (statsData.metrics?.http_responses?.['4xx'] || 0) + (statsData.metrics?.http_responses?.['5xx'] || 0),
      throughput_in: statsData.frontends?.aggregated?.total_bytes_in || 0,
      throughput_out: statsData.frontends?.aggregated?.total_bytes_out || 0,
      queue_depth: statsData.backends?.aggregated?.total_queue || 0,
      backends_active: (statsData.backends?.data || []).filter(b => b.status === 'UP').length,
      backends_total: statsData.backends?.count || 0,
      servers_up: overviewData.servers_up || 0,
      servers_total: overviewData.servers_total || 0,
      connection_rate: statsData.frontends?.aggregated?.session_rate || 0
    };
  }, [statsData, overviewData]);
  
  // Server status columns for table
  const serverColumns = useMemo(() => [
    {
      title: 'Server',
      dataIndex: 'name',
      key: 'name',
      sorter: (a, b) => a.name.localeCompare(b.name),
      render: (name) => <Text strong>{name}</Text>
    },
    {
      title: 'Backend',
      dataIndex: 'backend',
      key: 'backend',
      sorter: (a, b) => a.backend.localeCompare(b.backend),
      render: (backend) => <Tag color="blue">{backend}</Tag>
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      sorter: (a, b) => (a.status || '').localeCompare(b.status || ''),
      render: (status) => (
        <Badge 
          status={status === 'UP' ? 'success' : status === 'DOWN' ? 'error' : 'default'} 
          text={status}
        />
      )
    },
    {
      title: 'Weight',
      dataIndex: 'weight',
      key: 'weight',
      sorter: (a, b) => (a.weight || 0) - (b.weight || 0),
      render: (weight) => weight || '-'
    },
    {
      title: 'Sessions',
      dataIndex: 'current_sessions',
      key: 'current_sessions',
      sorter: (a, b) => (a.current_sessions || 0) - (b.current_sessions || 0),
      render: (sessions) => sessions || 0
    },
    {
      title: 'Response Time',
      dataIndex: 'response_time',
      key: 'response_time',
      sorter: (a, b) => (a.response_time || 0) - (b.response_time || 0),
      render: (time) => time ? `${time}ms` : '-'
    }
  ], []);
  
  // Extract data for visualization (before early returns - needed for hooks)
  const httpResponses = statsData.metrics?.http_responses || {};
  const responseCodeData = [
    { name: '2xx Success', value: httpResponses['2xx'] || 0, color: COLORS.success },
    { name: '3xx Redirect', value: httpResponses['3xx'] || 0, color: COLORS.cyan },
    { name: '4xx Client Error', value: httpResponses['4xx'] || 0, color: COLORS.warning },
    { name: '5xx Server Error', value: httpResponses['5xx'] || 0, color: COLORS.error }
  ].filter(item => item.value > 0);
  
  const responseTimeData = statsData.metrics?.response_time || {};
  
  // Prepare queue data for QueueMonitor - MUST be before any early returns
  const queueData = useMemo(() => {
    return (statsData.backends?.data || []).map(backend => ({
      name: backend.name,
      queue_current: backend.queue_current || 0,
      queue_max: backend.queue_max || 0,
      status: backend.status
    }));
  }, [statsData.backends]);
  
  // Prepare connection rate data - MUST be before any early returns
  const connectionRateData = useMemo(() => {
    const frontends = statsData.frontends?.data || [];
    const currentRate = frontends.reduce((sum, f) => sum + (f.session_rate || 0), 0);
    const maxRate = frontends.reduce((sum, f) => sum + (f.session_rate_max || 0), 0);
    const avgRate = frontends.length > 0 ? currentRate / frontends.length : 0;
    
    return {
      current_rate: currentRate,
      max_rate: maxRate,
      avg_rate: Math.round(avgRate),
      rate_limit: maxRate * 1.2 // Estimated
    };
  }, [statsData.frontends]);
  
  // Prepare health check data - MUST be before any early returns
  const healthCheckData = useMemo(() => {
    return (statsData.servers?.data || []).map(server => ({
      name: server.name,
      backend: server.backend,
      status: server.status,
      check_status: server.check_status,
      check_duration: server.check_duration,
      last_check: server.last_check,
      check_fail: server.check_fail,
      check_down: server.check_down
    }));
  }, [statsData.servers]);
  
  // Render error state (after all hooks)
  if (error) {
    return (
      <div style={{ padding: 50 }}>
        <Alert
          message="Dashboard Error"
          description={error}
          type="error"
          showIcon
          action={
            <Button size="small" onClick={handleRefresh}>
              Retry
            </Button>
          }
        />
      </div>
    );
  }
  
  // Render no cluster selected state (after all hooks)
  if (!selectedCluster) {
    return (
      <div style={{ padding: 50, textAlign: 'center' }}>
        <Card>
          <CloudServerOutlined style={{ fontSize: 48, color: '#d9d9d9', marginBottom: 16 }} />
          <Title level={3} type="secondary">No Cluster Selected</Title>
          <Text type="secondary">
            Please select a HAProxy cluster from the dropdown above to view dashboard metrics.
          </Text>
        </Card>
      </div>
    );
  }
  
  return (
    <div>
      {/* Enhanced Header with Auto-refresh Indicator and Cache Status */}
      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col xs={24} sm={24} md={24} lg={12}>
          <Title level={2} style={{ margin: 0 }}>
            <DashboardOutlined style={{ marginRight: 8, color: COLORS.primary }} />
            HAProxy Stats Dashboard
          </Title>
          {selectedCluster && (
            <Space wrap style={{ marginTop: 8 }}>
              <Tag color="green" icon={<CheckCircleOutlined />}>
                {selectedCluster.name}
              </Tag>
              <Divider type="vertical" />
              <Tooltip title="Last data refresh time">
                <Text type="secondary" style={{ fontSize: 12 }}>
                  <ClockCircleOutlined style={{ marginRight: 4 }} />
                  Updated: {formatLastUpdate}
                </Text>
              </Tooltip>
              <Divider type="vertical" />
              <Tooltip title="Auto-refresh countdown">
                <Tag color={autoRefreshCountdown <= 10 ? 'orange' : 'blue'} icon={<ReloadOutlined />}>
                  Next: {autoRefreshCountdown}s
                </Tag>
              </Tooltip>
            </Space>
          )}
        </Col>
        
        <Col xs={24} sm={24} md={24} lg={12} style={{ textAlign: 'right' }}>
          <Space wrap>
            <Tooltip title="Refresh all dashboard data and update cache">
              <Button 
                type="primary"
                icon={<ReloadOutlined spin={loading} />} 
                onClick={handleRefresh}
                loading={loading}
              >
                Refresh
              </Button>
            </Tooltip>
            
            <Tooltip title="Clear browser cache for filters">
              <Button 
                icon={<ClearOutlined />} 
                onClick={handleClearCache}
                disabled={!usingCache.frontends && !usingCache.backends}
              >
                Clear Cache
              </Button>
            </Tooltip>
          </Space>
        </Col>
      </Row>

      {/* Tabs Navigation */}
      <Tabs
        activeKey={activeTab}
        onChange={handleTabChange}
        type="card"
        size="large"
        destroyInactiveTabPane={false}
        animated={{ inkBar: true, tabPane: false }}
        tabBarGutter={8}
        tabBarStyle={{ 
          marginBottom: 0,
          willChange: 'transform, opacity',
          transform: 'translateZ(0)'
        }}
        style={{
          marginTop: 24,
          backgroundColor: '#fff',
          padding: '16px',
          borderRadius: 8,
          boxShadow: '0 2px 8px rgba(0,0,0,0.06)',
          contain: 'layout style paint',
          willChange: 'contents'
        }}
        items={[
          {
            key: 'overview',
            label: (
              <span>
                <DashboardOutlined /> Overview
              </span>
            ),
            children: (
              <div style={{ contain: 'layout style paint', willChange: 'auto' }}>
                <OverviewTab
                  loading={loading}
                  initialLoad={initialLoad}
                  realTimeMetricsData={realTimeMetricsData}
                  agentsStatus={agentsStatus}
                  overviewData={overviewData}
                  statsData={statsData}
                />
              </div>
            )
          },
          {
            key: 'trends',
            label: (
              <span>
                <LineChartOutlined /> Performance Trends
              </span>
            ),
            children: tabsInitialized.trends ? (
              <div style={{ contain: 'layout style paint', willChange: 'auto' }}>
                <PerformanceTrendsTab
                  loading={loading}
                  initialLoad={initialLoad}
                  requestsTimeseries={requestsTimeseries}
                  responseTimeTimeseries={responseTimeTimeseries}
                  errorsTimeseries={errorsTimeseries}
                  sessionsTimeseries={sessionsTimeseries}
                  throughputData={throughputData}
                  responseTimeHeatmapData={responseTimeHeatmapData}
                  frontendOptions={frontendOptions}
                  selectedFrontends={selectedFrontends}
                  onFrontendChange={handleFrontendChange}
                  cacheLoading={cacheLoading}
                />
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: 50 }}>
                <Spin size="large" tip="Loading performance data..." />
              </div>
            )
          },
          {
            key: 'capacity',
            label: (
              <span>
                <FundOutlined /> Capacity & Load
              </span>
            ),
            children: (
              <div style={{ contain: 'layout style paint', willChange: 'auto' }}>
                <CapacityLoadTab
                  loading={loading}
                  initialLoad={initialLoad}
                  queueData={queueData}
                  connectionRateData={connectionRateData}
                  responseCodeData={responseCodeData}
                  responseTimeData={responseTimeData}
                  httpResponses={httpResponses}
                />
              </div>
            )
          },
          {
            key: 'health',
            label: (
              <span>
                <HeartOutlined /> Health Matrix
              </span>
            ),
            children: tabsInitialized.health ? (
              <div style={{ contain: 'layout style paint', willChange: 'auto' }}>
                <HealthMatrixTab
                  loading={loading}
                  initialLoad={initialLoad}
                  healthCheckData={healthCheckData}
                  backendHealth={backendHealth}
                  slowestBackends={slowestBackends}
                  selectedBackends={selectedBackends}
                  setSelectedBackends={setSelectedBackends}
                  backendOptions={backendOptions}
                  onBackendChange={handleBackendChange}
                  cacheLoading={cacheLoading}
                />
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: 50 }}>
                <Spin size="large" tip="Loading health data..." />
              </div>
            )
          },
          {
            key: 'frontends',
            label: (
              <span>
                <GlobalOutlined /> Frontends
              </span>
            ),
            children: (
              <div style={{ contain: 'layout style paint', willChange: 'auto' }}>
                <FrontendsTab
                  loading={loading}
                  initialLoad={initialLoad}
                  frontendsData={statsData.frontends?.data}
                  selectedFrontends={selectedFrontends}
                  setSelectedFrontends={setSelectedFrontends}
                  frontendOptions={frontendOptions}
                  onFrontendChange={handleFrontendChange}
                  cacheLoading={cacheLoading}
                />
              </div>
            )
          },
          {
            key: 'backends',
            label: (
              <span>
                <DatabaseOutlined /> Backends & Servers
              </span>
            ),
            children: (
              <div style={{ contain: 'layout style paint', willChange: 'auto' }}>
                <BackendsTab
                  loading={loading}
                  initialLoad={initialLoad}
                  serversData={statsData.servers?.data}
                  statsData={statsData}
                  backendOptions={backendOptions}
                  selectedBackends={selectedBackends}
                  onBackendChange={handleBackendChange}
                  cacheLoading={cacheLoading}
                />
              </div>
            )
          }
        ]}
      />
      
      {/* Loading State for Initial Load */}
      {loading && initialLoad && (
        <div style={{ textAlign: 'center', padding: 50, marginTop: 24 }}>
          <Spin size="large" tip="Loading dashboard data..." />
        </div>
      )}
      
      {/* No Data Message */}
      {!loading && (!statsData.frontends || statsData.frontends.count === 0) && (
        <Row gutter={[24, 24]} style={{ marginTop: 24 }}>
          <Col span={24}>
            <Alert
              message="Waiting for Agent Data"
              description={
                <div>
                  <p>No HAProxy statistics available yet. This could mean:</p>
                  <ul>
                    <li>Agent hasn't sent stats data yet (heartbeat every 30 seconds)</li>
                    <li>HAProxy stats socket is not configured or accessible</li>
                    <li>Agent script needs to be updated</li>
                  </ul>
                  <p><strong>Cluster:</strong> {selectedCluster?.name || 'None'}</p>
                </div>
              }
              type="info"
              showIcon
              icon={<InfoCircleOutlined />}
            />
          </Col>
        </Row>
      )}
    </div>
  );
};

export default DashboardV2; 
