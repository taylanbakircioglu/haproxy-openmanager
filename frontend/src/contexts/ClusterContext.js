import React, { createContext, useContext, useState, useEffect, useRef, useCallback } from 'react';
import axios from 'axios';
import { useAuth } from './AuthContext';

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
  const [agentHealthByPool, setAgentHealthByPool] = useState({});  // Deprecated but kept for backward compatibility
  const [loading, setLoading] = useState(true);

  // Phase J fix — auth-gate the initial fetch.
  //
  // Before this fix the mount-time fetch raced AuthProvider's effect (see
  // AuthContext.js for the long-form explanation) and the first
  // /api/clusters request went out un-authenticated → 401 → empty list →
  // operators saw "no clusters" until the 30s auto-refresh interval
  // happened to land AFTER auth had hydrated.
  //
  // We now consume `isAuthenticated` from AuthContext (which is hydrated
  // synchronously in useState initialisers, so it's already truthy by the
  // time this provider renders) and:
  //   - skip fetching entirely while the user is not authenticated
  //     (login screen does its own thing);
  //   - retry the fetch with short exponential backoff if it fails despite
  //     auth being settled (covers transient k8s rolling-update windows
  //     where the new pod is Ready but kube-proxy iptables haven't
  //     converged yet).
  const { isAuthenticated, loading: authLoading } = useAuth();
  const retryTimerRef = useRef(null);
  const retryAttemptRef = useRef(0);

  // Phase J audit fix #2 — Avoid the stale-closure regression that the
  // first cut of this commit introduced.
  //
  // The legacy fetchClusters was a plain function (re-defined on every
  // render), so `selectedCluster?.id` inside its body always saw the
  // current state. When this commit wrapped fetchClusters with
  // `useCallback(…, [])` to give the auto-refresh interval a stable
  // reference, the closure froze `selectedCluster` to its initial value
  // (`null`), breaking the "update existing selection with fresh agent
  // data" branch — which is the WHOLE point of the 30-second
  // auto-refresh: it keeps the selector dot-indicator in sync with
  // agent heartbeats. Functional fall-through (savedClusterId from
  // localStorage) still rebinds to the user's selection so the UI
  // doesn't jump, but the operator-visible "agent health dot" went
  // stale across refreshes.
  //
  // The fix mirrors the well-known React pattern: keep the value the
  // callback needs in a ref, update the ref via a passive effect, and
  // read the ref inside the (stable) callback. The result preserves
  // the legacy live-state semantics AND keeps fetchClusters reference
  // stable for the useEffect deps array.
  const selectedClusterRef = useRef(null);
  useEffect(() => {
    selectedClusterRef.current = selectedCluster;
  }, [selectedCluster]);

  // Fetch all clusters
  const fetchClusters = useCallback(async () => {
    try {
      const response = await axios.get('/api/clusters', {
        headers: {
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache'
        }
      });
      // Successful response — clear any pending retry timer that might
      // have been queued by an earlier transient failure on this mount.
      if (retryTimerRef.current) {
        clearTimeout(retryTimerRef.current);
        retryTimerRef.current = null;
      }
      retryAttemptRef.current = 0;
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
      
      // Set or update selected cluster
      if (response.data.clusters.length > 0) {
        const defaultCluster = response.data.clusters.find(c => c.is_default);
        const savedClusterId = localStorage.getItem('selectedClusterId');
        
        // CRITICAL FIX: Update selectedCluster with fresh data if it exists in new clusters
        // This ensures agent status dot indicator stays current. Read via the ref
        // so the stable useCallback above sees the LIVE selectedCluster value
        // (see the "Phase J audit fix #2" comment for context).
        const currentSelectedId = selectedClusterRef.current?.id;
        
        if (currentSelectedId) {
          // Update existing selection with fresh data
          const updatedCluster = clustersData.find(c => c.id === currentSelectedId);
          if (updatedCluster) {
            setSelectedCluster(updatedCluster);  // Update with fresh agent health data
          } else {
            // Selected cluster no longer exists, fall back to default
            setSelectedCluster(defaultCluster || clustersData[0]);
          }
        } else if (savedClusterId) {
          // Initial load from localStorage
          const savedCluster = clustersData.find(c => c.id === parseInt(savedClusterId));
          if (savedCluster) {
            setSelectedCluster(savedCluster);
          } else {
            setSelectedCluster(defaultCluster || clustersData[0]);
          }
        } else {
          // No saved preference, use default
          setSelectedCluster(defaultCluster || clustersData[0]);
        }
      } else {
        // No clusters available - clear selection
        setSelectedCluster(null);
        localStorage.removeItem('selectedClusterId');
      }
    } catch (error) {
      console.error('Failed to fetch clusters:', error);
      // Phase J: short exponential-backoff retry instead of immediately
      // committing an empty list. The empty-state commit was the visible
      // symptom of the old mount-time race AND of the kube-proxy
      // convergence window after a rolling restart — operators saw "no
      // clusters" for up to 30s (the auto-refresh interval) until the
      // next scheduled retry happened to land. With auth-gate + 4 fast
      // retries (1s, 2s, 4s, 8s; total ~15s) the worst-case window
      // collapses to "≤ a few seconds" without ever surfacing an empty
      // list to the operator.
      //
      // We DO NOT clear the cluster list here — preserving the previous
      // value avoids the "everything blanks out" flash on a transient
      // hiccup of the periodic 30s refresh.
      const status = error && error.response && error.response.status;
      // For 401/403, do NOT retry — re-auth is required and the auth
      // layer will surface its own UI. For network errors and 5xx,
      // retry up to 4 times with exponential backoff.
      const transient = !status || status >= 500;
      if (transient && retryAttemptRef.current < 4) {
        const attempt = retryAttemptRef.current;
        retryAttemptRef.current = attempt + 1;
        const delayMs = Math.min(8000, 1000 * Math.pow(2, attempt));
        if (retryTimerRef.current) clearTimeout(retryTimerRef.current);
        retryTimerRef.current = setTimeout(() => {
          retryTimerRef.current = null;
          fetchClusters();
        }, delayMs);
      } else {
        // Non-retryable (auth) or retries exhausted — settle into the
        // empty state so the rest of the UI can render its "no cluster
        // selected" affordances.
        setClusters([]);
        setSelectedCluster(null);
        localStorage.removeItem('selectedClusterId');
        // Phase J audit fix #5 — Reset the retry counter once we've
        // settled. Without this reset, an exhausted retry chain (4
        // transient failures in a row) left `retryAttemptRef=4` and
        // any subsequent fetchClusters() invocation (the 30s
        // background refresh, an explicit `fetchClusters()` call from
        // a mutator like deleteCluster, etc.) would skip retries
        // entirely on the first transient failure and dump the user
        // straight into the empty state — defeating the whole point
        // of having a retry budget on transient errors. The mount-
        // time effect resets this counter too, but only when the auth
        // gate flips (login/logout); without this reset the counter
        // would carry the exhausted value across an entire user
        // session.
        retryAttemptRef.current = 0;
      }
    } finally {
      // Phase J audit fix #4 — Don't flip the global loading flag off
      // while a retry is still queued. Without this guard, a transient
      // first-fetch failure produced the following timeline:
      //   t=0   setLoading(true), clusters=[]
      //   t=0+  fetchClusters() in flight
      //   t=Δ   response fails → catch schedules a retry timer →
      //         finally setLoading(false)
      //   t=Δ   UI sees `loading=false + clusters=[]` and renders
      //         "No Cluster Selected" between retry waves
      //   t=Δ+1s retry succeeds → clusters populated → re-render
      // Up to 15 seconds (max 4 retries: 1s+2s+4s+8s) of "No Cluster
      // Selected" was visible to the operator, exactly the symptom
      // Phase J was supposed to eliminate. By only releasing
      // `loading=false` when no retry is queued, the spinner stays
      // visible across the entire retry budget so the operator never
      // sees the misleading empty state.
      if (retryTimerRef.current === null) {
        setLoading(false);
      }
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

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
    // Phase J auth-gate: wait until AuthContext has hydrated AND the
    // user is actually logged in before issuing the first /api/clusters
    // request. AuthContext now hydrates synchronously in useState
    // initialisers, so on a normal page load `authLoading` is already
    // false and `isAuthenticated` is already truthy by the time this
    // effect fires — but we still gate explicitly to:
    //   1) cover the login flow where `isAuthenticated` flips from false
    //      to true after the user submits credentials, and
    //   2) avoid a wasted 401 round-trip on the public login page.
    if (authLoading) return undefined;
    if (!isAuthenticated) {
      // Reset cluster state to anonymous defaults so a session swap
      // (logout → login as different user) doesn't show stale data
      // from the previous session.
      setClusters([]);
      setSelectedCluster(null);
      setLoading(false);
      return undefined;
    }

    // Reset retry counter for this mount — any pending timer from a
    // previous gate transition has already been cleared when this
    // effect re-runs because of the cleanup function below.
    retryAttemptRef.current = 0;
    // Phase J audit fix #3 — Surface a "loading" state for the very
    // first fetch of this auth gate. Without this, the login flow
    // briefly rendered `loading=false + clusters=[]` (because the
    // pre-login `!isAuthenticated` branch already settled
    // `loading=false`). Downstream consumers — Frontends, Backend
    // Servers, SSL Certificate Management, etc. — interpreted that
    // as "the cluster list has loaded and there are zero clusters"
    // and rendered the "No Cluster Selected" affordance for the
    // 1-2 seconds it took /api/clusters to round-trip after login.
    // We do NOT toggle loading on the 30s background refresh ticks
    // because the interval handler calls fetchClusters() directly,
    // and a periodic spinner would flicker the UI on every tick.
    setLoading(true);
    fetchClusters();

    // Auto-refresh cluster status every 30 seconds to keep agent health
    // updated. This complements the new exponential-backoff retry: the
    // retry covers "first fetch of this mount fails", the interval
    // covers "agent comes online / goes offline mid-session".
    const refreshInterval = setInterval(() => {
      fetchClusters();
    }, 30000);

    return () => {
      clearInterval(refreshInterval);
      if (retryTimerRef.current) {
        clearTimeout(retryTimerRef.current);
        retryTimerRef.current = null;
      }
    };
  }, [isAuthenticated, authLoading, fetchClusters]);

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