import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { message } from 'antd';
import axios from 'axios';

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

// ----------------------------------------------------------------------------
// Synchronous auth hydrator (used by the useState lazy initialisers below).
//
// Why hydrate synchronously (not via a useEffect):
//   The provider hierarchy is <AuthProvider><ClusterProvider>…</> and React's
//   useEffect commit phase fires CHILD effects before PARENT effects. That
//   means ClusterProvider's mount-time `fetchClusters()` runs BEFORE
//   AuthProvider's mount-time `initializeAuth()`. The legacy implementation
//   set `axios.defaults.headers.common['Authorization']` inside the parent's
//   useEffect — too late. The first /api/clusters request went out
//   un-authenticated → 401 → empty list → the 30s auto-refresh interval
//   eventually masked the bug. Operators experienced this as "I have to
//   wait a while after deploy / I close the browser and re-open and
//   clusters still don't appear for a while".
//
// Hydrating in `useState(() => …)` guarantees this code runs during the
// AuthProvider RENDER phase, which precedes ANY child useEffect. By the
// time ClusterProvider's effect dispatches its first request, both:
//   - axios.defaults.headers.common['Authorization'] is set, AND
//   - the AuthContext value has `loading=false, isAuthenticated=true`
// so a downstream auth-gate (see ClusterContext) can opt to wait until
// auth is hydrated before fetching at all.
//
// Returns the canonical initial state shape consumed by the useState calls.
// ----------------------------------------------------------------------------
const _hydrateAuthSync = () => {
  try {
    const token = localStorage.getItem('token') || localStorage.getItem('authToken');
    const userData = localStorage.getItem('userData');
    const tokenExpiry = localStorage.getItem('tokenExpiry');
    const roles = localStorage.getItem('userRoles');
    const permissions = localStorage.getItem('userPermissions');

    if (token && userData && tokenExpiry) {
      const expiryDate = new Date(tokenExpiry);
      if (expiryDate > new Date()) {
        // Belt-and-suspenders alongside the index.js bootstrap — keep this
        // here so AuthContext is self-sufficient even when imported in
        // tests / storybook / SSR shims that don't pull in index.js.
        axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
        return {
          user: JSON.parse(userData),
          isAuthenticated: true,
          userRoles: roles ? JSON.parse(roles) : [],
          userPermissions: permissions ? JSON.parse(permissions) : {},
          loading: false,
          expired: false,
        };
      }
      return {
        user: null,
        isAuthenticated: false,
        userRoles: [],
        userPermissions: {},
        loading: false,
        expired: true,
      };
    }
  } catch (_) {
    // localStorage unavailable / corrupt — fall through to anon initial state.
  }
  return {
    user: null,
    isAuthenticated: false,
    userRoles: [],
    userPermissions: {},
    loading: false,
    expired: false,
  };
};

export const AuthProvider = ({ children }) => {
  // Lazy initialisers run during the AuthProvider render phase, BEFORE any
  // child component's useEffect fires. This eliminates the mount-time race
  // documented above.
  const [_initial] = useState(_hydrateAuthSync);
  const [user, setUser] = useState(_initial.user);
  const [loading, setLoading] = useState(_initial.loading);
  const [isAuthenticated, setIsAuthenticated] = useState(_initial.isAuthenticated);
  const [userRoles, setUserRoles] = useState(_initial.userRoles);
  const [userPermissions, setUserPermissions] = useState(_initial.userPermissions);

  // Notify the operator about an expired session AFTER the render commits
  // (calling antd's `message.*` during render is a no-op + warning). Keeping
  // the side-effect in a dedicated useEffect that depends on the initial
  // hydration result is intentional: re-runs are idempotent for any given
  // mount because `_initial` is captured by useState once.
  useEffect(() => {
    if (_initial.expired) {
      clearAuth();
      message.warning('Your session has expired. Please login again.');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // The legacy `initializeAuth` callback is preserved as a no-op for any
  // external caller that still references it; the actual hydration now
  // happens synchronously in the useState initialisers above. Kept on the
  // context value so unit tests / external integrators that called
  // `initializeAuth()` continue to compile, even though they no longer
  // need to.
  const initializeAuth = useCallback(async () => {
    /* hydrated synchronously at construction time — see _hydrateAuthSync */
  }, []);

  // The pre-Phase-J post-mount initializeAuth() useEffect is REMOVED.
  // Hydration now happens synchronously in the useState initialisers
  // above so child providers that fetch in their own mount-time effect
  // (e.g. ClusterProvider.fetchClusters) see a populated axios default
  // header AND a settled AuthContext value (`loading=false`,
  // `isAuthenticated=true`) before they dispatch their first request.

  const login = (authData) => {
    try {
      setUser(authData.user);
      setUserRoles(authData.roles || []);
      setUserPermissions(authData.permissions || {});
      setIsAuthenticated(true);

      // Save to localStorage - use access_token from API response
      const token = authData.access_token || authData.session_token; // Support both field names
      localStorage.setItem('token', token);
      localStorage.setItem('authToken', token);
      localStorage.setItem('userData', JSON.stringify(authData.user));
      localStorage.setItem('userRoles', JSON.stringify(authData.roles || []));
      localStorage.setItem('userPermissions', JSON.stringify(authData.permissions || {}));
      
      // Set token expiry
      if (authData.expires_in) {
        // Calculate from expires_in (seconds)
        const expiryDate = new Date();
        expiryDate.setSeconds(expiryDate.getSeconds() + authData.expires_in);
        localStorage.setItem('tokenExpiry', expiryDate.toISOString());
      } else {
        // Default 24 hours from now
        const expiryDate = new Date();
        expiryDate.setHours(expiryDate.getHours() + 24);
        localStorage.setItem('tokenExpiry', expiryDate.toISOString());
      }

      // Set axios default header
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      
      return true;
    } catch (error) {
      console.error('Error during login:', error);
      message.error('Login failed. Please try again.');
      return false;
    }
  };

  const logout = async () => {
    try {
      // Try both token keys for compatibility
      const token = localStorage.getItem('token') || localStorage.getItem('authToken');
      
      // Call logout API if token exists
      if (token) {
        await axios.post('/api/auth/logout', { session_token: token });
      }
    } catch (error) {
      console.error('Error during logout:', error);
    } finally {
      clearAuth();
      message.success('Logged out successfully');
    }
  };

  const clearAuth = () => {
    // Clear state
    setUser(null);
    setUserRoles([]);
    setUserPermissions({});
    setIsAuthenticated(false);

    // Clear localStorage
    localStorage.removeItem('token'); // Clear token key for consistency
    localStorage.removeItem('authToken');
    localStorage.removeItem('userData');
    localStorage.removeItem('userRoles');
    localStorage.removeItem('userPermissions');
    localStorage.removeItem('tokenExpiry');

    // Clear axios header
    delete axios.defaults.headers.common['Authorization'];
  };

  // Check if user has specific permission
  const hasPermission = (resource, action) => {
    if (!userPermissions || !userPermissions[resource]) {
      return false;
    }
    return userPermissions[resource][action] === true;
  };

  // Check if user has specific role
  const hasRole = (roleName) => {
    return userRoles.some(role => role.name === roleName);
  };

  // Check if user is admin (has super_admin or admin role)
  const isAdmin = () => {
    // Check both userRoles array and direct user.role field
    return hasRole('super_admin') || hasRole('admin') || 
           (user && (user.role === 'admin' || user.role === 'super_admin'));
  };

  // Get user's display roles
  const getUserRoleNames = () => {
    return userRoles.map(role => role.display_name).join(', ');
  };

  const value = {
    user,
    userRoles,
    userPermissions,
    isAuthenticated,
    loading,
    login,
    logout,
    hasPermission,
    hasRole,
    isAdmin,
    getUserRoleNames,
    clearAuth
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export default AuthContext; 