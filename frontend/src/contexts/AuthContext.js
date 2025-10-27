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

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [userRoles, setUserRoles] = useState([]);
  const [userPermissions, setUserPermissions] = useState({});

  const initializeAuth = useCallback(async () => {
    try {
      // Try both token keys for compatibility
      const token = localStorage.getItem('token') || localStorage.getItem('authToken');
      const userData = localStorage.getItem('userData');
      const tokenExpiry = localStorage.getItem('tokenExpiry');
      const roles = localStorage.getItem('userRoles');
      const permissions = localStorage.getItem('userPermissions');

      if (token && userData && tokenExpiry) {
        // Check if token is expired
        const expiryDate = new Date(tokenExpiry);
        const now = new Date();

        if (expiryDate > now) {
          // Token is still valid
          setUser(JSON.parse(userData));
          setUserRoles(roles ? JSON.parse(roles) : []);
          setUserPermissions(permissions ? JSON.parse(permissions) : {});
          setIsAuthenticated(true);

          // Set axios default header
          axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
        } else {
          // Token expired, clear storage
          clearAuth();
          message.warning('Your session has expired. Please login again.');
        }
      }
    } catch (error) {
      console.error('Error initializing auth:', error);
      clearAuth();
    } finally {
      setLoading(false);
    }
  }, []);

  // Initialize authentication state from localStorage
  useEffect(() => {
    initializeAuth();
  }, [initializeAuth]);

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