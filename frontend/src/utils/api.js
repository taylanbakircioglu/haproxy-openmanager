/**
 * API Configuration
 * Centralized API URL management for the application
 * 
 * Environment Variables:
 * - REACT_APP_API_URL: Full API URL (e.g., https://api.example.com)
 * - NODE_ENV: Environment (development, production)
 */

// Get API URL from environment or use default based on environment
const getApiUrl = () => {
  // Priority 1: Explicit environment variable
  if (process.env.REACT_APP_API_URL) {
    return process.env.REACT_APP_API_URL;
  }
  
  // Priority 2: Detect from window location (for production deployments)
  if (typeof window !== 'undefined' && window.location) {
    const { protocol, hostname } = window.location;
    
    // In production, assume API is served from same origin
    if (process.env.NODE_ENV === 'production') {
      return `${protocol}//${hostname}`;
    }
  }
  
  // Priority 3: Development default
  return 'http://localhost:8000';
};

// API Base URL
export const API_BASE_URL = getApiUrl();

/**
 * Build full API endpoint URL
 * @param {string} endpoint - API endpoint path (e.g., '/api/agents')
 * @returns {string} Full URL
 */
export const buildApiUrl = (endpoint) => {
  // Remove leading slash if present to avoid double slashes
  const cleanEndpoint = endpoint.startsWith('/') ? endpoint.slice(1) : endpoint;
  
  // Remove trailing slash from base URL if present
  const cleanBase = API_BASE_URL.endsWith('/') ? API_BASE_URL.slice(0, -1) : API_BASE_URL;
  
  return `${cleanBase}/${cleanEndpoint}`;
};

/**
 * Make authenticated API request
 * @param {string} endpoint - API endpoint
 * @param {object} options - Fetch options
 * @returns {Promise<Response>}
 */
export const authenticatedFetch = async (endpoint, options = {}) => {
  const token = localStorage.getItem('token');
  
  const defaultHeaders = {
    'Content-Type': 'application/json',
  };
  
  if (token) {
    defaultHeaders['Authorization'] = `Bearer ${token}`;
  }
  
  const url = buildApiUrl(endpoint);
  
  const fetchOptions = {
    ...options,
    headers: {
      ...defaultHeaders,
      ...options.headers,
    },
  };
  
  return fetch(url, fetchOptions);
};

/**
 * API Helper Functions
 */
export const api = {
  /**
   * GET request
   */
  get: async (endpoint) => {
    const response = await authenticatedFetch(endpoint, {
      method: 'GET',
    });
    return response;
  },
  
  /**
   * POST request
   */
  post: async (endpoint, data) => {
    const response = await authenticatedFetch(endpoint, {
      method: 'POST',
      body: JSON.stringify(data),
    });
    return response;
  },
  
  /**
   * PUT request
   */
  put: async (endpoint, data) => {
    const response = await authenticatedFetch(endpoint, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
    return response;
  },
  
  /**
   * DELETE request
   */
  delete: async (endpoint) => {
    const response = await authenticatedFetch(endpoint, {
      method: 'DELETE',
    });
    return response;
  },
  
  /**
   * PATCH request
   */
  patch: async (endpoint, data) => {
    const response = await authenticatedFetch(endpoint, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
    return response;
  },
};

// Export for debugging
if (process.env.NODE_ENV === 'development') {
  console.log(`[API Config] Base URL: ${API_BASE_URL}`);
  console.log(`[API Config] Environment: ${process.env.NODE_ENV}`);
  console.log(`[API Config] REACT_APP_API_URL: ${process.env.REACT_APP_API_URL || 'not set'}`);
}

export default api;

