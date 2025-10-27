/**
 * Dashboard Browser-Side Cache Manager
 * Provides persistent caching for frontend/backend lists with TTL
 * Uses IndexedDB with LocalStorage fallback
 */

const CACHE_VERSION = 'v1';
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes in milliseconds
const CACHE_KEYS = {
  FRONTENDS: 'dashboard_frontends',
  BACKENDS: 'dashboard_backends'
};

class DashboardCache {
  constructor() {
    this.useIndexedDB = this._checkIndexedDBSupport();
    this.dbName = 'haproxy_dashboard_cache';
    this.storeName = 'filters';
    this.db = null;
    
    if (this.useIndexedDB) {
      this._initIndexedDB();
    }
  }

  /**
   * Check if IndexedDB is supported
   */
  _checkIndexedDBSupport() {
    try {
      return 'indexedDB' in window && window.indexedDB !== null;
    } catch (e) {
      return false;
    }
  }

  /**
   * Initialize IndexedDB
   */
  async _initIndexedDB() {
    if (!this.useIndexedDB || this.db) return;

    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, 1);

      request.onerror = () => {
        console.warn('IndexedDB failed to open, falling back to LocalStorage');
        this.useIndexedDB = false;
        reject(request.error);
      };

      request.onsuccess = () => {
        this.db = request.result;
        resolve(this.db);
      };

      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        
        // Create object store if it doesn't exist
        if (!db.objectStoreNames.contains(this.storeName)) {
          db.createObjectStore(this.storeName, { keyPath: 'key' });
        }
      };
    });
  }

  /**
   * Generate cache key with cluster ID
   */
  _getCacheKey(type, clusterId) {
    return `${CACHE_KEYS[type]}_${clusterId}_${CACHE_VERSION}`;
  }

  /**
   * Check if cached data is still valid (not expired)
   */
  _isValid(cachedData) {
    if (!cachedData || !cachedData.timestamp) {
      return false;
    }

    const now = Date.now();
    const age = now - cachedData.timestamp;
    return age < CACHE_TTL;
  }

  /**
   * Get data from IndexedDB
   */
  async _getFromIndexedDB(key) {
    if (!this.db) {
      await this._initIndexedDB();
    }

    if (!this.db) {
      return null;
    }

    return new Promise((resolve) => {
      try {
        const transaction = this.db.transaction([this.storeName], 'readonly');
        const store = transaction.objectStore(this.storeName);
        const request = store.get(key);

        request.onsuccess = () => {
          resolve(request.result ? request.result.data : null);
        };

        request.onerror = () => {
          console.warn('IndexedDB read error, falling back to LocalStorage');
          resolve(null);
        };
      } catch (error) {
        console.warn('IndexedDB transaction error:', error);
        resolve(null);
      }
    });
  }

  /**
   * Set data in IndexedDB
   */
  async _setInIndexedDB(key, data) {
    if (!this.db) {
      await this._initIndexedDB();
    }

    if (!this.db) {
      return false;
    }

    return new Promise((resolve) => {
      try {
        const transaction = this.db.transaction([this.storeName], 'readwrite');
        const store = transaction.objectStore(this.storeName);
        const request = store.put({ key, data });

        request.onsuccess = () => resolve(true);
        request.onerror = () => {
          console.warn('IndexedDB write error');
          resolve(false);
        };
      } catch (error) {
        console.warn('IndexedDB transaction error:', error);
        resolve(false);
      }
    });
  }

  /**
   * Get data from LocalStorage (fallback)
   */
  _getFromLocalStorage(key) {
    try {
      const item = localStorage.getItem(key);
      return item ? JSON.parse(item) : null;
    } catch (error) {
      console.error('LocalStorage read error:', error);
      return null;
    }
  }

  /**
   * Set data in LocalStorage (fallback)
   */
  _setInLocalStorage(key, data) {
    try {
      localStorage.setItem(key, JSON.stringify(data));
      return true;
    } catch (error) {
      console.error('LocalStorage write error (quota exceeded?):', error);
      return false;
    }
  }

  /**
   * Get cached frontends for a cluster
   * @param {number} clusterId - Cluster ID
   * @returns {Promise<Array|null>} - Cached frontends or null if expired/not found
   */
  async getFrontends(clusterId) {
    const key = this._getCacheKey('FRONTENDS', clusterId);
    
    let cachedData = null;
    
    if (this.useIndexedDB) {
      cachedData = await this._getFromIndexedDB(key);
    } else {
      cachedData = this._getFromLocalStorage(key);
    }

    if (this._isValid(cachedData)) {
      if (process.env.NODE_ENV === 'development') {
        console.log(`✅ Cache HIT: Frontends for cluster ${clusterId} (age: ${Math.round((Date.now() - cachedData.timestamp) / 1000)}s)`);
      }
      return cachedData.data;
    }

    if (process.env.NODE_ENV === 'development') {
      console.log(`❌ Cache MISS: Frontends for cluster ${clusterId}`);
    }
    return null;
  }

  /**
   * Get cached backends for a cluster
   * @param {number} clusterId - Cluster ID
   * @returns {Promise<Array|null>} - Cached backends or null if expired/not found
   */
  async getBackends(clusterId) {
    const key = this._getCacheKey('BACKENDS', clusterId);
    
    let cachedData = null;
    
    if (this.useIndexedDB) {
      cachedData = await this._getFromIndexedDB(key);
    } else {
      cachedData = this._getFromLocalStorage(key);
    }

    if (this._isValid(cachedData)) {
      if (process.env.NODE_ENV === 'development') {
        console.log(`✅ Cache HIT: Backends for cluster ${clusterId} (age: ${Math.round((Date.now() - cachedData.timestamp) / 1000)}s)`);
      }
      return cachedData.data;
    }

    if (process.env.NODE_ENV === 'development') {
      console.log(`❌ Cache MISS: Backends for cluster ${clusterId}`);
    }
    return null;
  }

  /**
   * Cache frontends for a cluster
   * @param {number} clusterId - Cluster ID
   * @param {Array} frontends - Array of frontend names
   * @returns {Promise<boolean>} - Success status
   */
  async setFrontends(clusterId, frontends) {
    const key = this._getCacheKey('FRONTENDS', clusterId);
    const cacheData = {
      data: frontends,
      timestamp: Date.now(),
      clusterId
    };

    let success = false;

    if (this.useIndexedDB) {
      success = await this._setInIndexedDB(key, cacheData);
    }
    
    // Always try LocalStorage as fallback or backup
    if (!success || !this.useIndexedDB) {
      success = this._setInLocalStorage(key, cacheData);
    }

    if (success && process.env.NODE_ENV === 'development') {
      console.log(`💾 Cached ${frontends.length} frontends for cluster ${clusterId}`);
    }

    return success;
  }

  /**
   * Cache backends for a cluster
   * @param {number} clusterId - Cluster ID
   * @param {Array} backends - Array of backend names
   * @returns {Promise<boolean>} - Success status
   */
  async setBackends(clusterId, backends) {
    const key = this._getCacheKey('BACKENDS', clusterId);
    const cacheData = {
      data: backends,
      timestamp: Date.now(),
      clusterId
    };

    let success = false;

    if (this.useIndexedDB) {
      success = await this._setInIndexedDB(key, cacheData);
    }
    
    // Always try LocalStorage as fallback or backup
    if (!success || !this.useIndexedDB) {
      success = this._setInLocalStorage(key, cacheData);
    }

    if (success && process.env.NODE_ENV === 'development') {
      console.log(`💾 Cached ${backends.length} backends for cluster ${clusterId}`);
    }

    return success;
  }

  /**
   * Invalidate cache for a specific cluster
   * @param {number} clusterId - Cluster ID
   */
  async invalidateCluster(clusterId) {
    const frontendKey = this._getCacheKey('FRONTENDS', clusterId);
    const backendKey = this._getCacheKey('BACKENDS', clusterId);

    if (this.useIndexedDB && this.db) {
      try {
        const transaction = this.db.transaction([this.storeName], 'readwrite');
        const store = transaction.objectStore(this.storeName);
        store.delete(frontendKey);
        store.delete(backendKey);
      } catch (error) {
        console.warn('IndexedDB delete error:', error);
      }
    }

    // Also clear from LocalStorage
    try {
      localStorage.removeItem(frontendKey);
      localStorage.removeItem(backendKey);
    } catch (error) {
      console.error('LocalStorage delete error:', error);
    }

    console.log(`🗑️  Invalidated cache for cluster ${clusterId}`);
  }

  /**
   * Clear all cache (useful for logout or major updates)
   */
  async clearAll() {
    if (this.useIndexedDB && this.db) {
      try {
        const transaction = this.db.transaction([this.storeName], 'readwrite');
        const store = transaction.objectStore(this.storeName);
        store.clear();
      } catch (error) {
        console.warn('IndexedDB clear error:', error);
      }
    }

    // Clear from LocalStorage
    try {
      const keysToRemove = [];
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && (key.startsWith('dashboard_frontends_') || key.startsWith('dashboard_backends_'))) {
          keysToRemove.push(key);
        }
      }
      keysToRemove.forEach(key => localStorage.removeItem(key));
    } catch (error) {
      console.error('LocalStorage clear error:', error);
    }

    console.log('🗑️  Cleared all dashboard cache');
  }

  /**
   * Get cache statistics
   */
  async getStats() {
    const stats = {
      storage: this.useIndexedDB ? 'IndexedDB' : 'LocalStorage',
      ttl: CACHE_TTL / 1000 + ' seconds',
      version: CACHE_VERSION
    };

    if (this.useIndexedDB && this.db) {
      try {
        const transaction = this.db.transaction([this.storeName], 'readonly');
        const store = transaction.objectStore(this.storeName);
        const countRequest = store.count();
        
        await new Promise((resolve) => {
          countRequest.onsuccess = () => {
            stats.itemsCount = countRequest.result;
            resolve();
          };
          countRequest.onerror = () => resolve();
        });
      } catch (error) {
        console.warn('Failed to get cache stats:', error);
      }
    }

    return stats;
  }
}

// Export singleton instance
export const dashboardCache = new DashboardCache();
export default dashboardCache;

