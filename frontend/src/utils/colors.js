// Consistent color scheme for the entire application
export const COLORS = {
  // Agent Sync Status Colors (Balanced soft colors)
  AGENT_SYNC: {
    SYNCED: '#52c41a',      // Standard Green - fully synced (like Config Status APPLIED)
    SYNCING: '#1890ff',     // Blue - syncing in progress  
    ERROR: '#ff7875',       // Balanced Soft Red - sync error (softer than bright red)
    UNKNOWN: '#d9d9d9'      // Gray - unknown status
  },
  
  // Config Status Colors  
  CONFIG_STATUS: {
    APPLIED: '#52c41a',     // Standard Green - applied successfully
    PENDING: '#fa8c16',     // Orange - pending changes
    REJECTED: '#ff7875'     // Balanced Soft Red - rejected changes
  },
  
  // Entity Status Colors
  ENTITY_STATUS: {
    ACTIVE: '#52c41a',      // Standard Green - active entity
    INACTIVE: '#ff7875'     // Balanced Soft Red - inactive entity  
  },
  
  // Progress Colors
  PROGRESS: {
    ACTIVE: '#1890ff',      // Blue - in progress
    SUCCESS: '#52c41a',     // Standard Green - completed
    ERROR: '#ff7875'        // Balanced Soft Red - failed
  },
  
  // SSL Certificate Status Colors
  SSL_STATUS: {
    VALID: '#52c41a',       // Standard Green - certificate valid
    EXPIRING_SOON: '#fa8c16', // Orange - expiring within 30 days
    EXPIRED: '#ff7875',     // Balanced Soft Red - certificate expired
    UNKNOWN: '#d9d9d9'      // Gray - unknown expiry status
  }
};

// Helper functions for consistent color usage
export const getAgentSyncColor = (syncedAgents, totalAgents, status = null) => {
  if (status === 'error') return COLORS.AGENT_SYNC.ERROR;
  if (status === 'syncing') return COLORS.AGENT_SYNC.SYNCING;
  if (syncedAgents === totalAgents) return COLORS.AGENT_SYNC.SYNCED;
  if (syncedAgents < totalAgents) return COLORS.AGENT_SYNC.ERROR;
  return COLORS.AGENT_SYNC.UNKNOWN;
};

export const getConfigStatusColor = (status) => {
  switch (status?.toUpperCase()) {
    case 'APPLIED': return 'green';    // Standard Ant Design green
    case 'PENDING': return 'orange';   // Standard Ant Design orange  
    case 'REJECTED': return 'red';     // Standard Ant Design red
    default: return 'default';         // Standard Ant Design default
  }
};

export const getEntityStatusColor = (isActive) => {
  return isActive ? COLORS.ENTITY_STATUS.ACTIVE : COLORS.ENTITY_STATUS.INACTIVE;
};

// SSL Certificate expiry helper function
export const getSSLExpiryInfo = (expiryDate) => {
  if (!expiryDate) {
    return { 
      color: COLORS.SSL_STATUS.UNKNOWN, 
      status: 'Unknown', 
      progress: 0,
      daysLeft: 0,
      tagColor: 'default'
    };
  }
  
  const now = new Date();
  const expiry = new Date(expiryDate);
  const totalDays = 365; // Assume 1 year certificate validity for progress calculation
  const daysUntilExpiry = Math.ceil((expiry - now) / (1000 * 60 * 60 * 24));
  
  // Calculate progress percentage (0-100)
  const progress = Math.max(0, Math.min(100, (daysUntilExpiry / totalDays) * 100));
  
  if (daysUntilExpiry < 0) {
    return { 
      color: COLORS.SSL_STATUS.EXPIRED, 
      status: 'Expired', 
      progress: 0,
      daysLeft: daysUntilExpiry,
      tagColor: 'red'
    };
  } else if (daysUntilExpiry <= 30) {
    return { 
      color: COLORS.SSL_STATUS.EXPIRING_SOON, 
      status: `${daysUntilExpiry}d left`, 
      progress: Math.max(10, progress), // Minimum 10% for visibility
      daysLeft: daysUntilExpiry,
      tagColor: 'orange'
    };
  } else {
    return { 
      color: COLORS.SSL_STATUS.VALID, 
      status: `${daysUntilExpiry}d left`, 
      progress: progress,
      daysLeft: daysUntilExpiry,
      tagColor: 'green'
    };
  }
};
