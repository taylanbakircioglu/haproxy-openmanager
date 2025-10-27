import React, { createContext, useContext, useState, useEffect } from 'react';
import { verifyRealAgentSync, waitForEntitySync } from '../utils/agentSync';

// Progress Context for global state management
const ProgressContext = createContext();

export const useProgress = () => {
  const context = useContext(ProgressContext);
  if (!context) {
    throw new Error('useProgress must be used within a ProgressProvider');
  }
  return context;
};

export const ProgressProvider = ({ children }) => {
  const [globalProgress, setGlobalProgress] = useState({
    visible: false,
    step: '',
    progress: 0,
    type: null, // 'apply', 'sync', 'deploy', etc.
    startTime: null,
    details: {},
    entityCounts: { synced: 0, total: 0 },
    agentCounts: { synced: 0, total: 0 }
  });

  // Auto-hide progress after completion
  useEffect(() => {
    if (globalProgress.progress === 100 && globalProgress.visible) {
      const timer = setTimeout(() => {
        setGlobalProgress(prev => ({
          ...prev,
          visible: false,
          step: '',
          progress: 0,
          type: null,
          startTime: null,
          details: {}
        }));
      }, 2000); // Hide after 2 seconds

      return () => clearTimeout(timer);
    }
  }, [globalProgress.progress, globalProgress.visible]);

  const startProgress = (type, initialStep = 'Starting...') => {
    setGlobalProgress({
      visible: true,
      step: initialStep,
      progress: 0,
      type,
      startTime: new Date(),
      details: {}
    });
  };

  const updateProgress = (step, progress, details = {}) => {
    setGlobalProgress(prev => ({
      ...prev,
      step,
      progress: Math.min(Math.max(progress, 0), 100), // Clamp between 0-100
      details: { ...prev.details, ...details }
    }));
  };

  const updateEntityCounts = (syncedEntities, totalEntities, syncedAgents, totalAgents) => {
    setGlobalProgress(prev => ({
      ...prev,
      entityCounts: { synced: syncedEntities || 0, total: totalEntities || 0 },
      agentCounts: { synced: syncedAgents || 0, total: totalAgents || 0 }
    }));
  };

  const completeProgress = (finalStep = 'Completed!') => {
    setGlobalProgress(prev => ({
      ...prev,
      step: finalStep,
      progress: 100
    }));
  };

  const hideProgress = () => {
    setGlobalProgress({
      visible: false,
      step: '',
      progress: 0,
      type: null,
      startTime: null,
      details: {}
    });
  };

  const isProgressActive = () => {
    return globalProgress.visible && globalProgress.progress < 100;
  };

  const getElapsedTime = () => {
    if (!globalProgress.startTime) return 0;
    return Math.floor((new Date() - globalProgress.startTime) / 1000);
  };

  const value = {
    progress: globalProgress,
    startProgress,
    updateProgress,
    updateEntityCounts,
    completeProgress,
    hideProgress,
    isProgressActive,
    getElapsedTime,
    verifyRealAgentSync,
    waitForEntitySync
  };

  return (
    <ProgressContext.Provider value={value}>
      {children}
    </ProgressContext.Provider>
  );
};
