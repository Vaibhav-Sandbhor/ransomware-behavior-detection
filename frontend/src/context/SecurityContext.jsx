import React, { createContext, useContext, useState, useCallback } from 'react';

const SecurityContext = createContext();

export function SecurityProvider({ children }) {
  const [timelineData, setTimelineData] = useState([]);
  const [currentData, setCurrentData] = useState({
    ransomware: 0,
    port_scan: 0,
    honeypot: 0,
  });
  const [previousData, setPreviousData] = useState({
    ransomware: 0,
    port_scan: 0,
    honeypot: 0,
  });
  const [isScanning, setIsScanning] = useState(false);

  // Calculate percentage change using exact logic
  const calculateChange = useCallback((current, previous) => {
    if (previous === 0) {
      if (current === 0) return 0;
      return 100;
    }
    return Math.round(((current - previous) / previous) * 100);
  }, []);

  // Reset timeline when starting new scan
  const resetTimeline = useCallback(() => {
    setTimelineData([]);
    setPreviousData({ ransomware: 0, port_scan: 0, honeypot: 0 });
  }, []);

  // Add new data point to timeline
  const addDataPoint = useCallback((data) => {
    // Ensure data has all three fields
    const newPoint = {
      timestamp: data.timestamp || new Date().toLocaleTimeString(),
      ransomware: data.ransomware ?? 0,
      port_scan: data.port_scan ?? 0,
      honeypot: data.honeypot ?? 0,
    };

    setTimelineData((prev) => {
      // Avoid duplicate timestamps
      if (prev.some((p) => p.timestamp === newPoint.timestamp)) {
        return prev;
      }
      const updated = [...prev, newPoint];
      // Keep last 48 points
      if (updated.length > 48) {
        return updated.slice(-48);
      }
      return updated;
    });
  }, []);

  // Update current data and append to timeline
  const updateMetrics = useCallback((data) => {
    // Update current data
    const newData = {
      ransomware: data.ransomware ?? 0,
      port_scan: data.port_scan ?? 0,
      honeypot: data.honeypot ?? 0,
    };

    setCurrentData(newData);

    // Add to timeline
    addDataPoint({
      timestamp: new Date().toLocaleTimeString(),
      ...newData,
    });

    // Update previous data after appending to timeline
    setPreviousData(newData);
  }, [addDataPoint]);

  const value = {
    timelineData,
    currentData,
    previousData,
    isScanning,
    setIsScanning,
    resetTimeline,
    updateMetrics,
    calculateChange,
  };

  return (
    <SecurityContext.Provider value={value}>
      {children}
    </SecurityContext.Provider>
  );
}

export function useSecurity() {
  const context = useContext(SecurityContext);
  if (!context) {
    throw new Error('useSecurity must be used within SecurityProvider');
  }
  return context;
}
