import React, { createContext, useState, useCallback } from "react";

export const ThreatTimelineContext = createContext();

export const ThreatTimelineProvider = ({ children }) => {
  const [timelineData, setTimelineData] = useState([]);
  const [previousCounts, setPreviousCounts] = useState({ ransomware: 0, portscan: 0, honeypot: 0 });

  // Reset timeline (called when global scan starts)
  const resetTimeline = useCallback(() => {
    setTimelineData([]);
    setPreviousCounts({ ransomware: 0, portscan: 0, honeypot: 0 });
  }, []);

  // Append new data point (ensure all 3 fields present)
  const addTimelinePoint = useCallback((point) => {
    setTimelineData((prev) => {
      // Avoid duplicates by timestamp
      if (prev.some(p => p.timestamp === point.timestamp)) {
        return prev;
      }

      // Ensure correct property names: ransomware, portscan, honeypot
      const normalizedPoint = {
        timestamp: point.timestamp,
        ransomware: point.ransomware || 0,
        portscan: point.portscan || point.port_scan || 0,  // Handle both formats
        honeypot: point.honeypot || 0,
      };

      const updated = [...prev, normalizedPoint];

      // Keep only last 48 data points
      if (updated.length > 48) {
        return updated.slice(-48);
      }
      return updated;
    });
  }, []);

  // Update previous counts for trend calculation
  const updatePreviousCounts = useCallback((counts) => {
    setPreviousCounts(counts);
  }, []);

  return (
    <ThreatTimelineContext.Provider value={{
      timelineData,
      previousCounts,
      resetTimeline,
      addTimelinePoint,
      updatePreviousCounts
    }}>
      {children}
    </ThreatTimelineContext.Provider>
  );
};

