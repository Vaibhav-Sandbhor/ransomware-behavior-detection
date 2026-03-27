import { useState, useEffect, useRef } from "react";
import { getSecurityMetrics } from "../services/api";

const POLL_INTERVAL = 30000; // 30 seconds

/**
 * Custom hook for polling real-time security metrics from backend.
 * Maintains a timeline of threat activity from all modules.
 * Resets when new scan starts.
 */
export function useSecurityMetrics(isScanning = false) {
  const [metrics, setMetrics] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [previousCounts, setPreviousCounts] = useState({ ransomware: 0, portscan: 0, honeypot: 0 });
  const pollIntervalRef = useRef(null);
  const lastFetchTimeRef = useRef(null);
  const scanStartedRef = useRef(false);

  // Fetch latest metrics from backend (all modules)
  const fetchMetrics = async () => {
    if (isLoading) return;

    setIsLoading(true);
    try {
      const data = await getSecurityMetrics();

      setMetrics((prevMetrics) => {
        // Add new metric if timestamp changed (avoid duplicates)
        if (lastFetchTimeRef.current !== data.timestamp) {
          lastFetchTimeRef.current = data.timestamp;

          // Store previous counts for trend calculation
          setPreviousCounts({
            ransomware: data.ransomware || 0,
            portscan: data.port_scan || 0,
            honeypot: data.honeypot || 0
          });

          const updated = [
            ...prevMetrics,
            {
              timestamp: data.timestamp,
              ransomware: data.ransomware || 0,
              portscan: data.port_scan || 0,
              honeypot: data.honeypot || 0,
              total: data.total || 0,
            },
          ];

          // Keep only last 48 data points (~24 hours)
          if (updated.length > 48) {
            return updated.slice(-48);
          }
          return updated;
        }
        return prevMetrics;
      });
    } catch (error) {
      console.warn("Failed to fetch security metrics:", error);
    } finally {
      setIsLoading(false);
    }
  };

  // Reset timeline and polling when scan starts
  useEffect(() => {
    if (isScanning) {
      // Reset timeline on scan start
      if (!scanStartedRef.current) {
        setMetrics([]);
        lastFetchTimeRef.current = null;
        scanStartedRef.current = true;
      }

      // Fetch immediately
      fetchMetrics();

      // Set up polling interval (all modules fetched every 30s)
      pollIntervalRef.current = setInterval(() => {
        fetchMetrics();
      }, POLL_INTERVAL);
    } else {
      // Stop polling and reset scan flag
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
        pollIntervalRef.current = null;
      }
      scanStartedRef.current = false;
    }

    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
    };
  }, [isScanning]);

  return { metrics, previousCounts, isLoading, fetchMetrics };
}
