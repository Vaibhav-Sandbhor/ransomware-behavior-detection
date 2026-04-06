import React, { useState, useEffect, useCallback, useRef } from "react";
import { Routes, Route, Navigate } from "react-router-dom";

import { AuthProvider, useAuth } from "./context/AuthContext.jsx";
import { ProtectedRoute } from "./components/ProtectedRoute.jsx";
import Sidebar from "./components/Sidebar.jsx";
import AlertsPanel from "./components/AlertsPanel.jsx";
import Topbar from "./components/Topbar.jsx";

import Dashboard from "./pages/Dashboard.jsx";
import Login from "./pages/Login.jsx";
import Register from "./pages/Register.jsx";
import PortScanDetails from "./pages/details/PortScanDetails.jsx";
import HoneypotDetails from "./pages/details/HoneypotDetails.jsx";
import DarkWebDetails from "./pages/details/DarkWebDetails.jsx";
import RansomwareDetails from "./pages/details/RansomwareDetails.jsx";
import {
  runRansomwarePipeline,
  fetchRansomwarePredictions,
  scanSystemPorts,
  fetchHoneypotLog,
} from "./services/api.js";

function AppContent() {
  const { isAuthenticated, loading } = useAuth();
  const [moduleData, setModuleData] = useState({
    ransomware: {
      count: null,
      status: "IDLE",
      summary: null,
      predictions: [],
      alerts: [],
      lastScan: null,
    },
    portscan: {
      count: null,
      status: "IDLE",
      scanData: null,
      lastScan: null,
    },
    honeypot: {
      count: null,
      status: "IDLE",
      summary: null,
      events: [],
      alerts: [],
      lastScan: null,
    },
  });
  const [alerts, setAlerts] = useState([]);

  // ✅ PERSISTENT TIMELINE DATA - Preserved across navigation
  const [timelineData, setTimelineData] = useState([]);

  // State for auto-scanning system
  const [previousCounts, setPreviousCounts] = useState({
    ransomware: 0,
    portscan: 0,
    honeypot: 0,
  });
  const [autoScanInterval, setAutoScanInterval] = useState(null);
  const [scanMode, setScanMode] = useState("simulation");

  // Ref to always have the latest version of runAllScansParallel
  const runAllScansParallelRef = useRef(null);

  // Load previousCounts from localStorage on mount
  useEffect(() => {
    const stored = localStorage.getItem("soc-dashboard-previousCounts");
    if (stored) {
      try {
        setPreviousCounts(JSON.parse(stored));
      } catch (e) {
        console.error("Failed to load previousCounts from localStorage:", e);
      }
    }
  }, []);

  // Update ref to always have the latest version of runAllScansParallel
  // This is inserted after runAllScansParallel is defined below

  // Cleanup auto-scan interval on unmount
  useEffect(() => {
    return () => {
      if (autoScanInterval) {
        clearInterval(autoScanInterval);
      }
    };
  }, [autoScanInterval]);

  const updateModuleData = (key, patch) => {
    setModuleData((prev) => ({
      ...prev,
      [key]: {
        ...prev[key],
        ...patch,
      },
    }));
  };

  // Generate alerts based on count deltas (new threats only)
  const generateNewAlerts = (oldCounts, newCounts) => {
    console.log("[generateNewAlerts] Old:", oldCounts, "New:", newCounts);
    const newAlerts = [];

    // Ransomware alerts
    const ransomwareDelta = newCounts.ransomware - oldCounts.ransomware;
    if (ransomwareDelta > 0) {
      newAlerts.push({
        severity: "critical",
        message: `[RANSOMWARE] New threat detected: ${ransomwareDelta} additional instance${ransomwareDelta > 1 ? "s" : ""} (+${ransomwareDelta})`,
        time: new Date().toLocaleTimeString(),
        module: "ransomware",
      });
    }

    // Port Scan alerts
    const portscanDelta = newCounts.portscan - oldCounts.portscan;
    if (portscanDelta > 0) {
      newAlerts.push({
        severity: "high",
        message: `[PORT SCAN] High-risk ports exposed: ${portscanDelta} additional port${portscanDelta > 1 ? "s" : ""} (+${portscanDelta})`,
        time: new Date().toLocaleTimeString(),
        module: "portscan",
      });
    }

    // Honeypot alerts
    const honeypotDelta = newCounts.honeypot - oldCounts.honeypot;
    if (honeypotDelta > 0) {
      newAlerts.push({
        severity: "medium",
        message: `[HONEYPOT] Critical file interactions: ${honeypotDelta} additional event${honeypotDelta > 1 ? "s" : ""} (+${honeypotDelta})`,
        time: new Date().toLocaleTimeString(),
        module: "honeypot",
      });
    }

    // Push new alerts to the front of alerts list
    if (newAlerts.length > 0) {
      console.log("[generateNewAlerts] Pushing alerts:", newAlerts);
      setAlerts((prev) => [...newAlerts, ...prev]);
    } else {
      console.log("[generateNewAlerts] No deltas detected");
    }
  };

  // Run all three scans in parallel
  const runAllScansParallel = useCallback(async () => {
    console.log("[runAllScansParallel] Starting scans...");
    try {
      const [ransomwareRes, portscanRes, honeypotRes] = await Promise.all([
        runRansomwarePipeline().catch((e) => ({
          status: "error",
          error: e.message,
        })),
        scanSystemPorts().catch((e) => ({
          status: "error",
          error: e.message,
        })),
        fetchHoneypotLog().catch((e) => ({
          status: "error",
          error: e.message,
        })),
      ]);

      // Extract new counts
      const newCounts = {
        ransomware: ransomwareRes?.summary?.ransomware ?? moduleData.ransomware.count ?? 0,
        portscan: portscanRes?.dashboard?.[0]?.total_ports ?? moduleData.portscan.count ?? 0,
        honeypot: honeypotRes?.summary?.total ?? moduleData.honeypot.count ?? 0,
      };

      console.log("[runAllScansParallel] New counts:", newCounts);
      console.log("[runAllScansParallel] Current previousCounts:", previousCounts);

      // Generate alerts based on deltas
      generateNewAlerts(previousCounts, newCounts);

      // Update previousCounts state and localStorage
      setPreviousCounts(newCounts);
      localStorage.setItem("soc-dashboard-previousCounts", JSON.stringify(newCounts));

      // Update module data
      // Ransomware
      updateModuleData("ransomware", {
        count: newCounts.ransomware,
        status: ransomwareRes?.summary?.ransomware > 0 ? "MALICIOUS" : "SAFE",
        summary: ransomwareRes?.summary || null,
        lastScan: new Date().toISOString(),
      });

      // Port Scan
      updateModuleData("portscan", {
        count: newCounts.portscan,
        status:
          portscanRes?.dashboard?.[0]?.final_risk &&
          ["CRITICAL", "HIGH"].includes(portscanRes.dashboard[0].final_risk)
            ? "MALICIOUS"
            : "SAFE",
        scanData: portscanRes || null,
        lastScan: new Date().toISOString(),
      });

      // Honeypot
      updateModuleData("honeypot", {
        count: newCounts.honeypot,
        status: honeypotRes?.summary?.critical > 0 ? "MALICIOUS" : "SAFE",
        summary: honeypotRes?.summary || null,
        events: honeypotRes?.events || [],
        lastScan: new Date().toISOString(),
      });

      return newCounts;
    } catch (error) {
      console.error("Error running all scans:", error);
      return null;
    }
  }, [moduleData, previousCounts]);

  // Update ref with latest version of runAllScansParallel
  // This ensures the interval always calls the latest version
  useEffect(() => {
    runAllScansParallelRef.current = runAllScansParallel;
  }, [runAllScansParallel]);

  // Start auto-scan 30 seconds after first global scan
  const startAutoScan = useCallback(() => {
    console.log("[startAutoScan] Called, autoScanInterval status:", autoScanInterval);
    if (autoScanInterval) {
      console.log("[startAutoScan] Auto-scan already running, skipping");
      return; // Already running
    }

    // Set initial delay of 30 seconds
    const timeout = setTimeout(() => {
      console.log("[startAutoScan] Initial 30s timeout completed, creating interval");
      // Create a repeating interval that calls the latest version via ref
      const interval = setInterval(() => {
        console.log("[startAutoScan] Interval triggered, calling runAllScansParallel via ref");
        if (runAllScansParallelRef.current) {
          runAllScansParallelRef.current();
        } else {
          console.warn("[startAutoScan] runAllScansParallelRef.current is null!");
        }
      }, 30000); // 30 seconds

      setAutoScanInterval(interval);
      console.log("[startAutoScan] Interval created:", interval);
    }, 30000);

    // Store timeout ID for cleanup if needed
    return () => clearTimeout(timeout);
  }, [autoScanInterval]);

  // Expose functions to Dashboard via props
  const scanFunctions = { runAllScansParallel, startAutoScan };

  return (
    <>
      {loading ? (
        <div style={{
          display: "flex",
          justifyContent: "center",
          alignItems: "center",
          height: "100vh",
          fontSize: "18px",
          color: "#888",
          background: "linear-gradient(135deg, #0f0f1e 0%, #1a1a2e 100%)",
        }}>
          Loading...
        </div>
      ) : !isAuthenticated ? (
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="*" element={<Navigate to="/login" replace />} />
        </Routes>
      ) : (
        <div className="app-wrapper">
          {/* ✅ GLOBAL TOPBAR */}
          <Topbar />

          {/* ✅ MAIN DASHBOARD GRID */}
          <div className="dashboard-layout">
            <Sidebar />

            <main className="dashboard-main">
              <Routes>
                <Route
                  path="/"
                  element={
                    <ProtectedRoute>
                      <Dashboard
                        moduleData={moduleData}
                        updateModuleData={updateModuleData}
                        alerts={alerts}
                        setAlerts={setAlerts}
                        scanFunctions={scanFunctions}
                        timelineData={timelineData}
                        setTimelineData={setTimelineData}
                      />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/details/portscan"
                  element={
                    <ProtectedRoute>
                      <PortScanDetails
                        moduleState={moduleData.portscan}
                        updateModuleState={(patch) => updateModuleData("portscan", patch)}
                      />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/details/honeypot"
                  element={
                    <ProtectedRoute>
                      <HoneypotDetails
                        moduleState={moduleData.honeypot}
                        updateModuleState={(patch) => updateModuleData("honeypot", patch)}
                      />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/details/darkweb"
                  element={
                    <ProtectedRoute>
                      <DarkWebDetails />
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/details/ransomware"
                  element={
                    <ProtectedRoute>
                      <RansomwareDetails
                        moduleState={moduleData.ransomware}
                        updateModuleState={(patch) => updateModuleData("ransomware", patch)}
                      />
                    </ProtectedRoute>
                  }
                />
              </Routes>
            </main>

            <AlertsPanel alerts={alerts} setAlerts={setAlerts} />
          </div>
        </div>
      )}
    </>
  );
}

function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}

export default App;
