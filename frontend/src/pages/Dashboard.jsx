import React, { useState } from "react";
import SummaryCards from "../components/SummaryCards.jsx";
import Charts from "../components/Charts.jsx";
import ThreatTable from "../components/ThreatTable.jsx";
import ScanningOverlay from "../components/ScanningOverlay.jsx";

function Dashboard({ moduleData, updateModuleData, alerts, setAlerts, scanFunctions, timelineData, setTimelineData, viewMode = "live", hasScanRun = false }) {
  const [isScanning, setIsScanning] = useState(false);

  const toStatus = (isThreat) => (isThreat ? "MALICIOUS" : "SAFE");

  const handleGlobalScan = async () => {
    // Don't allow scanning in history mode
    if (viewMode === "history") {
      console.log("Scanning disabled in history mode");
      return;
    }

    setIsScanning(true);

    // ✅ CLEAR TIMELINE DATA and start from origin (0,0,0)
    const startTime = new Date().toLocaleTimeString();
    setTimelineData([{
      time: startTime,
      ransomware: 0,
      port_scan: 0,
      honeypot: 0
    }]);

    try {
      // Call the centralized auto-scanning function from App.jsx
      if (scanFunctions?.runAllScansParallel) {
        await scanFunctions.runAllScansParallel();

        // Start auto-scan after first global scan
        if (scanFunctions?.startAutoScan) {
          scanFunctions.startAutoScan();
        }
      }
    } catch (error) {
      console.error("Global scan error:", error);
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <>
      <h1 className="page-title">Security Operations Center</h1>
      <p className="page-sub">
        AI Engine: <span className={viewMode === "live" ? "green" : "orange"}>
          {viewMode === "live" ? "RUNNING" : "VIEWING HISTORY"}
        </span>
      </p>

      {viewMode === "history" && (
        <div className="history-banner">
          <span>📜 You are viewing historical data. </span>
          <button 
            className="btn-return-live"
            onClick={scanFunctions?.switchToLiveMode}
          >
            Return to Live
          </button>
        </div>
      )}

      <div className="global-scan-wrap">
        <button 
          className="global-scan-btn" 
          onClick={handleGlobalScan} 
          disabled={isScanning || viewMode === "history"}
          title={viewMode === "history" ? "Scanning disabled in history mode" : ""}
        >
          {isScanning ? "Scanning..." : "Global Scan"}
        </button>
      </div>

      <SummaryCards moduleData={moduleData} />
      <Charts 
        moduleData={moduleData} 
        timelineData={timelineData} 
        setTimelineData={setTimelineData} 
        viewMode={viewMode}
        alerts={alerts}
      />
      <ThreatTable />

      <ScanningOverlay visible={isScanning} />

    </>
  );
}

export default Dashboard;