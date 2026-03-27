import React, { useState } from "react";
import SummaryCards from "../components/SummaryCards.jsx";
import Charts from "../components/Charts.jsx";
import ThreatTable from "../components/ThreatTable.jsx";
import ScanningOverlay from "../components/ScanningOverlay.jsx";

function Dashboard({ moduleData, updateModuleData, alerts, setAlerts, scanFunctions, timelineData, setTimelineData }) {
  const [isScanning, setIsScanning] = useState(false);

  const toStatus = (isThreat) => (isThreat ? "MALICIOUS" : "SAFE");

  const handleGlobalScan = async () => {
    setIsScanning(true);

    // ✅ CLEAR TIMELINE DATA when starting new global scan
    setTimelineData([]);

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
        AI Engine: <span className="green">RUNNING</span>
      </p>

      <div className="global-scan-wrap">
        <button className="global-scan-btn" onClick={handleGlobalScan} disabled={isScanning}>
          {isScanning ? "Scanning..." : "Global Scan"}
        </button>
      </div>

      <SummaryCards moduleData={moduleData} />
      <Charts moduleData={moduleData} timelineData={timelineData} setTimelineData={setTimelineData} />
      <ThreatTable />

      <ScanningOverlay visible={isScanning} />

    </>
  );
}

export default Dashboard;