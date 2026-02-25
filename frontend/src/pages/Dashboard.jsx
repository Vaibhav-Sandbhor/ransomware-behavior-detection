import React, { useState } from "react";
import SummaryCards from "../components/SummaryCards.jsx";
import Charts from "../components/Charts.jsx";
import ThreatTable from "../components/ThreatTable.jsx";
import AlertsPanel from "../components/AlertsPanel.jsx";

function Dashboard({ ransomwareCount, setRansomwareCount, alerts, setAlerts }) {

  

  const handleScanResult = (result) => {
    if (result.prediction === 1) {
      setRansomwareCount(prev => prev + 1);

      setAlerts(prev => [
        {
          severity: "critical",
          message: `Ransomware detected (${(result.probability * 100).toFixed(1)}%)`,
          time: new Date().toLocaleTimeString()
        },
        ...prev
      ]);
    }
  };

  return (
    <>
      <h1 className="page-title">Security Operations Center</h1>
      <p className="page-sub">
        AI Engine: <span className="green">RUNNING</span>
      </p>

      <SummaryCards ransomwareCount={ransomwareCount} />
      <Charts />
      <ThreatTable />

    </>
  );
}

export default Dashboard;