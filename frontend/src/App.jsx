import React, { useState } from "react";
import { Routes, Route } from "react-router-dom";

import Sidebar from "./components/Sidebar.jsx";
import AlertsPanel from "./components/AlertsPanel.jsx";
import Topbar from "./components/Topbar.jsx";

import Dashboard from "./pages/Dashboard.jsx";
import PortScanDetails from "./pages/details/PortScanDetails.jsx";
import HoneypotDetails from "./pages/details/HoneypotDetails.jsx";
import DarkWebDetails from "./pages/details/DarkWebDetails.jsx";
import RansomwareDetails from "./pages/details/RansomwareDetails.jsx";

function App() {
  const [ransomwareCount, setRansomwareCount] = useState(0);
  const [alerts, setAlerts] = useState([]);
  return (
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
                <Dashboard
                  ransomwareCount={ransomwareCount}
                  setRansomwareCount={setRansomwareCount}
                  alerts={alerts}
                  setAlerts={setAlerts}
                />
              }
            />
            <Route path="/details/portscan" element={<PortScanDetails />} />
            <Route path="/details/honeypot" element={<HoneypotDetails />} />
            <Route path="/details/darkweb" element={<DarkWebDetails />} />
            <Route path="/details/ransomware" element={<RansomwareDetails />} />
          </Routes>
        </main>

        <AlertsPanel alerts={alerts} />
      </div>
    </div>
  );
}

export default App;
