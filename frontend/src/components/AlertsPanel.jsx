import React, { useEffect, useState } from "react";

const AlertsPanel = ({ alerts = [] }) => {
  

  useEffect(() => {
    const alertPool = [
      { level: "critical", msg: "Ransomware detected from 192.168.1.10" },
      { level: "high", msg: "Port scan detected on port 22" },
      { level: "high", msg: "Multiple login attempts detected" },
      { level: "medium", msg: "Dark web credential leak found" },
      { level: "low", msg: "Suspicious network activity observed" }
    ];

    const interval = setInterval(() => {
      const random = alertPool[Math.floor(Math.random() * alertPool.length)];

      setAlerts(prev => [
        {
          ...random,
          time: new Date().toLocaleTimeString()
        },
        ...prev
      ]);
    }, 3000);

    return () => clearInterval(interval);
  }, []);

  return (
    <section className="alerts">
      <h2>Real-Time Alerts</h2>

     {alerts.length === 0 ? (
  <p style={{ color: "#888" }}>No alerts yet</p>
) : (
  alerts.map((alert, index) => (
    <div key={index} className={`alert ${alert.severity}`}>
      <span className="alert-time">{alert.time}</span>
      <span className="alert-msg">{alert.message}</span>
    </div>
  ))
)}
    </section>
  );
}

export default AlertsPanel;
