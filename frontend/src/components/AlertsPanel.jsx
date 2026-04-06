import React from "react";

// Get severity level (normalized to lowercase)
const getSeverity = (alert) => {
  const severity = alert.severity || alert.level || "info";
  return severity.toLowerCase();
};

const AlertsPanel = ({ alerts = [], setAlerts }) => {
  return (
    <section className="alerts">
      <h2>Real-Time Alerts</h2>

      {alerts.length === 0 ? (
        <p style={{ color: "#888" }}>No alerts yet</p>
      ) : (
        alerts.map((alert, index) => {
          const severity = getSeverity(alert);
          return (
            <div key={index} className={`alert ${severity}`}>
              <span className={`severity-badge ${severity}`}>
                {severity.toUpperCase()}
              </span>
              <div style={{ flex: 1 }}>
                <span className="alert-time">{alert.time}</span>
                <span className="alert-msg">{alert.message || alert.msg}</span>
              </div>
            </div>
          );
        })
      )}
    </section>
  );
};

export default AlertsPanel;
