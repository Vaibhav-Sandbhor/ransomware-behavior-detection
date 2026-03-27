import React from "react";

const AlertsPanel = ({ alerts = [], setAlerts }) => {
  return (
    <section className="alerts">
      <h2>Real-Time Alerts</h2>

      {alerts.length === 0 ? (
        <p style={{ color: "#888" }}>No alerts yet</p>
      ) : (
        alerts.map((alert, index) => (
          <div key={index} className={`alert ${alert.severity || alert.level}`}>
            <span className="alert-time">{alert.time}</span>
            <span className="alert-msg">{alert.message || alert.msg}</span>
          </div>
        ))
      )}
    </section>
  );
};

export default AlertsPanel;
