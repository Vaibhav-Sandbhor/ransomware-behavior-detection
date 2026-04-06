import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import CardPreview from "./CardPreview.jsx";

const SummaryCards = ({ moduleData }) => {
  const navigate = useNavigate();
  const [activeCard, setActiveCard] = useState(null);

  const ransomware = moduleData?.ransomware || {};
  const portscan = moduleData?.portscan || {};
  const honeypot = moduleData?.honeypot || {};

  const displayRansomware = ransomware.count ?? "--";
  const displayPortscan = portscan.count ?? "--";
  const displayHoneypot = honeypot.count ?? "--";

  const statusText = (status) =>
    status && status !== "IDLE" ? `Status: ${status}` : "No scan run yet";

  const cardConfig = {
    ransomware: {
      title: "RANSOMWARE ALERTS DETECTED",
      icon: "●",
      class: "danger",
      color: "#dc2626",
      path: "/details/ransomware",
      data: ransomware,
      display: displayRansomware,
    },
    portscan: {
      title: "PORT SCANS BLOCKED",
      icon: "🛡",
      class: "warning",
      color: "#f59e0b",
      path: "/details/portscan",
      data: portscan,
      display: displayPortscan,
    },
    honeypot: {
      title: "HONEYPOT INTERACTIONS",
      icon: "🌀",
      class: "info",
      color: "#3b82f6",
      path: "/details/honeypot",
      data: honeypot,
      display: displayHoneypot,
    },
  };

  return (
    <div className="summary-grid">
      {Object.entries(cardConfig).map(([key, config]) => (
        <div
          key={key}
          className={`summary-card ${config.class} ${activeCard && activeCard !== key ? 'card-inactive' : ''}`}
          onClick={() => navigate(config.path)}
          onMouseEnter={() => setActiveCard(key)}
          onMouseLeave={() => setActiveCard(null)}
          style={{ position: "relative" }}
        >
          <div className="card-header">
            <span className={`card-icon ${config.class}`}>{config.icon}</span>
            <span className="card-title">{config.title}</span>
          </div>
          <div className={`card-value ${config.class}`}>{config.display}</div>
          <div className="card-sub">{statusText(config.data.status)}</div>

          {/* Preview popup */}
          {activeCard === key && (
            <CardPreview
              module={key}
              data={config.data}
              color={config.color}
            />
          )}
        </div>
      ))}
    </div>
  );
};

export default SummaryCards;
