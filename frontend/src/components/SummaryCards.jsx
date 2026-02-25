import React from "react";
import { useNavigate } from "react-router-dom";

const SummaryCards = ({ ransomwareCount }) => {
  const navigate = useNavigate();

  return (
    <div className="summary-grid">
      <div className="summary-card danger" onClick={() => navigate("/details/ransomware")}>
        <div className="card-header">
          <span className="card-icon danger">●</span>
          <span className="card-title">RANSOMWARE DETECTED</span>
        </div>
        <div className="card-value danger">{ransomwareCount}</div>
        <div className="card-sub">In Last 24 Hours</div>
      </div>

      <div className="summary-card warning" onClick={() => navigate("/details/portscan")}>
        <div className="card-header">
          <span className="card-icon warning">🛡</span>
          <span className="card-title">PORT SCANS BLOCKED</span>
        </div>
        <div className="card-value warning">230</div>
        <div className="card-sub">In Last 24 Hours</div>
      </div>

      <div className="summary-card info" onClick={() => navigate("/details/honeypot")}>
        <div className="card-header">
          <span className="card-icon info">🌀</span>
          <span className="card-title">HONEYPOT INTERACTIONS</span>
        </div>
        <div className="card-value info">58</div>
        <div className="card-sub">In Last 24 Hours</div>
      </div>

      <div className="summary-card purple" onClick={() => navigate("/details/darkweb")}>
        <div className="card-header">
          <span className="card-icon purple">🔥</span>
          <span className="card-title">DARK WEB ALERTS</span>
        </div>
        <div className="card-value purple">32</div>
        <div className="card-sub">In Last 24 Hours</div>
      </div>
    </div>
  );
}

export default SummaryCards;
