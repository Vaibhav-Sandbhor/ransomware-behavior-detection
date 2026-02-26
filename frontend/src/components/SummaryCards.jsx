import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { fetchRansomwarePredictions, fetchHoneypotLog } from "../servives/api";

const SummaryCards = ({ ransomwareCount }) => {
  const navigate = useNavigate();
  const [liveRansomware, setLiveRansomware] = useState(null);
  const [liveHoneypot, setLiveHoneypot]     = useState(null);

  useEffect(() => {
    fetchRansomwarePredictions()
      .then(data => setLiveRansomware(data.summary?.ransomware ?? null))
      .catch(() => {});

    fetchHoneypotLog()
      .then(data => setLiveHoneypot(data.summary?.total ?? null))
      .catch(() => {});
  }, []);

  // Prefer live pipeline count; fall back to prop value passed from old scan flow
  const displayRansomware = liveRansomware !== null ? liveRansomware : (ransomwareCount ?? 0);
  const displayHoneypot   = liveHoneypot   !== null ? liveHoneypot   : 0;

  return (
    <div className="summary-grid">
      <div className="summary-card danger" onClick={() => navigate("/details/ransomware")}>
        <div className="card-header">
          <span className="card-icon danger">●</span>
          <span className="card-title">RANSOMWARE DETECTED</span>
        </div>
        <div className="card-value danger">{displayRansomware}</div>
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
        <div className="card-value info">{displayHoneypot}</div>
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
