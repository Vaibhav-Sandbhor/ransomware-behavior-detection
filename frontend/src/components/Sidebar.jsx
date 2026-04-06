import React from "react";
import { Link } from "react-router-dom";

function Sidebar() {
  return (
    <aside className="sidebar">
      <h2 className="logo">CyberSIEM</h2>
      <ul>
        <li><Link to="/">Dashboard</Link></li>
        <li><Link to="/threats">Threat Details</Link></li>
        <li><Link to="/honeypot">Honeypot Logs</Link></li>
        <li className="divider"></li>
        <li className="history-item"><Link to="/history">📅 History</Link></li>
      </ul>
    </aside>
  );
}

export default Sidebar;
