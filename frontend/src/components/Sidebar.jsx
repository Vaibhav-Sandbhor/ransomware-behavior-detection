import React from "react";
import { Link } from "react-router-dom";

function Sidebar() {
  return (
    <aside className="sidebar">
      <h2 className="logo">CyberSIEM</h2>
      <ul>
        <li><Link to="/">Dashboard</Link></li>
        <li><Link to="/threats">Threat Details</Link></li>
        <li><Link to="/darkweb">Dark Web Intel</Link></li>
        <li><Link to="/honeypot">Honeypot Logs</Link></li>
      </ul>
    </aside>
  );
}

export default Sidebar;
