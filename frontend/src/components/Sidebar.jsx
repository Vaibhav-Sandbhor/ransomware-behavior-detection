import React from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext.jsx";

function Sidebar() {
  const { logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate("/", { replace: true });
  };

  return (
    <aside className="sidebar">
      <h2 className="logo">CyberSIEM</h2>
      <ul>
        <li><Link to="/">Dashboard</Link></li>
        <li className="divider"></li>
        <li className="history-item"><Link to="/sessions">📊 Sessions</Link></li>
        <li><Link to="/profile">👤 Profile</Link></li>
      </ul>
      
      {/* Logout Button at Bottom */}
      <div className="sidebar-footer">
        <button className="logout-btn" onClick={handleLogout}>
          🚪 Logout
        </button>
      </div>
    </aside>
  );
}

export default Sidebar;
