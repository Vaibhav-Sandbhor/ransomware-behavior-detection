import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext.jsx";

function Topbar({ viewMode, onSwitchToLive }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [showLogout, setShowLogout] = useState(false);

  const handleLogout = async () => {
    await logout();
    navigate("/login");
  };

  return (
    <header className="topbar">
      {/* LEFT BRAND */}
      <div className="topbar-left">
        <span className="brand-icon">🛡️</span>
        <span className="brand-name">CTI-MAF-WATCH</span>
        {viewMode === "history" && (
          <span className="mode-badge history-mode">
            📜 HISTORY MODE
            <button 
              className="btn-exit-history"
              onClick={onSwitchToLive}
              title="Return to live dashboard"
            >
              ✕
            </button>
          </span>
        )}
      </div>

      {/* CENTER MESSAGE */}
      <div className="topbar-center">
        Welcome back, <b>{user?.name || "User"}</b>
      </div>

      {/* RIGHT ICONS */}
      <div className="topbar-right">
        <span className="top-icon">🔔</span>
        <span className="top-icon">⚙️</span>

        <div className="profile" style={{ position: "relative" }}>
          <img
            src={`https://i.pravatar.cc/40?u=${user?.email || "user"}`}
            alt="user"
            className="profile-img"
            style={{ cursor: "pointer" }}
            onClick={() => setShowLogout(!showLogout)}
            title={user?.email}
          />
          {showLogout && (
            <div style={{
              position: "absolute",
              top: "50px",
              right: "0",
              background: "#1a1a2e",
              border: "1px solid #64c8ff",
              borderRadius: "6px",
              padding: "8px 12px",
              whiteSpace: "nowrap",
              zIndex: 1000,
            }}>
              <button
                onClick={handleLogout}
                style={{
                  background: "none",
                  border: "none",
                  color: "#ff6464",
                  cursor: "pointer",
                  fontSize: "14px",
                  fontWeight: "600",
                  padding: "0",
                }}
              >
                Logout
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}

export default Topbar;
