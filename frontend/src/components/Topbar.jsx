import React from "react";

function Topbar() {
  return (
    <header className="topbar">
      {/* LEFT BRAND */}
      <div className="topbar-left">
        <span className="brand-icon">🛡️</span>
        <span className="brand-name">CTI-MAF-WATCH</span>
      </div>

      {/* CENTER MESSAGE */}
      <div className="topbar-center">
        Welcome back, <b>Pranay Salunkhe</b>
      </div>

      {/* RIGHT ICONS */}
      <div className="topbar-right">
        <span className="top-icon">🔔</span>
        <span className="top-icon">⚙️</span>

        <div className="profile">
          <img
            src="https://i.pravatar.cc/40"
            alt="user"
            className="profile-img"
          />
        </div>
      </div>
    </header>
  );
}

export default Topbar;
