import React from "react";

export default function ScanningOverlay({ visible }) {
  if (!visible) return null;

  return (
    <div className="global-scan-overlay" role="status" aria-live="polite">
      <div className="global-scan-spinner-wrap">
        <div className="global-scan-ring" />
        <div className="global-scan-ring inner" />
        <div className="global-scan-center" />
      </div>
      <p className="global-scan-text">Scanning all modules...</p>
    </div>
  );
}
