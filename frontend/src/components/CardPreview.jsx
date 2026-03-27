import React from "react";

const CardPreview = ({ module, data, color }) => {
  // Format preview data based on module type
  const getPreviewContent = () => {
    switch (module) {
      case "ransomware":
        return {
          title: "Ransomware Summary",
          stats: [
            { label: "Malicious", value: data.summary?.ransomware ?? 0, color: "#ff4444" },
            { label: "Suspicious", value: data.summary?.suspicious ?? 0, color: "#ff9800" },
            { label: "Benign", value: data.summary?.benign ?? 0, color: "#4caf50" },
          ],
        };
      case "portscan":
        const openPorts = data.scanData?.dashboard?.[0]?.open_ports ?? [];
        const criticalPorts = Array.isArray(openPorts) ? openPorts.filter(p => p.risk === "CRITICAL").length : 0;
        const highRiskPorts = Array.isArray(openPorts) ? openPorts.filter(p => p.risk === "HIGH").length : 0;
        return {
          title: "Port Scan Summary",
          stats: [
            { label: "Critical Ports", value: criticalPorts, color: "#ff4444" },
            { label: "High Risk Ports", value: highRiskPorts, color: "#ff9800" },
          ],
        };
      case "honeypot":
        return {
          title: "Honeypot Summary",
          stats: [
            { label: "Total Events", value: data.summary?.total ?? 0, color: "#3b82f6" },
            { label: "Critical", value: data.summary?.critical ?? 0, color: "#ff4444" },
            { label: "Warnings", value: data.summary?.warning ?? 0, color: "#ff9800" },
          ],
        };
      default:
        return { title: "Preview", stats: [] };
    }
  };

  const content = getPreviewContent();

  return (
    <div className="card-preview-popup" style={{ borderColor: color }}>
      <div className="card-preview-header">{content.title}</div>
      <div className="card-preview-stats">
        {content.stats.map((stat, i) => (
          <div key={i} className="card-preview-stat-box">
            <div className="stat-count" style={{ color: stat.color }}>
              {stat.value}
            </div>
            <div className="stat-label">{stat.label}</div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default CardPreview;
