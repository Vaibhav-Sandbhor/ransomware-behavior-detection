import React, { useState, useEffect } from "react";
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  ResponsiveContainer
} from "recharts";

const COLORS = {
  ransomware: "#dc2626",
  port_scan: "#f59e0b",
  honeypot: "#3b82f6"
};

// Severity colors for breakdown chart
const SEVERITY_COLORS = {
  CRITICAL: "#ff4d4f",
  HIGH: "#fa8c16",
  MEDIUM: "#fadb14",
  LOW: "#52c41a"
};

function Charts({ moduleData, timelineData, setTimelineData, viewMode = "live", alerts = [] }) {
  // ✅ SINGLE SOURCE OF TRUTH - From moduleData (SAME as summary cards)
  const currentRansomware = moduleData?.ransomware?.count || 0;
  const currentPortScan = moduleData?.portscan?.count || 0;
  const currentHoneypot = moduleData?.honeypot?.count || 0;

  const [hasScanned, setHasScanned] = useState(false);

  // ✅ UPDATE TIMELINE WHEN MODULE DATA CHANGES (ONLY IN LIVE MODE)
  useEffect(() => {
    // Check if we have data
    const hasData = currentRansomware > 0 || currentPortScan > 0 || currentHoneypot > 0;
    if (hasData) {
      setHasScanned(true);
    }

    // ✅ ONLY update timeline in LIVE mode - NEVER in history mode
    if (viewMode !== "live") {
      console.log("📊 [Charts] Skipping timeline update - in history mode");
      return;
    }

    // ✅ APPEND CURRENT VALUES TO TIMELINE (persists across navigation)
    setTimelineData(prev => {
      const now = new Date();
      const timestamp = now.toLocaleTimeString();

      // Only append if data is different from last point (avoid duplicates)
      const lastPoint = prev.length > 0 ? prev[prev.length - 1] : null;
      if (
        lastPoint &&
        lastPoint.ransomware === currentRansomware &&
        lastPoint.port_scan === currentPortScan &&
        lastPoint.honeypot === currentHoneypot
      ) {
        return prev; // No change, skip
      }

      const timelinePoint = {
        time: timestamp,
        ransomware: currentRansomware,     // EXACT value from moduleData
        port_scan: currentPortScan,        // EXACT value from moduleData
        honeypot: currentHoneypot          // EXACT value from moduleData
      };

      console.log("📊 Timeline updated:", timelinePoint);
      console.log("📊 Summary card values - Ransomware:", currentRansomware, "Port:", currentPortScan, "Honeypot:", currentHoneypot);

      const updated = [...prev, timelinePoint];

      // Keep only last 48 points (for ~24 hours at 30-sec intervals)
      if (updated.length > 48) {
        return updated.slice(-48);
      }
      return updated;
    });

  }, [currentRansomware, currentPortScan, currentHoneypot, setTimelineData, viewMode]);

  const total = currentRansomware + currentPortScan + currentHoneypot;
  const hasData = total > 0;

  // ✅ THREAT DISTRIBUTION FOR PIE CHART (from moduleData)
  const threatData = [
    {
      name: "Ransomware",
      value: hasData ? Math.round((currentRansomware / total) * 100) : 0,
      count: currentRansomware
    },
    {
      name: "Port Scan",
      value: hasData ? Math.round((currentPortScan / total) * 100) : 0,
      count: currentPortScan
    },
    {
      name: "Honeypot",
      value: hasData ? Math.round((currentHoneypot / total) * 100) : 0,
      count: currentHoneypot
    }
  ];

  return (
    <section className="ml-section">
      <h2 className="section-title">Threat Analysis</h2>

      {/* INITIAL STATE */}
      {!hasScanned && (
        <div style={{
          padding: "24px",
          background: "#1a1a2e",
          border: "1px solid #333",
          borderRadius: "10px",
          textAlign: "center",
          color: "#888",
          marginBottom: "16px"
        }}>
          <p style={{ margin: 0, fontSize: "14px" }}>
            Click <strong>Global Scan</strong> to begin real-time monitoring.
          </p>
        </div>
      )}

      {/* ROW 1: DONUT + ACTIVITY */}
      {hasScanned && (
        <div className="ml-grid">
          {/* DONUT CHART */}
          <div className="ml-card">
            <div className="ml-card-header">Threat Distribution</div>
            {hasData ? (
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie
                    data={threatData}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={55}
                    outerRadius={80}
                    paddingAngle={4}
                    label={({ value }) => `${value}%`}
                  >
                    {threatData.map((entry, i) => (
                      <Cell
                        key={`cell-${i}`}
                        fill={[COLORS.ransomware, COLORS.port_scan, COLORS.honeypot][i]}
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    formatter={(value, name, props) => `${props.payload.count} events (${value}%)`}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div style={{
                height: 200,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#666",
                fontSize: "14px"
              }}>
                No active threats
              </div>
            )}
            {/* ✅ SUMMARY COUNTS - SAME SOURCE AS SUMMARY CARDS */}
            <div style={{
              marginTop: "12px",
              fontSize: "12px",
              color: "#aaa",
              display: "grid",
              gridTemplateColumns: "1fr 1fr 1fr",
              gap: "8px"
            }}>
              <div style={{ textAlign: "center", padding: "8px", background: "#1a1a2e", borderRadius: "4px" }}>
                <div style={{ color: COLORS.ransomware, fontWeight: 600 }}>Ransomware</div>
                <div>{currentRansomware} events</div>
              </div>
              <div style={{ textAlign: "center", padding: "8px", background: "#1a1a2e", borderRadius: "4px" }}>
                <div style={{ color: COLORS.port_scan, fontWeight: 600 }}>Port Scan</div>
                <div>{currentPortScan} events</div>
              </div>
              <div style={{ textAlign: "center", padding: "8px", background: "#1a1a2e", borderRadius: "4px" }}>
                <div style={{ color: COLORS.honeypot, fontWeight: 600 }}>Honeypot</div>
                <div>{currentHoneypot} events</div>
              </div>
            </div>
          </div>

          {/* THREAT SEVERITY BREAKDOWN CHART */}
          <div className="ml-card">
            <div className="ml-card-header">Threat Severity Breakdown</div>
            {(() => {
              // Compute severity counts from alerts (handle both uppercase and lowercase)
              const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
              alerts.forEach(alert => {
                const sev = (alert.severity || "").toUpperCase();
                if (severityCounts[sev] !== undefined) {
                  severityCounts[sev]++;
                }
              });
              
              console.log("[Charts] Alerts count:", alerts.length, "Severity counts:", severityCounts);
              
              const totalAlerts = Object.values(severityCounts).reduce((a, b) => a + b, 0);
              
              const severityData = [
                { name: "Critical", value: severityCounts.CRITICAL, fill: SEVERITY_COLORS.CRITICAL },
                { name: "High", value: severityCounts.HIGH, fill: SEVERITY_COLORS.HIGH },
                { name: "Medium", value: severityCounts.MEDIUM, fill: SEVERITY_COLORS.MEDIUM },
                { name: "Low", value: severityCounts.LOW, fill: SEVERITY_COLORS.LOW }
              ];
              
              const hasSeverityData = totalAlerts > 0;
              
              return hasSeverityData ? (
                <>
                  <ResponsiveContainer width="100%" height={200}>
                    <BarChart data={severityData} margin={{ top: 10, right: 20, left: 0, bottom: 5 }}>
                      <XAxis 
                        dataKey="name" 
                        stroke="#666" 
                        tick={{ fontSize: 11 }}
                      />
                      <YAxis 
                        stroke="#666" 
                        tick={{ fontSize: 11 }}
                        allowDecimals={false}
                      />
                      <Tooltip 
                        contentStyle={{ background: "#0a0a0a", border: "1px solid #333", borderRadius: "4px" }}
                        formatter={(value, name, props) => {
                          const pct = totalAlerts > 0 ? ((value / totalAlerts) * 100).toFixed(1) : 0;
                          return [`${value} alerts (${pct}%)`, props.payload.name];
                        }}
                      />
                      <Bar 
                        dataKey="value" 
                        radius={[6, 6, 0, 0]}
                        isAnimationActive={true}
                      >
                        {severityData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.fill} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                  <div style={{
                    marginTop: "16px",
                    display: "grid",
                    gridTemplateColumns: "repeat(4, 1fr)",
                    gap: "8px",
                    fontSize: "11px"
                  }}>
                    {severityData.map(item => (
                      <div key={item.name} style={{ 
                        textAlign: "center", 
                        padding: "8px 6px", 
                        background: "#1a1a2e", 
                        borderRadius: "4px",
                        borderLeft: `3px solid ${item.fill}`
                      }}>
                        <div style={{ color: item.fill, fontWeight: 600, fontSize: "12px" }}>{item.name}</div>
                        <div style={{ color: "#aaa", marginTop: "4px" }}>{item.value}</div>
                      </div>
                    ))}
                  </div>
                </>
              ) : (
                <div style={{
                  height: 200,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: "#666",
                  fontSize: "14px"
                }}>
                  No alerts to display
                </div>
              );
            })()}
          </div>
        </div>
      )}

      {/* ROW 2: THREE SEPARATE TIMELINE GRAPHS - STACKED VERTICALLY */}
      {hasScanned && timelineData.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: "16px", marginTop: "16px" }}>

          {/* RANSOMWARE TIMELINE - RED */}
          <div className="ml-card">
            <div className="ml-card-header">🔒 Ransomware Activity Timeline</div>
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={timelineData} margin={{ top: 5, right: 30, left: 0, bottom: 5 }}>
                <XAxis
                  dataKey="time"
                  stroke="#666"
                  tick={{ fontSize: 10 }}
                  interval={Math.max(0, Math.floor(timelineData.length / 6))}
                />
                <YAxis stroke="#666" tick={{ fontSize: 11 }} domain={[0, 'auto']} />
                <Tooltip
                  contentStyle={{ background: "#0a0a0a", border: "1px solid #333", borderRadius: "4px" }}
                  formatter={(value) => [`${value} events`, "Ransomware"]}
                />
                <Line
                  type="linear"
                  dataKey="ransomware"
                  stroke={COLORS.ransomware}
                  strokeWidth={3}
                  dot={{ fill: COLORS.ransomware, r: 5, strokeWidth: 2, stroke: "#fff" }}
                  activeDot={{ r: 7 }}
                  name="Ransomware"
                  isAnimationActive={true}
                />
              </LineChart>
            </ResponsiveContainer>
            <div style={{ marginTop: "6px", fontSize: "11px", color: "#888", textAlign: "center" }}>
              Current: <span style={{ color: COLORS.ransomware, fontWeight: 600 }}>{currentRansomware}</span> ransomware events
            </div>
          </div>

          {/* PORT SCAN TIMELINE - ORANGE/YELLOW */}
          <div className="ml-card">
            <div className="ml-card-header">🌐 Port Scan Activity Timeline</div>
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={timelineData} margin={{ top: 5, right: 30, left: 0, bottom: 5 }}>
                <XAxis
                  dataKey="time"
                  stroke="#666"
                  tick={{ fontSize: 10 }}
                  interval={Math.max(0, Math.floor(timelineData.length / 6))}
                />
                <YAxis stroke="#666" tick={{ fontSize: 11 }} domain={[0, 'auto']} />
                <Tooltip
                  contentStyle={{ background: "#0a0a0a", border: "1px solid #333", borderRadius: "4px" }}
                  formatter={(value) => [`${value} ports`, "Port Scan"]}
                />
                <Line
                  type="linear"
                  dataKey="port_scan"
                  stroke={COLORS.port_scan}
                  strokeWidth={3}
                  dot={{ fill: COLORS.port_scan, r: 5, strokeWidth: 2, stroke: "#fff" }}
                  activeDot={{ r: 7 }}
                  name="Port Scans"
                  isAnimationActive={true}
                />
              </LineChart>
            </ResponsiveContainer>
            <div style={{ marginTop: "6px", fontSize: "11px", color: "#888", textAlign: "center" }}>
              Current: <span style={{ color: COLORS.port_scan, fontWeight: 600 }}>{currentPortScan}</span> ports scanned
            </div>
          </div>

          {/* HONEYPOT TIMELINE - BLUE */}
          <div className="ml-card">
            <div className="ml-card-header">🍯 Honeypot Activity Timeline</div>
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={timelineData} margin={{ top: 5, right: 30, left: 0, bottom: 5 }}>
                <XAxis
                  dataKey="time"
                  stroke="#666"
                  tick={{ fontSize: 10 }}
                  interval={Math.max(0, Math.floor(timelineData.length / 6))}
                />
                <YAxis stroke="#666" tick={{ fontSize: 11 }} domain={[0, 'auto']} />
                <Tooltip
                  contentStyle={{ background: "#0a0a0a", border: "1px solid #333", borderRadius: "4px" }}
                  formatter={(value) => [`${value} events`, "Honeypot"]}
                />
                <Line
                  type="linear"
                  dataKey="honeypot"
                  stroke={COLORS.honeypot}
                  strokeWidth={3}
                  dot={{ fill: COLORS.honeypot, r: 5, strokeWidth: 2, stroke: "#fff" }}
                  activeDot={{ r: 7 }}
                  name="Honeypot"
                  isAnimationActive={true}
                />
              </LineChart>
            </ResponsiveContainer>
            <div style={{ marginTop: "6px", fontSize: "11px", color: "#888", textAlign: "center" }}>
              Current: <span style={{ color: COLORS.honeypot, fontWeight: 600 }}>{currentHoneypot}</span> honeypot events
            </div>
          </div>

        </div>
      )}

      {/* ROW 3: LIVE SECURITY EVENT FEED - REMOVED (use AlertsPanel instead) */}

      <div className="ml-footer">
        Status: <b>{viewMode === "history" ? "Viewing History" : (hasScanned ? "Active" : "Waiting")}</b>
        <span style={{ marginLeft: "12px", color: "#666" }}>
          {viewMode === "live" 
            ? "✓ Real-time data • ✓ Synced with Summary Cards" 
            : "📜 Historical snapshot data"}
        </span>
      </div>
    </section>
  );
}

export default Charts;
