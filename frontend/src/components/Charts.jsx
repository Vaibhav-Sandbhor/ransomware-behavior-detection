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

function Charts({ moduleData, timelineData, setTimelineData }) {
  // ✅ SINGLE SOURCE OF TRUTH - From moduleData (SAME as summary cards)
  const currentRansomware = moduleData?.ransomware?.count || 0;
  const currentPortScan = moduleData?.portscan?.count || 0;
  const currentHoneypot = moduleData?.honeypot?.count || 0;

  const [hasScanned, setHasScanned] = useState(false);

  // ✅ UPDATE TIMELINE WHEN MODULE DATA CHANGES (use prop-based state)
  useEffect(() => {
    // Check if we have data
    const hasData = currentRansomware > 0 || currentPortScan > 0 || currentHoneypot > 0;
    if (hasData) {
      setHasScanned(true);
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

  }, [currentRansomware, currentPortScan, currentHoneypot, setTimelineData]);

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

          {/* TOTAL ACTIVITY BAR */}
          <div className="ml-card">
            <div className="ml-card-header">Total Threat Activity</div>
            {timelineData.length > 0 ? (
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={[{ name: "Total", value: total }]}>
                  <XAxis dataKey="name" stroke="#666" />
                  <YAxis stroke="#666" tick={{ fontSize: 11 }} />
                  <Tooltip contentStyle={{ background: "#1a1a2e", border: "1px solid #333" }} />
                  <Bar dataKey="value" fill="#3b82f6" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div style={{
                height: 200,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#666"
              }}>
                Loading...
              </div>
            )}
          </div>
        </div>
      )}

      {/* ROW 2: TWO SEPARATE TIMELINE GRAPHS - SIDE BY SIDE */}
      {hasScanned && timelineData.length > 0 && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginTop: "16px" }}>

          {/* LEFT: HONEYPOT TIMELINE */}
          <div className="ml-card">
            <div className="ml-card-header">Honeypot Activity Timeline</div>
            <ResponsiveContainer width="100%" height={280}>
              <LineChart data={timelineData} margin={{ top: 5, right: 30, left: 0, bottom: 5 }}>
                <XAxis
                  dataKey="time"
                  stroke="#666"
                  tick={{ fontSize: 10 }}
                  interval={Math.max(0, Math.floor(timelineData.length / 6))}
                />
                <YAxis stroke="#666" tick={{ fontSize: 11 }} />
                <Tooltip
                  contentStyle={{ background: "#1a1a2e", border: "1px solid #333", borderRadius: "4px" }}
                  formatter={(value) => [`${value} events`, "Honeypot"]}
                />
                <Legend wrapperStyle={{ paddingTop: "10px" }} />

                {/* ✅ HONEYPOT ONLY - BLUE */}
                <Line
                  type="linear"
                  dataKey="honeypot"
                  stroke={COLORS.honeypot}
                  strokeWidth={3}
                  dot={{ fill: COLORS.honeypot, r: 6, strokeWidth: 2, stroke: "#fff" }}
                  activeDot={{ r: 8 }}
                  name="Honeypot"
                  isAnimationActive={true}
                />
              </LineChart>
            </ResponsiveContainer>
            <div style={{ marginTop: "8px", fontSize: "10px", color: "#888", textAlign: "center" }}>
              Current: {currentHoneypot} events
            </div>
          </div>

          {/* RIGHT: RANSOMWARE + PORT SCAN TIMELINE */}
          <div className="ml-card">
            <div className="ml-card-header">Ransomware & Port Scan Timeline</div>
            <ResponsiveContainer width="100%" height={280}>
              <LineChart data={timelineData} margin={{ top: 5, right: 30, left: 0, bottom: 5 }}>
                <XAxis
                  dataKey="time"
                  stroke="#666"
                  tick={{ fontSize: 10 }}
                  interval={Math.max(0, Math.floor(timelineData.length / 6))}
                />
                <YAxis stroke="#666" tick={{ fontSize: 11 }} />
                <Tooltip
                  contentStyle={{ background: "#1a1a2e", border: "1px solid #333", borderRadius: "4px" }}
                  formatter={(value, name) => {
                    const names = {
                      ransomware: "Ransomware",
                      port_scan: "Port Scans"
                    };
                    return [`${value} events`, names[name] || name];
                  }}
                />
                <Legend wrapperStyle={{ paddingTop: "10px" }} />

                {/* ✅ RANSOMWARE - RED */}
                <Line
                  type="linear"
                  dataKey="ransomware"
                  stroke={COLORS.ransomware}
                  strokeWidth={3}
                  dot={{ fill: COLORS.ransomware, r: 6, strokeWidth: 2, stroke: "#fff" }}
                  activeDot={{ r: 8 }}
                  name="Ransomware"
                  isAnimationActive={true}
                />

                {/* ✅ PORT SCAN - YELLOW */}
                <Line
                  type="linear"
                  dataKey="port_scan"
                  stroke={COLORS.port_scan}
                  strokeWidth={3}
                  dot={{ fill: COLORS.port_scan, r: 6, strokeWidth: 2, stroke: "#fff" }}
                  activeDot={{ r: 8 }}
                  name="Port Scans"
                  isAnimationActive={true}
                />
              </LineChart>
            </ResponsiveContainer>
            <div style={{ marginTop: "8px", fontSize: "10px", color: "#888", textAlign: "center" }}>
              Current: Ransomware={currentRansomware}, Ports={currentPortScan}
            </div>
          </div>
        </div>
      )}

      {/* ROW 3: LIVE SECURITY EVENT FEED - REMOVED (use AlertsPanel instead) */}

      <div className="ml-footer">
        Status: <b>{hasScanned ? "Active" : "Waiting"}</b>
        <span style={{ marginLeft: "12px", color: "#666" }}>
          ✓ Real-time data • ✓ Synced with Summary Cards
        </span>
      </div>
    </section>
  );
}

export default Charts;
