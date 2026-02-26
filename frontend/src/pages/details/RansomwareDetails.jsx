import { useState } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";
import {
  runRansomwarePipeline,
  fetchRansomwarePredictions,
  fetchRansomwareAlerts,
} from "../../servives/api";

const LEVEL_COLOR = {
  CRITICAL: { bg: "#ff4444", text: "#fff", badge: "#c62828" },
  WARNING:  { bg: "#ff9800", text: "#fff", badge: "#e65100" },
  INFO:     { bg: "#2a2a3a", text: "#aaa", badge: "#444" },
};

function ThreatBadge({ level }) {
  const c = LEVEL_COLOR[level] || LEVEL_COLOR.INFO;
  return (
    <span style={{
      background: c.badge, color: "#fff",
      padding: "2px 10px", borderRadius: 12,
      fontSize: 11, fontWeight: 700, letterSpacing: 1,
    }}>
      {level}
    </span>
  );
}

function ConfidenceBar({ value }) {
  const pct = Math.round(value * 100);
  const color = pct >= 70 ? "#ff4444" : pct >= 40 ? "#ff9800" : "#4caf50";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div style={{
        flex: 1, height: 8, background: "#2a2a3a", borderRadius: 4, overflow: "hidden"
      }}>
        <div style={{ width: `${pct}%`, height: "100%", background: color, borderRadius: 4 }} />
      </div>
      <span style={{ fontSize: 12, color: "#ccc", minWidth: 38, textAlign: "right" }}>
        {pct}%
      </span>
    </div>
  );
}

function SummaryCard({ label, value, color }) {
  return (
    <div style={{
      background: "#1a1a2e", border: `1px solid ${color}`,
      borderRadius: 10, padding: "18px 24px", minWidth: 130, textAlign: "center",
    }}>
      <div style={{ fontSize: 30, fontWeight: 800, color }}>{value}</div>
      <div style={{ fontSize: 12, color: "#aaa", marginTop: 4 }}>{label}</div>
    </div>
  );
}

export default function RansomwareDetails() {
  const [loading, setLoading]       = useState(false);
  const [pipelineMsg, setPipelineMsg] = useState("");
  const [predictions, setPredictions] = useState([]);
  const [alerts, setAlerts]         = useState([]);
  const [summary, setSummary]       = useState(null);
  const [activeTab, setActiveTab]   = useState("processes");
  const [error, setError]           = useState("");

  const loadResults = async () => {
    try {
      const [predData, alertData] = await Promise.all([
        fetchRansomwarePredictions(),
        fetchRansomwareAlerts(),
      ]);
      setPredictions(predData.predictions || []);
      setSummary(predData.summary || null);
      setAlerts(alertData.alerts || []);
    } catch (e) {
      setError("Failed to load results. Is the backend running on port 8000?");
    }
  };

  const handleRunPipeline = async () => {
    setLoading(true);
    setPipelineMsg("Running pipeline...");
    setError("");
    try {
      const res = await runRansomwarePipeline();
      if (res.status === "ok") {
        setPipelineMsg("Pipeline complete. Loading results...");
        await loadResults();
        setPipelineMsg("Done.");
      } else {
        setError(`Pipeline error: ${res.message}`);
        setPipelineMsg("");
      }
    } catch (e) {
      setError("Cannot reach backend. Start it with: uvicorn api_server:app --reload");
      setPipelineMsg("");
    }
    setLoading(false);
  };

  const handleLoadExisting = async () => {
    setLoading(true);
    setError("");
    try {
      await loadResults();
    } catch (e) {
      setError("Failed to load. Is the backend running on port 8000?");
    }
    setLoading(false);
  };

  // Chart data: top processes by confidence (non-benign first, then benign)
  const chartData = [...predictions]
    .sort((a, b) => b.confidence - a.confidence)
    .slice(0, 12)
    .map(r => ({
      name: r.process.replace(".exe", ""),
      confidence: Math.round(r.confidence * 100),
      level: r.threatLevel,
    }));

  return (
    <div className="report-page" style={{ color: "#e0e0e0" }}>
      <h1 style={{ marginBottom: 6 }}>Ransomware Detection Report</h1>
      <p style={{ color: "#888", marginBottom: 24, fontSize: 13 }}>
        Honeypot + ML pipeline — behavioral anomaly detection
      </p>

      {/* Action buttons */}
      <div style={{ display: "flex", gap: 12, marginBottom: 24 }}>
        <button className="scan-btn" onClick={handleRunPipeline} disabled={loading}>
          {loading ? "Running..." : "Run Full Pipeline"}
        </button>
        <button
          className="scan-btn"
          onClick={handleLoadExisting}
          disabled={loading}
          style={{ background: "#1a2a4a" }}
        >
          Load Existing Results
        </button>
      </div>

      {pipelineMsg && (
        <p style={{ color: "#4caf50", marginBottom: 16, fontSize: 13 }}>{pipelineMsg}</p>
      )}
      {error && (
        <p style={{ color: "#ff4444", marginBottom: 16, fontSize: 13 }}>{error}</p>
      )}

      {/* Summary cards */}
      {summary && (
        <div style={{ display: "flex", gap: 16, marginBottom: 28, flexWrap: "wrap" }}>
          <SummaryCard label="Total Processes"   value={summary.total}      color="#7c83fd" />
          <SummaryCard label="Ransomware"         value={summary.ransomware} color="#ff4444" />
          <SummaryCard label="Suspicious"         value={summary.suspicious} color="#ff9800" />
          <SummaryCard label="Benign"             value={summary.benign}     color="#4caf50" />
        </div>
      )}

      {predictions.length > 0 && (
        <>
          {/* Tabs */}
          <div style={{ display: "flex", gap: 0, marginBottom: 0, borderBottom: "1px solid #333" }}>
            {["processes", "chart", "alerts"].map(tab => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                style={{
                  padding: "8px 22px", border: "none", cursor: "pointer",
                  background: activeTab === tab ? "#7c83fd" : "transparent",
                  color: activeTab === tab ? "#fff" : "#888",
                  fontWeight: activeTab === tab ? 700 : 400,
                  borderRadius: "6px 6px 0 0", marginRight: 2, fontSize: 13,
                }}
              >
                {tab === "processes" ? "Process Table" : tab === "chart" ? "Confidence Chart" : `Alerts (${alerts.length})`}
              </button>
            ))}
          </div>

          {/* Process Table */}
          {activeTab === "processes" && (
            <div style={{ overflowX: "auto", marginTop: 0 }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
                <thead>
                  <tr style={{ background: "#1a1a2e", color: "#888" }}>
                    {["Timestamp", "Process", "Prediction", "Confidence", "Threat Level", "Source"].map(h => (
                      <th key={h} style={{ padding: "10px 14px", textAlign: "left", fontWeight: 600 }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {predictions.map((row, i) => {
                    const c = LEVEL_COLOR[row.threatLevel] || LEVEL_COLOR.INFO;
                    return (
                      <tr
                        key={i}
                        style={{
                          background: i % 2 === 0 ? "#12121e" : "#1a1a2e",
                          borderLeft: row.threatLevel !== "INFO" ? `3px solid ${c.badge}` : "3px solid transparent",
                        }}
                      >
                        <td style={{ padding: "9px 14px", color: "#888", whiteSpace: "nowrap" }}>
                          {row.timestamp}
                        </td>
                        <td style={{ padding: "9px 14px", fontWeight: 600 }}>{row.process}</td>
                        <td style={{ padding: "9px 14px", color: row.prediction === "RANSOMWARE" ? "#ff4444" : "#4caf50" }}>
                          {row.prediction}
                        </td>
                        <td style={{ padding: "9px 14px", minWidth: 160 }}>
                          <ConfidenceBar value={row.confidence} />
                        </td>
                        <td style={{ padding: "9px 14px" }}>
                          <ThreatBadge level={row.threatLevel} />
                        </td>
                        <td style={{ padding: "9px 14px", color: "#666", fontSize: 11 }}>{row.source}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          {/* Confidence Chart */}
          {activeTab === "chart" && (
            <div style={{ marginTop: 16 }}>
              <p style={{ color: "#888", fontSize: 12, marginBottom: 12 }}>
                Top processes by ML confidence score (red = CRITICAL, orange = WARNING, green = benign)
              </p>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={chartData} margin={{ top: 8, right: 20, left: 0, bottom: 40 }}>
                  <XAxis dataKey="name" tick={{ fill: "#888", fontSize: 11 }} angle={-35} textAnchor="end" />
                  <YAxis domain={[0, 100]} tick={{ fill: "#888", fontSize: 11 }} unit="%" />
                  <Tooltip
                    formatter={(v) => [`${v}%`, "Confidence"]}
                    contentStyle={{ background: "#1a1a2e", border: "1px solid #333", color: "#e0e0e0" }}
                  />
                  <Bar dataKey="confidence" radius={[4, 4, 0, 0]}>
                    {chartData.map((entry, i) => (
                      <Cell
                        key={i}
                        fill={
                          entry.level === "CRITICAL" ? "#ff4444" :
                          entry.level === "WARNING"  ? "#ff9800" : "#4caf50"
                        }
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Alerts Tab */}
          {activeTab === "alerts" && (
            <div style={{ marginTop: 16 }}>
              {alerts.length === 0 ? (
                <p style={{ color: "#666" }}>No alerts generated.</p>
              ) : (
                alerts.map((alert, i) => {
                  const c = LEVEL_COLOR[alert.level] || LEVEL_COLOR.INFO;
                  return (
                    <div key={i} style={{
                      background: "#1a1a2e",
                      border: `1px solid ${c.badge}`,
                      borderLeft: `4px solid ${c.badge}`,
                      borderRadius: 8, padding: "14px 20px", marginBottom: 12,
                    }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                        <ThreatBadge level={alert.level} />
                        <span style={{ color: "#666", fontSize: 11 }}>{alert.timestamp}</span>
                      </div>
                      <div style={{ fontWeight: 700, fontSize: 15, marginBottom: 4 }}>{alert.process}</div>
                      <div style={{ color: "#aaa", fontSize: 12, marginBottom: 4 }}>{alert.detection}</div>
                      <div style={{ display: "flex", gap: 20, fontSize: 12 }}>
                        <span style={{ color: "#888" }}>
                          Confidence: <strong style={{ color: c.badge }}>
                            {alert.confidence != null ? `${(alert.confidence * 100).toFixed(1)}%` : "N/A"}
                          </strong>
                        </span>
                        <span style={{ color: "#555" }}>Source: {alert.source}</span>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}
