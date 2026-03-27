import { useEffect, useState } from "react";
import { BarChart, Bar, LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, Legend } from "recharts";
import {
  runRansomwarePipeline,
  fetchRansomwarePredictions,
  fetchRansomwareAlerts,
  scanRealSystem,
  startSimulationScan,
  startSystemScan,
  stopScan,
  getScanStatus,
} from "../../services/api";

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

export default function RansomwareDetails({ moduleState, updateModuleState }) {
  // UI state
  const [predictions, setPredictions] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [summary, setSummary] = useState(null);
  const [activeTab, setActiveTab] = useState("processes");
  const [error, setError] = useState("");
  const [pipelineMsg, setPipelineMsg] = useState("");

  // Dual scan mode state
  const [scanMode, setScanMode] = useState(null); // null | "simulation" | "system"
  const [isScanning, setIsScanning] = useState(false);
  const [currentDuration, setCurrentDuration] = useState(null);
  const [statusPollInterval, setStatusPollInterval] = useState(null);

  // Load initial data from moduleState
  useEffect(() => {
    if (!moduleState) return;
    if (moduleState.predictions?.length) setPredictions(moduleState.predictions);
    if (moduleState.summary) setSummary(moduleState.summary);
    if (moduleState.alerts?.length) setAlerts(moduleState.alerts);
  }, [moduleState]);

  // Cleanup polling interval on unmount
  useEffect(() => {
    return () => {
      if (statusPollInterval) {
        clearInterval(statusPollInterval);
      }
    };
  }, [statusPollInterval]);

  // Clear all outputs when switching modes
  const clearScanOutputs = () => {
    setPredictions([]);
    setAlerts([]);
    setSummary(null);
    setActiveTab("processes");
    setPipelineMsg("");
    setError("");
  };

  // Load results from disk
  const loadResults = async () => {
    try {
      const [predData, alertData] = await Promise.all([
        fetchRansomwarePredictions(),
        fetchRansomwareAlerts(),
      ]);
      setPredictions(predData.predictions || []);
      setSummary(predData.summary || null);
      setAlerts(alertData.alerts || []);

      const ransomwareCount = Number(predData.summary?.ransomware ?? 0);
      updateModuleState({
        count: ransomwareCount,
        status: ransomwareCount > 0 ? "MALICIOUS" : "SAFE",
        summary: predData.summary || null,
        predictions: predData.predictions || [],
        alerts: alertData.alerts || [],
        lastScan: new Date().toISOString(),
      });
    } catch (e) {
      setError("Failed to load results. Is the backend running on port 8000?");
    }
  };

  // Poll scan status until complete
  const pollScanStatus = async () => {
    try {
      const status = await getScanStatus();
      setCurrentDuration(status.duration_seconds);

      if (!status.active) {
        // Scan finished, load results and clear polling
        setIsScanning(false);
        setScanMode(null);
        setPipelineMsg("Scan complete. Loading results...");
        clearInterval(statusPollInterval);
        setStatusPollInterval(null);

        await loadResults();
        setPipelineMsg("Done.");
      }
    } catch (e) {
      console.error("Error polling scan status:", e);
    }
  };

  // Start simulation mode scan
  const handleStartSimulationScan = async () => {
    clearScanOutputs();
    setIsScanning(true);
    setScanMode("simulation");
    setPipelineMsg("Starting simulation scan...");
    setError("");

    try {
      const res = await startSimulationScan();
      if (res.status === "started") {
        // Start polling for status
        const interval = setInterval(pollScanStatus, 2000);
        setStatusPollInterval(interval);
      } else {
        setError("Failed to start simulation scan");
        setIsScanning(false);
        setScanMode(null);
      }
    } catch (e) {
      setError(`Error starting simulation: ${e.message}`);
      setIsScanning(false);
      setScanMode(null);
    }
  };

  // Start system monitoring scan
  const handleStartSystemScan = async () => {
    clearScanOutputs();
    setIsScanning(true);
    setScanMode("system");
    setPipelineMsg("Starting real system monitoring...");
    setError("");

    try {
      const res = await startSystemScan();
      if (res.status === "started") {
        // Start polling for status
        const interval = setInterval(pollScanStatus, 2000);
        setStatusPollInterval(interval);
      } else {
        setError("Failed to start system scan");
        setIsScanning(false);
        setScanMode(null);
      }
    } catch (e) {
      setError(`Error starting system scan: ${e.message}`);
      setIsScanning(false);
      setScanMode(null);
    }
  };

  // Stop current scan
  const handleStopScan = async () => {
    try {
      await stopScan();
      setIsScanning(false);
      setScanMode(null);
      setPipelineMsg("Scan stopped");
      if (statusPollInterval) {
        clearInterval(statusPollInterval);
        setStatusPollInterval(null);
      }
    } catch (e) {
      setError(`Error stopping scan: ${e.message}`);
    }
  };

  // Chart data: top processes by confidence (non-benign first, then benign)
  const chartData = [...predictions]
    .sort((a, b) => b.confidence - a.confidence)
    .slice(0, 12)
    .map(r => ({
      name: (r.process || r.process_name || "unknown").replace(".exe", ""),
      confidence: Math.round(r.confidence * 100),
      level: r.threatLevel,
    }));

  return (
    <div className="report-page" style={{ color: "#e0e0e0" }}>
      <h1 style={{ marginBottom: 6 }}>Ransomware Detection Report</h1>
      <p style={{ color: "#888", marginBottom: 24, fontSize: 13 }}>
        Honeypot + ML pipeline — behavioral anomaly detection
      </p>

      {/* Dual Scan Mode Buttons - Exclusive Selection */}
      <div style={{ display: "flex", gap: 12, marginBottom: 24, flexWrap: "wrap", alignItems: "center" }}>
        <div style={{ display: "flex", gap: 8, borderRadius: 8, background: "#1a1a2e", padding: 4 }}>
          <button
            className="scan-btn"
            onClick={handleStartSimulationScan}
            disabled={isScanning}
            style={{
              background: scanMode === "simulation" ? "#2a5a3a" : "#1a2a2a",
              border: scanMode === "simulation" ? "2px solid #4caf50" : "2px solid #444",
              color: scanMode === "simulation" ? "#4caf50" : "#aaa",
              minWidth: 140,
              transition: "all 0.3s",
            }}
            title="Run simulation pipeline with synthetic events"
          >
            {isScanning && scanMode === "simulation" ? "⏱ Simulating..." : "Simulation Scan"}
          </button>

          <button
            className="scan-btn"
            onClick={handleStartSystemScan}
            disabled={isScanning}
            style={{
              background: scanMode === "system" ? "#2a3a5a" : "#1a2a2a",
              border: scanMode === "system" ? "2px solid #7c83fd" : "2px solid #444",
              color: scanMode === "system" ? "#7c83fd" : "#aaa",
              minWidth: 140,
              transition: "all 0.3s",
            }}
            title="Monitor real system activity while running safe test scripts"
          >
            {isScanning && scanMode === "system" ? "🔍 Scanning..." : "System Scan"}
          </button>
        </div>

        {isScanning && (
          <button
            onClick={handleStopScan}
            style={{
              background: "#4a1a1a",
              border: "1px solid #c62828",
              color: "#ff6b6b",
              padding: "8px 16px",
              borderRadius: 6,
              cursor: "pointer",
              fontSize: 13,
              fontWeight: 600,
            }}
          >
            ⏹ Stop Scan
          </button>
        )}

        {currentDuration !== null && (
          <span style={{ fontSize: 12, color: "#888", marginLeft: 8 }}>
            Duration: <span style={{ color: "#aaa", fontWeight: 600 }}>{Math.round(currentDuration)}s</span>
          </span>
        )}
      </div>

      {/* Legacy buttons for compatibility */}
      <div style={{ display: "flex", gap: 12, marginBottom: 24, flexWrap: "wrap" }}>
        <button
          className="scan-btn"
          onClick={async () => {
            clearScanOutputs();
            try {
              const res = await runRansomwarePipeline();
              if (res.status === "ok") {
                setPipelineMsg("Pipeline complete. Loading results...");
                await loadResults();
                setPipelineMsg("Done.");
              } else {
                setError(`Pipeline error: ${res.message}`);
              }
            } catch (e) {
              setError("Cannot reach backend. Start it with: uvicorn api_server:app --reload");
            }
          }}
          disabled={isScanning}
          style={{ minWidth: 180, fontSize: 14, display: "flex", alignItems: "center", justifyContent: "center" }}
          title="Legacy: Run the full ransomware pipeline (simulation mode)"
        >
          {isScanning ? "Scanning..." : "Run Full Pipeline"}
        </button>

        <button
          className="scan-btn"
          onClick={loadResults}
          disabled={isScanning}
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

      {/* Real-Time Activity Graph */}
      {summary && (
        <div style={{
          background: "#0f172a",
          border: "1px solid #333",
          borderRadius: "10px",
          padding: "16px",
          marginBottom: "28px"
        }}>
          <h3 style={{ margin: "0 0 16px 0", color: "#e0e0e0", fontSize: "15px", fontWeight: 700 }}>
            Process Classification Summary
          </h3>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={[{
              name: "Processes",
              Total: summary.total || 0,
              Ransomware: summary.ransomware || 0,
              Suspicious: summary.suspicious || 0,
              Benign: summary.benign || 0
            }]}>
              <XAxis dataKey="name" stroke="#666" />
              <YAxis stroke="#666" tick={{ fontSize: 11 }} />
              <Tooltip
                contentStyle={{ background: "#1a1a2e", border: "1px solid #333" }}
                labelStyle={{ color: "#e0e0e0" }}
              />
              <Legend />
              <Bar dataKey="Total" fill="#7c83fd" radius={[4, 4, 0, 0]} />
              <Bar dataKey="Ransomware" fill="#ff4444" radius={[4, 4, 0, 0]} />
              <Bar dataKey="Suspicious" fill="#ff9800" radius={[4, 4, 0, 0]} />
              <Bar dataKey="Benign" fill="#4caf50" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
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
                        <td style={{ padding: "9px 14px", fontWeight: 600 }}>{row.process || row.process_name || "unknown"}</td>
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
                      <div style={{ fontWeight: 700, fontSize: 15, marginBottom: 4 }}>{alert.process || alert.process_name || "unknown"}</div>
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
