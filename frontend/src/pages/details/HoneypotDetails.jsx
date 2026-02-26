import { useState } from "react";
import { fetchHoneypotLog, fetchRansomwareAlerts } from "../../servives/api";

const LEVEL_COLOR = {
  CRITICAL: { bg: "#ff4444", badge: "#c62828", text: "#fff" },
  WARNING:  { bg: "#ff9800", badge: "#e65100", text: "#fff" },
  INFO:     { bg: "#2a2a3a", badge: "#444",    text: "#aaa" },
};

const OP_COLOR = {
  WRITE:  "#7c83fd",
  READ:   "#4caf50",
  RENAME: "#ff9800",
  DELETE: "#ff4444",
  CREATE: "#26c6da",
};

function LevelBadge({ level }) {
  const c = LEVEL_COLOR[level] || LEVEL_COLOR.INFO;
  return (
    <span style={{
      background: c.badge, color: "#fff",
      padding: "2px 9px", borderRadius: 10,
      fontSize: 11, fontWeight: 700, letterSpacing: 1,
    }}>
      {level}
    </span>
  );
}

function ScoreBar({ value }) {
  const pct  = Math.round(value * 100);
  const color = pct >= 70 ? "#ff4444" : pct >= 40 ? "#ff9800" : "#4caf50";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div style={{ flex: 1, height: 7, background: "#2a2a3a", borderRadius: 4, overflow: "hidden" }}>
        <div style={{ width: `${pct}%`, height: "100%", background: color, borderRadius: 4 }} />
      </div>
      <span style={{ fontSize: 11, color: "#ccc", minWidth: 34, textAlign: "right" }}>{pct}%</span>
    </div>
  );
}

function SummaryCard({ label, value, color }) {
  return (
    <div style={{
      background: "#1a1a2e", border: `1px solid ${color}`,
      borderRadius: 10, padding: "16px 22px", minWidth: 120, textAlign: "center",
    }}>
      <div style={{ fontSize: 28, fontWeight: 800, color }}>{value}</div>
      <div style={{ fontSize: 11, color: "#aaa", marginTop: 4 }}>{label}</div>
    </div>
  );
}

export default function HoneypotDetails() {
  const [loading, setLoading]   = useState(false);
  const [events, setEvents]     = useState([]);
  const [alerts, setAlerts]     = useState([]);
  const [summary, setSummary]   = useState(null);
  const [activeTab, setActiveTab] = useState("events");
  const [error, setError]       = useState("");

  const loadData = async () => {
    setLoading(true);
    setError("");
    try {
      const [logData, alertData] = await Promise.all([
        fetchHoneypotLog(),
        fetchRansomwareAlerts(),
      ]);
      setEvents(logData.events   || []);
      setSummary(logData.summary || null);
      setAlerts(alertData.alerts || []);
    } catch {
      setError("Cannot reach backend. Start it with: uvicorn api_server:app --reload");
    }
    setLoading(false);
  };

  return (
    <div className="report-page" style={{ color: "#e0e0e0" }}>
      <h1 style={{ marginBottom: 6 }}>Honeypot Deception Module</h1>
      <p style={{ color: "#888", marginBottom: 24, fontSize: 13 }}>
        Decoy file monitoring — behavioral signals from the CyberSIEM honeypot
      </p>

      {/* Load button */}
      <div style={{ marginBottom: 24 }}>
        <button className="scan-btn" onClick={loadData} disabled={loading}>
          {loading ? "Loading..." : "Load Honeypot Data"}
        </button>
      </div>

      {error && <p style={{ color: "#ff4444", marginBottom: 16, fontSize: 13 }}>{error}</p>}

      {/* Summary cards */}
      {summary && (
        <div style={{ display: "flex", gap: 16, marginBottom: 28, flexWrap: "wrap" }}>
          <SummaryCard label="Total Events"       value={summary.total}    color="#7c83fd" />
          <SummaryCard label="Ransomware CRITICAL" value={summary.critical} color="#ff4444" />
          <SummaryCard label="WARNING"            value={summary.warning}  color="#ff9800" />
          <SummaryCard label="Benign"             value={summary.benign}   color="#4caf50" />
          <SummaryCard label="ML Alerts"          value={alerts.length}    color="#26c6da" />
        </div>
      )}

      {(events.length > 0 || alerts.length > 0) && (
        <>
          {/* Tabs */}
          <div style={{ display: "flex", gap: 0, marginBottom: 0, borderBottom: "1px solid #333" }}>
            {[
              { key: "events",  label: `Honeypot Events (${events.length})` },
              { key: "alerts",  label: `ML Alerts (${alerts.length})` },
            ].map(({ key, label }) => (
              <button
                key={key}
                onClick={() => setActiveTab(key)}
                style={{
                  padding: "8px 22px", border: "none", cursor: "pointer",
                  background: activeTab === key ? "#7c83fd" : "transparent",
                  color:      activeTab === key ? "#fff"    : "#888",
                  fontWeight: activeTab === key ? 700 : 400,
                  borderRadius: "6px 6px 0 0", marginRight: 2, fontSize: 13,
                }}
              >
                {label}
              </button>
            ))}
          </div>

          {/* ── Honeypot Events Table ── */}
          {activeTab === "events" && (
            <div style={{ overflowX: "auto", marginTop: 0 }}>
              {events.length === 0 ? (
                <p style={{ color: "#666", padding: "20px 0" }}>
                  No honeypot events found. Run the pipeline first.
                </p>
              ) : (
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                  <thead>
                    <tr style={{ background: "#1a1a2e", color: "#888" }}>
                      {["Timestamp","Process","File","Operation","Entropy","Writes","Renames","Suspicion Score","Level"].map(h => (
                        <th key={h} style={{ padding: "9px 12px", textAlign: "left", fontWeight: 600, whiteSpace: "nowrap" }}>
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {events.map((ev, i) => {
                      const c = LEVEL_COLOR[ev.level] || LEVEL_COLOR.INFO;
                      const opColor = OP_COLOR[ev.operation] || "#888";
                      return (
                        <tr
                          key={i}
                          style={{
                            background: i % 2 === 0 ? "#12121e" : "#1a1a2e",
                            borderLeft: ev.level !== "INFO"
                              ? `3px solid ${c.badge}`
                              : "3px solid transparent",
                          }}
                        >
                          <td style={{ padding: "7px 12px", color: "#666", whiteSpace: "nowrap" }}>
                            {ev.timestamp}
                          </td>
                          <td style={{ padding: "7px 12px", fontWeight: 600, color: "#ddd" }}>
                            {ev.process}
                          </td>
                          <td style={{ padding: "7px 12px", color: "#888", maxWidth: 160, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                              title={ev.filePath}>
                            {ev.filePath.split("/").pop() || ev.filePath}
                          </td>
                          <td style={{ padding: "7px 12px" }}>
                            <span style={{
                              background: opColor + "22", color: opColor,
                              padding: "2px 8px", borderRadius: 6, fontSize: 11, fontWeight: 700,
                            }}>
                              {ev.operation}
                            </span>
                          </td>
                          <td style={{ padding: "7px 12px", color: ev.entropy > 6.5 ? "#ff6b6b" : "#aaa" }}>
                            {ev.entropy.toFixed(2)}
                          </td>
                          <td style={{ padding: "7px 12px", color: ev.writeCount > 20 ? "#ff9800" : "#aaa", textAlign: "center" }}>
                            {ev.writeCount}
                          </td>
                          <td style={{ padding: "7px 12px", color: ev.renameCount > 0 ? "#ff9800" : "#aaa", textAlign: "center" }}>
                            {ev.renameCount}
                          </td>
                          <td style={{ padding: "7px 12px", minWidth: 140 }}>
                            <ScoreBar value={ev.suspiciousScore} />
                          </td>
                          <td style={{ padding: "7px 12px" }}>
                            <LevelBadge level={ev.level} />
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {/* ── ML Alerts Section ── */}
          {activeTab === "alerts" && (
            <div style={{ marginTop: 16 }}>
              {alerts.length === 0 ? (
                <p style={{ color: "#666" }}>
                  No ML alerts found. Run the full pipeline from the Ransomware Detection page first.
                </p>
              ) : (
                alerts.map((alert, i) => {
                  const c = LEVEL_COLOR[alert.level] || LEVEL_COLOR.INFO;
                  return (
                    <div key={i} style={{
                      background: "#1a1a2e",
                      border:     `1px solid ${c.badge}`,
                      borderLeft: `4px solid ${c.badge}`,
                      borderRadius: 8, padding: "14px 20px", marginBottom: 12,
                    }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                        <LevelBadge level={alert.level} />
                        <span style={{ color: "#666", fontSize: 11 }}>{alert.timestamp}</span>
                      </div>
                      <div style={{ fontWeight: 700, fontSize: 15, marginBottom: 4, color: "#ddd" }}>
                        {alert.process}
                      </div>
                      <div style={{ color: "#aaa", fontSize: 12, marginBottom: 8 }}>{alert.detection}</div>
                      <div style={{ display: "flex", gap: 24, fontSize: 12 }}>
                        <span style={{ color: "#888" }}>
                          Confidence:{" "}
                          <strong style={{ color: c.badge }}>
                            {alert.confidence != null
                              ? `${(alert.confidence * 100).toFixed(1)}%`
                              : "N/A"}
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

      {/* Empty state before loading */}
      {!loading && events.length === 0 && alerts.length === 0 && !error && (
        <div style={{ textAlign: "center", color: "#444", marginTop: 60, fontSize: 14 }}>
          <div style={{ fontSize: 40, marginBottom: 12 }}>&#128737;</div>
          <div>Click <strong style={{ color: "#7c83fd" }}>Load Honeypot Data</strong> to view live honeypot events.</div>
          <div style={{ fontSize: 12, color: "#555", marginTop: 8 }}>
            Reads from <code>ransomware_module/honeypot/honeypot_log.csv</code>
          </div>
        </div>
      )}
    </div>
  );
}
