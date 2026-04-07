import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { getUserSessions, getSessionDetail } from "../services/api.js";
import "../styles/history.css";

function SessionHistory({ onSelectSession, onBackToLive }) {
  const navigate = useNavigate();
  const [sessions, setSessions] = useState([]);
  const [selectedSession, setSelectedSession] = useState(null);
  const [sessionDetail, setSessionDetail] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // Fetch sessions on mount
  useEffect(() => {
    const fetchSessions = async () => {
      try {
        setLoading(true);
        const data = await getUserSessions();
        if (data.sessions) {
          setSessions(data.sessions);
        }
      } catch (err) {
        setError(`❌ Failed to load sessions: ${err.message}`);
      } finally {
        setLoading(false);
      }
    };

    fetchSessions();
  }, []);

  const handleSessionSelect = async (session) => {
    try {
      setLoading(true);
      setError("");
      setSelectedSession(session);

      const detail = await getSessionDetail(session.id);
      setSessionDetail(detail);
    } catch (err) {
      setError(`❌ Failed to load session: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleViewOnDashboard = () => {
    if (sessionDetail?.final_snapshot?.snapshot_data) {
      // Convert snapshot data to moduleData format for dashboard
      const snapshot = sessionDetail.final_snapshot.snapshot_data;
      
      // Debug log to verify port data
      console.log("[SessionHistory] Raw snapshot ports:", snapshot.ports);
      console.log("[SessionHistory] Port count:", snapshot.ports?.length || 0);
      const moduleData = {
        ransomware: {
          count: snapshot.ransomware?.ransomware || 0,
          status: snapshot.ransomware?.ransomware > 0 ? "MALICIOUS" : "SAFE",
          summary: {
            total: snapshot.ransomware?.total_processes || 0,
            ransomware: snapshot.ransomware?.ransomware || 0,
            suspicious: snapshot.ransomware?.suspicious || 0,
            benign: snapshot.ransomware?.benign || 0,
          },
          lastScan: sessionDetail.end_time,
        },
        portscan: {
          count: snapshot.ports?.length || 0,
          status: snapshot.ports?.some(p => p.risk_level === "CRITICAL") ? "MALICIOUS" : "SAFE",
          scanData: {
            ports: snapshot.ports || [],
            dashboard: [{
              total_ports: snapshot.ports?.length || 0,
              final_risk: snapshot.ports?.some(p => p.risk_level === "CRITICAL") ? "CRITICAL" : "LOW",
            }],
          },
          lastScan: sessionDetail.end_time,
        },
        honeypot: {
          count: snapshot.summary?.total_events - 
                 (snapshot.ransomware?.total_processes || 0) - 
                 (snapshot.ports?.length || 0) || 0,
          status: "SAFE",
          summary: {
            total: 0,
            critical: 0,
          },
          events: [],
          lastScan: sessionDetail.end_time,
        },
      };

      // Convert timeline snapshots to timeline data points for charts
      // Backend returns timeline_snapshots, not timeline
      const timelinePoints = (sessionDetail.timeline_snapshots || []).map(t => {
        const data = t.snapshot_data || {};
        return {
          time: new Date(t.timestamp).toLocaleTimeString(),
          ransomware: data.ransomware?.ransomware || 0,
          port_scan: data.ports?.length || 0,
          honeypot: (data.summary?.total_events || 0) - 
                   (data.ransomware?.total_processes || 0) - 
                   (data.ports?.length || 0),
        };
      });

      console.log("[SessionHistory] moduleData to send:", moduleData);
      console.log("[SessionHistory] moduleData.portscan.count:", moduleData.portscan.count);
      onSelectSession(moduleData, timelinePoints);
      navigate("/");
    }
  };

  const formatDateTime = (dateStr) => {
    if (!dateStr) return "N/A";
    try {
      const date = new Date(dateStr);
      return date.toLocaleString("en-US", {
        weekday: "short",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
    } catch {
      return dateStr;
    }
  };

  const formatDuration = (start, end) => {
    if (!start || !end) return "Active";
    try {
      const startDate = new Date(start);
      const endDate = new Date(end);
      const diffMs = endDate - startDate;
      const diffMins = Math.round(diffMs / 60000);
      if (diffMins < 60) return `${diffMins} min`;
      const hours = Math.floor(diffMins / 60);
      const mins = diffMins % 60;
      return `${hours}h ${mins}m`;
    } catch {
      return "Unknown";
    }
  };

  return (
    <div className="history-viewer">
      <div className="history-header">
        <h2>📊 Session History</h2>
        <button
          className="history-close"
          onClick={() => {
            onBackToLive();
            navigate("/");
          }}
          title="Go back to live dashboard"
        >
          ✕
        </button>
      </div>

      <div className="history-container">
        {/* Session List */}
        <div className="history-dates">
          <h3>Your Sessions</h3>

          {error && <div className="history-error">{error}</div>}

          {loading && sessions.length === 0 ? (
            <div className="history-loading">Loading sessions...</div>
          ) : sessions.length === 0 ? (
            <div className="history-empty">No session history available</div>
          ) : (
            <div className="dates-list">
              {sessions.map((session) => (
                <button
                  key={session.id}
                  className={`date-item ${selectedSession?.id === session.id ? "active" : ""}`}
                  onClick={() => handleSessionSelect(session)}
                  disabled={loading}
                >
                  <span className="date-label">
                    {session.status === "ACTIVE" ? "🟢" : "⚪"} Session #{session.id}
                  </span>
                  <span className="date-value">
                    {formatDateTime(session.start_time)}
                  </span>
                  <span className="session-duration">
                    {formatDuration(session.start_time, session.end_time)}
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Session Detail */}
        <div className="history-data">
          {selectedSession && (
            <>
              <div className="data-header">
                <h3>Session #{selectedSession.id}</h3>
                <span className={`status-badge ${selectedSession.status.toLowerCase()}`}>
                  {selectedSession.status}
                </span>
              </div>

              {loading ? (
                <div className="history-loading">Loading session data...</div>
              ) : sessionDetail ? (
                <>
                  {/* Session Info */}
                  <div className="data-section">
                    <h4>📅 Session Info</h4>
                    <div className="metrics-grid">
                      <div className="metric-box">
                        <span className="metric-label">Started</span>
                        <span className="metric-value">
                          {formatDateTime(sessionDetail.start_time)}
                        </span>
                      </div>
                      <div className="metric-box">
                        <span className="metric-label">Ended</span>
                        <span className="metric-value">
                          {sessionDetail.end_time ? formatDateTime(sessionDetail.end_time) : "Active"}
                        </span>
                      </div>
                      <div className="metric-box">
                        <span className="metric-label">Duration</span>
                        <span className="metric-value">
                          {formatDuration(sessionDetail.start_time, sessionDetail.end_time)}
                        </span>
                      </div>
                      <div className="metric-box">
                        <span className="metric-label">Timeline Snapshots</span>
                        <span className="metric-value">
                          {sessionDetail.timeline_snapshots?.length || 0}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Final Snapshot Summary */}
                  {sessionDetail.final_snapshot?.snapshot_data && (
                    <div className="data-section metrics-section">
                      <h4>📸 Final Snapshot</h4>
                      <div className="metrics-grid">
                        <div className="metric-box">
                          <span className="metric-label">Total Events</span>
                          <span className="metric-value">
                            {sessionDetail.final_snapshot.snapshot_data.summary?.total_events || 0}
                          </span>
                        </div>
                        <div className="metric-box">
                          <span className="metric-label">Ransomware Critical</span>
                          <span className="metric-value metric-critical">
                            {sessionDetail.final_snapshot.snapshot_data.summary?.ransomware_critical || 0}
                          </span>
                        </div>
                        <div className="metric-box">
                          <span className="metric-label">Warnings</span>
                          <span className="metric-value metric-high">
                            {sessionDetail.final_snapshot.snapshot_data.summary?.warning || 0}
                          </span>
                        </div>
                        <div className="metric-box">
                          <span className="metric-label">Benign</span>
                          <span className="metric-value metric-medium">
                            {sessionDetail.final_snapshot.snapshot_data.summary?.benign || 0}
                          </span>
                        </div>
                      </div>

                      {/* Ransomware Details */}
                      {sessionDetail.final_snapshot.snapshot_data.ransomware && (
                        <div className="subsection">
                          <h5>🔒 Ransomware Details</h5>
                          <div className="mini-stats">
                            <span>Total: {sessionDetail.final_snapshot.snapshot_data.ransomware.total_processes}</span>
                            <span className="stat-critical">Ransomware: {sessionDetail.final_snapshot.snapshot_data.ransomware.ransomware}</span>
                            <span className="stat-warning">Suspicious: {sessionDetail.final_snapshot.snapshot_data.ransomware.suspicious}</span>
                            <span className="stat-safe">Benign: {sessionDetail.final_snapshot.snapshot_data.ransomware.benign}</span>
                          </div>
                        </div>
                      )}

                      {/* Port Scan Summary */}
                      {sessionDetail.final_snapshot.snapshot_data.ports?.length > 0 && (
                        <div className="subsection">
                          <h5>🌐 Port Scan ({sessionDetail.final_snapshot.snapshot_data.ports.length} ports)</h5>
                          <div className="ports-preview">
                            {sessionDetail.final_snapshot.snapshot_data.ports.slice(0, 5).map((port, idx) => (
                              <span key={idx} className={`port-tag ${port.risk_level?.toLowerCase()}`}>
                                {port.port}/{port.service} ({port.risk_level})
                              </span>
                            ))}
                            {sessionDetail.final_snapshot.snapshot_data.ports.length > 5 && (
                              <span className="port-tag more">
                                +{sessionDetail.final_snapshot.snapshot_data.ports.length - 5} more
                              </span>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Timeline Snapshots */}
                  {sessionDetail.timeline_snapshots?.length > 0 && (
                    <div className="data-section events-section">
                      <h4>📈 Timeline ({sessionDetail.timeline_snapshots.length} snapshots)</h4>
                      <div className="timeline-list">
                        {sessionDetail.timeline_snapshots.map((snap, idx) => (
                          <div key={snap.id} className="timeline-item">
                            <span className="timeline-num">#{snap.sequence_number}</span>
                            <span className="timeline-time">{formatDateTime(snap.timestamp)}</span>
                            <span className="timeline-stats">
                              Events: {snap.snapshot_data.summary?.total_events || 0}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* View on Dashboard Button */}
                  {sessionDetail.final_snapshot && (
                    <button
                      className="btn-view-dashboard"
                      onClick={handleViewOnDashboard}
                    >
                      📊 View on Dashboard
                    </button>
                  )}
                </>
              ) : (
                <div className="history-empty">Select a session to view details</div>
              )}
            </>
          )}
        </div>
      </div>

      {/* Action Bar */}
      <div className="history-actions">
        <button
          className="btn-back-live"
          onClick={() => {
            onBackToLive();
            navigate("/");
          }}
        >
          ← Back to Live Dashboard
        </button>
      </div>
    </div>
  );
}

export default SessionHistory;
