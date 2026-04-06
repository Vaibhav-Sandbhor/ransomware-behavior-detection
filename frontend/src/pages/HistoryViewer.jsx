import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { getHistoryDates, getHistoryMetrics, getHistoryEvents } from "../services/api.js";
import "../styles/history.css";

function HistoryViewer({ onSelectDate }) {
  const navigate = useNavigate();
  const [dates, setDates] = useState([]);
  const [selectedDate, setSelectedDate] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [metrics, setMetrics] = useState(null);
  const [events, setEvents] = useState(null);

  // Fetch available dates on mount
  useEffect(() => {
    const fetchDates = async () => {
      try {
        setLoading(true);
        const data = await getHistoryDates();
        if (data.dates) {
          setDates(data.dates);
          // Auto-select most recent date
          if (data.dates.length > 0) {
            handleDateSelect(data.dates[0]);
          }
        }
      } catch (err) {
        setError(`❌ Failed to load history dates: ${err.message}`);
      } finally {
        setLoading(false);
      }
    };

    fetchDates();
  }, []);

  const handleDateSelect = async (date) => {
    try {
      setLoading(true);
      setError("");
      setSelectedDate(date);

      // Fetch metrics and events for the selected date
      const [metricsData, eventsData] = await Promise.all([
        getHistoryMetrics(date),
        getHistoryEvents(date),
      ]);

      setMetrics(metricsData);
      setEvents(eventsData);

      // Call parent handler to update dashboard
      if (onSelectDate) {
        onSelectDate(date, metricsData, eventsData);
      }
    } catch (err) {
      setError(`❌ Failed to load data for ${date}: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateStr) => {
    try {
      const date = new Date(dateStr + "T00:00:00Z");
      return date.toLocaleDateString("en-US", {
        weekday: "short",
        year: "numeric",
        month: "short",
        day: "numeric",
      });
    } catch {
      return dateStr;
    }
  };

  return (
    <div className="history-viewer">
      <div className="history-header">
        <h2>📅 Historical Data Viewer</h2>
        <button
          className="history-close"
          onClick={() => navigate("/")}
          title="Go back to live dashboard"
        >
          ✕
        </button>
      </div>

      <div className="history-container">
        {/* Date List */}
        <div className="history-dates">
          <h3>Available Dates</h3>

          {error && <div className="history-error">{error}</div>}

          {loading && dates.length === 0 ? (
            <div className="history-loading">Loading dates...</div>
          ) : dates.length === 0 ? (
            <div className="history-empty">No historical data available</div>
          ) : (
            <div className="dates-list">
              {dates.map((date) => (
                <button
                  key={date}
                  className={`date-item ${selectedDate === date ? "active" : ""}`}
                  onClick={() => handleDateSelect(date)}
                  disabled={loading}
                >
                  <span className="date-label">{formatDate(date)}</span>
                  <span className="date-value">{date}</span>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Data Display */}
        <div className="history-data">
          {selectedDate && (
            <>
              <div className="data-header">
                <h3>Viewing history for {formatDate(selectedDate)}</h3>
              </div>

              {loading ? (
                <div className="history-loading">Loading data...</div>
              ) : (
                <>
                  {/* Metrics Summary */}
                  {metrics && (
                    <div className="data-section metrics-section">
                      <h4>📊 Metrics Summary</h4>
                      {metrics.summary && (
                        <div className="metrics-grid">
                          <div className="metric-box">
                            <span className="metric-label">Max Ransomware</span>
                            <span className="metric-value metric-critical">
                              {metrics.summary.max_ransomware}
                            </span>
                          </div>
                          <div className="metric-box">
                            <span className="metric-label">Max Ports Open</span>
                            <span className="metric-value metric-high">
                              {metrics.summary.max_portscan}
                            </span>
                          </div>
                          <div className="metric-box">
                            <span className="metric-label">Max Honeypot Hits</span>
                            <span className="metric-value metric-medium">
                              {metrics.summary.max_honeypot}
                            </span>
                          </div>
                          <div className="metric-box">
                            <span className="metric-label">Total Readings</span>
                            <span className="metric-value">{metrics.total}</span>
                          </div>
                        </div>
                      )}
                      <div className="time-range">
                        <small>
                          From: {metrics.summary?.first_recorded || "N/A"}
                          <br />
                          To: {metrics.summary?.last_recorded || "N/A"}
                        </small>
                      </div>
                    </div>
                  )}

                  {/* Events Summary */}
                  {events && (
                    <div className="data-section events-section">
                      <h4>📝 Threat Events</h4>
                      {events.total > 0 ? (
                        <>
                          <div className="severity-grid">
                            <div className="severity-box">
                              <span className="severity-label">🔴 Critical</span>
                              <span className="severity-count">
                                {events.severity_counts.CRITICAL}
                              </span>
                            </div>
                            <div className="severity-box">
                              <span className="severity-label">🟠 High</span>
                              <span className="severity-count">
                                {events.severity_counts.HIGH}
                              </span>
                            </div>
                            <div className="severity-box">
                              <span className="severity-label">🟡 Medium</span>
                              <span className="severity-count">
                                {events.severity_counts.MEDIUM}
                              </span>
                            </div>
                            <div className="severity-box">
                              <span className="severity-label">🟢 Low</span>
                              <span className="severity-count">
                                {events.severity_counts.LOW}
                              </span>
                            </div>
                          </div>

                          <div className="events-list">
                            <small className="event-count">Total: {events.total} events</small>
                            {events.events.slice(0, 5).map((event) => (
                              <div key={event.id} className={`event-item severity-${event.severity.toLowerCase()}`}>
                                <span className="event-module">[{event.module.toUpperCase()}]</span>
                                <span className="event-type">{event.event_type}</span>
                                <span className="event-severity">{event.severity}</span>
                              </div>
                            ))}
                            {events.total > 5 && (
                              <small className="more-events">
                                + {events.total - 5} more events
                              </small>
                            )}
                          </div>
                        </>
                      ) : (
                        <div className="history-empty">No threats detected on this date</div>
                      )}
                    </div>
                  )}
                </>
              )}
            </>
          )}
        </div>
      </div>

      {/* Action Bar */}
      <div className="history-actions">
        <button
          className="btn-back-live"
          onClick={() => navigate("/")}
        >
          ← Back to Live Dashboard
        </button>
      </div>
    </div>
  );
}

export default HistoryViewer;
