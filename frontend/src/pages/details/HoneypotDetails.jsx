import React from "react";

function HoneypotDetails() {
  // ✅ Mock data (Later this will come from MongoDB/Postgres API)
  const honeypotLogs = [
    {
      timestamp: "2026-01-20 11:43:59",
      src_ip: "127.0.0.1",
      session: "290b86c921ab",
      command: "5543.0",
      sensor: "cowrie",
      ransomware_label: "0.0",
    },
    {
      timestamp: "2026-01-20 12:07:27",
      src_ip: "127.0.0.1",
      session: "e162c9344ad9",
      command: "0.215355",
      sensor: "cowrie",
      ransomware_label: "0.0",
    },
    {
      timestamp: "2026-01-20 12:18:23",
      src_ip: "127.0.0.1",
      session: "3efe1e26e86e",
      command: "2255.0",
      sensor: "cowrie",
      ransomware_label: "0.0",
    },
    {
      timestamp: "2026-01-20 12:18:42",
      src_ip: "127.0.0.1",
      session: "3efe1e26e86e",
      command: "122002.0",
      sensor: "cowrie",
      ransomware_label: "0.0",
    },
    {
      timestamp: "2026-01-20 12:47:13",
      src_ip: "127.0.0.1",
      session: "ab413f36bb2a",
      command: "2154.0",
      sensor: "cowrie",
      ransomware_label: "0.0",
    },
  ];

  return (
    <div className="report-page">
      {/* HEADER */}
      <div className="report-header">
        <h1>Honeypot Interaction Investigation</h1>
        <p>
          Logs captured from <b>Cowrie SSH Honeypot</b>
        </p>
      </div>

      {/* SUMMARY */}
      <div className="report-summary">
        <div>
          <span className="label">Total Sessions</span>
          <span className="value">{honeypotLogs.length}</span>
        </div>

        <div>
          <span className="label">Top Attacker IP</span>
          <span className="value">127.0.0.1</span>
        </div>

        <div>
          <span className="label">Threat Level</span>
          <span className="value badge low">LOW</span>
        </div>
      </div>

      {/* TABLE */}
      <div className="report-card">
        <h2>Attacker Activity Logs</h2>

        <table className="report-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Source IP</th>
              <th>Session ID</th>
              <th>Command</th>
              <th>Sensor</th>
              <th>Label</th>
            </tr>
          </thead>
          <tbody>
            {honeypotLogs.map((log, index) => (
              <tr key={index}>
                <td>{log.timestamp}</td>
                <td>{log.src_ip}</td>
                <td>{log.session}</td>
                <td>{log.command}</td>
                <td>{log.sensor}</td>
                <td>
                  <span className="badge low">{log.ransomware_label}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* RAW OUTPUT */}
      <div className="report-card">
        <h2>Raw Honeypot Output (CSV Preview)</h2>

        <pre className="log-block">
{`timestamp,src_ip,session,command,sensor,ransomware_label
2026-01-20 11:43:59,127.0.0.1,290b86c921ab,5543.0,cowrie,0.0
2026-01-20 12:07:27,127.0.0.1,e162c9344ad9,0.215355,cowrie,0.0
2026-01-20 12:18:23,127.0.0.1,3efe1e26e86e,2255.0,cowrie,0.0
...`}
        </pre>
      </div>
    </div>
  );
}

export default HoneypotDetails;
