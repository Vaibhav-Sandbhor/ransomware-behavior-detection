import React from "react";

function ThreatTable() {
  return (
    <section className="table-section">
      <h2>Threat Details</h2>
      <table>
        <thead>
          <tr>
            <th>IP Address</th>
            <th>Threat Type</th>
            <th>Source</th>
            <th>Time</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>192.168.1.10</td>
            <td>Ransomware</td>
            <td>ML Engine</td>
            <td>10:32 AM</td>
          </tr>
          <tr>
            <td>195.125.45.67</td>
            <td>Port Scan</td>
            <td>Nmap</td>
            <td>10:18 AM</td>
          </tr>
        </tbody>
      </table>
    </section>
  );
}

export default ThreatTable;
