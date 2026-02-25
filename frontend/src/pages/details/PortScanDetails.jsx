import React from "react";

function PortScanDetails() {
  const services = [
    { port: 21, service: "FTP", cvss: 9.8, risk: "LOW" },
    { port: 22, service: "SSH", cvss: 6.5, risk: "LOW" },
    { port: 23, service: "TELNET", cvss: 9.0, risk: "LOW" },
    { port: 25, service: "SMTP", cvss: 6.8, risk: "LOW" },
    { port: 53, service: "DNS", cvss: 7.5, risk: "LOW" },
    { port: 80, service: "HTTP", cvss: 7.2, risk: "LOW" },
    { port: 139, service: "NETBIOS", cvss: 8.5, risk: "LOW" },
    { port: 445, service: "SMB", cvss: 8.5, risk: "LOW" },
    { port: 3306, service: "MYSQL", cvss: 7.8, risk: "LOW" },
  ];

  return (
    <div className="report-page">
      {/* HEADER */}
      <div className="report-header">
        <h1>Port Scan Investigation</h1>
        <p>Target Host: <b>192.168.254.130</b></p>
      </div>

      {/* SUMMARY BOX */}
      <div className="report-summary">
        <div>
          <span className="label">Scan Duration</span>
          <span className="value">24.48s</span>
        </div>

        <div>
          <span className="label">Open Services Found</span>
          <span className="value">9</span>
        </div>

        <div>
          <span className="label">ML Risk Prediction</span>
          <span className="value badge low">LOW</span>
        </div>
      </div>

      {/* SERVICE TABLE */}
      <div className="report-card">
        <h2>Detected Open Ports & CVSS Report</h2>

        <table className="report-table">
          <thead>
            <tr>
              <th>Port</th>
              <th>Service</th>
              <th>CVSS Score</th>
              <th>Predicted Risk</th>
            </tr>
          </thead>
          <tbody>
            {services.map((s, i) => (
              <tr key={i}>
                <td>{s.port}</td>
                <td>{s.service}</td>
                <td>
                  <span className="cvss">{s.cvss}</span>
                </td>
                <td>
                  <span className="badge low">{s.risk}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* RAW LOG OUTPUT */}
      <div className="report-card">
        <h2>Raw Nmap Output</h2>
        <pre className="log-block">
{`[*] Running Nmap scan with Vulners...
Host is up (0.0011s latency)

PORT     SERVICE     VERSION
21/tcp   open   ftp   vsftpd 2.3.4
22/tcp   open   ssh   OpenSSH 4.7p1
23/tcp   open   telnet Linux telnetd
...
[+] Final risk report generated
[+] DONE — Risk analysis completed`}
        </pre>
      </div>
    </div>
  );
}

export default PortScanDetails;
