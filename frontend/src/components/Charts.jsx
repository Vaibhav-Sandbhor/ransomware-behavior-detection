import React from "react";
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer
} from "recharts";

const threatData = [
  { name: "Ransomware", value: 40 },
  { name: "Port Scan", value: 30 },
  { name: "Phishing", value: 20 },
  { name: "Malware", value: 10 }
];

const predictionData = [
  { name: "Malicious", value: 80 },
  { name: "Safe", value: 20 }
];

const COLORS = ["#dc2626", "#f59e0b", "#3b82f6", "#22c55e"];

function Charts() {
  return (
    <section className="ml-section">
      <h2 className="section-title">Threat Analysis</h2>

      <div className="ml-grid">
        {/* PIE */}
        <div className="ml-card">
          <div className="ml-card-header">Threat Distribution</div>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie
                data={threatData}
                dataKey="value"
                nameKey="name"
                innerRadius={55}
                outerRadius={80}
                paddingAngle={4}
              >
                {threatData.map((_, i) => (
                  <Cell key={i} fill={COLORS[i % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* BAR */}
        <div className="ml-card">
          <div className="ml-card-header">Prediction Confidence</div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={predictionData}>
              <XAxis dataKey="name" />
              <YAxis hide />
              <Tooltip />
              <Bar
                dataKey="value"
                radius={[6, 6, 0, 0]}
                fill="#3b82f6"
              />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="ml-footer">
        Latest File: <b>invoice.exe</b>
        <span className="ml-status danger"> MALICIOUS</span>
      </div>
    </section>
  );
}

export default Charts;
