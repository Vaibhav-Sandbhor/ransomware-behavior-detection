import { useState } from "react";

import { scanRansomware } from "../../servives/api";
function RansomwareDetails() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

 const handleScan = async () => {
  setLoading(true);

 const result = await scanRansomware(
  "C:/Users/Svaib/OneDrive/Desktop/CyberSIEM/data/raw/ransomware/conti/conti_01"
);

  setResult(result);
  setLoading(false);
};
  return (
    <div className="report-page">
      <h1>Ransomware Detection</h1>

      <button className="scan-btn" onClick={handleScan}>
        {loading ? "Scanning..." : "Run Ransomware Scan"}
      </button>

      {result && (
  <div className={`result-card ${result.prediction === 1 ? "danger" : "safe"}`}>
    <h2>Status: {result.status}</h2>
    <p>Prediction Code: {result.prediction}</p>
    <p>Risk Score: {(result.probability * 100).toFixed(2)}%</p>
  </div>
)}
    </div>
  );
}

export default RansomwareDetails;