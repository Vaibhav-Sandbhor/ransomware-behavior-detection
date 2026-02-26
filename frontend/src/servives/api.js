const API_BASE = "http://localhost:8000";

export const fetchAlerts = async () => {
  return fetch("/api/alerts").then(res => res.json());
};

export const fetchDashboardStats = async () => {
  return fetch("/api/dashboard").then(res => res.json());
};

export const scanRansomware = async (samplePath) => {
  const response = await fetch(`${API_BASE}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sample_path: samplePath, label: 1 }),
  });
  return response.json();
};

// ---------------------------------------------------------------------------
// Ransomware Module Pipeline API
// ---------------------------------------------------------------------------

export const runRansomwarePipeline = async () => {
  const response = await fetch(`${API_BASE}/api/ransomware/run-pipeline`, {
    method: "POST",
  });
  return response.json();
};

export const fetchRansomwarePredictions = async () => {
  const response = await fetch(`${API_BASE}/api/ransomware/predictions`);
  return response.json();
};

export const fetchRansomwareAlerts = async () => {
  const response = await fetch(`${API_BASE}/api/ransomware/alerts`);
  return response.json();
};

// ---------------------------------------------------------------------------
// Honeypot Module API
// ---------------------------------------------------------------------------

export const fetchHoneypotLog = async () => {
  const response = await fetch(`${API_BASE}/api/honeypot/log`);
  return response.json();
};
