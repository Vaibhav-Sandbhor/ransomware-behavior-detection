const API_BASE = import.meta.env.VITE_MAIN_API_BASE || "http://127.0.0.1:8000";

// Helper function to get JWT token from localStorage
function getAuthHeaders() {
  const token = localStorage.getItem("auth-token");
  const headers = { "Content-Type": "application/json" };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  return headers;
}

// ---------------------------------------------------------------------------
// Authentication API
// ---------------------------------------------------------------------------

export const registerUser = async (name, email, password) => {
  const response = await fetch(`${API_BASE}/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, email, password }),
  });
  return response.json();
};

export const loginUser = async (email, password) => {
  const response = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  return response.json();
};

export const getCurrentUser = async () => {
  const response = await fetch(`${API_BASE}/auth/me`, {
    method: "GET",
    headers: getAuthHeaders(),
  });
  return response.json();
};

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
    headers: getAuthHeaders(),
  });
  return response.json();
};

export const fetchRansomwarePredictions = async () => {
  const response = await fetch(`${API_BASE}/api/ransomware/predictions`, {
    headers: getAuthHeaders(),
  });
  return response.json();
};

export const fetchRansomwareAlerts = async () => {
  const response = await fetch(`${API_BASE}/api/ransomware/alerts`, {
    headers: getAuthHeaders(),
  });
  return response.json();
};

export const scanRealSystem = async () => {
  const response = await fetch(`${API_BASE}/api/ransomware/scan-real-system`, {
    method: "POST",
    headers: getAuthHeaders(),
  });
  return response.json();
};

export const startSimulationScan = async () => {
  const response = await fetch(`${API_BASE}/api/ransomware/start-scan-simulation`, {
    method: "POST",
    headers: getAuthHeaders(),
  });
  return response.json();
};

export const startSystemScan = async () => {
  const response = await fetch(`${API_BASE}/api/ransomware/start-scan-system`, {
    method: "POST",
    headers: getAuthHeaders(),
  });
  return response.json();
};

export const stopScan = async () => {
  const response = await fetch(`${API_BASE}/api/ransomware/stop-scan`, {
    method: "POST",
    headers: getAuthHeaders(),
  });
  return response.json();
};

export const getScanStatus = async () => {
  const response = await fetch(`${API_BASE}/api/ransomware/scan-status`, {
    headers: getAuthHeaders(),
  });
  return response.json();
};

// ---------------------------------------------------------------------------
// Honeypot Module API
// ---------------------------------------------------------------------------

export const fetchHoneypotLog = async () => {
  const response = await fetch(`${API_BASE}/api/honeypot/log`, {
    headers: getAuthHeaders(),
  });
  return response.json();
};

export const startHoneypotSimulation = async () => {
  const response = await fetch(`${API_BASE}/api/honeypot/start-simulation`, {
    method: "POST",
    headers: getAuthHeaders(),
  });
  return response.json();
};

export const startHoneypotMonitor = async () => {
  const response = await fetch(`${API_BASE}/api/honeypot/start-monitor`, {
    method: "POST",
    headers: getAuthHeaders(),
  });
  return response.json();
};

export const stopHoneypotScan = async () => {
  const response = await fetch(`${API_BASE}/api/honeypot/stop`, {
    method: "POST",
    headers: getAuthHeaders(),
  });
  return response.json();
};

export const getHoneypotScanStatus = async () => {
  const response = await fetch(`${API_BASE}/api/honeypot/scan-status`, {
    headers: getAuthHeaders(),
  });
  return response.json();
};

// ---------------------------------------------------------------------------
// Port Scan API
// ---------------------------------------------------------------------------

const PORTSCAN_BASE = import.meta.env.VITE_PORTSCAN_API_BASE || "http://127.0.0.1:8001";

export const scanSystemPorts = async () => {
  const response = await fetch(`${PORTSCAN_BASE}/scan/target`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target: "127.0.0.1" }),
  });
  if (!response.ok) throw new Error(`Server returned ${response.status}`);
  return response.json();
};

export const startPortScan = async (target) => {
  const response = await fetch(`${PORTSCAN_BASE}/scan/target`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target }),
  });
  return response.json();
};

export const fetchPortScanReport = async (scanId) => {
  const response = await fetch(`${PORTSCAN_BASE}/report/${scanId}`);
  return response.json();
};

// ---------------------------------------------------------------------------
// Security Metrics API - Real-time threat aggregation
// ---------------------------------------------------------------------------

export const getSecurityMetrics = async () => {
  const response = await fetch(`${API_BASE}/api/security-metrics`, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) throw new Error(`Failed to fetch security metrics: ${response.status}`);
  return response.json();
};

// ---------------------------------------------------------------------------
// Historical Data Viewer API
// ---------------------------------------------------------------------------

export const getHistoryDates = async () => {
  const response = await fetch(`${API_BASE}/history/dates`, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) throw new Error("Failed to fetch history dates");
  return response.json();
};

export const getHistoryMetrics = async (date) => {
  const response = await fetch(`${API_BASE}/history/metrics?date=${date}`, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) throw new Error(`Failed to fetch metrics for ${date}`);
  return response.json();
};

export const getHistoryEvents = async (date) => {
  const response = await fetch(`${API_BASE}/history/events?date=${date}`, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) throw new Error(`Failed to fetch events for ${date}`);
  return response.json();
};

export const getHistoryHealth = async () => {
  const response = await fetch(`${API_BASE}/health/history`, {
    headers: getAuthHeaders(),
  });
  return response.json();
};

