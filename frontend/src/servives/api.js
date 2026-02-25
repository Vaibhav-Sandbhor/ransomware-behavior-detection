export const fetchAlerts = async () => {
  return fetch("/api/alerts").then(res => res.json());
};

export const fetchDashboardStats = async () => {
  return fetch("/api/dashboard").then(res => res.json());
};
const API_BASE = "http://localhost:8000";

export const scanRansomware = async (samplePath) => {
  const response = await fetch("http://localhost:8000/scan", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      sample_path: samplePath,
      label: 1,
    }),
  });

  return response.json();
};