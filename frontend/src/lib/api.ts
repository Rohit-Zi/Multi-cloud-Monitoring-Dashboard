const API_BASE = import.meta.env.VITE_API_BASE_URL;
export const getAlerts = async () => {
  const response = await fetch(`${API_BASE}/alerts`);
  return response.json();
};

export const testBackend = async () => {
  const response = await fetch(`${API_BASE}/`);
  const data = await response.json();
  return data;
};
export const getLogs = async () => {
  const res = await fetch("http://127.0.0.1:8000/logs");

  if (!res.ok) {
    throw new Error("Failed to fetch logs");
  }

  const data = await res.json();
  return data.logs;
};