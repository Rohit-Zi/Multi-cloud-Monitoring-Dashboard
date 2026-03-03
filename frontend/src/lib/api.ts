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