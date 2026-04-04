import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// API Service Functions

export const fetchStats = async () => {
  const response = await api.get('/stats');
  return response.data;
};

export const fetchAlerts = async (params?: { severity?: string; limit?: number; offset?: number }) => {
  const response = await api.get('/alerts', { params });
  return response.data;
};

export const fetchAlertById = async (id: string) => {
  const response = await api.get(`/alerts/${id}`);
  return response.data;
};

export const fetchIncidents = async () => {
  const response = await api.get('/incidents');
  return response.data;
};

export const fetchCampaigns = async () => {
  const response = await api.get('/campaigns');
  return response.data;
};

export const fetchTimelines = async () => {
  const response = await api.get('/timelines');
  return response.data;
};

export const fetchFlows = async (params?: { suspicious_only?: boolean; limit?: number }) => {
  const response = await api.get('/flows', { params });
  return response.data;
};

export const fetchSeverityChart = async () => {
  const response = await api.get('/charts/severity');
  return response.data;
};

export const fetchTopSources = async () => {
  const response = await api.get('/charts/top-sources');
  return response.data;
};

export const fetchTimelineChart = async () => {
  const response = await api.get('/charts/timeline');
  return response.data;
};

export const fetchHealth = async () => {
  const response = await api.get('/health');
  return response.data;
};

export default api;
