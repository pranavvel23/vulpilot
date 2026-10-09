import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000/api';

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
});

export const setApiHeaders = (apiKey, provider) => {
  if (apiKey) {
    apiClient.defaults.headers.common['X-API-Key'] = apiKey;
  } else {
    delete apiClient.defaults.headers.common['X-API-Key'];
  }
  if (provider) {
    apiClient.defaults.headers.common['X-LLM-Provider'] = provider;
  }
};

export const fetchHealth = async () => {
  const response = await apiClient.get('/health');
  return response.data;
};

export const scanSnippet = async (projectName, language, code) => {
  const response = await apiClient.post('/scan/snippet', {
    project_name: projectName,
    language,
    code,
  });
  return response.data;
};

export const scanUpload = async (file, projectName) => {
  const formData = new FormData();
  formData.append('file', file);
  if (projectName) formData.append('project_name', projectName);

  const response = await apiClient.post('/scan/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return response.data;
};

export const fetchScans = async () => {
  const response = await apiClient.get('/scans');
  return response.data;
};

export const fetchScanDetails = async (scanId) => {
  const response = await apiClient.get(`/scans/${scanId}`);
  return response.data;
};

export const rescanVerification = async (vulnerabilityId, updatedCode) => {
  const response = await apiClient.post('/rescan', {
    vulnerability_id: vulnerabilityId,
    updated_code: updatedCode,
  });
  return response.data;
};

export const searchRAG = async (query, topK = 5) => {
  const response = await apiClient.get('/rag/search', {
    params: { query, top_k: topK },
  });
  return response.data;
};

export const downloadReport = async (scanId, format = 'pdf') => {
  const response = await apiClient.post(
    '/report',
    { scan_id: scanId, format },
    { responseType: 'blob' }
  );

  const blob = new Blob([response.data], {
    type: format === 'pdf' ? 'application/pdf' : 'text/plain',
  });
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', `VulnPilot_Report_${scanId}.${format}`);
  document.body.appendChild(link);
  link.click();
  link.remove();
};

export const fetchSampleCode = async () => {
  const response = await apiClient.get('/sample-vulnerable-code');
  return response.data;
};
