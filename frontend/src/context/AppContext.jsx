import React, { createContext, useContext, useState, useEffect } from 'react';
import { fetchHealth, fetchScans, setApiHeaders } from '../api/client';

const AppContext = createContext();

export const AppProvider = ({ children }) => {
  const [scans, setScans] = useState([]);
  const [currentScan, setCurrentScan] = useState(null);
  const [apiKey, setApiKey] = useState(localStorage.getItem('vulpilot_api_key') || '');
  const [provider, setProvider] = useState(localStorage.getItem('vulpilot_provider') || 'gemini');
  const [activeTab, setActiveTab] = useState('dashboard');
  const [isScanning, setIsScanning] = useState(false);
  const [systemHealth, setSystemHealth] = useState(null);
  const [notification, setNotification] = useState(null);

  useEffect(() => {
    setApiHeaders(apiKey, provider);
    loadHealth();
    loadScans();
  }, [apiKey, provider]);

  const loadHealth = async () => {
    try {
      const health = await fetchHealth();
      setSystemHealth(health);
    } catch (err) {
      console.warn('Backend API offline or starting up...');
    }
  };

  const loadScans = async () => {
    try {
      const data = await fetchScans();
      setScans(data);
      if (data && data.length > 0 && !currentScan) {
        setCurrentScan(data[0]);
      }
    } catch (err) {
      console.warn('Failed to load past scans:', err);
    }
  };

  const saveSettings = (key, prov) => {
    setApiKey(key);
    setProvider(prov);
    localStorage.setItem('vulpilot_api_key', key);
    localStorage.setItem('vulpilot_provider', prov);
    setApiHeaders(key, prov);
    showNotification('Settings updated successfully', 'success');
  };

  const showNotification = (message, type = 'info') => {
    setNotification({ message, type });
    setTimeout(() => setNotification(null), 4000);
  };

  return (
    <AppContext.Provider
      value={{
        scans,
        setScans,
        currentScan,
        setCurrentScan,
        apiKey,
        provider,
        activeTab,
        setActiveTab,
        isScanning,
        setIsScanning,
        systemHealth,
        loadScans,
        saveSettings,
        notification,
        showNotification,
      }}
    >
      {children}
    </AppContext.Provider>
  );
};

export const useApp = () => useContext(AppContext);
