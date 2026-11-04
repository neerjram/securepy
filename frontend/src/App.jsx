import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import Dashboard from './pages/Dashboard';
import NewScan from './pages/NewScan';
import ScanResults from './pages/ScanResults';
import ScanHistory from './pages/ScanHistory';
import { fetchHealth, fetchScans } from './services/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [health, setHealth] = useState(null);
  const [scans, setScans] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState(null);

  useEffect(() => {
    checkHealth();
    loadScans();
  }, []);

  const checkHealth = async () => {
    try {
      const data = await fetchHealth();
      setHealth(data);
    } catch {
      setHealth(null);
    }
  };

  const loadScans = async () => {
    try {
      const data = await fetchScans();
      setScans(data);
    } catch (err) {
      console.error('Failed to load scans:', err);
    }
  };

  const handleSelectScan = (scanId) => {
    setSelectedScanId(scanId);
    setActiveTab('results');
  };

  const handleScanComplete = (newScanId) => {
    loadScans();
    setSelectedScanId(newScanId);
    setActiveTab('results');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      <Navbar
        activeTab={activeTab}
        setActiveTab={(tab) => {
          setActiveTab(tab);
          if (tab !== 'results') setSelectedScanId(null);
        }}
        health={health}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 md:p-8">
        {activeTab === 'dashboard' && (
          <Dashboard
            scans={scans}
            setActiveTab={setActiveTab}
            onSelectScan={handleSelectScan}
          />
        )}

        {activeTab === 'new-scan' && (
          <NewScan onScanComplete={handleScanComplete} />
        )}

        {activeTab === 'results' && selectedScanId && (
          <ScanResults
            scanId={selectedScanId}
            onBack={() => setActiveTab('dashboard')}
          />
        )}

        {activeTab === 'history' && (
          <ScanHistory
            scans={scans}
            onSelectScan={handleSelectScan}
            onRefresh={loadScans}
          />
        )}
      </main>

      <footer className="border-t border-slate-800/80 py-4 px-6 text-center text-xs text-slate-500">
        SecurePy — Explainable Static Security Analysis Tool for Python • Static AST & Taint Tracking
      </footer>
    </div>
  );
}
