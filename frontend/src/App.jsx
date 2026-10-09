import React, { useState } from 'react';
import { AppProvider, useApp } from './context/AppContext';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import MetricsOverview from './components/MetricsOverview';
import VulnerabilityTable from './components/VulnerabilityTable';
import VulnerabilityDetailModal from './components/VulnerabilityDetailModal';
import CodeDiffViewer from './components/CodeDiffViewer';
import WorkflowGraph from './components/WorkflowGraph';
import ScanUploader from './components/ScanUploader';
import KnowledgeBase from './components/KnowledgeBase';
import ReportsView from './components/ReportsView';
import SettingsModal from './components/SettingsModal';
import { ShieldCheck, PlaySquare, ArrowRight, CheckCircle2, AlertTriangle } from 'lucide-react';

const DashboardContent = () => {
  const { activeTab, setActiveTab, currentScan, notification } = useApp();
  const [selectedVulnModal, setSelectedVulnModal] = useState(null);
  const [selectedVulnDiff, setSelectedVulnDiff] = useState(null);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);

  const handleOpenDiff = (vuln) => {
    setSelectedVulnDiff(vuln);
    setActiveTab('scan_details');
  };

  return (
    <div className="min-h-screen flex flex-col bg-navy-950 text-slate-100">
      {/* Toast Notification Banner */}
      {notification && (
        <div
          className={`fixed top-20 right-6 z-50 px-4 py-3 rounded-xl border shadow-xl text-xs font-semibold flex items-center gap-2.5 animate-bounce ${
            notification.type === 'success'
              ? 'bg-emerald-950 border-emerald-500/50 text-emerald-300'
              : 'bg-red-950 border-red-500/50 text-red-300'
          }`}
        >
          {notification.type === 'success' ? (
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          ) : (
            <AlertTriangle className="w-4 h-4 text-red-400" />
          )}
          <span>{notification.message}</span>
        </div>
      )}

      {/* Header Navbar */}
      <Navbar onOpenSettings={() => setIsSettingsOpen(true)} />

      <div className="flex-1 flex overflow-hidden">
        {/* Navigation Sidebar */}
        <Sidebar onOpenSettings={() => setIsSettingsOpen(true)} />

        {/* Main Content Body */}
        <main className="flex-1 p-6 overflow-y-auto space-y-6 max-w-7xl">
          {activeTab === 'dashboard' && (
            <div className="space-y-6">
              {/* Active Audit Banner */}
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 p-5 rounded-2xl glass-panel border border-slate-800">
                <div>
                  <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
                    <ShieldCheck className="w-5 h-5 text-cyan-400" />
                    Security Overview: <span className="text-cyan-300">{currentScan?.project_name || 'No Active Scan'}</span>
                  </h2>
                  <p className="text-xs text-slate-400 mt-1">
                    AI-powered vulnerability assessment, severity metrics, and automated remediation suggestions.
                  </p>
                </div>
                <button
                  onClick={() => setActiveTab('new_scan')}
                  className="px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-purple-600 hover:from-cyan-400 hover:to-purple-500 text-white font-bold text-xs shadow-lg shadow-cyan-500/20 flex items-center gap-2 transition-all shrink-0"
                >
                  <PlaySquare className="w-4 h-4" />
                  <span>Start New Code Scan</span>
                </button>
              </div>

              {/* Metrics Overview Cards */}
              <MetricsOverview scan={currentScan} />

              {/* LangGraph Pipeline Workflow Graph */}
              <WorkflowGraph />

              {/* Interactive Findings Data Table */}
              {currentScan && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-bold text-slate-200">
                      Vulnerability Findings ({currentScan.vulnerabilities?.length || 0})
                    </h3>
                  </div>
                  <VulnerabilityTable
                    vulnerabilities={currentScan.vulnerabilities}
                    onSelectVulnerability={(v) => setSelectedVulnModal(v)}
                    onOpenDiff={handleOpenDiff}
                  />
                </div>
              )}
            </div>
          )}

          {activeTab === 'new_scan' && (
            <div className="space-y-6">
              <div className="p-5 rounded-2xl glass-panel border border-slate-800">
                <h2 className="text-lg font-bold text-slate-100">Initiate New Vulnerability Scan</h2>
                <p className="text-xs text-slate-400 mt-1">
                  Upload raw source snippets or full project archives to trigger SAST scanning and AI remediation.
                </p>
              </div>
              <ScanUploader onScanComplete={() => setActiveTab('scan_details')} />
            </div>
          )}

          {activeTab === 'scan_details' && (
            <div className="space-y-6">
              {currentScan ? (
                <>
                  <div className="p-5 rounded-2xl glass-panel border border-slate-800 flex items-center justify-between">
                    <div>
                      <h2 className="text-lg font-bold text-slate-100">
                        Detailed Vulnerability Audit: {currentScan.project_name}
                      </h2>
                      <p className="text-xs text-slate-400 mt-1">
                        Select a vulnerability to review line-by-line diffs and trigger rescan verification.
                      </p>
                    </div>
                  </div>

                  <MetricsOverview scan={currentScan} />

                  {/* Code Diff Viewer for selected vulnerability */}
                  <CodeDiffViewer
                    vulnerability={selectedVulnDiff || currentScan.vulnerabilities?.[0]}
                    onVerificationSuccess={() => {}}
                  />

                  {/* Table of all findings */}
                  <div className="pt-4">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3">All Findings Table</h3>
                    <VulnerabilityTable
                      vulnerabilities={currentScan.vulnerabilities}
                      onSelectVulnerability={(v) => setSelectedVulnModal(v)}
                      onOpenDiff={(v) => setSelectedVulnDiff(v)}
                    />
                  </div>
                </>
              ) : (
                <div className="glass-panel p-12 rounded-2xl border border-slate-800 text-center text-slate-400">
                  <ShieldCheck className="w-12 h-12 text-slate-600 mx-auto mb-3" />
                  <h3 className="text-sm font-bold text-slate-200">No Scan Data Available</h3>
                  <button
                    onClick={() => setActiveTab('new_scan')}
                    className="mt-4 px-4 py-2 rounded-xl bg-cyan-500 text-slate-950 font-bold text-xs"
                  >
                    Run Your First Scan
                  </button>
                </div>
              )}
            </div>
          )}

          {activeTab === 'workflow' && <WorkflowGraph />}

          {activeTab === 'knowledge_base' && <KnowledgeBase />}

          {activeTab === 'reports' && <ReportsView />}
        </main>
      </div>

      {/* Modals */}
      <VulnerabilityDetailModal
        vulnerability={selectedVulnModal}
        onClose={() => setSelectedVulnModal(null)}
        onOpenDiff={handleOpenDiff}
      />

      <SettingsModal isOpen={isSettingsOpen} onClose={() => setIsSettingsOpen(false)} />
    </div>
  );
};

export default function App() {
  return (
    <AppProvider>
      <DashboardContent />
    </AppProvider>
  );
}
