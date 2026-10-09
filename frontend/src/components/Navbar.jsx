import React from 'react';
import { useApp } from '../context/AppContext';
import { ShieldCheck, Cpu, Key, PlusCircle, Settings, Activity } from 'lucide-react';

const Navbar = ({ onOpenSettings }) => {
  const { apiKey, provider, systemHealth, setActiveTab } = useApp();

  return (
    <header className="sticky top-0 z-40 h-16 border-b border-slate-800 bg-navy-900/90 backdrop-blur-md px-6 flex items-center justify-between">
      {/* Brand Logo & Title */}
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 via-purple-500 to-blue-600 p-0.5 shadow-lg shadow-cyan-500/20">
          <div className="w-full h-full bg-navy-950 rounded-[10px] flex items-center justify-center">
            <ShieldCheck className="w-6 h-6 text-cyan-400" />
          </div>
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="font-bold text-lg text-slate-100 tracking-tight">
              VulnPilot <span className="text-cyan-400 font-extrabold">AI</span>
            </h1>
            <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/60 font-semibold">
              v1.0 SAST
            </span>
          </div>
          <p className="text-xs text-slate-400">AI-Powered Vulnerability Analysis & Remediation</p>
        </div>
      </div>

      {/* Header Controls & Status Badges */}
      <div className="flex items-center gap-4">
        {/* API Key Status Indicator */}
        <div
          onClick={onOpenSettings}
          className="cursor-pointer px-3 py-1.5 rounded-lg bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition-colors flex items-center gap-2 text-xs"
        >
          <Key className="w-3.5 h-3.5 text-purple-400" />
          <span className="text-slate-400">AI Engine:</span>
          {apiKey ? (
            <span className="text-emerald-400 font-medium flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              {provider.toUpperCase()} (Connected)
            </span>
          ) : (
            <span className="text-amber-400 font-medium flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
              Local Rule Fallback
            </span>
          )}
        </div>

        {/* Scanner Engine Health Badge */}
        {systemHealth && (
          <div className="hidden lg:flex items-center gap-2 text-xs px-3 py-1.5 rounded-lg bg-navy-950 border border-slate-800 text-slate-300">
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
            <span>SAST Engine:</span>
            <span className="text-cyan-300 font-mono">AST</span>
            {systemHealth.scanners.semgrep_cli && <span className="text-purple-400 font-mono">+ Semgrep</span>}
            {systemHealth.scanners.trivy_cli && <span className="text-blue-400 font-mono">+ Trivy</span>}
          </div>
        )}

        {/* Action Buttons */}
        <button
          onClick={() => setActiveTab('new_scan')}
          className="px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-purple-600 hover:from-cyan-400 hover:to-purple-500 text-white font-medium text-xs shadow-lg shadow-cyan-500/20 flex items-center gap-2 transition-all"
        >
          <PlusCircle className="w-4 h-4" />
          <span>New Security Scan</span>
        </button>

        <button
          onClick={onOpenSettings}
          className="p-2 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-300 transition-colors"
          title="Settings"
        >
          <Settings className="w-4 h-4" />
        </button>
      </div>
    </header>
  );
};

export default Navbar;
