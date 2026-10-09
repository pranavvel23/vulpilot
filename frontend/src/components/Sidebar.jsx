import React from 'react';
import { useApp } from '../context/AppContext';
import {
  LayoutDashboard,
  ShieldAlert,
  PlaySquare,
  BookOpen,
  FileText,
  Workflow,
  Settings
} from 'lucide-react';

const Sidebar = ({ onOpenSettings }) => {
  const { activeTab, setActiveTab, currentScan } = useApp();

  const navItems = [
    { id: 'dashboard', label: 'Security Dashboard', icon: LayoutDashboard },
    { id: 'new_scan', label: 'New Code Scan', icon: PlaySquare },
    { id: 'scan_details', label: 'Vulnerabilities & Diff', icon: ShieldAlert, badge: currentScan?.total_vulnerabilities },
    { id: 'workflow', label: 'LangGraph Pipeline', icon: Workflow },
    { id: 'knowledge_base', label: 'OWASP RAG Explorer', icon: BookOpen },
    { id: 'reports', label: 'Export Reports', icon: FileText },
  ];

  return (
    <aside className="w-64 border-r border-slate-800 bg-navy-900/60 backdrop-blur-md flex flex-col justify-between shrink-0 min-h-[calc(100vh-4rem)]">
      <div className="p-4 space-y-1">
        <div className="px-3 py-2 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
          Main Menu
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-xs font-medium transition-all ${
                isActive
                  ? 'bg-gradient-to-r from-cyan-950 to-slate-900 border border-cyan-500/40 text-cyan-300 shadow-md shadow-cyan-950/50'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </div>
              {item.badge !== undefined && item.badge > 0 && (
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-purple-950 text-purple-300 border border-purple-800/50">
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Sidebar Footer Info */}
      <div className="p-4 border-t border-slate-800 space-y-3">
        <div className="p-3 rounded-xl bg-slate-900/90 border border-slate-800 text-xs space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="text-slate-400">Active Audit:</span>
            <span className="font-mono text-cyan-400 truncate max-w-[100px]">
              {currentScan ? currentScan.project_name : 'None'}
            </span>
          </div>
          {currentScan && (
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-slate-400">Score:</span>
              <span
                className={`font-bold ${
                  currentScan.security_score >= 80
                    ? 'text-emerald-400'
                    : currentScan.security_score >= 50
                    ? 'text-yellow-400'
                    : 'text-red-400'
                }`}
              >
                {currentScan.security_score}/100
              </span>
            </div>
          )}
        </div>

        <button
          onClick={onOpenSettings}
          className="w-full py-2 px-3 rounded-lg border border-slate-800 hover:bg-slate-800 text-slate-400 hover:text-slate-200 text-xs flex items-center justify-center gap-2 transition-colors"
        >
          <Settings className="w-3.5 h-3.5" />
          <span>Config & API Keys</span>
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;
