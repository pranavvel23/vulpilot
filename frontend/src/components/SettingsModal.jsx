import React, { useState } from 'react';
import { useApp } from '../context/AppContext';
import { X, Key, Cpu, ShieldCheck, Check } from 'lucide-react';

const SettingsModal = ({ isOpen, onClose }) => {
  const { apiKey, provider, saveSettings } = useApp();
  const [keyInput, setKeyInput] = useState(apiKey);
  const [providerInput, setProviderInput] = useState(provider);

  if (!isOpen) return null;

  const handleSave = () => {
    saveSettings(keyInput, providerInput);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-navy-950/80 backdrop-blur-md animate-fadeIn">
      <div className="glass-panel w-full max-w-lg rounded-2xl border border-slate-700 shadow-2xl overflow-hidden space-y-6">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 bg-navy-900 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Key className="w-5 h-5 text-cyan-400" />
            <h2 className="text-sm font-bold text-slate-100">AI Engine & API Configuration</h2>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="px-6 space-y-5 text-xs">
          <div>
            <label className="text-slate-400 font-semibold block mb-1">Select AI Provider</label>
            <select
              value={providerInput}
              onChange={(e) => setProviderInput(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-xl px-3.5 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
            >
              <option value="gemini">Google Gemini AI (gemini-1.5-flash)</option>
              <option value="openai">OpenAI (gpt-4o-mini)</option>
              <option value="local_fallback">Local OWASP Rule Engine (No Key Required)</option>
            </select>
          </div>

          <div>
            <label className="text-slate-400 font-semibold block mb-1">API Key</label>
            <input
              type="password"
              value={keyInput}
              onChange={(e) => setKeyInput(e.target.value)}
              placeholder="Paste Gemini or OpenAI API Key here..."
              className="w-full bg-slate-900 border border-slate-700 rounded-xl px-3.5 py-2.5 font-mono text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
            />
            <p className="text-[11px] text-slate-400 mt-1.5 leading-normal">
              Leave empty to run in offline local mode. VulnPilot AI will use pre-populated OWASP Top 10 RAG rules and AST pattern explanations as a fallback.
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-navy-900 flex items-center justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            className="px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-purple-600 hover:from-cyan-400 hover:to-purple-500 text-white font-bold text-xs flex items-center gap-1.5 shadow-lg shadow-cyan-500/20"
          >
            <Check className="w-4 h-4" />
            <span>Save Configuration</span>
          </button>
        </div>
      </div>
    </div>
  );
};

export default SettingsModal;
