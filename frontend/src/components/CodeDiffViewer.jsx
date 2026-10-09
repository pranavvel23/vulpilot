import React, { useState } from 'react';
import { rescanVerification } from '../api/client';
import { useApp } from '../context/AppContext';
import { RefreshCw, CheckCircle2, XCircle, ArrowRight, Code2, ShieldCheck } from 'lucide-react';

const CodeDiffViewer = ({ vulnerability, onVerificationSuccess }) => {
  const { showNotification, loadScans } = useApp();
  const [editableCode, setEditableCode] = useState(vulnerability?.secure_code_fix || '');
  const [verifying, setVerifying] = useState(false);
  const [result, setResult] = useState(null);

  if (!vulnerability) {
    return (
      <div className="glass-panel p-12 rounded-2xl border border-slate-800 text-center text-slate-400">
        <Code2 className="w-12 h-12 text-slate-600 mx-auto mb-3" />
        <h3 className="text-sm font-bold text-slate-200">No Vulnerability Selected</h3>
        <p className="text-xs mt-1">Select a vulnerability finding from the dashboard table to inspect code diffs and rescan fixes.</p>
      </div>
    );
  }

  const handleRescan = async () => {
    setVerifying(true);
    setResult(null);
    try {
      const res = await rescanVerification(vulnerability.id, editableCode);
      setResult(res);
      if (res.verification_status === 'PASSED') {
        showNotification('Verification Passed! Vulnerability has been resolved.', 'success');
        if (onVerificationSuccess) onVerificationSuccess();
        loadScans();
      } else {
        showNotification('Rescan Verification Failed. Vulnerable pattern still detected.', 'error');
      }
    } catch (err) {
      showNotification('Failed to run rescan verification.', 'error');
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="glass-panel p-5 rounded-2xl border border-slate-800 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800/50">
              {vulnerability.cwe_id}
            </span>
            <span className="text-xs text-slate-400">{vulnerability.owasp_category}</span>
          </div>
          <h2 className="text-lg font-bold text-slate-100 mt-1">{vulnerability.title}</h2>
          <p className="text-xs font-mono text-cyan-400">
            {vulnerability.file_path} (Line {vulnerability.line_number})
          </p>
        </div>

        <button
          onClick={handleRescan}
          disabled={verifying}
          className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-purple-600 hover:from-cyan-400 hover:to-purple-500 text-white font-bold text-xs shadow-lg shadow-cyan-500/20 flex items-center gap-2 transition-all disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${verifying ? 'animate-spin' : ''}`} />
          <span>{verifying ? 'Rescanning Code...' : 'Rescan Code to Verify Fix'}</span>
        </button>
      </div>

      {/* Verification Status Banner */}
      {result && (
        <div
          className={`p-4 rounded-xl border flex items-center gap-3 text-xs font-semibold ${
            result.verification_status === 'PASSED'
              ? 'bg-emerald-950/60 border-emerald-500/50 text-emerald-300'
              : 'bg-red-950/60 border-red-500/50 text-red-300'
          }`}
        >
          {result.verification_status === 'PASSED' ? (
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
          ) : (
            <XCircle className="w-5 h-5 text-red-400 shrink-0" />
          )}
          <div>
            <div className="font-bold">{result.message}</div>
            <div className="text-[11px] opacity-80 mt-0.5">
              Remaining Vulnerability Findings: {result.remaining_vulnerabilities_count}
            </div>
          </div>
        </div>
      )}

      {/* Side-by-Side Diff Panels */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Original Vulnerable Code */}
        <div className="glass-panel rounded-2xl border border-red-900/40 overflow-hidden">
          <div className="p-3 bg-red-950/40 border-b border-red-900/40 flex items-center justify-between text-xs font-bold text-red-400">
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-red-500" />
              Before (Vulnerable Original Code)
            </span>
            <span className="font-mono text-[11px] text-slate-500">Line {vulnerability.line_number}</span>
          </div>
          <div className="p-4 bg-navy-950 font-mono text-xs text-red-300 overflow-x-auto min-h-[220px] whitespace-pre-wrap">
            {vulnerability.vulnerable_code}
          </div>
        </div>

        {/* Right: Editable Proposed Secure Fix */}
        <div className="glass-panel rounded-2xl border border-emerald-900/40 overflow-hidden">
          <div className="p-3 bg-emerald-950/40 border-b border-emerald-900/40 flex items-center justify-between text-xs font-bold text-emerald-400">
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-500" />
              After (Proposed Secure Code Replacement)
            </span>
            <span className="text-[11px] text-slate-400 font-sans font-normal">Editable</span>
          </div>
          <textarea
            value={editableCode}
            onChange={(e) => setEditableCode(e.target.value)}
            className="w-full p-4 bg-navy-950 font-mono text-xs text-emerald-300 border-none focus:outline-none focus:ring-1 focus:ring-emerald-500/50 min-h-[220px] resize-y"
            placeholder="Edit secure replacement snippet here..."
          />
        </div>
      </div>
    </div>
  );
};

export default CodeDiffViewer;
