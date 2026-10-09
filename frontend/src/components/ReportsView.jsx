import React, { useState } from 'react';
import { useApp } from '../context/AppContext';
import { downloadReport } from '../api/client';
import { FileText, Download, FileCode, FileSpreadsheet, ShieldCheck } from 'lucide-react';

const ReportsView = () => {
  const { currentScan, scans } = useApp();
  const [selectedScanId, setSelectedScanId] = useState(currentScan?.id || (scans[0]?.id ?? ''));
  const [downloading, setDownloading] = useState(false);

  const activeScan = scans.find((s) => s.id === Number(selectedScanId)) || currentScan;

  const handleDownload = async (format) => {
    if (!selectedScanId) return;
    setDownloading(true);
    try {
      await downloadReport(Number(selectedScanId), format);
    } catch (err) {
      console.error('Download report failed:', err);
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <FileText className="w-5 h-5 text-cyan-400" />
              Downloadable Security Audit Reports
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Export comprehensive security compliance and vulnerability audit reports for executive stakeholders or engineering teams.
            </p>
          </div>
        </div>

        {/* Scan Selector */}
        <div className="max-w-md">
          <label className="text-xs font-semibold text-slate-400 block mb-1">Select Audit Scan Record</label>
          <select
            value={selectedScanId}
            onChange={(e) => setSelectedScanId(e.target.value)}
            className="w-full bg-slate-900 border border-slate-700 rounded-xl px-3.5 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
          >
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                Scan #{s.id}: {s.project_name} - Score: {s.security_score}/100 ({s.total_vulnerabilities} vulns)
              </option>
            ))}
          </select>
        </div>
      </div>

      {activeScan && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {/* Export PDF Button */}
          <div className="glass-card p-5 rounded-2xl border border-slate-800 hover:border-cyan-500/50 transition-all space-y-3 flex flex-col justify-between">
            <div className="space-y-1">
              <div className="w-9 h-9 rounded-xl bg-red-950/80 border border-red-800/50 flex items-center justify-center text-red-400">
                <FileText className="w-5 h-5" />
              </div>
              <h3 className="text-xs font-bold text-slate-200">PDF Audit Report</h3>
              <p className="text-[11px] text-slate-400">Formal printable PDF report with executive stats & vulnerability tables.</p>
            </div>

            <button
              onClick={() => handleDownload('pdf')}
              disabled={downloading}
              className="w-full py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white font-semibold text-xs flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export PDF</span>
            </button>
          </div>

          {/* Export Markdown Button */}
          <div className="glass-card p-5 rounded-2xl border border-slate-800 hover:border-purple-500/50 transition-all space-y-3 flex flex-col justify-between">
            <div className="space-y-1">
              <div className="w-9 h-9 rounded-xl bg-purple-950/80 border border-purple-800/50 flex items-center justify-center text-purple-400">
                <FileCode className="w-5 h-5" />
              </div>
              <h3 className="text-xs font-bold text-slate-200">Markdown (.md)</h3>
              <p className="text-[11px] text-slate-400">GitHub-flavored Markdown document for developer repositories.</p>
            </div>

            <button
              onClick={() => handleDownload('markdown')}
              disabled={downloading}
              className="w-full py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-semibold text-xs flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Markdown</span>
            </button>
          </div>

          {/* Export HTML Button */}
          <div className="glass-card p-5 rounded-2xl border border-slate-800 hover:border-cyan-500/50 transition-all space-y-3 flex flex-col justify-between">
            <div className="space-y-1">
              <div className="w-9 h-9 rounded-xl bg-cyan-950/80 border border-cyan-800/50 flex items-center justify-center text-cyan-400">
                <FileSpreadsheet className="w-5 h-5" />
              </div>
              <h3 className="text-xs font-bold text-slate-200">Dark HTML Report</h3>
              <p className="text-[11px] text-slate-400">Self-contained styled HTML file for browser viewing.</p>
            </div>

            <button
              onClick={() => handleDownload('html')}
              disabled={downloading}
              className="w-full py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export HTML</span>
            </button>
          </div>

          {/* Export JSON Button */}
          <div className="glass-card p-5 rounded-2xl border border-slate-800 hover:border-blue-500/50 transition-all space-y-3 flex flex-col justify-between">
            <div className="space-y-1">
              <div className="w-9 h-9 rounded-xl bg-blue-950/80 border border-blue-800/50 flex items-center justify-center text-blue-400">
                <FileCode className="w-5 h-5" />
              </div>
              <h3 className="text-xs font-bold text-slate-200">Raw JSON Feed</h3>
              <p className="text-[11px] text-slate-400">Structured JSON output for CI/CD integration pipelines.</p>
            </div>

            <button
              onClick={() => handleDownload('json')}
              disabled={downloading}
              className="w-full py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export JSON</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default ReportsView;
