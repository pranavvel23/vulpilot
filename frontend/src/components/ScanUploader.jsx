import React, { useState, useEffect } from 'react';
import { scanSnippet, scanUpload, fetchSampleCode } from '../api/client';
import { useApp } from '../context/AppContext';
import { Play, Upload, Code2, FileCode, CheckCircle2, ShieldAlert } from 'lucide-react';

const ScanUploader = ({ onScanComplete }) => {
  const { setIsScanning, isScanning, showNotification, loadScans, setCurrentScan, setActiveTab } = useApp();
  const [activeTab, setActiveTabLocal] = useState('snippet');
  
  // Snippet state
  const [projectName, setProjectName] = useState('Web API Audit');
  const [language, setLanguage] = useState('python');
  const [code, setCode] = useState('');
  const [samples, setSamples] = useState([]);
  
  // Upload state
  const [selectedFile, setSelectedFile] = useState(null);

  useEffect(() => {
    loadSamples();
  }, []);

  const loadSamples = async () => {
    try {
      const data = await fetchSampleCode();
      setSamples(data);
      if (data && data.length > 0) {
        setCode(data[0].code);
        setLanguage(data[0].language);
      }
    } catch (err) {
      console.warn('Could not load samples');
    }
  };

  const handleSelectSample = (sample) => {
    setCode(sample.code);
    setLanguage(sample.language);
    setProjectName(sample.name);
  };

  const handleRunSnippetScan = async () => {
    if (!code.trim()) {
      showNotification('Please enter source code or select a sample snippet to scan.', 'error');
      return;
    }
    setIsScanning(true);
    try {
      const res = await scanSnippet(projectName, language, code);
      showNotification(`Scan Completed! Found ${res.total_vulnerabilities} findings.`, 'success');
      await loadScans();
      setCurrentScan(res);
      if (onScanComplete) onScanComplete(res);
      setActiveTab('scan_details');
    } catch (err) {
      showNotification('Scan failed. Ensure backend API server is running.', 'error');
    } finally {
      setIsScanning(false);
    }
  };

  const handleRunFileUpload = async () => {
    if (!selectedFile) {
      showNotification('Please select a file or ZIP archive to upload.', 'error');
      return;
    }
    setIsScanning(true);
    try {
      const res = await scanUpload(selectedFile, projectName);
      showNotification(`File Scan Completed! Found ${res.total_vulnerabilities} findings.`, 'success');
      await loadScans();
      setCurrentScan(res);
      if (onScanComplete) onScanComplete(res);
      setActiveTab('scan_details');
    } catch (err) {
      showNotification('File upload scan failed.', 'error');
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-6">
      {/* Tab Selectors */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div className="flex items-center gap-3">
          <button
            onClick={() => setActiveTabLocal('snippet')}
            className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 ${
              activeTab === 'snippet'
                ? 'bg-cyan-500 text-slate-950 shadow-lg shadow-cyan-500/20'
                : 'bg-slate-900 text-slate-400 hover:text-slate-200'
            }`}
          >
            <Code2 className="w-4 h-4" />
            <span>Code Snippet Editor</span>
          </button>
          <button
            onClick={() => setActiveTabLocal('upload')}
            className={`px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center gap-2 ${
              activeTab === 'upload'
                ? 'bg-cyan-500 text-slate-950 shadow-lg shadow-cyan-500/20'
                : 'bg-slate-900 text-slate-400 hover:text-slate-200'
            }`}
          >
            <Upload className="w-4 h-4" />
            <span>Upload File or ZIP Archive</span>
          </button>
        </div>

        <span className="text-[11px] text-slate-400 font-mono hidden sm:inline">
          Sandboxed SAST Engine & Rule Validator
        </span>
      </div>

      {activeTab === 'snippet' ? (
        <div className="space-y-4">
          {/* Preset Sample Code Loaders */}
          {samples.length > 0 && (
            <div className="space-y-2">
              <label className="text-xs font-semibold text-slate-400 block">
                Quick Test: Load Sample Vulnerable Code Snippets
              </label>
              <div className="flex flex-wrap gap-2">
                {samples.map((s) => (
                  <button
                    key={s.id}
                    onClick={() => handleSelectSample(s)}
                    className="px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-800 hover:border-cyan-500/50 text-slate-300 text-xs flex items-center gap-1.5 transition-colors"
                  >
                    <FileCode className="w-3.5 h-3.5 text-purple-400" />
                    <span>{s.name}</span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Form Inputs */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-xs font-semibold text-slate-400 block mb-1">Audit Project Name</label>
              <input
                type="text"
                value={projectName}
                onChange={(e) => setProjectName(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700/80 rounded-xl px-3.5 py-2 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="text-xs font-semibold text-slate-400 block mb-1">Target Language</label>
              <select
                value={language}
                onChange={(e) => setLanguage(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700/80 rounded-xl px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
              >
                <option value="python">Python (.py)</option>
                <option value="javascript">JavaScript / Node.js (.js, .jsx)</option>
                <option value="typescript">TypeScript (.ts, .tsx)</option>
                <option value="php">PHP (.php)</option>
                <option value="java">Java (.java)</option>
              </select>
            </div>
          </div>

          {/* Code Textarea */}
          <div>
            <label className="text-xs font-semibold text-slate-400 block mb-1">Source Code Snippet</label>
            <textarea
              rows={10}
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="Paste source code snippet here to analyze for OWASP vulnerabilities..."
              className="w-full bg-navy-950 border border-slate-800 rounded-xl p-4 font-mono text-xs text-cyan-300 focus:outline-none focus:border-cyan-500 shadow-inner"
            />
          </div>

          <button
            onClick={handleRunSnippetScan}
            disabled={isScanning}
            className="w-full py-3 rounded-xl bg-gradient-to-r from-cyan-500 via-purple-600 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-bold text-xs shadow-xl shadow-cyan-500/20 flex items-center justify-center gap-2 transition-all disabled:opacity-50"
          >
            <Play className={`w-4 h-4 ${isScanning ? 'animate-spin' : ''}`} />
            <span>{isScanning ? 'Running LangGraph Workflow Pipeline...' : 'Execute Security Vulnerability Scan'}</span>
          </button>
        </div>
      ) : (
        <div className="space-y-6">
          <div className="border-2 border-dashed border-slate-700 hover:border-cyan-500/60 rounded-2xl p-10 text-center space-y-3 transition-colors bg-slate-900/40">
            <Upload className="w-10 h-10 text-cyan-400 mx-auto" />
            <div>
              <p className="text-sm font-bold text-slate-200">Select File or Zip Repository Archive</p>
              <p className="text-xs text-slate-400 mt-1">
                Supports single source files (.py, .js, .php, .java, .go) or compressed .zip project repositories.
              </p>
            </div>
            <input
              type="file"
              onChange={(e) => setSelectedFile(e.target.files[0])}
              className="block mx-auto text-xs text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-xl file:border-0 file:text-xs file:font-semibold file:bg-slate-800 file:text-cyan-400 hover:file:bg-slate-700 cursor-pointer"
            />
          </div>

          <button
            onClick={handleRunFileUpload}
            disabled={isScanning || !selectedFile}
            className="w-full py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-purple-600 hover:from-cyan-400 hover:to-purple-500 text-white font-bold text-xs shadow-xl shadow-cyan-500/20 flex items-center justify-center gap-2 transition-all disabled:opacity-50"
          >
            <Play className={`w-4 h-4 ${isScanning ? 'animate-spin' : ''}`} />
            <span>{isScanning ? 'Extracting & Scanning Archive...' : 'Upload & Start Security Scan'}</span>
          </button>
        </div>
      )}
    </div>
  );
};

export default ScanUploader;
