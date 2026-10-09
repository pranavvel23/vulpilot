import React, { useState, useEffect } from 'react';
import { searchRAG } from '../api/client';
import { Search, BookOpen, ShieldAlert, CheckCircle2, ArrowRight } from 'lucide-react';

const KnowledgeBase = () => {
  const [query, setQuery] = useState('SQL Injection');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    handleSearch();
  }, []);

  const handleSearch = async () => {
    if (!query.trim()) return;
    setLoading(true);
    try {
      const data = await searchRAG(query, 5);
      setResults(data);
    } catch (err) {
      console.warn('RAG search error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <BookOpen className="w-5 h-5 text-cyan-400" />
              OWASP Top 10 & CWE RAG Knowledge Explorer
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Search curated application security intelligence, attack vectors, and secure coding guidelines.
            </p>
          </div>
          <span className="px-2.5 py-1 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/60 text-[11px] font-mono font-semibold">
            Vector Similarity RAG
          </span>
        </div>

        {/* Search Bar */}
        <div className="flex items-center gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
              placeholder="Query security concepts (e.g. SQL Injection, Path Traversal, CORS, Command Injection)..."
              className="w-full bg-slate-900 border border-slate-700/80 rounded-xl pl-10 pr-4 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <button
            onClick={handleSearch}
            className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-purple-600 hover:from-cyan-400 hover:to-purple-500 text-white font-bold text-xs shadow-md shadow-cyan-500/20"
          >
            {loading ? 'Searching...' : 'Search Vector Knowledge'}
          </button>
        </div>
      </div>

      {/* RAG Results Cards */}
      <div className="space-y-4">
        {results.map((item, idx) => (
          <div key={idx} className="glass-card p-6 rounded-2xl border border-slate-800 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <span className="px-2.5 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800/50 font-mono text-xs font-bold">
                  {item.cwe_id}
                </span>
                <span className="text-xs font-semibold text-cyan-400">{item.owasp_id}</span>
              </div>
              {item.similarity_score && (
                <span className="text-[11px] text-slate-400 font-mono">
                  Similarity Match: <strong className="text-emerald-400">{(item.similarity_score * 100).toFixed(1)}%</strong>
                </span>
              )}
            </div>

            <h3 className="text-sm font-bold text-slate-100">{item.title}</h3>
            <p className="text-xs text-slate-300 leading-relaxed">{item.description}</p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
              <div className="p-3.5 rounded-xl bg-red-950/20 border border-red-900/30 space-y-1.5">
                <span className="text-xs font-bold text-red-400 block">Vulnerable Pattern Example</span>
                <pre className="font-mono text-[11px] text-red-300 overflow-x-auto whitespace-pre-wrap">
                  {item.code_example_vulnerable}
                </pre>
              </div>

              <div className="p-3.5 rounded-xl bg-emerald-950/20 border border-emerald-900/30 space-y-1.5">
                <span className="text-xs font-bold text-emerald-400 block">Secure Remediation Pattern</span>
                <pre className="font-mono text-[11px] text-emerald-300 overflow-x-auto whitespace-pre-wrap">
                  {item.code_example_secure}
                </pre>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default KnowledgeBase;
