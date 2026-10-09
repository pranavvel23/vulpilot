import React from 'react';
import { Play, Database, Cpu, RefreshCw, FileCheck2, ArrowRight } from 'lucide-react';

const WorkflowGraph = () => {
  const nodes = [
    {
      id: 1,
      name: '1. SAST Scanner',
      desc: 'Semgrep + Trivy + Builtin AST Engine',
      icon: Play,
      color: 'from-cyan-500 to-blue-600',
      status: 'Active / Completed',
    },
    {
      id: 2,
      name: '2. RAG Knowledge',
      desc: 'Vector Similarity OWASP/CWE Retrieval',
      icon: Database,
      color: 'from-blue-600 to-purple-600',
      status: 'Enriched',
    },
    {
      id: 3,
      name: '3. LLM Remediation',
      desc: 'Gemini / OpenAI / Local Rule Engine',
      icon: Cpu,
      color: 'from-purple-600 to-pink-600',
      status: 'Generated',
    },
    {
      id: 4,
      name: '4. Rescan Verify',
      desc: 'Automated Fix Verification Pipeline',
      icon: RefreshCw,
      color: 'from-pink-600 to-emerald-600',
      status: 'Verified',
    },
    {
      id: 5,
      name: '5. Assembly & Reports',
      desc: 'SQLite Indexing & Report Export',
      icon: FileCheck2,
      color: 'from-emerald-600 to-cyan-500',
      status: 'Ready',
    },
  ];

  return (
    <div className="glass-panel p-6 rounded-2xl border border-slate-800 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-bold text-slate-100">LangGraph StateGraph Pipeline</h2>
          <p className="text-xs text-slate-400">
            Autonomous multi-stage agentic workflow orchestrating scanning, RAG context enrichment, AI remediation, and rescan verification.
          </p>
        </div>
        <span className="px-2.5 py-1 rounded bg-purple-950 text-purple-300 border border-purple-800/60 text-[11px] font-mono font-semibold">
          StateGraph Orchestrator
        </span>
      </div>

      {/* Visual Workflow Steps Flow */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4 relative">
        {nodes.map((node, index) => {
          const Icon = node.icon;
          return (
            <div key={node.id} className="relative group">
              <div className="glass-card p-4 rounded-xl border border-slate-800 hover:border-cyan-500/50 transition-all flex flex-col justify-between h-full space-y-3">
                <div className="flex items-center justify-between">
                  <div className={`w-8 h-8 rounded-lg bg-gradient-to-tr ${node.color} p-0.5 shadow-md`}>
                    <div className="w-full h-full bg-navy-950 rounded-[6px] flex items-center justify-center">
                      <Icon className="w-4 h-4 text-cyan-400" />
                    </div>
                  </div>
                  <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-1.5 py-0.5 rounded border border-emerald-800/40">
                    {node.status}
                  </span>
                </div>

                <div>
                  <h3 className="text-xs font-bold text-slate-200">{node.name}</h3>
                  <p className="text-[11px] text-slate-400 mt-0.5 leading-snug">{node.desc}</p>
                </div>
              </div>

              {index < nodes.length - 1 && (
                <div className="hidden md:block absolute -right-3 top-1/2 -translate-y-1/2 z-10">
                  <ArrowRight className="w-4 h-4 text-slate-600" />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default WorkflowGraph;
