import React from 'react';
import { ShieldAlert, AlertTriangle, AlertCircle, Info, ShieldCheck, FileCode } from 'lucide-react';

const MetricsOverview = ({ scan }) => {
  if (!scan) return null;

  const score = scan.security_score || 100;
  let scoreColor = 'text-emerald-400 border-emerald-500/40 bg-emerald-950/20';
  let scoreText = 'EXCELLENT';
  if (score < 50) {
    scoreColor = 'text-red-400 border-red-500/40 bg-red-950/20';
    scoreText = 'CRITICAL RISK';
  } else if (score < 80) {
    scoreColor = 'text-yellow-400 border-yellow-500/40 bg-yellow-950/20';
    scoreText = 'MODERATE RISK';
  }

  const cards = [
    {
      title: 'Critical Severity',
      count: scan.critical_count || 0,
      icon: ShieldAlert,
      color: 'text-red-400',
      border: 'border-red-500/30 bg-red-950/10',
    },
    {
      title: 'High Severity',
      count: scan.high_count || 0,
      icon: AlertTriangle,
      color: 'text-orange-400',
      border: 'border-orange-500/30 bg-orange-950/10',
    },
    {
      title: 'Medium Severity',
      count: scan.medium_count || 0,
      icon: AlertCircle,
      color: 'text-yellow-400',
      border: 'border-yellow-500/30 bg-yellow-950/10',
    },
    {
      title: 'Low Severity',
      count: scan.low_count || 0,
      icon: Info,
      color: 'text-blue-400',
      border: 'border-blue-500/30 bg-blue-950/10',
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-6">
      {/* Security Health Score Card */}
      <div className={`col-span-1 md:col-span-2 glass-panel p-5 rounded-2xl border flex items-center justify-between ${scoreColor}`}>
        <div className="space-y-1">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-400 uppercase tracking-wider">
            <ShieldCheck className="w-4 h-4 text-cyan-400" />
            <span>Security Health Index</span>
          </div>
          <div className="flex items-baseline gap-3">
            <span className="text-4xl font-extrabold tracking-tight text-slate-100">{score}</span>
            <span className="text-xs text-slate-400">/ 100</span>
          </div>
          <div className="text-[11px] font-bold uppercase tracking-wider">{scoreText}</div>
        </div>

        {/* Circular Gauge Graphic */}
        <div className="relative w-16 h-16 flex items-center justify-center">
          <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
            <path
              className="text-slate-800"
              strokeWidth="3.5"
              stroke="currentColor"
              fill="none"
              d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
            />
            <path
              className={score >= 80 ? 'text-emerald-400' : score >= 50 ? 'text-yellow-400' : 'text-red-500'}
              strokeDasharray={`${score}, 100`}
              strokeWidth="3.5"
              strokeLinecap="round"
              stroke="currentColor"
              fill="none"
              d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
            />
          </svg>
          <span className="absolute text-xs font-bold text-slate-200">{score}%</span>
        </div>
      </div>

      {/* Severity Stat Cards */}
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <div
            key={idx}
            className={`glass-panel p-4 rounded-2xl border ${card.border} flex flex-col justify-between transition-transform hover:-translate-y-0.5`}
          >
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>{card.title}</span>
              <Icon className={`w-4 h-4 ${card.color}`} />
            </div>
            <div className="mt-3 flex items-baseline justify-between">
              <span className={`text-3xl font-extrabold ${card.color}`}>{card.count}</span>
              <span className="text-[10px] text-slate-400 uppercase">Findings</span>
            </div>
          </div>
        );
      })}
    </div>
  );
};

export default MetricsOverview;
