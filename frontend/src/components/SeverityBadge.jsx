import React from 'react';

const SeverityBadge = ({ severity }) => {
  const sev = (severity || 'Low').toUpperCase();

  const styles = {
    CRITICAL: 'bg-red-950/80 text-red-400 border-red-500/50 shadow-red-900/30',
    HIGH: 'bg-orange-950/80 text-orange-400 border-orange-500/50 shadow-orange-900/30',
    MEDIUM: 'bg-yellow-950/80 text-yellow-400 border-yellow-500/50 shadow-yellow-900/30',
    LOW: 'bg-blue-950/80 text-blue-400 border-blue-500/50 shadow-blue-900/30',
  };

  const currentStyle = styles[sev] || styles.LOW;

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wider border shadow-sm ${currentStyle}`}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" />
      {sev}
    </span>
  );
};

export default SeverityBadge;
