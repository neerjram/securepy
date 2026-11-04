import React from 'react';

const SEVERITY_STYLES = {
  CRITICAL: 'bg-rose-500/15 text-rose-400 border-rose-500/30',
  HIGH: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  MEDIUM: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  LOW: 'bg-sky-500/15 text-sky-400 border-sky-500/30',
  INFO: 'bg-slate-500/15 text-slate-400 border-slate-500/30',
};

export default function SeverityBadge({ severity }) {
  const sevUpper = (severity || 'INFO').toUpperCase();
  const style = SEVERITY_STYLES[sevUpper] || SEVERITY_STYLES.INFO;

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold border ${style}`}>
      {sevUpper}
    </span>
  );
}
