import React from 'react';

const STATUS_STYLES = {
  OPEN: 'bg-rose-500/10 text-rose-300 border-rose-500/20',
  REVIEWED: 'bg-blue-500/10 text-blue-300 border-blue-500/20',
  FALSE_POSITIVE: 'bg-slate-500/20 text-slate-400 border-slate-600',
  FIXED: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/20',
};

export default function StatusBadge({ status, onStatusChange, editable = true }) {
  const currentStatus = (status || 'OPEN').toUpperCase();

  if (!editable || !onStatusChange) {
    return (
      <span className={`px-2 py-0.5 rounded text-xs font-medium border ${STATUS_STYLES[currentStatus] || STATUS_STYLES.OPEN}`}>
        {currentStatus}
      </span>
    );
  }

  return (
    <select
      value={currentStatus}
      onChange={(e) => onStatusChange(e.target.value)}
      className={`text-xs font-medium rounded px-2 py-0.5 border bg-slate-900 cursor-pointer focus:outline-none focus:ring-1 focus:ring-sky-500 ${
        STATUS_STYLES[currentStatus] || STATUS_STYLES.OPEN
      }`}
    >
      <option value="OPEN" className="bg-slate-900 text-slate-100">OPEN</option>
      <option value="REVIEWED" className="bg-slate-900 text-slate-100">REVIEWED</option>
      <option value="FALSE_POSITIVE" className="bg-slate-900 text-slate-100">FALSE POSITIVE</option>
      <option value="FIXED" className="bg-slate-900 text-slate-100">FIXED</option>
    </select>
  );
}
