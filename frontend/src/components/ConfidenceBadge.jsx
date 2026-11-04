import React from 'react';

const CONFIDENCE_STYLES = {
  HIGH: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  MEDIUM: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  LOW: 'bg-slate-500/10 text-slate-400 border-slate-500/20',
};

export default function ConfidenceBadge({ confidence }) {
  const confUpper = (confidence || 'LOW').toUpperCase();
  const style = CONFIDENCE_STYLES[confUpper] || CONFIDENCE_STYLES.LOW;

  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[11px] font-medium border ${style}`}>
      Conf: {confUpper}
    </span>
  );
}
