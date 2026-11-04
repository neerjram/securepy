import React, { useState } from 'react';
import { History, Download, ArrowRight, Search, FileCode } from 'lucide-react';
import { fetchScanReport } from '../services/api';

export default function ScanHistory({ scans, onSelectScan, onRefresh }) {
  const [searchTerm, setSearchTerm] = useState('');

  const filteredScans = scans.filter((s) =>
    s.target_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    s.scan_id.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleDownload = async (e, scanId) => {
    e.stopPropagation();
    try {
      const report = await fetchScanReport(scanId);
      const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `securepy_report_${scanId}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert(`Report download failed: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <History className="w-5 h-5 text-sky-400" />
            Scan History
          </h2>
          <p className="text-xs text-slate-400">
            Review past security scans, audit reports, and risk scores.
          </p>
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search by target or ID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-sky-500"
          />
        </div>
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        {filteredScans.length === 0 ? (
          <div className="text-center py-12 text-slate-400 text-sm">
            <FileCode className="w-10 h-10 text-slate-600 mx-auto mb-2" />
            <p>No scans found matching your search.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[11px] bg-slate-950/40">
                <tr>
                  <th className="py-3 px-4">Scan ID</th>
                  <th className="py-3 px-4">Target</th>
                  <th className="py-3 px-4">Type</th>
                  <th className="py-3 px-4">Lines</th>
                  <th className="py-3 px-4">Findings</th>
                  <th className="py-3 px-4">Risk Score</th>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-slate-200">
                {filteredScans.map((s) => (
                  <tr
                    key={s.scan_id}
                    onClick={() => onSelectScan(s.scan_id)}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                  >
                    <td className="py-3.5 px-4 font-mono text-sky-400 font-semibold">{s.scan_id}</td>
                    <td className="py-3.5 px-4 font-mono font-medium text-white">{s.target_name}</td>
                    <td className="py-3.5 px-4">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px]">
                        {s.target_type}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 font-mono">{s.total_lines}</td>
                    <td className="py-3.5 px-4">
                      <span className={`font-semibold ${s.findings_count > 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
                        {s.findings_count}
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      <span className={`font-bold ${s.risk_score > 50 ? 'text-rose-400' : s.risk_score > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
                        {s.risk_score}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 font-mono">
                      {new Date(s.created_at).toLocaleString()}
                    </td>
                    <td className="py-3.5 px-4 text-right space-x-2">
                      <button
                        onClick={(e) => handleDownload(e, s.scan_id)}
                        className="p-1 rounded hover:bg-slate-700 text-slate-400 hover:text-white"
                        title="Download JSON Report"
                      >
                        <Download className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => onSelectScan(s.scan_id)}
                        className="text-sky-400 hover:text-sky-300 font-medium inline-flex items-center gap-1"
                      >
                        Inspect <ArrowRight className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
