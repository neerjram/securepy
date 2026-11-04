import React from 'react';
import { ShieldAlert, AlertTriangle, FileCode, CheckCircle, ArrowRight, Terminal, Database, Key, Play } from 'lucide-react';

export default function Dashboard({ scans, setActiveTab, onSelectScan }) {
  const totalScans = scans.length;
  const totalFindings = scans.reduce((acc, s) => acc + (s.findings_count || 0), 0);
  const avgRiskScore = totalScans > 0 ? Math.round(scans.reduce((acc, s) => acc + (s.risk_score || 0), 0) / totalScans) : 0;
  const recentScans = scans.slice(0, 5);

  return (
    <div className="space-y-8">
      {/* Top Welcome / Hero Banner */}
      <div className="bg-gradient-to-r from-sky-950/40 via-slate-900 to-slate-900 border border-sky-500/20 rounded-2xl p-6 md:p-8 flex flex-col md:flex-row items-start md:items-center justify-between gap-6 shadow-xl">
        <div className="space-y-2 max-w-2xl">
          <h2 className="text-2xl font-bold text-white tracking-tight">
            Explainable Security Analysis for Python
          </h2>
          <p className="text-sm text-slate-300 leading-relaxed">
            SecurePy inspects Python source code using AST analysis and taint propagation.
            It provides verifiable source-to-sink data-flow evidence, separate severity & confidence metrics, and actionable remediation without ever executing analyzed code.
          </p>
        </div>
        <div className="flex flex-wrap gap-3">
          <button
            onClick={() => setActiveTab('new-scan')}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold text-sm transition-all shadow-lg shadow-sky-500/20"
          >
            <Play className="w-4 h-4 fill-current" />
            Start Analysis
          </button>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Total Scans</span>
            <FileCode className="w-5 h-5 text-sky-400" />
          </div>
          <p className="text-2xl font-bold text-white mt-2">{totalScans}</p>
          <span className="text-xs text-slate-500 mt-1 block">Local project audits</span>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Total Vulnerabilities</span>
            <AlertTriangle className="w-5 h-5 text-rose-400" />
          </div>
          <p className="text-2xl font-bold text-rose-400 mt-2">{totalFindings}</p>
          <span className="text-xs text-slate-500 mt-1 block">Across all scans</span>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Avg Risk Score</span>
            <ShieldAlert className="w-5 h-5 text-amber-400" />
          </div>
          <p className="text-2xl font-bold text-amber-400 mt-2">{avgRiskScore} / 100</p>
          <span className="text-xs text-slate-500 mt-1 block">Normalized project risk</span>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Analysis Engine</span>
            <CheckCircle className="w-5 h-5 text-emerald-400" />
          </div>
          <p className="text-base font-bold text-emerald-400 mt-2">AST + Taint</p>
          <span className="text-xs text-slate-500 mt-1 block">Zero Code Execution</span>
        </div>
      </div>

      {/* Detection Coverage Cards */}
      <div className="space-y-4">
        <h3 className="text-lg font-semibold text-white">Detection Capabilities & Categories</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-colors">
            <div className="flex items-center gap-3 mb-2 text-rose-400">
              <Terminal className="w-5 h-5" />
              <h4 className="font-semibold text-white text-sm">Command Injection (CWE-78)</h4>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Traces untrusted inputs propagating to <code className="text-sky-300">os.system</code>, <code className="text-sky-300">subprocess.Popen</code>, and verifies shell argument separation.
            </p>
          </div>

          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-colors">
            <div className="flex items-center gap-3 mb-2 text-sky-400">
              <Database className="w-5 h-5" />
              <h4 className="font-semibold text-white text-sm">SQL Injection (CWE-89)</h4>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Detects string-formatted dynamic database queries while validating parameterization markers (<code className="text-sky-300">?</code>, <code className="text-sky-300">%s</code>).
            </p>
          </div>

          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-colors">
            <div className="flex items-center gap-3 mb-2 text-amber-400">
              <Key className="w-5 h-5" />
              <h4 className="font-semibold text-white text-sm">Hardcoded Credentials (CWE-798)</h4>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Flags passwords, secret tokens, and API keys committed in source text with automated secret masking.
            </p>
          </div>
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold text-white">Recent Security Scans</h3>
          {recentScans.length > 0 && (
            <button
              onClick={() => setActiveTab('history')}
              className="text-xs text-sky-400 hover:text-sky-300 flex items-center gap-1 font-medium"
            >
              View all history <ArrowRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {recentScans.length === 0 ? (
          <div className="text-center py-8 text-slate-400 text-sm">
            <p>No scans recorded yet.</p>
            <button
              onClick={() => setActiveTab('new-scan')}
              className="mt-3 text-xs text-sky-400 hover:underline"
            >
              Analyze your first Python code snippet &rarr;
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[11px]">
                <tr>
                  <th className="py-3 px-4">Target</th>
                  <th className="py-3 px-4">Type</th>
                  <th className="py-3 px-4">Lines</th>
                  <th className="py-3 px-4">Findings</th>
                  <th className="py-3 px-4">Risk Score</th>
                  <th className="py-3 px-4">Date</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-slate-200">
                {recentScans.map((s) => (
                  <tr key={s.scan_id} className="hover:bg-slate-800/50 transition-colors">
                    <td className="py-3 px-4 font-mono font-medium text-white">{s.target_name}</td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px]">
                        {s.target_type}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono">{s.total_lines}</td>
                    <td className="py-3 px-4">
                      <span className={`font-semibold ${s.findings_count > 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
                        {s.findings_count}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <span className={`font-semibold ${s.risk_score > 50 ? 'text-rose-400' : s.risk_score > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
                        {s.risk_score}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-400 font-mono">
                      {new Date(s.created_at).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => onSelectScan(s.scan_id)}
                        className="text-sky-400 hover:text-sky-300 font-medium hover:underline"
                      >
                        View Results
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
