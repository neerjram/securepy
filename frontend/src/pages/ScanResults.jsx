import React, { useState, useEffect } from 'react';
import {
  ShieldAlert, Download, Filter, ArrowLeft, Check, Copy,
  BookOpen, Terminal, Code2, GitFork, AlertCircle
} from 'lucide-react';
import SeverityBadge from '../components/SeverityBadge';
import ConfidenceBadge from '../components/ConfidenceBadge';
import StatusBadge from '../components/StatusBadge';
import FlowVisualizer from '../components/FlowVisualizer';
import { fetchScanDetail, updateFindingStatus, fetchScanReport } from '../services/api';

export default function ScanResults({ scanId, onBack }) {
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [activeDetailTab, setActiveDetailTab] = useState('flow'); // 'flow', 'code', 'beginner', 'developer', 'remediation'
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    loadScan();
  }, [scanId]);

  const loadScan = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchScanDetail(scanId);
      setScan(data);
      if (data.findings && data.findings.length > 0) {
        setSelectedFinding(data.findings[0]);
      }
    } catch (err) {
      setError(err.message || 'Failed to load scan details.');
    } finally {
      setLoading(false);
    }
  };

  const handleStatusChange = async (findingId, newStatus) => {
    try {
      const updated = await updateFindingStatus(findingId, newStatus);
      setScan((prev) => ({
        ...prev,
        findings: prev.findings.map((f) => (f.id === findingId ? updated : f)),
      }));
      if (selectedFinding?.id === findingId) {
        setSelectedFinding(updated);
      }
    } catch (err) {
      alert(`Failed to update status: ${err.message}`);
    }
  };

  const handleDownloadReport = async () => {
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

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center p-16 text-slate-400">
        <div className="w-8 h-8 border-2 border-sky-500 border-t-transparent rounded-full animate-spin mb-3" />
        <p className="text-sm font-medium">Retrieving scan results & data flow models...</p>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="bg-rose-950/30 border border-rose-800/40 p-6 rounded-xl text-rose-200">
        <p className="font-semibold mb-2">Error loading scan {scanId}</p>
        <p className="text-sm">{error || 'Scan not found'}</p>
        <button
          onClick={onBack}
          className="mt-4 px-3 py-1.5 text-xs rounded bg-slate-800 text-slate-200 hover:bg-slate-700"
        >
          &larr; Back to Dashboard
        </button>
      </div>
    );
  }

  const filteredFindings = scan.findings.filter((f) => {
    if (severityFilter === 'ALL') return true;
    return f.severity.toUpperCase() === severityFilter;
  });

  return (
    <div className="space-y-6">
      {/* Top Banner and Summary */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <button
            onClick={onBack}
            className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
            title="Back"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div>
            <div className="flex items-center gap-3">
              <h2 className="text-xl font-bold text-white font-mono">{scan.target_name}</h2>
              <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">
                {scan.target_type}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Scan ID: <code className="text-sky-300">{scan.scan_id}</code> • {scan.total_lines} lines analyzed • {new Date(scan.created_at).toLocaleString()}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="text-right">
            <span className="text-[11px] text-slate-400 block uppercase font-medium">Risk Score</span>
            <span className={`text-2xl font-bold ${scan.risk_score > 50 ? 'text-rose-400' : scan.risk_score > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
              {scan.risk_score} <span className="text-xs font-normal text-slate-500">/ 100</span>
            </span>
          </div>

          <button
            onClick={handleDownloadReport}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition-colors shadow-sm"
          >
            <Download className="w-4 h-4 text-sky-400" />
            Export JSON
          </button>
        </div>
      </div>

      {/* Main Master-Detail Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Findings List (5 cols) */}
        <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl flex flex-col h-[750px]">
          {/* Findings Filter Bar */}
          <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/40">
            <div className="flex items-center gap-2">
              <Filter className="w-4 h-4 text-slate-400" />
              <span className="text-xs font-semibold text-white">
                Findings ({filteredFindings.length} of {scan.findings.length})
              </span>
            </div>

            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-slate-900 border border-slate-800 rounded px-2 py-1 text-xs text-slate-300 focus:outline-none focus:border-sky-500"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          {/* Scrollable Findings Cards */}
          <div className="flex-1 overflow-y-auto divide-y divide-slate-800/60 p-2 space-y-1">
            {filteredFindings.length === 0 ? (
              <div className="p-8 text-center text-slate-400 text-xs">
                No findings match the selected filter.
              </div>
            ) : (
              filteredFindings.map((finding) => {
                const isSelected = selectedFinding?.id === finding.id;
                return (
                  <div
                    key={finding.id}
                    onClick={() => setSelectedFinding(finding)}
                    className={`p-3.5 rounded-lg cursor-pointer transition-all ${
                      isSelected
                        ? 'bg-sky-500/10 border border-sky-500/30'
                        : 'hover:bg-slate-800/40 border border-transparent'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2 mb-1.5">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <SeverityBadge severity={finding.severity} />
                        <ConfidenceBadge confidence={finding.confidence} />
                        <span className="text-[11px] font-mono text-slate-400">
                          {finding.cwe_id}
                        </span>
                      </div>
                      <StatusBadge
                        status={finding.status}
                        onStatusChange={(newSt) => handleStatusChange(finding.id, newSt)}
                      />
                    </div>

                    <h4 className="text-xs font-semibold text-white truncate mb-1">
                      {finding.title}
                    </h4>

                    <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono">
                      <span>{finding.file_path || 'snippet.py'}:{finding.line_number}</span>
                      {finding.flow_steps?.length > 0 && (
                        <span className="text-sky-400 flex items-center gap-1">
                          <GitFork className="w-3 h-3" /> Data flow ({finding.flow_steps.length} steps)
                        </span>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Deep-Dive Inspector (7 cols) */}
        <div className="lg:col-span-7 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl h-[750px] flex flex-col">
          {selectedFinding ? (
            <>
              {/* Finding Title & Coordinates */}
              <div className="p-5 border-b border-slate-800 bg-slate-950/40">
                <div className="flex items-start justify-between gap-4 mb-2">
                  <div>
                    <span className="text-[11px] font-mono text-sky-400 uppercase tracking-wider block">
                      {selectedFinding.category} • {selectedFinding.rule_id}
                    </span>
                    <h3 className="text-base font-bold text-white mt-0.5">
                      {selectedFinding.title}
                    </h3>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <SeverityBadge severity={selectedFinding.severity} />
                    <ConfidenceBadge confidence={selectedFinding.confidence} />
                  </div>
                </div>

                <div className="flex items-center gap-4 text-xs font-mono text-slate-400">
                  <span>Location: Line {selectedFinding.line_number}</span>
                  <span>CWE: {selectedFinding.cwe_id}</span>
                  <span>Status: {selectedFinding.status}</span>
                </div>
              </div>

              {/* Detail Navigation Tabs */}
              <div className="flex items-center border-b border-slate-800 px-4 bg-slate-950/20 text-xs">
                <button
                  onClick={() => setActiveDetailTab('flow')}
                  className={`flex items-center gap-1.5 py-3 px-3 font-medium border-b-2 transition-colors ${
                    activeDetailTab === 'flow'
                      ? 'border-sky-500 text-sky-400'
                      : 'border-transparent text-slate-400 hover:text-white'
                  }`}
                >
                  <GitFork className="w-3.5 h-3.5" />
                  Data Flow Path
                </button>

                <button
                  onClick={() => setActiveDetailTab('code')}
                  className={`flex items-center gap-1.5 py-3 px-3 font-medium border-b-2 transition-colors ${
                    activeDetailTab === 'code'
                      ? 'border-sky-500 text-sky-400'
                      : 'border-transparent text-slate-400 hover:text-white'
                  }`}
                >
                  <Code2 className="w-3.5 h-3.5" />
                  Code Evidence
                </button>

                <button
                  onClick={() => setActiveDetailTab('beginner')}
                  className={`flex items-center gap-1.5 py-3 px-3 font-medium border-b-2 transition-colors ${
                    activeDetailTab === 'beginner'
                      ? 'border-sky-500 text-sky-400'
                      : 'border-transparent text-slate-400 hover:text-white'
                  }`}
                >
                  <BookOpen className="w-3.5 h-3.5" />
                  Beginner Guide
                </button>

                <button
                  onClick={() => setActiveDetailTab('developer')}
                  className={`flex items-center gap-1.5 py-3 px-3 font-medium border-b-2 transition-colors ${
                    activeDetailTab === 'developer'
                      ? 'border-sky-500 text-sky-400'
                      : 'border-transparent text-slate-400 hover:text-white'
                  }`}
                >
                  <Terminal className="w-3.5 h-3.5" />
                  Developer Analysis
                </button>

                <button
                  onClick={() => setActiveDetailTab('remediation')}
                  className={`flex items-center gap-1.5 py-3 px-3 font-medium border-b-2 transition-colors ${
                    activeDetailTab === 'remediation'
                      ? 'border-sky-500 text-sky-400'
                      : 'border-transparent text-slate-400 hover:text-white'
                  }`}
                >
                  <Check className="w-3.5 h-3.5" />
                  Remediation & Fix
                </button>
              </div>

              {/* Tab Content Panel */}
              <div className="flex-1 overflow-y-auto p-5 text-sm">
                {activeDetailTab === 'flow' && (
                  <div className="space-y-4">
                    <div className="text-xs text-slate-300">
                      Visual representation of untrusted data propagation from input source to dangerous sink:
                    </div>
                    <FlowVisualizer flowSteps={selectedFinding.flow_steps} />
                    <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800 text-xs text-slate-300">
                      <p className="font-semibold text-sky-400 mb-1">Flow Summary:</p>
                      <p>{selectedFinding.description}</p>
                    </div>
                  </div>
                )}

                {activeDetailTab === 'code' && (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between text-xs text-slate-400">
                      <span>Source code evidence at line {selectedFinding.line_number}:</span>
                      <button
                        onClick={() => handleCopy(selectedFinding.evidence)}
                        className="text-xs text-sky-400 hover:underline flex items-center gap-1"
                      >
                        {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        {copied ? 'Copied' : 'Copy Evidence'}
                      </button>
                    </div>
                    <pre className="bg-slate-950 p-4 rounded-xl border border-slate-800 text-slate-200 font-mono text-xs overflow-x-auto whitespace-pre-wrap">
                      {selectedFinding.evidence}
                    </pre>
                  </div>
                )}

                {activeDetailTab === 'beginner' && (
                  <div className="space-y-4">
                    <div className="bg-sky-500/10 border border-sky-500/20 p-4 rounded-xl text-slate-200 leading-relaxed text-sm">
                      <h4 className="font-semibold text-sky-400 mb-2 flex items-center gap-2">
                        <BookOpen className="w-4 h-4" /> Understanding This Risk
                      </h4>
                      <p>{selectedFinding.beginner_explanation}</p>
                    </div>

                    <div className="bg-slate-950/60 border border-slate-800 p-4 rounded-xl space-y-2">
                      <h5 className="font-semibold text-white text-xs">Why is this dangerous?</h5>
                      <p className="text-xs text-slate-400 leading-relaxed">
                        Computers follow program instructions step-by-step. When code mixes executable instructions with data from untrusted outside users, an attacker can format their data so that the computer mistakes it for command instructions.
                      </p>
                    </div>
                  </div>
                )}

                {activeDetailTab === 'developer' && (
                  <div className="space-y-4">
                    <div className="bg-slate-950/80 border border-slate-800 p-4 rounded-xl text-slate-200 text-xs leading-relaxed space-y-2">
                      <h4 className="font-semibold text-sky-400 flex items-center gap-2">
                        <Terminal className="w-4 h-4" /> Technical Root Cause
                      </h4>
                      <p>{selectedFinding.developer_explanation}</p>
                    </div>

                    <div className="bg-slate-950/40 border border-slate-800 p-4 rounded-xl text-xs space-y-2">
                      <span className="font-semibold text-slate-300 block">General Remediation Guidance</span>
                      <p className="text-slate-400">{selectedFinding.remediation}</p>
                    </div>
                  </div>
                )}

                {activeDetailTab === 'remediation' && (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between text-xs text-slate-400">
                      <span>Recommended Python code refactoring:</span>
                      <button
                        onClick={() => handleCopy(selectedFinding.mitigation_code)}
                        className="text-xs text-sky-400 hover:underline flex items-center gap-1"
                      >
                        {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        {copied ? 'Copied' : 'Copy Fix Code'}
                      </button>
                    </div>

                    <pre className="bg-slate-950 p-4 rounded-xl border border-emerald-500/30 text-emerald-300 font-mono text-xs overflow-x-auto whitespace-pre-wrap">
                      {selectedFinding.mitigation_code}
                    </pre>

                    <div className="bg-slate-950/60 border border-slate-800 p-3 rounded-lg text-xs text-slate-400">
                      <strong>Tip:</strong> Always test your code changes locally to ensure functional requirements remain intact.
                    </div>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="flex flex-col items-center justify-center h-full p-8 text-slate-500 text-center">
              <ShieldAlert className="w-12 h-12 mb-2 text-slate-600" />
              <p className="text-sm font-medium">Select a finding on the left to inspect its details and data flow path.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
