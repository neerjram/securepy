import React, { useState } from 'react';
import Editor from '@monaco-editor/react';
import { Play, UploadCloud, Code, FileText, CheckCircle2, AlertCircle } from 'lucide-react';
import { scanSnippet, uploadAndScan } from '../services/api';

const SAMPLE_PRESETS = {
  command_injection: `# Vulnerable to Command Injection via Taint Flow
import os

name = input("Enter host: ")
cmd = "ping " + name
os.system(cmd)
`,
  sql_injection: `# Vulnerable to SQL Injection
user_input = input("Enter username: ")
query = "SELECT * FROM users WHERE username = '" + user_input + "'"
cursor.execute(query)
`,
  credentials: `# Vulnerable to Hardcoded Plaintext Secrets
api_key = "sk_live_94892482424824824892"
db_password = "ProductionPassword123!"

print("Connecting to database...")
`,
  safe_subprocess: `# Secure Subprocess Execution
import subprocess

host = input("Enter host: ")
# Safe: Passed as an explicit argument list, shell=False
subprocess.run(["ping", host], check=True)
`,
  safe_sql: `# Secure Parameterized SQL Query
user_id = input("Enter ID: ")
# Safe: Parameterized query placeholder
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
`,
};

export default function NewScan({ onScanComplete }) {
  const [mode, setMode] = useState('snippet'); // 'snippet' or 'upload'
  const [code, setCode] = useState(SAMPLE_PRESETS.command_injection);
  const [targetName, setTargetName] = useState('vulnerable_demo.py');
  const [selectedFile, setSelectedFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSnippetSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const res = await scanSnippet(code, targetName);
      if (onScanComplete) {
        onScanComplete(res.scan_id);
      }
    } catch (err) {
      setError(err.message || 'Analysis failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (e) => {
    e.preventDefault();
    if (!selectedFile) {
      setError('Please select a .py or .zip file.');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await uploadAndScan(selectedFile);
      if (onScanComplete) {
        onScanComplete(res.scan_id);
      }
    } catch (err) {
      setError(err.message || 'File analysis failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      {/* Header and Mode Selector */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-bold text-white">Start New Security Scan</h2>
          <p className="text-xs text-slate-400">
            Analyze Python code snippet or upload project archives without executing target code.
          </p>
        </div>

        <div className="flex items-center bg-slate-900 border border-slate-800 rounded-lg p-1">
          <button
            onClick={() => setMode('snippet')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
              mode === 'snippet'
                ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <Code className="w-3.5 h-3.5" />
            Snippet Editor
          </button>
          <button
            onClick={() => setMode('upload')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
              mode === 'upload'
                ? 'bg-sky-500/20 text-sky-400 border border-sky-500/30'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <UploadCloud className="w-3.5 h-3.5" />
            File / ZIP Upload
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-rose-950/30 border border-rose-800/40 p-4 rounded-xl text-rose-200 text-xs flex items-start gap-3">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          <div>
            <p className="font-semibold">Analysis Error</p>
            <p className="mt-0.5 text-rose-300">{error}</p>
          </div>
        </div>
      )}

      {mode === 'snippet' ? (
        <form onSubmit={handleSnippetSubmit} className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <span className="text-xs font-medium text-slate-400">Sample Presets:</span>
              <button
                type="button"
                onClick={() => { setCode(SAMPLE_PRESETS.command_injection); setTargetName('cmd_demo.py'); }}
                className="px-2 py-1 text-xs rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700"
              >
                Command Injection
              </button>
              <button
                type="button"
                onClick={() => { setCode(SAMPLE_PRESETS.sql_injection); setTargetName('sql_demo.py'); }}
                className="px-2 py-1 text-xs rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700"
              >
                SQL Injection
              </button>
              <button
                type="button"
                onClick={() => { setCode(SAMPLE_PRESETS.credentials); setTargetName('creds_demo.py'); }}
                className="px-2 py-1 text-xs rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700"
              >
                Credentials
              </button>
              <button
                type="button"
                onClick={() => { setCode(SAMPLE_PRESETS.safe_subprocess); setTargetName('safe_demo.py'); }}
                className="px-2 py-1 text-xs rounded bg-slate-800 hover:bg-slate-700 text-emerald-400 border border-slate-700"
              >
                Safe Code
              </button>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400">Target File:</span>
              <input
                type="text"
                value={targetName}
                onChange={(e) => setTargetName(e.target.value)}
                className="bg-slate-900 border border-slate-800 rounded px-2.5 py-1 text-xs text-white font-mono w-40 focus:outline-none focus:border-sky-500"
              />
            </div>
          </div>

          {/* Monaco Editor */}
          <div className="rounded-xl border border-slate-800 overflow-hidden bg-slate-950 shadow-xl">
            <Editor
              height="350px"
              defaultLanguage="python"
              theme="vs-dark"
              value={code}
              onChange={(newVal) => setCode(newVal || '')}
              options={{
                minimap: { enabled: false },
                fontSize: 13,
                scrollBeyondLastLine: false,
                wordWrap: 'on',
              }}
            />
          </div>

          <div className="flex items-center justify-end">
            <button
              type="submit"
              disabled={loading}
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-sky-500 hover:bg-sky-400 disabled:opacity-50 text-slate-950 font-semibold text-sm transition-all shadow-lg shadow-sky-500/20"
            >
              <Play className="w-4 h-4 fill-current" />
              {loading ? 'Running Static Analysis...' : 'Run Security Analysis'}
            </button>
          </div>
        </form>
      ) : (
        <form onSubmit={handleFileUpload} className="space-y-6">
          <div className="border-2 border-dashed border-slate-800 rounded-2xl p-10 text-center hover:border-sky-500/50 transition-colors bg-slate-900/40">
            <UploadCloud className="w-12 h-12 text-sky-400 mx-auto mb-3" />
            <h3 className="text-sm font-semibold text-white mb-1">Select Python Project or Script</h3>
            <p className="text-xs text-slate-400 max-w-sm mx-auto mb-4">
              Upload a single <code className="text-sky-300">.py</code> file (up to 2MB) or a <code className="text-sky-300">.zip</code> archive (up to 10MB) for whole-project static analysis.
            </p>

            <input
              type="file"
              accept=".py,.zip"
              onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
              className="text-xs text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-xs file:font-semibold file:bg-sky-500/10 file:text-sky-400 hover:file:bg-sky-500/20 cursor-pointer"
            />

            {selectedFile && (
              <div className="mt-4 inline-flex items-center gap-2 text-xs text-emerald-400 bg-emerald-500/10 px-3 py-1.5 rounded-lg border border-emerald-500/20">
                <CheckCircle2 className="w-4 h-4" />
                Selected: {selectedFile.name} ({(selectedFile.size / 1024).toFixed(1)} KB)
              </div>
            )}
          </div>

          <div className="flex items-center justify-end">
            <button
              type="submit"
              disabled={loading || !selectedFile}
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-sky-500 hover:bg-sky-400 disabled:opacity-50 text-slate-950 font-semibold text-sm transition-all shadow-lg shadow-sky-500/20"
            >
              <Play className="w-4 h-4 fill-current" />
              {loading ? 'Extracting & Scanning...' : 'Upload & Analyze'}
            </button>
          </div>
        </form>
      )}
    </div>
  );
}
