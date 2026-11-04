import React from 'react';
import { ShieldAlert, Activity, CheckCircle2, XCircle, PlusCircle, History, LayoutDashboard } from 'lucide-react';

export default function Navbar({ activeTab, setActiveTab, health }) {
  return (
    <header className="border-b border-slate-800 bg-slate-900/90 backdrop-blur sticky top-0 z-50 px-6 py-3 flex items-center justify-between">
      <div className="flex items-center space-x-6">
        <div
          onClick={() => setActiveTab('dashboard')}
          className="flex items-center space-x-3 cursor-pointer group"
        >
          <div className="bg-sky-500/10 p-2 rounded-lg border border-sky-500/20 text-sky-400 group-hover:border-sky-500/40 transition-colors">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-white flex items-center gap-2">
              SecurePy
              <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-sky-500/10 text-sky-400 border border-sky-500/30">
                v0.1.0
              </span>
            </h1>
            <p className="text-[11px] text-slate-400">Explainable Static Security Analyzer</p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="hidden md:flex items-center space-x-1 border-l border-slate-800 pl-6">
          <button
            onClick={() => setActiveTab('dashboard')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
              activeTab === 'dashboard'
                ? 'bg-sky-500/10 text-sky-400 border border-sky-500/20'
                : 'text-slate-300 hover:bg-slate-800 hover:text-white'
            }`}
          >
            <LayoutDashboard className="w-4 h-4" />
            Dashboard
          </button>

          <button
            onClick={() => setActiveTab('new-scan')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
              activeTab === 'new-scan'
                ? 'bg-sky-500/10 text-sky-400 border border-sky-500/20'
                : 'text-slate-300 hover:bg-slate-800 hover:text-white'
            }`}
          >
            <PlusCircle className="w-4 h-4" />
            New Scan
          </button>

          <button
            onClick={() => setActiveTab('history')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
              activeTab === 'history'
                ? 'bg-sky-500/10 text-sky-400 border border-sky-500/20'
                : 'text-slate-300 hover:bg-slate-800 hover:text-white'
            }`}
          >
            <History className="w-4 h-4" />
            Scan History
          </button>
        </nav>
      </div>

      {/* Backend Health Badge */}
      <div className="flex items-center gap-2 text-xs">
        {health ? (
          <span className="flex items-center gap-1.5 text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded-full border border-emerald-500/20">
            <CheckCircle2 className="w-3.5 h-3.5" />
            API Connected
          </span>
        ) : (
          <span className="flex items-center gap-1.5 text-rose-400 bg-rose-500/10 px-2.5 py-1 rounded-full border border-rose-500/20">
            <XCircle className="w-3.5 h-3.5" />
            API Offline
          </span>
        )}
      </div>
    </header>
  );
}
