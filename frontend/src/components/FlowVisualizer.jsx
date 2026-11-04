import React, { useMemo } from 'react';
import ReactFlow, { Background, Controls, MarkerType } from 'reactflow';
import 'reactflow/dist/style.css';

export default function FlowVisualizer({ flowSteps }) {
  if (!flowSteps || flowSteps.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center p-8 text-center text-slate-400 bg-slate-950/60 rounded-xl border border-slate-800">
        <p className="text-sm">No multi-step data flow path recorded for this pattern finding.</p>
        <p className="text-xs text-slate-500 mt-1">
          Pattern rules inspect local syntax; data-flow graphs appear when untrusted inputs propagate to sensitive sinks.
        </p>
      </div>
    );
  }

  const { nodes, edges } = useMemo(() => {
    const calculatedNodes = [];
    const calculatedEdges = [];

    flowSteps.forEach((step, idx) => {
      let bgClass = 'bg-slate-900 border-sky-500/50 text-sky-200';
      let typeBadge = 'bg-sky-500/20 text-sky-300';

      if (step.type === 'SOURCE') {
        bgClass = 'bg-slate-900 border-emerald-500 text-emerald-200 shadow-emerald-950/50 shadow-lg';
        typeBadge = 'bg-emerald-500/20 text-emerald-300';
      } else if (step.type === 'SINK') {
        bgClass = 'bg-slate-900 border-rose-500 text-rose-200 shadow-rose-950/50 shadow-lg';
        typeBadge = 'bg-rose-500/20 text-rose-300';
      } else if (step.type === 'SANITIZER') {
        bgClass = 'bg-slate-900 border-amber-500 text-amber-200';
        typeBadge = 'bg-amber-500/20 text-amber-300';
      }

      calculatedNodes.push({
        id: `node-${idx}`,
        position: { x: 30 + idx * 240, y: 50 + (idx % 2 === 0 ? 0 : 30) },
        data: {
          label: (
            <div className="p-3 text-left w-52">
              <div className="flex items-center justify-between mb-1">
                <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wider ${typeBadge}`}>
                  {step.type}
                </span>
                <span className="text-[11px] font-mono text-slate-400">Line {step.line}</span>
              </div>
              <div className="font-mono text-xs font-semibold text-white truncate mb-1">
                {step.variable ? `var: ${step.variable}` : step.label}
              </div>
              <div className="text-[11px] font-mono bg-slate-950/80 p-1.5 rounded border border-slate-800 text-slate-300 truncate">
                {step.code || step.description}
              </div>
            </div>
          ),
        },
        style: {
          background: 'transparent',
          border: 'none',
          padding: 0,
        },
        className: `rounded-xl border ${bgClass}`,
      });

      if (idx > 0) {
        calculatedEdges.push({
          id: `edge-${idx - 1}-${idx}`,
          source: `node-${idx - 1}`,
          target: `node-${idx}`,
          animated: true,
          style: { stroke: '#38bdf8', strokeWidth: 2 },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: '#38bdf8',
          },
        });
      }
    });

    return { nodes: calculatedNodes, edges: calculatedEdges };
  }, [flowSteps]);

  return (
    <div className="h-64 w-full bg-slate-950 rounded-xl border border-slate-800 overflow-hidden relative">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        fitView
        attributionPosition="bottom-right"
        nodesDraggable={false}
      >
        <Background color="#334155" gap={16} size={1} />
        <Controls showInteractive={false} className="bg-slate-900 border-slate-800 text-white fill-white" />
      </ReactFlow>
    </div>
  );
}
