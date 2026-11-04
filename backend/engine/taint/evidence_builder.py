"""Evidence Construction for SecurePy Taint Analysis.

Constructs comprehensive, explainable source-to-sink data-flow traces,
evidence snippets, and flow steps for visualization.
"""

from __future__ import annotations

from typing import Any, Optional

from backend.engine.analysis.intermediate_representation import IRCall
from backend.engine.models.finding import Confidence, Finding
from backend.engine.taint.sinks import TaintSink
from backend.engine.taint.taint_state import PropagationStep, TaintTag


class EvidenceBuilder:
    """Builds structured data-flow evidence and explainable security findings."""

    def build_finding(
        self,
        sink: TaintSink,
        call: IRCall,
        tainted_arg_name: str,
        tag: TaintTag,
        chain: list[PropagationStep],
        file_path: Optional[str] = None,
    ) -> Finding:
        """Construct a standardized Finding with complete source-to-sink evidence."""
        # 1. Build flow steps for React Flow visualization & reporting
        flow_steps: list[dict[str, Any]] = []

        # Source step
        flow_steps.append(
            {
                "step": 1,
                "type": "SOURCE",
                "label": f"Source: {tag.source_name}()",
                "variable": chain[0].to_name if chain else tainted_arg_name,
                "line": tag.location.line,
                "code": tag.origin_repr,
                "description": f"Untrusted input originates from {tag.source_name}()",
            }
        )

        # Intermediate propagation steps
        for step in chain[1:]:
            flow_steps.append(
                {
                    "step": step.step_number,
                    "type": "SANITIZER" if step.is_sanitizer else "PROPAGATION",
                    "label": f"Step {step.step_number}: {step.from_name} -> {step.to_name}",
                    "variable": step.to_name,
                    "line": step.location.line,
                    "code": step.expression,
                    "description": step.description,
                }
            )

        # Sink step
        sink_step_num = len(flow_steps) + 1
        flow_steps.append(
            {
                "step": sink_step_num,
                "type": "SINK",
                "label": f"Sink: {call.caller}()",
                "variable": tainted_arg_name,
                "line": call.location.line,
                "code": f"{call.caller}({', '.join(a.value_repr for a in call.args)})",
                "description": f"Tainted value enters dangerous operation '{call.caller}()'",
            }
        )

        # 2. Build multi-line code evidence summary
        evidence_lines = [
            f"Source (L{tag.location.line}): {tag.origin_repr}",
        ]
        for step in chain[1:]:
            evidence_lines.append(f"Flow   (L{step.location.line}): {step.expression}")
        evidence_lines.append(
            f"Sink   (L{call.location.line}): {call.caller}({', '.join(a.value_repr for a in call.args)})"
        )
        evidence_str = "\n".join(evidence_lines)

        # 3. Build explainable description
        hops = [step.to_name for step in chain]
        path_str = " -> ".join([tag.source_name] + hops + [call.caller])
        description = (
            f"Proven data-flow vulnerability ({sink.title}): Untrusted data originating from "
            f"'{tag.source_name}()' at line {tag.location.line} propagates along path "
            f"[{path_str}] and reaches sensitive sink '{call.caller}()' at line {call.location.line} "
            f"without appropriate sanitization."
        )

        return Finding(
            rule_id=sink.sink_id,
            title=f"{sink.title} (Proven Data Flow)",
            category=sink.category.value.replace("_", " ").title(),
            cwe_id=sink.cwe_id,
            severity=sink.severity,
            confidence=Confidence.HIGH,  # High confidence because flow is verified
            line_number=call.location.line,
            column=call.location.col,
            end_line_number=call.location.end_line,
            file_path=file_path,
            description=description,
            evidence=evidence_str,
            remediation=sink.remediation,
            flow_steps=flow_steps,
        )
