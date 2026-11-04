"""Taint Analyzer for SecurePy.

Main orchestration engine for intra-procedural taint analysis, connecting
sources, propagations, sanitizers, and sensitive sinks to report proven
vulnerability flows.
"""

from __future__ import annotations

from typing import Optional

from backend.engine.analysis.ast_analyzer import ASTAnalyzer
from backend.engine.analysis.intermediate_representation import IRModule, IRScope
from backend.engine.models.finding import Finding
from backend.engine.parser.parser_models import ParsedModule
from backend.engine.parser.python_parser import PythonParser
from backend.engine.taint.evidence_builder import EvidenceBuilder
from backend.engine.taint.propagation import TaintPropagator
from backend.engine.taint.sinks import find_matching_sink
from backend.engine.taint.taint_state import TaintState


class TaintAnalyzer:
    """Performs static taint analysis over SecurePy Intermediate Representation."""

    def __init__(self) -> None:
        self.evidence_builder = EvidenceBuilder()
        self.ast_analyzer = ASTAnalyzer()
        self.parser = PythonParser()

    def analyze(
        self, ir_mod: IRModule, parsed: Optional[ParsedModule] = None
    ) -> list[Finding]:
        """Perform taint analysis across all scopes in an IRModule.

        Args:
            ir_mod: The analyzed IRModule containing scopes, statements, and calls.
            parsed: Optional ParsedModule.

        Returns:
            List of findings backed by source-to-sink evidence chains.
        """
        findings: list[Finding] = []

        for scope_name, scope in ir_mod.scopes.items():
            scope_findings = self._analyze_scope(scope, ir_mod.file_path)
            findings.extend(scope_findings)

        findings.sort(key=lambda f: f.line_number)
        return findings

    def _analyze_scope(
        self, scope: IRScope, file_path: Optional[str] = None
    ) -> list[Finding]:
        """Analyze a single lexical scope for source-to-sink taint flows."""
        findings: list[Finding] = []
        state = TaintState()
        propagator = TaintPropagator(state=state)

        # 1. Sequential propagation pass
        propagator.process_scope(scope)

        # 2. Sink check pass
        for stmt in scope.statements:
            if not stmt.call:
                continue

            call = stmt.call
            sink = find_matching_sink(call.caller)
            if not sink:
                continue

            # Special case for subprocess: If no shell=True, list arguments are safe from shell injection!
            if "subprocess." in call.caller:
                has_shell_true = any(kw.name == "shell" and kw.value_repr == "True" for kw in call.kwargs)
                if not has_shell_true:
                    continue

            # Check sensitive arguments
            for arg_idx in sink.sensitive_arg_indices:
                if arg_idx >= len(call.args):
                    continue

                arg = call.args[arg_idx]
                tainted_var_found: Optional[str] = None

                # Direct variable argument: os.system(x)
                if arg.value_type == "Name":
                    var_name = arg.value_repr
                    if state.is_tainted(var_name, sink.category):
                        tainted_var_found = var_name

                # Binary expression or composite string: os.system("ping " + x)
                else:
                    # Check any variable referenced inside the argument expression with word boundaries
                    import re
                    for var_candidate in state.tainted_vars.keys():
                        if re.search(r"\b" + re.escape(var_candidate) + r"\b", arg.value_repr):
                            if state.is_tainted(var_candidate, sink.category):
                                tainted_var_found = var_candidate
                                break

                if tainted_var_found:
                    tag = state.get_tag(tainted_var_found)
                    chain = state.get_chain(tainted_var_found)
                    if tag:
                        finding = self.evidence_builder.build_finding(
                            sink=sink,
                            call=call,
                            tainted_arg_name=tainted_var_found,
                            tag=tag,
                            chain=chain,
                            file_path=file_path,
                        )
                        findings.append(finding)

        return findings

    def analyze_code(
        self, source_code: str, file_path: Optional[str] = None
    ) -> list[Finding]:
        """Convenience method to analyze raw Python source code."""
        parsed = self.parser.parse_code(source_code, file_path=file_path)
        if not parsed.is_valid:
            return []
        ir_mod = self.ast_analyzer.analyze_parsed_module(parsed)
        return self.analyze(ir_mod, parsed=parsed)
