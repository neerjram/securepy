"""Security Rule Engine for SecurePy.

Coordinates and executes registered security rules against analyzed IR modules,
aggregating findings and eliminating duplicates.
"""

from __future__ import annotations

from typing import Optional

from backend.engine.analysis.ast_analyzer import ASTAnalyzer
from backend.engine.analysis.intermediate_representation import IRModule
from backend.engine.models.finding import Finding
from backend.engine.parser.parser_models import ParsedModule
from backend.engine.parser.python_parser import PythonParser
from backend.engine.rules.registry import RuleRegistry, default_registry


class RuleEngine:
    """Executes registered security rules against analyzed source code representations."""

    def __init__(self, registry: Optional[RuleRegistry] = None) -> None:
        self.registry = registry or default_registry
        self.analyzer = ASTAnalyzer()
        self.parser = PythonParser()

    def run(
        self, ir_mod: IRModule, parsed: Optional[ParsedModule] = None
    ) -> list[Finding]:
        """Execute all active rules against an analyzed IRModule.

        Args:
            ir_mod: The analyzed intermediate representation module.
            parsed: Optional original ParsedModule if available.

        Returns:
            Deduplicated list of security findings.
        """
        all_findings: list[Finding] = []
        seen_fingerprints: set[str] = set()

        for rule in self.registry.get_all_rules():
            try:
                rule_findings = rule.check(ir_mod=ir_mod, parsed=parsed)
                for finding in rule_findings:
                    if finding.id not in seen_fingerprints:
                        seen_fingerprints.add(finding.id)
                        all_findings.append(finding)
            except Exception as exc:
                # Log or handle rule-level exceptions gracefully without failing analysis
                continue

        # Sort findings by line number
        all_findings.sort(key=lambda f: f.line_number)
        return all_findings

    def run_on_code(
        self, source_code: str, file_path: Optional[str] = None
    ) -> list[Finding]:
        """Convenience method to parse, analyze, and execute rules on raw Python source."""
        parsed = self.parser.parse_code(source_code, file_path=file_path)
        if not parsed.is_valid:
            return []
        ir_mod = self.analyzer.analyze_parsed_module(parsed)
        return self.run(ir_mod=ir_mod, parsed=parsed)
