"""Security Rule: Dangerous Evaluation Functions.

Detects dynamic evaluation via eval() and exec(), which can lead to
arbitrary remote code execution if supplied with untrusted input.
"""

from __future__ import annotations

from typing import Optional

from backend.engine.analysis.intermediate_representation import IRModule
from backend.engine.models.finding import Confidence, Finding, Severity
from backend.engine.parser.parser_models import ParsedModule
from backend.engine.rules.base_rule import BaseRule

DANGEROUS_CALLS = {"eval", "exec"}


class DangerousFunctionsRule(BaseRule):
    """Detects usage of eval() and exec() for dynamic code execution."""

    rule_id = "SEC-R002"
    title = "Dangerous Dynamic Code Execution Function"
    category = "Code Execution"
    cwe_id = "CWE-95"
    default_severity = Severity.HIGH
    default_confidence = Confidence.HIGH

    def check(
        self, ir_mod: IRModule, parsed: Optional[ParsedModule] = None
    ) -> list[Finding]:
        findings: list[Finding] = []

        for call in ir_mod.all_calls:
            if call.caller not in DANGEROUS_CALLS:
                continue

            arg_repr = call.args[0].value_repr if call.args else "None"
            is_literal_const = (
                len(call.args) > 0
                and call.args[0].value_type == "Constant"
            )

            # Lower severity/confidence if evaluated on a static constant string
            severity = Severity.LOW if is_literal_const else Severity.CRITICAL
            confidence = Confidence.LOW if is_literal_const else Confidence.HIGH

            evidence = f"{call.caller}({arg_repr})"
            findings.append(
                self.create_finding(
                    line_number=call.location.line,
                    column=call.location.col,
                    end_line_number=call.location.end_line,
                    file_path=ir_mod.file_path,
                    severity=severity,
                    confidence=confidence,
                    description=(
                        f"Direct invocation of '{call.caller}()' dynamically interprets Python code at runtime. "
                        f"If untrusted data reaches this argument, an attacker can execute arbitrary system commands."
                    ),
                    evidence=evidence,
                    remediation=(
                        f"Avoid '{call.caller}()'. For evaluating mathematical expressions or literal data structures, "
                        f"use safe parsers like 'ast.literal_eval()' or dedicated domain-specific interpreters."
                    ),
                )
            )

        return findings
