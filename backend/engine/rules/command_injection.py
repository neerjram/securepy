"""Security Rule: Command Injection Patterns.

Detects unsafe invocation of system shells via os.system, os.popen, or subprocess
with shell=True or dynamic string composition.
"""

from __future__ import annotations

from typing import Optional

from backend.engine.analysis.intermediate_representation import IRModule
from backend.engine.models.finding import Confidence, Finding, Severity
from backend.engine.parser.parser_models import ParsedModule
from backend.engine.rules.base_rule import BaseRule

SHELL_FUNCTIONS = {"os.system", "os.popen"}
SUBPROCESS_CALLS = {
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.run",
    "subprocess.check_output",
    "subprocess.check_call",
}


class CommandInjectionRule(BaseRule):
    """Detects dangerous shell execution patterns susceptible to command injection."""

    rule_id = "SEC-R003"
    title = "Potential OS Command Injection Pattern"
    category = "Command Injection"
    cwe_id = "CWE-78"
    default_severity = Severity.HIGH
    default_confidence = Confidence.HIGH

    def check(
        self, ir_mod: IRModule, parsed: Optional[ParsedModule] = None
    ) -> list[Finding]:
        findings: list[Finding] = []

        for call in ir_mod.all_calls:
            caller = call.caller

            if caller in SHELL_FUNCTIONS:
                arg_repr = call.args[0].value_repr if call.args else ""
                is_constant = len(call.args) > 0 and call.args[0].value_type == "Constant"

                # Check if all dynamic components are sanitized with shlex.quote
                assignments_by_target = {a.target: a for a in ir_mod.all_assignments}
                all_dynamic_sanitized = False
                if not is_constant:
                    import re
                    referenced_vars = [
                        a.target
                        for a in ir_mod.all_assignments
                        if re.search(r"\b" + re.escape(a.target) + r"\b", arg_repr)
                    ]
                    if referenced_vars and all(
                        assignments_by_target.get(v)
                        and assignments_by_target[v].call
                        and "shlex.quote" in assignments_by_target[v].call.caller
                        for v in referenced_vars
                    ):
                        all_dynamic_sanitized = True

                if all_dynamic_sanitized:
                    continue  # Sanitized via shlex.quote

                severity = Severity.LOW if is_constant else Severity.CRITICAL
                confidence = Confidence.MEDIUM if is_constant else Confidence.HIGH
                desc = (
                    f"Use of '{caller}()' executes commands through the system shell. "
                    + (
                        "Passing dynamic variables or formatted strings to the shell allows command injection."
                        if not is_constant
                        else "Consider replacing static os.system calls with subprocess.run() using argument lists."
                    )
                )

                findings.append(
                    self.create_finding(
                        line_number=call.location.line,
                        column=call.location.col,
                        end_line_number=call.location.end_line,
                        file_path=ir_mod.file_path,
                        severity=severity,
                        confidence=confidence,
                        description=desc,
                        evidence=f"{caller}({arg_repr})",
                        remediation=(
                            "Replace shell execution with 'subprocess.run([cmd, arg1, arg2], check=True)' "
                            "without 'shell=True' to prevent shell metacharacter interpretation."
                        ),
                    )
                )

            elif caller in SUBPROCESS_CALLS:
                # Check for shell=True kwarg
                shell_kw = next((kw for kw in call.kwargs if kw.name == "shell"), None)
                has_shell_true = shell_kw is not None and shell_kw.value_repr == "True"

                if has_shell_true:
                    cmd_repr = call.args[0].value_repr if call.args else "command"
                    findings.append(
                        self.create_finding(
                            line_number=call.location.line,
                            column=call.location.col,
                            end_line_number=call.location.end_line,
                            file_path=ir_mod.file_path,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=(
                                f"Call to '{caller}' specifies 'shell=True'. When shell=True is enabled, "
                                f"strings passed to the command argument are parsed by the shell, enabling command injection."
                            ),
                            evidence=f"{caller}({cmd_repr}, shell=True)",
                            remediation=(
                                "Set 'shell=False' and pass arguments as a list of strings: "
                                f"{caller}(['program', 'arg1', 'arg2'])"
                            ),
                        )
                    )

        return findings
