"""Security Rule: Insecure Deserialization Detection.

Detects unsafe deserialization of untrusted data using pickle, _pickle,
shelve, or unsafe PyYAML loaders.
"""

from __future__ import annotations

from typing import Optional

from backend.engine.analysis.intermediate_representation import IRModule
from backend.engine.models.finding import Confidence, Finding, Severity
from backend.engine.parser.parser_models import ParsedModule
from backend.engine.rules.base_rule import BaseRule

UNSAFE_DESERIALIZERS = {
    "pickle.loads",
    "pickle.load",
    "_pickle.loads",
    "_pickle.load",
    "shelve.open",
}


class InsecureDeserializationRule(BaseRule):
    """Detects unsafe serialization and object reconstruction operations."""

    rule_id = "SEC-R005"
    title = "Insecure Object Deserialization"
    category = "Insecure Deserialization"
    cwe_id = "CWE-502"
    default_severity = Severity.HIGH
    default_confidence = Confidence.HIGH

    def check(
        self, ir_mod: IRModule, parsed: Optional[ParsedModule] = None
    ) -> list[Finding]:
        findings: list[Finding] = []

        for call in ir_mod.all_calls:
            caller = call.caller

            # 1. Check pickle and shelve functions
            if caller in UNSAFE_DESERIALIZERS:
                arg_repr = call.args[0].value_repr if call.args else ""
                findings.append(
                    self.create_finding(
                        line_number=call.location.line,
                        column=call.location.col,
                        end_line_number=call.location.end_line,
                        file_path=ir_mod.file_path,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=(
                            f"Invocation of '{caller}()' allows arbitrary object deserialization. "
                            f"The pickle protocol can execute arbitrary code during object reconstruction via __reduce__."
                        ),
                        evidence=f"{caller}({arg_repr})",
                        remediation=(
                            "Never unpickle untrusted data. Use safer data serialization formats "
                            "such as JSON (json.loads()), Protocol Buffers, or cryptographically sign serialized payloads."
                        ),
                    )
                )

            # 2. Check unsafe yaml.load
            elif caller == "yaml.load":
                # Check Loader argument
                loader_kw = next((kw for kw in call.kwargs if kw.name == "Loader"), None)
                is_safe_loader = (
                    loader_kw is not None and "SafeLoader" in loader_kw.value_repr
                )

                if not is_safe_loader:
                    findings.append(
                        self.create_finding(
                            line_number=call.location.line,
                            column=call.location.col,
                            end_line_number=call.location.end_line,
                            file_path=ir_mod.file_path,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=(
                                "Call to 'yaml.load()' without SafeLoader allows execution of arbitrary Python code "
                                "embedded in YAML tags (e.g. !!python/object/apply)."
                            ),
                            evidence=f"yaml.load(...)",
                            remediation=(
                                "Use 'yaml.safe_load(data)' or specify 'Loader=yaml.SafeLoader'."
                            ),
                        )
                    )

        return findings
