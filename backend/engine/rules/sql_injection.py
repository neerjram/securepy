"""Security Rule: SQL Injection Detection.

Detects dynamic SQL query construction via string concatenation, f-strings,
or % formatting executed through database cursors.
"""

from __future__ import annotations

import re
from typing import Optional

from backend.engine.analysis.intermediate_representation import IRModule
from backend.engine.models.finding import Confidence, Finding, Severity
from backend.engine.parser.parser_models import ParsedModule
from backend.engine.rules.base_rule import BaseRule

SQL_EXECUTE_REGEX = re.compile(r"(\.execute|\.executemany)$")
SQL_KEYWORD_REGEX = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|FROM|WHERE)\b",
    re.IGNORECASE,
)


class SQLInjectionRule(BaseRule):
    """Detects unsafe SQL query formatting and dynamic construction."""

    rule_id = "SEC-R004"
    title = "Potential SQL Injection via Dynamic Query Construction"
    category = "SQL Injection"
    cwe_id = "CWE-89"
    default_severity = Severity.HIGH
    default_confidence = Confidence.HIGH

    def check(
        self, ir_mod: IRModule, parsed: Optional[ParsedModule] = None
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Map variable targets to their assignments for query origin resolution
        assignments_by_target = {a.target: a for a in ir_mod.all_assignments}

        for call in ir_mod.all_calls:
            if not SQL_EXECUTE_REGEX.search(call.caller) and call.caller != "execute":
                continue

            if not call.args:
                continue

            query_arg = call.args[0]
            val_repr = query_arg.value_repr
            val_type = query_arg.value_type

            is_dynamic_sql = False
            evidence = f"{call.caller}({val_repr})"

            # Direct dynamic construction in the call argument
            if val_type in ("BinOp", "JoinedStr"):
                if "+" in val_repr or "f'" in val_repr or 'f"' in val_repr or "%" in val_repr:
                    is_dynamic_sql = True
            elif ".format(" in val_repr:
                is_dynamic_sql = True

            # If query is passed as a variable (e.g. cursor.execute(query)), trace variable origin
            if not is_dynamic_sql and val_type == "Name":
                var_name = val_repr
                assign = assignments_by_target.get(var_name)
                if assign:
                    # Check if the assigned expression combined SQL keywords with dynamic components
                    has_sql = bool(SQL_KEYWORD_REGEX.search(assign.value_repr))
                    has_concat = (
                        "+" in assign.value_repr
                        or "f'" in assign.value_repr
                        or 'f"' in assign.value_repr
                        or "%" in assign.value_repr
                        or ".format(" in assign.value_repr
                    )
                    if has_sql and (has_concat or assign.referenced_vars):
                        is_dynamic_sql = True
                        evidence = f"{assign.target} = {assign.value_repr} ... {call.caller}({var_name})"

            if is_dynamic_sql:
                findings.append(
                    self.create_finding(
                        line_number=call.location.line,
                        column=call.location.col,
                        end_line_number=call.location.end_line,
                        file_path=ir_mod.file_path,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=(
                            f"Dynamic SQL query constructed using string formatting or concatenation passed to '{call.caller}()'. "
                            f"If attacker-controlled data is interpolated into the SQL string, arbitrary database commands can be executed."
                        ),
                        evidence=evidence,
                        remediation=(
                            "Use parameterized queries with placeholders instead of string formatting, e.g.: "
                            "cursor.execute('SELECT * FROM users WHERE name = ?', (username,))"
                        ),
                    )
                )

        return findings
