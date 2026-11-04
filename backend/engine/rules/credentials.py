"""Security Rule: Hardcoded Credentials Detection.

Detects hardcoded secrets, API keys, and passwords assigned directly to
variables in Python source code.
"""

from __future__ import annotations

import re
from typing import Optional

from backend.engine.analysis.intermediate_representation import IRModule
from backend.engine.models.finding import Confidence, Finding, Severity
from backend.engine.parser.parser_models import ParsedModule
from backend.engine.rules.base_rule import BaseRule

CREDENTIAL_KEYWORD_REGEX = re.compile(
    r"(password|passwd|pwd|api_?key|secret_?key|auth_?token|access_?token|private_?key|client_?secret)",
    re.IGNORECASE,
)

PLACEHOLDER_REGEX = re.compile(
    r"^(TODO.*|YOUR_.*|PLACEHOLDER.*|CHANGEME.*|DUMMY.*|EXAMPLE.*|TEST.*|NONE|DEFAULT)$",
    re.IGNORECASE,
)


class HardcodedCredentialsRule(BaseRule):
    """Detects hardcoded passwords, tokens, and cryptographic keys in source code."""

    rule_id = "SEC-R001"
    title = "Hardcoded Credential in Source Code"
    category = "Hardcoded Credentials"
    cwe_id = "CWE-798"
    default_severity = Severity.HIGH
    default_confidence = Confidence.HIGH

    def check(
        self, ir_mod: IRModule, parsed: Optional[ParsedModule] = None
    ) -> list[Finding]:
        findings: list[Finding] = []

        for assignment in ir_mod.all_assignments:
            # Check target name against suspicious credential identifiers
            if not CREDENTIAL_KEYWORD_REGEX.search(assignment.target):
                continue

            # Must be a string constant (indicated by Constant value_type with quotes)
            val = assignment.value_repr.strip()
            if not (
                (val.startswith("'") and val.endswith("'"))
                or (val.startswith('"') and val.endswith('"'))
            ):
                continue

            # Strip outer quotes
            literal_content = val[1:-1].strip()

            # Filter out empty strings or obvious placeholders
            if len(literal_content) < 4:
                continue
            if PLACEHOLDER_REGEX.match(literal_content):
                continue

            # Mask credential in description and evidence
            masked_val = (
                literal_content[:2] + "*" * (len(literal_content) - 4) + literal_content[-2:]
                if len(literal_content) > 6
                else "****"
            )

            evidence = f"{assignment.target} = {val}"
            findings.append(
                self.create_finding(
                    line_number=assignment.location.line,
                    column=assignment.location.col,
                    end_line_number=assignment.location.end_line,
                    file_path=ir_mod.file_path,
                    description=(
                        f"Variable '{assignment.target}' appears to store a hardcoded credential or secret "
                        f"directly in plaintext source code (masked: '{masked_val}')."
                    ),
                    evidence=evidence,
                    remediation=(
                        f"Never commit credentials directly into source code. Store sensitive values in environment "
                        f"variables or a secret manager, e.g.: import os; {assignment.target} = os.getenv('{assignment.target.upper()}')."
                    ),
                )
            )

        return findings
