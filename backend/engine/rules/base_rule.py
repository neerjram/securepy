"""Abstract Base Rule for SecurePy Security Rules.

Defines the interface that all security rules must implement to be executed
by the rule engine.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from backend.engine.analysis.intermediate_representation import IRModule
from backend.engine.models.finding import Confidence, Finding, Severity
from backend.engine.parser.parser_models import ParsedModule


class BaseRule(ABC):
    """Abstract base class for static security analysis rules."""

    rule_id: str
    title: str
    category: str
    cwe_id: str
    default_severity: Severity
    default_confidence: Confidence

    @abstractmethod
    def check(
        self, ir_mod: IRModule, parsed: Optional[ParsedModule] = None
    ) -> list[Finding]:
        """Inspect the IRModule and ParsedModule to identify security violations."""
        pass

    def create_finding(
        self,
        line_number: int,
        description: str,
        evidence: str,
        remediation: str,
        file_path: Optional[str] = None,
        column: int = 0,
        end_line_number: Optional[int] = None,
        severity: Optional[Severity] = None,
        confidence: Optional[Confidence] = None,
    ) -> Finding:
        """Helper to build a standardized Finding instance with rule defaults."""
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            category=self.category,
            cwe_id=self.cwe_id,
            severity=severity or self.default_severity,
            confidence=confidence or self.default_confidence,
            file_path=file_path,
            line_number=line_number,
            column=column,
            end_line_number=end_line_number,
            description=description,
            evidence=evidence,
            remediation=remediation,
        )
