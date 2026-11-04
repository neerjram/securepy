"""Standardized Security Finding Models for SecurePy.

Defines unified finding representations, severity levels, confidence scores,
and remediation metadata used across rule-based and taint-based analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
from typing import Any, Optional


class Severity(str, Enum):
    """Potential security impact if exploited."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    """Strength of evidence supporting the finding."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class FindingStatus(str, Enum):
    """Lifecycle status of a finding."""

    OPEN = "OPEN"
    REVIEWED = "REVIEWED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    FIXED = "FIXED"


@dataclass(slots=True)
class Finding:
    """Represents a discrete security finding reported by SecurePy."""

    rule_id: str
    title: str
    category: str
    cwe_id: str
    severity: Severity
    confidence: Confidence
    line_number: int
    description: str
    evidence: str
    remediation: str
    file_path: Optional[str] = None
    column: int = 0
    end_line_number: Optional[int] = None
    status: FindingStatus = FindingStatus.OPEN
    flow_steps: list[dict[str, Any]] = field(default_factory=list)
    beginner_explanation: str = ""
    developer_explanation: str = ""
    mitigation_code: str = ""
    id: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.id:
            # Deterministic fingerprint hash
            raw = f"{self.rule_id}:{self.file_path or '<memory>'}:{self.line_number}:{self.evidence.strip()}"
            self.id = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category,
            "cwe_id": self.cwe_id,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "status": self.status.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column": self.column,
            "end_line_number": self.end_line_number,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "beginner_explanation": self.beginner_explanation,
            "developer_explanation": self.developer_explanation,
            "mitigation_code": self.mitigation_code,
            "flow_steps": self.flow_steps,
        }
