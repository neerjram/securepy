"""Finding API Schemas."""

from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, Field


class FindingResponse(BaseModel):
    id: str
    scan_id: Optional[str] = None
    rule_id: str
    title: str
    category: str
    cwe_id: str
    severity: str
    confidence: str
    status: str
    file_path: Optional[str] = None
    line_number: int
    column_offset: int = 0
    end_line_number: Optional[int] = None
    description: str
    evidence: str
    remediation: str
    beginner_explanation: Optional[str] = None
    developer_explanation: Optional[str] = None
    mitigation_code: Optional[str] = None
    flow_steps: list[dict[str, Any]] = Field(default_factory=list)


class FindingStatusUpdate(BaseModel):
    status: str = Field(
        ...,
        description="New finding status: 'OPEN', 'REVIEWED', 'FALSE_POSITIVE', or 'FIXED'",
    )
