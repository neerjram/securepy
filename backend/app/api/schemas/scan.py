"""Scan API Schemas."""

from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, Field

from backend.app.api.schemas.finding import FindingResponse


class SnippetScanRequest(BaseModel):
    code: str = Field(..., description="Python source code to inspect")
    target_name: str = Field(default="snippet.py", description="Optional file name")
    project_id: Optional[str] = None


class ScanSummary(BaseModel):
    scan_id: str
    target_name: str
    target_type: str = "SNIPPET"
    status: str
    file_count: int = 1
    total_lines: int = 0
    risk_score: int = 0
    findings_count: int = 0
    created_at: str


class ScanDetailResponse(ScanSummary):
    summary: dict[str, Any] = Field(default_factory=dict)
    findings: list[FindingResponse] = Field(default_factory=list)


class ScanReportResponse(BaseModel):
    scan_id: str
    target_name: str
    status: str
    risk_score: int
    total_lines: int
    created_at: str
    summary: dict[str, Any]
    findings: list[FindingResponse]
