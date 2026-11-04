"""Scan API Routes for SecurePy.

Handles code snippet submissions, file uploads (.py and .zip), scan queries,
finding filters, and report generation.
"""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import tempfile
from typing import Any, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status

from backend.app.api.schemas.finding import FindingResponse
from backend.app.api.schemas.scan import (
    ScanDetailResponse,
    ScanReportResponse,
    ScanSummary,
    SnippetScanRequest,
)
from backend.app.dependencies.db import get_db
from backend.app.services.scan_service import ScanService
from backend.app.services.upload_service import UploadSecurityError, UploadService

router = APIRouter(prefix="/scans", tags=["Scans"])


def _row_to_finding(row: sqlite3.Row) -> FindingResponse:
    flow_steps = []
    if row["flow_steps_json"]:
        try:
            flow_steps = json.loads(row["flow_steps_json"])
        except Exception:
            flow_steps = []

    return FindingResponse(
        id=row["id"],
        scan_id=row["scan_id"],
        rule_id=row["rule_id"],
        title=row["title"],
        category=row["category"],
        cwe_id=row["cwe_id"],
        severity=row["severity"],
        confidence=row["confidence"],
        status=row["status"],
        file_path=row["file_path"],
        line_number=row["line_number"],
        column_offset=row["column_offset"],
        end_line_number=row["end_line_number"],
        description=row["description"],
        evidence=row["evidence"],
        remediation=row["remediation"],
        beginner_explanation=row["beginner_explanation"],
        developer_explanation=row["developer_explanation"],
        mitigation_code=row["mitigation_code"],
        flow_steps=flow_steps,
    )


@router.post("", response_model=dict[str, Any], status_code=status.HTTP_201_CREATED)
def scan_snippet(
    request: SnippetScanRequest,
    conn: sqlite3.Connection = Depends(get_db),
) -> dict[str, Any]:
    """Initiate a static security analysis on raw Python code snippet."""
    service = ScanService(conn)
    result = service.run_scan_on_snippet(
        code=request.code,
        target_name=request.target_name,
        project_id=request.project_id,
    )
    if result.get("status") == "FAILED":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=result.get("error", "Failed to parse Python code syntax."),
        )
    return result


@router.post("/upload", response_model=dict[str, Any], status_code=status.HTTP_201_CREATED)
async def upload_and_scan(
    file: UploadFile = File(...),
    conn: sqlite3.Connection = Depends(get_db),
) -> dict[str, Any]:
    """Upload and analyze a single .py file or .zip archive."""
    filename = file.filename or "unknown.py"
    file_bytes = await file.read()

    service = ScanService(conn)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            if filename.lower().endswith(".zip"):
                extracted_files = UploadService.extract_zip(file_bytes, tmp_path)
                if not extracted_files:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="No valid Python (.py) files found in archive.",
                    )
                return service.run_scan_on_files(
                    file_paths=extracted_files,
                    target_name=filename,
                    target_type="ZIP",
                )
            elif filename.lower().endswith(".py"):
                saved_file = UploadService.save_single_file(file_bytes, filename, tmp_path)
                return service.run_scan_on_files(
                    file_paths=[saved_file],
                    target_name=filename,
                    target_type="FILE",
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Unsupported file format. Please upload a .py file or a .zip archive.",
                )
        except UploadSecurityError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            )


@router.get("", response_model=list[ScanSummary])
def list_scans(
    limit: int = Query(default=50, ge=1, le=200),
    conn: sqlite3.Connection = Depends(get_db),
) -> list[ScanSummary]:
    """Retrieve historical scan runs ordered by timestamp descending."""
    cur = conn.execute(
        """
        SELECT s.id as scan_id, s.target_name, s.target_type, s.status,
               s.file_count, s.total_lines, s.risk_score, s.created_at,
               COUNT(f.id) as findings_count
        FROM scans s
        LEFT JOIN findings f ON s.id = f.scan_id
        GROUP BY s.id
        ORDER BY s.created_at DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = cur.fetchall()
    return [
        ScanSummary(
            scan_id=r["scan_id"],
            target_name=r["target_name"],
            target_type=r["target_type"],
            status=r["status"],
            file_count=r["file_count"],
            total_lines=r["total_lines"],
            risk_score=r["risk_score"],
            findings_count=r["findings_count"],
            created_at=r["created_at"],
        )
        for r in rows
    ]


@router.get("/{scan_id}", response_model=ScanDetailResponse)
def get_scan(
    scan_id: str,
    conn: sqlite3.Connection = Depends(get_db),
) -> ScanDetailResponse:
    """Retrieve details and findings summary for a specific scan."""
    cur = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    scan = cur.fetchone()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found.",
        )

    f_cur = conn.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY line_number ASC", (scan_id,))
    f_rows = f_cur.fetchall()
    findings = [_row_to_finding(r) for r in f_rows]

    # Calculate summary breakdown
    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    return ScanDetailResponse(
        scan_id=scan["id"],
        target_name=scan["target_name"],
        target_type=scan["target_type"],
        status=scan["status"],
        file_count=scan["file_count"],
        total_lines=scan["total_lines"],
        risk_score=scan["risk_score"],
        findings_count=len(findings),
        created_at=scan["created_at"],
        summary={"severity_breakdown": sev_counts},
        findings=findings,
    )


@router.get("/{scan_id}/findings", response_model=list[FindingResponse])
def get_scan_findings(
    scan_id: str,
    severity: Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    category: Optional[str] = Query(default=None),
    conn: sqlite3.Connection = Depends(get_db),
) -> list[FindingResponse]:
    """Query findings for a scan with optional filters."""
    query = "SELECT * FROM findings WHERE scan_id = ?"
    params: list[Any] = [scan_id]

    if severity:
        query += " AND severity = ?"
        params.append(severity.upper())
    if status_filter:
        query += " AND status = ?"
        params.append(status_filter.upper())
    if category:
        query += " AND category = ?"
        params.append(category)

    query += " ORDER BY line_number ASC"
    cur = conn.execute(query, tuple(params))
    return [_row_to_finding(r) for r in cur.fetchall()]


@router.get("/{scan_id}/report", response_model=ScanReportResponse)
def get_scan_report(
    scan_id: str,
    conn: sqlite3.Connection = Depends(get_db),
) -> ScanReportResponse:
    """Generate and export a comprehensive JSON audit report for a scan."""
    cur = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    scan = cur.fetchone()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

    f_cur = conn.execute("SELECT * FROM findings WHERE scan_id = ? ORDER BY line_number ASC", (scan_id,))
    findings = [_row_to_finding(r) for r in f_cur.fetchall()]

    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    return ScanReportResponse(
        scan_id=scan["id"],
        target_name=scan["target_name"],
        status=scan["status"],
        risk_score=scan["risk_score"],
        total_lines=scan["total_lines"],
        created_at=scan["created_at"],
        summary={"severity_breakdown": sev_counts, "total_findings": len(findings)},
        findings=findings,
    )
