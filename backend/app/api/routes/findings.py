"""Findings API Routes for SecurePy.

Provides individual finding lookup and status lifecycle transitions.
"""

from __future__ import annotations

import json
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, status

from backend.app.api.schemas.finding import FindingResponse, FindingStatusUpdate
from backend.app.dependencies.db import get_db

router = APIRouter(prefix="/findings", tags=["Findings"])

VALID_STATUSES = {"OPEN", "REVIEWED", "FALSE_POSITIVE", "FIXED"}


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


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(
    finding_id: str,
    conn: sqlite3.Connection = Depends(get_db),
) -> FindingResponse:
    """Retrieve full finding details including visual flow steps and explanations."""
    cur = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found.",
        )
    return _row_to_finding(row)


@router.patch("/{finding_id}", response_model=FindingResponse)
def update_finding_status(
    finding_id: str,
    update: FindingStatusUpdate,
    conn: sqlite3.Connection = Depends(get_db),
) -> FindingResponse:
    """Update the lifecycle status of a finding (OPEN, REVIEWED, FALSE_POSITIVE, FIXED)."""
    new_status = update.status.upper()
    if new_status not in VALID_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status '{update.status}'. Allowed values: {sorted(list(VALID_STATUSES))}",
        )

    with conn:
        cur = conn.execute(
            "UPDATE findings SET status = ? WHERE id = ?",
            (new_status, finding_id),
        )
        if cur.rowcount == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Finding '{finding_id}' not found.",
            )

    return get_finding(finding_id, conn)
