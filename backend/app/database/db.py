"""SQLite Database Manager for SecurePy.

Manages persistent storage for projects, scans, and security findings.
"""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from typing import Any, Iterator, Optional

DB_PATH = Path(__file__).resolve().parent / "securepy.db"


def get_connection(db_file: Optional[Path | str] = None) -> sqlite3.Connection:
    """Create and return an initialized SQLite connection with dict rows."""
    path = str(db_file) if db_file else str(DB_PATH)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_file: Optional[Path | str] = None) -> None:
    """Initialize database tables for projects, scans, and findings."""
    conn = get_connection(db_file)
    with conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                project_id TEXT,
                target_name TEXT NOT NULL,
                target_type TEXT NOT NULL, -- 'SNIPPET', 'FILE', 'ZIP'
                file_count INTEGER DEFAULT 1,
                total_lines INTEGER DEFAULT 0,
                risk_score INTEGER DEFAULT 0,
                status TEXT NOT NULL,      -- 'COMPLETED', 'FAILED'
                created_at TEXT NOT NULL,
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                cwe_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                status TEXT NOT NULL,      -- 'OPEN', 'REVIEWED', 'FALSE_POSITIVE', 'FIXED'
                file_path TEXT,
                line_number INTEGER NOT NULL,
                column_offset INTEGER DEFAULT 0,
                end_line_number INTEGER,
                description TEXT NOT NULL,
                evidence TEXT NOT NULL,
                remediation TEXT NOT NULL,
                beginner_explanation TEXT,
                developer_explanation TEXT,
                mitigation_code TEXT,
                flow_steps_json TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
            """
        )
    conn.close()
