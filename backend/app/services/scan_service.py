"""Scan Coordination Service for SecurePy.

Coordinates multi-stage static security analysis across Python parser,
intermediate representation, security rules, taint engine, and SQLite persistence.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Optional
import uuid

from backend.engine.aggregation import FindingAggregator
from backend.engine.analysis.ast_analyzer import ASTAnalyzer
from backend.engine.models.finding import Finding
from backend.engine.parser.python_parser import PythonParser
from backend.engine.rules.rule_engine import RuleEngine
from backend.engine.scoring import Scorer
from backend.engine.taint.taint_analyzer import TaintAnalyzer


class ScanService:
    """Coordinates static security analysis workflows and persistence."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self.parser = PythonParser()
        self.analyzer = ASTAnalyzer()
        self.rule_engine = RuleEngine()
        self.taint_analyzer = TaintAnalyzer()
        self.aggregator = FindingAggregator()

    def run_scan_on_snippet(
        self,
        code: str,
        target_name: str = "snippet.py",
        project_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Execute complete static analysis scan on an in-memory code string."""
        scan_id = uuid.uuid4().hex[:12]
        now_iso = datetime.now(timezone.utc).isoformat()
        total_lines = len(code.splitlines())

        # 1. Parse AST
        parsed = self.parser.parse_code(code, file_path=target_name)

        if not parsed.is_valid:
            # Syntax error handled gracefully
            with self.conn:
                self.conn.execute(
                    """
                    INSERT INTO scans (id, project_id, target_name, target_type, file_count, total_lines, risk_score, status, created_at)
                    VALUES (?, ?, ?, 'SNIPPET', 1, ?, 0, 'FAILED', ?)
                    """,
                    (scan_id, project_id, target_name, total_lines, now_iso),
                )
            return {
                "scan_id": scan_id,
                "status": "FAILED",
                "error": parsed.error.to_dict() if parsed.error else None,
                "findings": [],
            }

        # 2. Build IR
        ir_mod = self.analyzer.analyze_parsed_module(parsed)

        # 3. Execute Rules & Taint Analysis
        rule_findings = self.rule_engine.run(ir_mod, parsed)
        taint_findings = self.taint_analyzer.analyze(ir_mod, parsed)

        # 4. Aggregate & Score
        consolidated = self.aggregator.aggregate(rule_findings, taint_findings)
        summary = Scorer.get_summary(consolidated)
        risk_score = summary["risk_score"]

        # 5. Persist to SQLite
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO scans (id, project_id, target_name, target_type, file_count, total_lines, risk_score, status, created_at)
                VALUES (?, ?, ?, 'SNIPPET', 1, ?, ?, 'COMPLETED', ?)
                """,
                (scan_id, project_id, target_name, total_lines, risk_score, now_iso),
            )

            for f in consolidated:
                finding_db_id = f"{scan_id}_{f.id}"
                flow_json = json.dumps(f.flow_steps) if f.flow_steps else None
                self.conn.execute(
                    """
                    INSERT INTO findings (
                        id, scan_id, rule_id, title, category, cwe_id, severity, confidence,
                        status, file_path, line_number, column_offset, end_line_number,
                        description, evidence, remediation, beginner_explanation,
                        developer_explanation, mitigation_code, flow_steps_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding_db_id,
                        scan_id,
                        f.rule_id,
                        f.title,
                        f.category,
                        f.cwe_id,
                        f.severity.value,
                        f.confidence.value,
                        f.status.value,
                        target_name,
                        f.line_number,
                        f.column,
                        f.end_line_number,
                        f.description,
                        f.evidence,
                        f.remediation,
                        f.beginner_explanation,
                        f.developer_explanation,
                        f.mitigation_code,
                        flow_json,
                        now_iso,
                    ),
                )

        return {
            "scan_id": scan_id,
            "target_name": target_name,
            "status": "COMPLETED",
            "file_count": 1,
            "total_lines": total_lines,
            "risk_score": risk_score,
            "findings_count": len(consolidated),
            "summary": summary,
            "created_at": now_iso,
        }

    def run_scan_on_files(
        self,
        file_paths: list[Path],
        target_name: str,
        target_type: str = "FILE",
        project_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Execute static analysis on multiple extracted Python files."""
        scan_id = uuid.uuid4().hex[:12]
        now_iso = datetime.now(timezone.utc).isoformat()
        total_lines = 0
        all_findings: list[Finding] = []

        for p in file_paths:
            try:
                code = p.read_text(encoding="utf-8", errors="replace")
                total_lines += len(code.splitlines())
                parsed = self.parser.parse_code(code, file_path=p.name)
                if not parsed.is_valid:
                    continue

                ir_mod = self.analyzer.analyze_parsed_module(parsed)
                rf = self.rule_engine.run(ir_mod, parsed)
                tf = self.taint_analyzer.analyze(ir_mod, parsed)
                consolidated = self.aggregator.aggregate(rf, tf)
                all_findings.extend(consolidated)
            except Exception:
                continue

        summary = Scorer.get_summary(all_findings)
        risk_score = summary["risk_score"]

        with self.conn:
            self.conn.execute(
                """
                INSERT INTO scans (id, project_id, target_name, target_type, file_count, total_lines, risk_score, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'COMPLETED', ?)
                """,
                (scan_id, project_id, target_name, target_type, len(file_paths), total_lines, risk_score, now_iso),
            )

            for f in all_findings:
                finding_db_id = f"{scan_id}_{f.id}"
                flow_json = json.dumps(f.flow_steps) if f.flow_steps else None
                self.conn.execute(
                    """
                    INSERT INTO findings (
                        id, scan_id, rule_id, title, category, cwe_id, severity, confidence,
                        status, file_path, line_number, column_offset, end_line_number,
                        description, evidence, remediation, beginner_explanation,
                        developer_explanation, mitigation_code, flow_steps_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding_db_id,
                        scan_id,
                        f.rule_id,
                        f.title,
                        f.category,
                        f.cwe_id,
                        f.severity.value,
                        f.confidence.value,
                        f.status.value,
                        f.file_path,
                        f.line_number,
                        f.column,
                        f.end_line_number,
                        f.description,
                        f.evidence,
                        f.remediation,
                        f.beginner_explanation,
                        f.developer_explanation,
                        f.mitigation_code,
                        flow_json,
                        now_iso,
                    ),
                )

        return {
            "scan_id": scan_id,
            "target_name": target_name,
            "target_type": target_type,
            "status": "COMPLETED",
            "file_count": len(file_paths),
            "total_lines": total_lines,
            "risk_score": risk_score,
            "findings_count": len(all_findings),
            "summary": summary,
            "created_at": now_iso,
        }
