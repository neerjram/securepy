"""End-to-End Integration Tests for SecurePy."""

from pathlib import Path
import sqlite3
import pytest

from backend.app.database.db import init_db
from backend.app.services.scan_service import ScanService


@pytest.fixture
def test_db(tmp_path: Path):
    db_file = tmp_path / "integration_test.db"
    init_db(db_file)
    conn = sqlite3.connect(str(db_file))
    conn.row_factory = sqlite3.Row
    yield conn
    conn.close()


def test_full_pipeline_vulnerable_and_secure_samples(test_db: sqlite3.Connection):
    """Verify that sample vulnerable app triggers findings and sample secure app is completely clean."""
    service = ScanService(test_db)
    samples_dir = Path(__file__).resolve().parent.parent.parent / "samples"

    vuln_path = samples_dir / "vulnerable_app" / "main.py"
    secure_path = samples_dir / "secure_app" / "main.py"

    # 1. Scan Vulnerable Application
    vuln_res = service.run_scan_on_files([vuln_path], target_name="vulnerable_app", target_type="FILE")
    assert vuln_res["status"] == "COMPLETED"
    assert vuln_res["findings_count"] >= 4
    assert vuln_res["risk_score"] > 50

    # Verify findings in database
    cur = test_db.execute("SELECT * FROM findings WHERE scan_id = ?", (vuln_res["scan_id"],))
    db_findings = cur.fetchall()
    cwes = {r["cwe_id"] for r in db_findings}

    assert "CWE-78" in cwes   # Command Injection
    assert "CWE-89" in cwes   # SQL Injection
    assert "CWE-798" in cwes  # Hardcoded Credentials
    assert "CWE-95" in cwes   # Dangerous Eval

    # 2. Scan Secure Application
    secure_res = service.run_scan_on_files([secure_path], target_name="secure_app", target_type="FILE")
    assert secure_res["status"] == "COMPLETED"
    assert secure_res["findings_count"] == 0
    assert secure_res["risk_score"] == 0
