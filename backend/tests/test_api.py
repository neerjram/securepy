"""Integration tests for SecurePy FastAPI REST API and SQLite persistence."""

import io
from pathlib import Path
import zipfile
import pytest
from fastapi.testclient import TestClient

from backend.app.database.db import init_db
from backend.app.main import app


@pytest.fixture(scope="module", autouse=True)
def setup_test_db(tmp_path_factory):
    """Initialize a dedicated SQLite database for testing."""
    test_db = tmp_path_factory.mktemp("data") / "test_securepy.db"
    init_db(test_db)


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_scan_snippet_and_lifecycle(client: TestClient):
    """Test full workflow: create scan from snippet, list scans, query detail, and update status."""
    code = (
        "import os\n"
        "x = input()\n"
        "y = x\n"
        "os.system(y)\n"
    )

    # 1. POST /api/scans
    post_res = client.post("/api/scans", json={"code": code, "target_name": "test_script.py"})
    assert post_res.status_code == 201
    scan_data = post_res.json()

    assert "scan_id" in scan_data
    scan_id = scan_data["scan_id"]
    assert scan_data["status"] == "COMPLETED"
    assert scan_data["findings_count"] >= 1
    assert scan_data["risk_score"] > 0

    # 2. GET /api/scans
    list_res = client.get("/api/scans")
    assert list_res.status_code == 200
    scans_list = list_res.json()
    assert any(s["scan_id"] == scan_id for s in scans_list)

    # 3. GET /api/scans/{id}
    detail_res = client.get(f"/api/scans/{scan_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["scan_id"] == scan_id
    assert len(detail["findings"]) >= 1

    first_finding = detail["findings"][0]
    finding_id = first_finding["id"]
    assert first_finding["cwe_id"] == "CWE-78"
    assert len(first_finding["flow_steps"]) > 0

    # 4. GET /api/scans/{id}/findings with severity filter
    filtered_res = client.get(f"/api/scans/{scan_id}/findings?severity=CRITICAL")
    assert filtered_res.status_code == 200
    assert len(filtered_res.json()) >= 1

    # 5. GET /api/findings/{id}
    f_res = client.get(f"/api/findings/{finding_id}")
    assert f_res.status_code == 200
    f_data = f_res.json()
    assert f_data["status"] == "OPEN"
    assert f_data["beginner_explanation"] is not None
    assert f_data["mitigation_code"] is not None

    # 6. PATCH /api/findings/{id}
    patch_res = client.patch(f"/api/findings/{finding_id}", json={"status": "REVIEWED"})
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "REVIEWED"

    # 7. GET /api/scans/{id}/report
    report_res = client.get(f"/api/scans/{scan_id}/report")
    assert report_res.status_code == 200
    report = report_res.json()
    assert report["scan_id"] == scan_id
    assert "summary" in report


def test_upload_single_py_file(client: TestClient):
    """Test uploading a single .py file."""
    code = b"import os\nx = input()\nos.system(x)\n"
    files = {"file": ("vulnerable.py", io.BytesIO(code), "text/x-python")}
    res = client.post("/api/scans/upload", files=files)

    assert res.status_code == 201
    data = res.json()
    assert data["target_name"] == "vulnerable.py"
    assert data["target_type"] == "FILE"
    assert data["findings_count"] >= 1


def test_upload_zip_archive(client: TestClient):
    """Test uploading a zip archive containing python files."""
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("app/main.py", "import os\ncmd = input()\nos.system(cmd)\n")
        zf.writestr("app/utils.py", "def add(a, b):\n    return a + b\n")

    zip_bytes = zip_buffer.getvalue()
    files = {"file": ("project.zip", io.BytesIO(zip_bytes), "application/zip")}
    res = client.post("/api/scans/upload", files=files)

    assert res.status_code == 201
    data = res.json()
    assert data["target_type"] == "ZIP"
    assert data["file_count"] == 2
    assert data["findings_count"] >= 1


def test_upload_security_zip_slip_rejected(client: TestClient):
    """Zip slip path traversal attack should be blocked with HTTP 400."""
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        # Malicious traversal path
        zf.writestr("../../../evil.py", "import os; os.system('pwn')")

    files = {"file": ("malicious.zip", io.BytesIO(zip_buffer.getvalue()), "application/zip")}
    res = client.post("/api/scans/upload", files=files)

    assert res.status_code == 400
    assert "Path traversal" in res.json()["detail"]


def test_upload_security_unsupported_extension(client: TestClient):
    """Uploading executable or unsupported files should be rejected."""
    files = {"file": ("malware.exe", io.BytesIO(b"binary data"), "application/octet-stream")}
    res = client.post("/api/scans/upload", files=files)

    assert res.status_code == 400
    assert "Unsupported file format" in res.json()["detail"]
