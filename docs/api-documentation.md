# SecurePy REST API Documentation

The FastAPI backend runs locally by default at `http://127.0.0.1:8000`. Interactive OpenAPI documentation is accessible at `/docs` (Swagger UI) and `/redoc`.

---

## 1. Endpoints

### 1.1 Health Check
- **`GET /api/health`**
  - Response:
    ```json
    {
      "status": "healthy",
      "app_name": "SecurePy",
      "version": "0.1.0",
      "timestamp": "2026-11-03T12:00:00Z"
    }
    ```

---

### 1.2 Scan Code Snippet
- **`POST /api/scans`**
  - Request Body:
    ```json
    {
      "code": "x = input()\nos.system(x)\n",
      "target_name": "snippet.py"
    }
    ```
  - Response (HTTP 201 Created):
    ```json
    {
      "scan_id": "a1b2c3d4e5f6",
      "target_name": "snippet.py",
      "status": "COMPLETED",
      "file_count": 1,
      "total_lines": 2,
      "risk_score": 25,
      "findings_count": 1,
      "created_at": "2026-11-03T12:00:00Z"
    }
    ```

---

### 1.3 Upload & Scan Project
- **`POST /api/scans/upload`**
  - Content-Type: `multipart/form-data`
  - Form field: `file` (a `.py` file or `.zip` archive)
  - Security protections: Max 10MB archive, max 2MB file, Zip Slip path traversal defense, symlink rejection.

---

### 1.4 Scan History & Details
- **`GET /api/scans`**: Returns historical scans with risk scores and timestamps.
- **`GET /api/scans/{id}`**: Returns full scan details, summary, and findings.
- **`GET /api/scans/{id}/findings?severity=CRITICAL&status=OPEN`**: Filter findings by severity, status, or category.
- **`GET /api/scans/{id}/report`**: Download full JSON audit report.

---

### 1.5 Finding Management
- **`GET /api/findings/{id}`**: Retrieve single finding with visual data-flow steps and explanations.
- **`PATCH /api/findings/{id}`**: Update finding lifecycle status.
  - Request: `{"status": "REVIEWED"}` (Allowed: `OPEN`, `REVIEWED`, `FALSE_POSITIVE`, `FIXED`).
