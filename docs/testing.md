# SecurePy Testing Architecture & Suites

SecurePy employs automated testing across both backend and frontend layers to guarantee engine independence, detection accuracy, and safety constraints.

---

## 1. Backend Pytest Suite

The backend test suite is configured in `backend/pytest.ini` and tests the pure Python engine and FastAPI REST APIs.

### Test Structure

```text
backend/tests/
├── test_health.py        # Health and root service endpoints
├── test_parser.py        # AST parsing, syntax errors, visitors, and coordinates (10 tests)
├── test_ir_analysis.py   # Scope tables, shadowing, variable aliases, and reassignments (7 tests)
├── test_rules.py         # 5 core security rules, registry, and custom rule extension (13 tests)
├── test_taint.py         # Source-to-sink tracking, sanitizers, and multi-hop propagation (10 tests)
├── test_aggregation.py   # Deduplication, risk scoring, explanations, and statuses (4 tests)
├── test_api.py           # REST endpoints, file uploads, Zip Slip defenses (5 tests)
├── test_benchmarks.py    # Metric math, precision, recall, and evaluation runner (2 tests)
└── test_integration.py   # Full pipeline scan on vulnerable and secure sample projects (1 test)
```

### Running Backend Tests

```powershell
.\.venv\Scripts\pytest -c backend/pytest.ini
```

Total tests: **54 passed**.

---

## 2. Frontend Vitest Suite

Frontend testing uses **Vitest** with **React Testing Library** and **jsdom**:

```text
frontend/src/
└── App.test.jsx          # Component rendering, tab switching, and API mock integration
```

### Running Frontend Tests

```powershell
cd frontend
npm test
```

### Building for Production

```powershell
cd frontend
npm run build
```
