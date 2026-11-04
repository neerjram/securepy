# Local Demonstration Guide

Follow this sequence to present a local live demonstration of SecurePy.

---

## 1. Environment Startup

### Terminal 1: FastAPI Backend
```powershell
# From project root:
.\.venv\Scripts\uvicorn backend.app.main:app --reload --port 8000
```
- Verify API: `http://127.0.0.1:8000/docs`

### Terminal 2: React Frontend
```powershell
cd frontend
npm run dev
```
- Open browser: `http://localhost:5173`

---

## 2. Demonstration Flow

### Step 1: Health & Overview Dashboard
- Show the **Dashboard**: Highlight connected status, metrics cards, and vulnerability category overview.

### Step 2: Live Snippet Analysis (Command Injection)
- Navigate to **New Scan**.
- Click the **Command Injection** preset:
  ```python
  import os
  name = input("Enter host: ")
  cmd = "ping " + name
  os.system(cmd)
  ```
- Click **Run Security Analysis**.
- Point out the resulting **Risk Score** (25) and finding card.
- Open the **Data Flow Path** tab:
  - Demonstrate the **React Flow diagram** showing:
    - Step 1: `SOURCE` at line 3 (`input()`)
    - Step 2: `PROPAGATION` at line 4 (`cmd = "ping " + name`)
    - Step 3: `SINK` at line 5 (`os.system(cmd)`)

### Step 3: Demonstrate Dual Explanations
- Open the **Beginner Guide** tab: Explain the plain-English analogy for non-security students.
- Open the **Developer Analysis** tab: Highlight technical exploit vectors and AST evidence.
- Open the **Remediation & Fix** tab: Show the safe refactoring using `subprocess.run(["ping", name])`.

### Step 4: Demonstrate Sanitizer Neutralization
- In the New Scan editor, load the **Safe Code** preset:
  ```python
  import subprocess
  host = input("Enter host: ")
  subprocess.run(["ping", host], check=True)
  ```
- Run analysis: Show that the finding is neutralized because subprocess without shell does not invoke the command interpreter.

### Step 5: Finding Lifecycle Management
- In **Scan Results**, change the finding status dropdown from `OPEN` to `REVIEWED`.
- Refresh or view **Scan History**: The change is persisted in the local SQLite database.

### Step 6: Export JSON Audit Report
- Click **Export JSON**: Show the generated machine-readable audit report.
