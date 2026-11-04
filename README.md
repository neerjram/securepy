# SecurePy

> **Explainable Static Security Analysis Tool for Python**  
> AST Parsing • Modular Rule Engine • Basic Taint Analysis • FastAPI • React + Tailwind CSS

SecurePy is a static security analysis tool designed to inspect Python code for potential security vulnerabilities without executing it. SecurePy prioritizes **explainability**, providing developers and students with clear source-to-sink evidence, severity and confidence scoring, and actionable remediation guidance.

---

## Architecture Overview

```
React (Vite + Tailwind) <--> FastAPI Backend <--> SecurePy Analysis Engine (Pure Python AST + Taint)
                                       |
                                    SQLite
```

For detailed architectural diagrams and component descriptions, see [docs/architecture.md](docs/architecture.md).

---

## Repository Layout

```text
practice/
├── backend/
│   ├── app/                 # FastAPI web application & REST APIs
│   │   ├── api/             # Routes and Pydantic schemas
│   │   ├── core/            # Configuration and settings
│   │   ├── database/        # SQLite database models and sessions
│   │   ├── dependencies/    # FastAPI dependency injections
│   │   └── services/        # Scan coordinator and upload handling
│   ├── engine/              # Decoupled Security Engine
│   │   ├── parser/          # AST extraction and visitors
│   │   ├── analysis/        # Scope and Intermediate Representation
│   │   ├── rules/           # Security rule definitions
│   │   ├── taint/           # Source-to-sink taint analysis
│   │   ├── models/          # Finding schemas and evidence models
│   │   ├── aggregation/     # Deduplication and finding merging
│   │   ├── scoring/         # Severity and confidence calculation
│   │   └── remediation/     # Explanations and fix recommendations
│   ├── tests/               # Backend and engine pytest suite
│   ├── pytest.ini           # Pytest configuration
│   └── requirements.txt     # Python dependencies
│
├── frontend/                # React + Vite + Tailwind CSS Web UI
│   ├── src/                 # React components, pages, tests
│   ├── package.json         # Node dependencies
│   ├── vite.config.js       # Vite configuration with API proxying
│   └── tailwind.config.js   # Tailwind CSS configuration
│
├── benchmarks/              # Evaluation dataset and runners (Bandit, Semgrep)
├── docs/                    # Technical documentation and roadmap
├── AGENTS.md                # AI Agent guidelines and safety rules
├── TASKS.md                 # Roadmap and phase progress tracker
└── README.md
```

---

## Getting Started

### Prerequisites

- **Python**: 3.11+
- **Node.js**: v18+ (tested on Node v22)
- **Git**

---

### 1. Backend Setup

Create and activate the Python virtual environment:

```powershell
# In project root:
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install backend dependencies:
pip install -r backend/requirements.txt
```

Run the backend test suite:

```powershell
.\.venv\Scripts\pytest -c backend/pytest.ini
```

Start the FastAPI development server:

```powershell
.\.venv\Scripts\uvicorn backend.app.main:app --reload --port 8000
```

- API Base URL: `http://127.0.0.1:8000`
- Interactive Swagger Docs: `http://127.0.0.1:8000/docs`
- Health Endpoint: `http://127.0.0.1:8000/api/health`

---

### 2. Frontend Setup

In a new terminal window:

```powershell
cd frontend
npm install
```

Run frontend tests:

```powershell
npm test
```

Start the Vite development server:

```powershell
npm run dev
```

- Web UI: `http://localhost:5173`

The frontend automatically proxies `/api` calls to the FastAPI backend running on port 8000.

---

## Core Security Guarantee

SecurePy **never executes uploaded Python source code**. Analysis is performed strictly through syntax tree inspection and static taint propagation.
