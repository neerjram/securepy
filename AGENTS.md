# AGENTS.md — AI Agent Operating Guidelines for SecurePy

This file documents the mandatory operational principles, safety constraints, and conventions for AI coding agents working on **SecurePy**.

---

## 1. Core Operating Principles

1. **Static Analysis Only — Never Execute Analyzed Code**
   - SecurePy inspects Python source code strictly through AST parsing, lexical analysis, and symbol tracking.
   - Under no circumstances should untrusted user code be executed (no `eval`, `exec`, `subprocess`, `importlib` or dynamic invocation of target code).

2. **Engine Independence**
   - The security analysis engine (`backend/engine/`) MUST remain completely independent of the FastAPI web layer and React frontend.
   - The engine must be executable as a standalone Python library and testable directly via pytest.

3. **Incremental Phase-by-Phase Implementation**
   - Never skip phases or implement features ahead of approval.
   - Before implementing any phase or major component, propose the design, verify requirements, implement cleanly, and run all unit tests.
   - Ask for confirmation before moving between phases.

4. **Preserve Documentation & Code Integrity**
   - Do not delete existing tests or weaken test assertions to force passing suites.
   - Maintain docstrings and comments.
   - Keep `TASKS.md` updated as phases advance.

---

## 2. Coding Standards & Conventions

### Python (Backend & Engine)
- Python 3.11+ compatibility.
- Type hints on all functions and methods.
- Modular separation:
  - `engine/parser/`: AST parsing and syntax extraction
  - `engine/analysis/`: Intermediate representation and lexical scopes
  - `engine/rules/`: Security rule definitions and rule engine
  - `engine/taint/`: Source-to-sink taint analysis
  - `engine/models/`: Standardized finding and IR schemas
  - `engine/aggregation/`: Deduplication and result consolidation
  - `engine/scoring/`: Separate severity vs. confidence scoring
  - `engine/remediation/`: Explainable recommendations and fix guidance
- Fast, clean pytest test suite for every module.

### Frontend (React + Vite)
- Functional React components with hooks.
- Tailwind CSS for responsive, modern dark-themed styling.
- Vitest + React Testing Library for frontend component testing.
- Accessible UI patterns with clear loading and error states.

---

## 3. Communication Protocol

- Keep progress updates concise, clear, and actionable.
- Link relevant files with Markdown links.
- Clearly differentiate findings supported by evidence from heuristic pattern warnings.
