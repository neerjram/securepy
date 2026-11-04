# SecurePy System Architecture

## 1. Overview

**SecurePy** is an explainable static security analysis tool for Python source code. It combines Python's native Abstract Syntax Tree (`ast`), a modular security rule engine, and an intra-procedural taint analysis engine to detect vulnerabilities and provide source-to-sink data-flow evidence.

```
                 USER
                   |
                   v
       React Frontend (Vite + Tailwind)
                   |
                   v  REST API
         FastAPI Backend (Port 8000)
                   |
                   v
             Scan Coordinator
                   |
                   v
          SecurePy Analysis Engine (Pure Python)
          +--------+--------+
          |                 |
          v                 v
      AST Parser       Rule Engine
          |                 |
          v                 |
       AST / IR             |
          |                 |
          v                 |
      Taint Analysis        |
          |                 |
          +--------+--------+
                   |
                   v
             Finding Aggregator
                   |
                   v
           Severity / Confidence Scorer
                   |
                   v
          Explanation & Remediation Generator
                   |
                   v
             Scan Results
          +--------+--------+
          |                 |
          v                 v
       SQLite           JSON Report
```

---

## 2. Component Breakdown

### 2.1 Backend Engine (`backend/engine/`)
The security analysis engine is decoupled from the web application and operates on pure Python syntax:
- **`parser/`**: Safe parsing using Python's `ast.parse()`, extracting nodes, arguments, and line spans without executing target code.
- **`analysis/`**: Scope resolution, lexical symbol tables, and Intermediate Representation (IR) generation.
- **`rules/`**: Extensible rule engine evaluating AST patterns for common insecure idioms (SQL injection, hardcoded credentials, unsafe deserialization, `eval`/`exec`).
- **`taint/`**: Taint propagation engine tracking untrusted sources (e.g. `input()`, request payloads) to sensitive sinks (e.g. `os.system()`, `sqlite3.execute()`), recognizing context-aware sanitizers.
- **`models/`**: Unified data definitions for findings, evidence chains, and scan metadata.
- **`aggregation/`**: Result deduplication and merging of rule and taint outputs.
- **`scoring/`**: Decoupled severity (impact) and confidence (evidence strength) scoring.
- **`remediation/`**: Beginner-friendly explanations and actionable remediation steps.

### 2.2 Backend Web Service (`backend/app/`)
- Built on **FastAPI** with Pydantic v2 validation.
- Endpoints for initiating scans, querying findings, managing finding statuses (`OPEN`, `REVIEWED`, `FALSE_POSITIVE`, `FIXED`), and exporting reports.
- Safe file handling: ZIP path traversal protection, symlink rejection, and file-size/file-count limits.
- **SQLite** database for persistence.

### 2.3 Frontend Interface (`frontend/`)
- Modern Single Page Application built with **React**, **Vite**, and **Tailwind CSS**.
- **Monaco Editor** for source code viewing with affected line highlighting.
- **React Flow** for interactive visual representation of source-to-sink data-flow paths.
- Comprehensive status tracking and downloadable audit reports.

---

## 3. Security Boundary & Product Principles

1. **Zero Execution Guarantee**: User-submitted code is never imported, invoked, or executed.
2. **Explainable Findings**: Every reported vulnerability includes precise source-code locations, reasoning, and data-flow evidence.
3. **Decoupled Scoring**: Severity reflects worst-case impact; confidence reflects evidence strength.
