# SecurePy Implementation Roadmap & Milestones

This document details the completed development phases, technical architecture, and verification criteria for **SecurePy**.

---

## Completed Phases

### Phase 0: Requirements, Architecture & Repository Setup
- Initialized clean Git repository with strict `.gitignore`.
- Designed decoupled module architecture: engine, web API, and frontend.
- Created virtual environment instructions and verified Python 3.13 / Node 22 toolchain.
- Configured FastAPI backend with CORS middleware and health-check endpoint.
- Configured React + Vite + Tailwind CSS frontend with initial unit testing.
- Published project guidelines and operating invariants in `AGENTS.md`.

### Phase 1: Python AST Parser
- Built non-executing AST parser based strictly on Python's native `ast` library.
- Implemented `SecurePyASTVisitor` extracting function definitions, function calls, variable assignments, and imports.
- Extracted exact coordinates (`line`, `col`, `end_line`, `end_col`) without executing target source code.
- Handled syntax errors gracefully with structured `ParserError` models.
- Verified with 10 comprehensive unit tests.

### Phase 2: Intermediate Representation & Scope Analysis
- Translated AST nodes into security-oriented `IRModule`, `IRScope`, `IRStatement`, `IRAssignment`, and `IRCall`.
- Implemented hierarchical `SymbolTable` tracking variable lifetimes and lexical scopes.
- Implemented forward and transitive variable alias mapping (`alias_map`).
- Tracked variable reassignments and compound expression references.
- Verified with 7 unit tests covering scoping, shadowing, and canonical alias flows.

### Phase 3: Security Rule Engine
- Created extensible `BaseRule` interface with declarative rule IDs, CWE mappings, default severity, and confidence.
- Implemented `RuleRegistry` for dynamic catalog management.
- Implemented 5 core vulnerability detection rules:
  - `SEC-R001` (CWE-798): Plaintext hardcoded credentials.
  - `SEC-R002` (CWE-95): Dynamic code execution via `eval()` and `exec()`.
  - `SEC-R003` (CWE-78): Command injection patterns and `shell=True`.
  - `SEC-R004` (CWE-89): Dynamic SQL query construction.
  - `SEC-R005` (CWE-502): Insecure deserialization via `pickle` and `yaml.load()`.
- Verified with 13 unit tests covering vulnerable and secure test cases.

### Phase 4: Taint Analysis Engine
- Designed intra-procedural source-to-sink data-flow tracker.
- Formalized untrusted sources (`input()`, web request parameters, environment variables).
- Formalized sensitive sinks (`os.system`, `subprocess`, `cursor.execute`, `eval`, `pickle.loads`).
- Implemented context-aware sanitizers (`shlex.quote`, primitive type coercion `int()`, `os.path.basename`).
- Implemented `EvidenceBuilder` constructing 4-stage data-flow paths for graph visualization.
- Verified with 10 unit tests covering multi-hop propagations and sanitization neutralization.

### Phase 5: Finding Aggregation, Scoring & Remediation
- Implemented `FindingAggregator` merging rule heuristics with proven taint flows to confirm `HIGH` confidence.
- Implemented decoupled `Scorer` calculating project risk score (0-100) and severity breakdowns.
- Created dual explanation generators: beginner educational guidance and developer root-cause analysis.
- Generated concrete Python mitigation code templates for every finding.
- Formalized finding lifecycle transitions (`OPEN`, `REVIEWED`, `FALSE_POSITIVE`, `FIXED`).

### Phase 6: FastAPI Backend & SQLite Database
- Implemented SQLite persistence layer (`projects`, `scans`, and `findings` tables with indexes).
- Implemented upload security: Zip Slip traversal protection, file size/count limits, and symlink rejection.
- Implemented full REST API endpoints for scans, uploads (.py and .zip), findings, reports, and status transitions.
- Verified with 5 API and upload security integration tests.

### Phase 7: React Frontend & Visualizer
- Implemented responsive dark-themed user interface with Tailwind CSS.
- Built interactive Dashboard with scan metrics and vulnerability coverage cards.
- Built New Scan page featuring Monaco Editor snippet mode with sample presets and File/ZIP uploader.
- Implemented React Flow data-flow graph visualizer rendering source-to-sink paths.
- Implemented Scan History table with search filters and one-click JSON report export.
- Verified with Vitest component tests and successful production Vite build.

### Phase 8: Benchmarking & Evaluation Framework
- Created controlled dataset of 20 benchmark programs (12 vulnerable, 8 secure).
- Defined expected ground-truth labels in `expected_results/ground_truth.json`.
- Implemented benchmark runners for SecurePy, Bandit, and Semgrep.
- Computed confusion matrix: TP=12, FP=0, TN=8, FN=0 (100% Precision, 100% Recall, 100% F1).
- Generated machine-readable JSON and CSV evaluation reports.

### Phase 9: Final Integration & Demonstration
- Created sample applications in `samples/vulnerable_app` and `samples/secure_app`.
- Verified end-to-end integration with passing test suite (54/54 tests passing).
- Authored complete technical documentation, local demonstration guide, and viva defense reference.
