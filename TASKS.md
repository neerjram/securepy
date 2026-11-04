# TASKS.md — SecurePy Project Roadmap & Phase Tracker

| Phase | Description | Status | Verification Criteria |
|---|---|---|---|
| **Phase 0** | Requirements, Architecture & Setup | ✅ Completed | Backend health API passes; React frontend connects; pytest & vitest configured; Git initialized. |
| **Phase 1** | Python AST Parser | ✅ Completed | `ast.parse()` non-executing wrapper, AST visitors, call/assignment/import extraction, syntax error recovery, comprehensive tests (12/12 passing). |
| **Phase 2** | Intermediate Representation & Scopes | ✅ Completed | Hierarchical symbol tables, lexical scope isolation, variable reassignment tracking, alias maps & propagation (19/19 tests passing). |
| **Phase 3** | Security Rule Engine | ✅ Completed | Modular base rule interface, registry, 5 core detection rules (Credentials, eval/exec, Command Injection, SQLi, Deserialization), 32/32 tests passing. |
| **Phase 4** | Taint Analysis Engine | ✅ Completed | Intra-procedural source-sink tracking, sequential propagation, context-aware sanitizers, complete evidence builder with React Flow steps (42/42 tests passing). |
| **Phase 5** | Aggregation, Scoring & Remediation | ✅ Completed | FindingAggregator, decoupled Scorer (risk score 0-100), beginner/developer explanations, mitigation code snippets (46/46 tests passing). |
| **Phase 6** | FastAPI Backend & SQLite | ✅ Completed | REST endpoints for scans, uploads (.py and .zip), findings, reports, status lifecycle, SQLite persistence, and upload security defenses (51/51 tests passing). |
| **Phase 7** | React Frontend & Visualizer | ✅ Completed | Modern Dashboard, Monaco snippet editor, File/ZIP uploader, React Flow data-flow graph, dual explanations, status management (Vitest + Vite build passed). |
| **Phase 8** | Benchmarking & Evaluation | ✅ Completed | 20-program ground truth dataset, evaluation runner, confusion matrix (TP=12, FP=0, TN=8, FN=0), 100% Precision & Recall, JSON/CSV exports (53/53 tests passing). |
| **Phase 9** | Final Integration & Viva Prep | ✅ Completed | End-to-end integration test (54/54 backend tests, all frontend tests passing), full documentation suite, local demonstration walkthrough, and viva examination defense guide. |
