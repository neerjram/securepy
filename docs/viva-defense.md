# Academic Viva Defense & Examination Reference

Prepare for project presentation questions using this guide.

---

## 1. Core Architecture Questions

### Q1: Why did you build a custom static analysis engine instead of just wrapping Bandit or Semgrep?
**Answer:** Existing tools primarily focus on pattern matching rather than explainability. While Bandit can flag that `os.system()` was called, it does not explain how untrusted data reached that function. SecurePy's primary differentiator is **source-to-sink data-flow tracking**: it constructs a verifiable proof chain (`input() -> name -> cmd -> os.system()`), displays the graph in React Flow, and provides beginner-friendly remediation.

### Q2: What is the difference between an AST and an Intermediate Representation (IR)?
**Answer:** An AST reflects Python's concrete syntax grammar (e.g. grammar rules, syntax tokens). An Intermediate Representation (IR) models information specifically required for semantic security analysis: symbol lifetimes, lexical scope hierarchies, variable reassignments, and variable alias maps (`b = a`). The IR simplifies data-flow tracking without having to traverse raw syntax trees repeatedly.

### Q3: How do you guarantee that user-uploaded Python code is safe to analyze?
**Answer:** SecurePy guarantees **zero execution of analyzed code**. Source code is analyzed strictly via static AST parsing (`ast.parse()`) and symbol tracking. We never invoke `eval()`, `exec()`, `importlib`, or `subprocess` on uploaded files. In addition, uploaded ZIP archives are protected against Zip Slip path traversal and symlink attacks.

---

## 2. Analysis & Taint Questions

### Q4: Why must Severity and Confidence be kept separate?
**Answer:** 
- **Severity** measures the potential business or technical impact if a vulnerability is exploited (e.g. Command Injection is `CRITICAL` because it allows arbitrary server takeover).
- **Confidence** measures how strongly our static evidence proves the vulnerability (e.g., whether we have a complete source-to-sink trace or merely a heuristic pattern warning).
A critical issue supported only by a heuristic might have `LOW` confidence, whereas a proven taint flow has `HIGH` confidence. Conflating the two leads to alert fatigue.

### Q5: What is a context-aware sanitizer?
**Answer:** A sanitizer neutralizes untrusted data only for specific vulnerability sinks. For example, `shlex.quote()` escapes shell metacharacters, making input safe for `os.system()`, but it does *not* protect against SQL injection. Conversely, primitive type casting (`int()`, `float()`) neutralizes both command and SQL injection. SecurePy's taint engine maps sanitizers specifically to compatible sink categories.

### Q6: What are the theoretical limitations of static analysis in SecurePy?
**Answer:** By Rice's Theorem, any non-trivial semantic property of a program is undecidable. SecurePy operates intra-procedurally (within a function/module body) and does not yet track inter-procedural call returns across multi-file boundaries or evaluate complex heap object graphs.
