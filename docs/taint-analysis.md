# Taint Analysis Engine Architecture

## 1. Overview

The Taint Analysis Engine ([`backend/engine/taint/`](file:///c:/Users/vkram/OneDrive/Desktop/practice/backend/engine/taint/)) tracks the flow of untrusted input from **Sources** through **Propagations** and **Sanitizers** to sensitive **Sinks**.

Unlike heuristic pattern matchers, SecurePy's taint analysis produces proven data-flow evidence with line-by-line propagation steps.

---

## 2. Core Concepts

```text
[ SOURCE ] -------------> [ PROPAGATION ] -------------> [ SINK ]
  input()                   y = x                         os.system(y)
                            z = "ping " + y
```

### 2.1 Sources (`sources.py`)
- CLI input: `input()`, `sys.stdin.readline()`
- Web frameworks: `request.args.get()`, `request.form.get()`, `request.json`
- Environment variables: `os.getenv()`, `os.environ[...]`

### 2.2 Sinks (`sinks.py`)
- Command Execution: `os.system()`, `subprocess.Popen(..., shell=True)`
- SQL Execution: `cursor.execute()`, `db.execute()`
- Code Execution: `eval()`, `exec()`
- Insecure Deserialization: `pickle.loads()`, `yaml.load()`

### 2.3 Sanitizers & Neutralizers (`sanitizers.py`)
Sanitizers are **context-aware**:
- `shlex.quote`: Neutralizes command injection by escaping POSIX shell metacharacters. Does *not* neutralize SQL injection.
- `int()`, `float()`, `bool()`: Numeric casting neutralizes string-based injection across command, SQL, and code execution.
- `os.path.basename`: Neutralizes directory traversal for file system operations.

### 2.4 Propagation Logic (`propagation.py`)
- Direct assignments: `y = x`
- Binary operations & formatting: `z = "ping " + y` or `f"ping {y}"`
- Constant overwrite: `x = "safe"` immediately clears taint on `x`.
- Sanitizer invocation: `clean = shlex.quote(x)` tags the target variable as neutralized.

---

## 3. Evidence Construction (`evidence_builder.py`)

When a tainted variable reaches an unneutralized sink, SecurePy reconstructs the complete chain of hops:
1. `SOURCE`: Origin call and line number.
2. `PROPAGATION`: Each intermediate assignment or expression step.
3. `SINK`: Dangerous callable invocation and coordinate span.

These steps are returned as structured JSON nodes and edges for the React Flow visualizer.
