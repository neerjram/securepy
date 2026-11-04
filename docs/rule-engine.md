# Security Rule Engine Architecture

## 1. Overview

The SecurePy Rule Engine ([`backend/engine/rules/`](file:///c:/Users/vkram/OneDrive/Desktop/practice/backend/engine/rules/)) inspects Intermediate Representation (IR) structures and AST nodes to identify dangerous coding patterns, insecure functions, and credential leaks.

---

## 2. Rule Architecture & Registry

All security rules inherit from the abstract base class `BaseRule`:

```python
class BaseRule(ABC):
    rule_id: str
    title: str
    category: str
    cwe_id: str
    default_severity: Severity
    default_confidence: Confidence

    @abstractmethod
    def check(self, ir_mod: IRModule, parsed: Optional[ParsedModule] = None) -> list[Finding]:
        pass
```

Rules are cataloged in `RuleRegistry`, which allows adding or removing rules dynamically without modifying the engine core.

---

## 3. Initial Built-in Rules

| Rule ID | Title | CWE | Detection Heuristic |
|---|---|---|---|
| `SEC-R001` | Hardcoded Credentials | CWE-798 | Detects variables matching password/key patterns assigned string literals. Filters empty strings and placeholders (`YOUR_API_KEY`). |
| `SEC-R002` | Dangerous Evaluation | CWE-95 | Flags `eval()` and `exec()`. Evaluates literal constants as LOW severity; dynamic expressions as CRITICAL. |
| `SEC-R003` | Command Injection Pattern | CWE-78 | Flags `os.system`, `os.popen`, and `subprocess.*(shell=True)`. Recognizes safe argument lists in subprocess. |
| `SEC-R004` | SQL Injection Pattern | CWE-89 | Detects dynamic SQL query construction via `+`, f-strings, or `%` formatting passed to `cursor.execute()`. |
| `SEC-R005` | Insecure Deserialization | CWE-502 | Detects `pickle.loads()`, `_pickle`, `shelve.open()`, and `yaml.load()` without `SafeLoader`. |

---

## 4. Adding a Custom Rule

1. Subclass `BaseRule`.
2. Define metadata (`rule_id`, `cwe_id`, `category`, `default_severity`).
3. Implement `check(self, ir_mod, parsed)`.
4. Register the rule via `RuleRegistry.register(YourRule())`.
