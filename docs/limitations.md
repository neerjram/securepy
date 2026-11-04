# SecurePy Limitations & Technical Boundaries

Static analysis operates without running untrusted code and is subject to fundamental theoretical boundaries (e.g. Rice's Theorem). This document details the specific boundaries and unsupported language features of SecurePy.

---

## 1. Intra-procedural vs. Inter-procedural Scope

- **Supported**: Data flow within a function or module body, tracking local assignments, aliases, and string expressions.
- **Limitation**: Taint propagation does not currently trace across user-defined function boundaries (inter-procedural analysis). For instance:
  ```python
  def get_input():
      return input()

  x = get_input()
  os.system(x)
  ```
  The current engine models `x = get_input()` as a call return; it does not symbolically inline the function body to trace that the return value originated from `input()`.

---

## 2. Dynamic Attribute & Container Mutations

- **Supported**: Simple variable references, scalar aliases (`b = a`), and basic assignments.
- **Limitation**: Complex dictionary or object attribute mutations are tracked at the container level:
  ```python
  config = {}
  config["safe_key"] = "safe"
  config["danger_key"] = input()
  os.system(config["safe_key"])
  ```
  SecurePy does not maintain a fine-grained heap alias graph; mutating fields on a shared dictionary is treated conservatively.

---

## 3. Path Sensitivity & Control Flow

- **Supported**: Sequential statement order within scopes.
- **Limitation**: The engine does not solve SMT constraints or evaluate branch conditions (`if False:`). If a dangerous call exists inside dead or unreachable code, a pattern warning may still be emitted unless eliminated by symbolic execution.

---

## 4. Dynamic Introspection (`getattr`, `setattr`, `globals()`)

- Code utilizing dynamic attribute lookups (`getattr(os, "sys" + "tem")(cmd)`) cannot be statically resolved without symbolic execution.
