# Python AST Parser Architecture

## 1. Overview

SecurePy's parser module ([`backend/engine/parser/`](file:///c:/Users/vkram/OneDrive/Desktop/practice/backend/engine/parser/)) converts raw Python source code into a structured Abstract Syntax Tree (AST) using Python's native `ast` standard library module.

Under no circumstances is untrusted code executed, imported, or dynamically invoked.

---

## 2. Core Components

### `PythonParser`
- `parse_code(source_code: str, file_path: str = None) -> ParsedModule`:
  - Parses code safely using `ast.parse()`.
  - Traps `SyntaxError` and returns structured `ParserError` metadata (line, column, error text).
  - Handles whitespace or empty files gracefully.
- `parse_file(file_path: Path) -> ParsedModule`:
  - Safely reads disk files with UTF-8 / fallback encodings.

### `SecurePyASTVisitor` (`visitors.py`)
Subclasses `ast.NodeVisitor` to traverse syntax nodes:
- **`visit_Call`**: Extracts caller string (e.g., `os.system`, `cursor.execute`), positional arguments, keyword arguments, line numbers, and scope context.
- **`visit_Assign`**: Extracts target names (identifiers, tuple unpacking, attributes), assigned expression values, and types.
- **`visit_FunctionDef` / `visit_AsyncFunctionDef`**: Registers function signatures, parameter names (`*args`, `**kwargs`), and tracks lexical scope entry/exit.
- **`visit_Import` / `visit_ImportFrom`**: Resolves module names, imported symbols, and aliases (`import sys as system`).

---

## 3. Data Models (`parser_models.py`)

- **`SourceLocation`**: Line and column coordinates (`line`, `col`, `end_line`, `end_col`).
- **`ArgumentInfo`**: Argument value string representation, AST node type, and name (for kwargs).
- **`CallInfo`**: Invocation record linking caller name, arguments, and parent scope.
- **`AssignmentInfo`**: Variable mutation record capturing targets, values, and augmented operators.
- **`ParsedModule`**: Unified container holding all extracted syntactical entities alongside the original AST root for downstream IR construction.
