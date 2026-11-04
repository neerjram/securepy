"""Data models for Python AST parser output.

Defines structured representations for extracted AST elements such as
source locations, imports, function calls, variable assignments, and functions.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class SourceLocation:
    """Represents a coordinate span in Python source code."""

    line: int
    col: int
    end_line: int | None = None
    end_col: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "line": self.line,
            "col": self.col,
            "end_line": self.end_line,
            "end_col": self.end_col,
        }


@dataclass(slots=True)
class ImportInfo:
    """Represents an imported module or imported symbols."""

    module: str
    names: list[str] = field(default_factory=list)
    aliases: dict[str, str] = field(default_factory=dict)
    is_from_import: bool = False
    location: SourceLocation = field(
        default_factory=lambda: SourceLocation(line=1, col=0)
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "names": self.names,
            "aliases": self.aliases,
            "is_from_import": self.is_from_import,
            "location": self.location.to_dict(),
        }


@dataclass(slots=True)
class ArgumentInfo:
    """Represents a positional or keyword argument passed to a function call."""

    value_repr: str
    value_type: str
    name: str | None = None  # None for positional arguments, string for keyword args
    location: SourceLocation = field(
        default_factory=lambda: SourceLocation(line=1, col=0)
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value_repr": self.value_repr,
            "value_type": self.value_type,
            "location": self.location.to_dict(),
        }


@dataclass(slots=True)
class CallInfo:
    """Represents a function or method invocation extracted from the AST."""

    caller: str
    args: list[ArgumentInfo] = field(default_factory=list)
    kwargs: list[ArgumentInfo] = field(default_factory=list)
    location: SourceLocation = field(
        default_factory=lambda: SourceLocation(line=1, col=0)
    )
    parent_scope: str = "<module>"

    def to_dict(self) -> dict[str, Any]:
        return {
            "caller": self.caller,
            "args": [arg.to_dict() for arg in self.args],
            "kwargs": [kw.to_dict() for kw in self.kwargs],
            "location": self.location.to_dict(),
            "parent_scope": self.parent_scope,
        }


@dataclass(slots=True)
class AssignmentInfo:
    """Represents variable assignments, multiple assignments, or augmented assignments."""

    targets: list[str]
    value_repr: str
    value_type: str
    location: SourceLocation = field(
        default_factory=lambda: SourceLocation(line=1, col=0)
    )
    is_augmented: bool = False
    aug_operator: str | None = None
    parent_scope: str = "<module>"

    def to_dict(self) -> dict[str, Any]:
        return {
            "targets": self.targets,
            "value_repr": self.value_repr,
            "value_type": self.value_type,
            "location": self.location.to_dict(),
            "is_augmented": self.is_augmented,
            "aug_operator": self.aug_operator,
            "parent_scope": self.parent_scope,
        }


@dataclass(slots=True)
class FunctionDefInfo:
    """Represents a defined function or async function in the module."""

    name: str
    args: list[str] = field(default_factory=list)
    is_async: bool = False
    location: SourceLocation = field(
        default_factory=lambda: SourceLocation(line=1, col=0)
    )
    parent_scope: str = "<module>"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "args": self.args,
            "is_async": self.is_async,
            "location": self.location.to_dict(),
            "parent_scope": self.parent_scope,
        }


@dataclass(slots=True)
class ParserError:
    """Represents a syntax error encountered when attempting to parse source code."""

    message: str
    line: int | None = None
    column: int | None = None
    text: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "message": self.message,
            "line": self.line,
            "column": self.column,
            "text": self.text,
        }


@dataclass(slots=True)
class ParsedModule:
    """Container for the complete AST extraction of a Python source file or snippet."""

    source_code: str
    file_path: str | None = None
    is_valid: bool = True
    error: ParserError | None = None
    imports: list[ImportInfo] = field(default_factory=list)
    function_defs: list[FunctionDefInfo] = field(default_factory=list)
    calls: list[CallInfo] = field(default_factory=list)
    assignments: list[AssignmentInfo] = field(default_factory=list)
    ast_root: ast.AST | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "is_valid": self.is_valid,
            "error": self.error.to_dict() if self.error else None,
            "imports": [i.to_dict() for i in self.imports],
            "function_defs": [f.to_dict() for f in self.function_defs],
            "calls": [c.to_dict() for c in self.calls],
            "assignments": [a.to_dict() for a in self.assignments],
        }
