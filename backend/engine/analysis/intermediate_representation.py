"""Intermediate Representation (IR) data models for SecurePy.

Provides a normalized, security-oriented representation of Python syntax trees
preserving scopes, symbol bindings, variable aliases, and data propagation links.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from backend.engine.analysis.symbol_table import SymbolTable
from backend.engine.parser.parser_models import ArgumentInfo, SourceLocation


class IROpType(str, Enum):
    """Types of operations captured in intermediate statements."""

    ASSIGNMENT = "ASSIGNMENT"
    CALL = "CALL"
    RETURN = "RETURN"
    FUNCTION_DEF = "FUNCTION_DEF"
    IMPORT = "IMPORT"
    EXPRESSION = "EXPRESSION"


@dataclass(slots=True)
class IRVariable:
    """Represents a variable occurrence in the IR."""

    name: str
    scope: str
    origin_expr: str
    value_type: str
    location: SourceLocation
    aliases: list[str] = field(default_factory=list)
    referenced_vars: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "scope": self.scope,
            "origin_expr": self.origin_expr,
            "value_type": self.value_type,
            "location": self.location.to_dict(),
            "aliases": self.aliases,
            "referenced_vars": self.referenced_vars,
        }


@dataclass(slots=True)
class IRCall:
    """Represents a function or method invocation in the IR."""

    caller: str
    args: list[ArgumentInfo]
    kwargs: list[ArgumentInfo]
    location: SourceLocation
    scope: str
    assigned_to: Optional[str] = None  # Variable receiving return value, e.g. x = input()

    def to_dict(self) -> dict[str, Any]:
        return {
            "caller": self.caller,
            "args": [arg.to_dict() for arg in self.args],
            "kwargs": [kw.to_dict() for kw in self.kwargs],
            "location": self.location.to_dict(),
            "scope": self.scope,
            "assigned_to": self.assigned_to,
        }


@dataclass(slots=True)
class IRAssignment:
    """Represents variable binding or mutation in the IR."""

    target: str
    value_repr: str
    value_type: str
    location: SourceLocation
    scope: str
    aliases: list[str] = field(default_factory=list)
    referenced_vars: list[str] = field(default_factory=list)
    call: Optional[IRCall] = None
    is_reassignment: bool = False
    is_augmented: bool = False
    aug_operator: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "value_repr": self.value_repr,
            "value_type": self.value_type,
            "location": self.location.to_dict(),
            "scope": self.scope,
            "aliases": self.aliases,
            "referenced_vars": self.referenced_vars,
            "call": self.call.to_dict() if self.call else None,
            "is_reassignment": self.is_reassignment,
            "is_augmented": self.is_augmented,
            "aug_operator": self.aug_operator,
        }


@dataclass(slots=True)
class IRStatement:
    """A single sequential instruction in an IR scope."""

    op_type: IROpType
    scope: str
    location: SourceLocation
    assignment: Optional[IRAssignment] = None
    call: Optional[IRCall] = None
    raw_repr: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "op_type": self.op_type.value,
            "scope": self.scope,
            "location": self.location.to_dict(),
            "raw_repr": self.raw_repr,
            "assignment": self.assignment.to_dict() if self.assignment else None,
            "call": self.call.to_dict() if self.call else None,
        }


@dataclass(slots=True)
class IRScope:
    """A lexical execution scope containing statements, variables, and symbol table."""

    name: str
    parent_name: Optional[str]
    statements: list[IRStatement] = field(default_factory=list)
    variables: dict[str, IRVariable] = field(default_factory=dict)
    symbol_table: SymbolTable = field(default_factory=lambda: SymbolTable("<module>"))
    child_scopes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "parent_name": self.parent_name,
            "child_scopes": self.child_scopes,
            "statements": [s.to_dict() for s in self.statements],
            "variables": {k: v.to_dict() for k, v in self.variables.items()},
            "symbol_table": self.symbol_table.to_dict(),
        }


@dataclass(slots=True)
class IRModule:
    """The root IR container representing the complete analyzed Python file."""

    file_path: Optional[str]
    scopes: dict[str, IRScope] = field(default_factory=dict)
    global_scope_name: str = "<module>"
    all_calls: list[IRCall] = field(default_factory=list)
    all_assignments: list[IRAssignment] = field(default_factory=list)
    alias_map: dict[str, set[str]] = field(default_factory=dict)

    def get_scope(self, name: str) -> Optional[IRScope]:
        return self.scopes.get(name)

    def get_aliases_for(self, var_name: str) -> set[str]:
        """Return all direct and transitive aliases for a variable."""
        visited: set[str] = set()
        to_visit: list[str] = [var_name]
        while to_visit:
            curr = to_visit.pop()
            if curr in visited:
                continue
            visited.add(curr)
            for alias in self.alias_map.get(curr, set()):
                if alias not in visited:
                    to_visit.append(alias)
        return visited

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "global_scope_name": self.global_scope_name,
            "scopes": {k: v.to_dict() for k, v in self.scopes.items()},
            "all_calls": [c.to_dict() for c in self.all_calls],
            "all_assignments": [a.to_dict() for a in self.all_assignments],
            "alias_map": {k: sorted(list(v)) for k, v in self.alias_map.items()},
        }
