"""Scope-aware Symbol Table for SecurePy.

Tracks variable symbols, lexical scopes (module, function, nested closures),
reassignments, and variable aliases.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from backend.engine.parser.parser_models import SourceLocation


@dataclass(slots=True)
class Symbol:
    """Represents a variable, parameter, or imported name in a lexical scope."""

    name: str
    scope_name: str
    initial_location: SourceLocation
    current_value: str = ""
    value_type: str = "Unknown"
    aliases: set[str] = field(default_factory=set)
    assignment_locations: list[SourceLocation] = field(default_factory=list)
    is_reassigned: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "scope_name": self.scope_name,
            "initial_location": self.initial_location.to_dict(),
            "current_value": self.current_value,
            "value_type": self.value_type,
            "aliases": sorted(list(self.aliases)),
            "assignment_locations": [loc.to_dict() for loc in self.assignment_locations],
            "is_reassigned": self.is_reassigned,
        }


class SymbolTable:
    """Hierarchical symbol table supporting nested lexical scopes."""

    def __init__(
        self,
        scope_name: str,
        parent: Optional[SymbolTable] = None,
    ) -> None:
        self.scope_name: str = scope_name
        self.parent: Optional[SymbolTable] = parent
        self.symbols: dict[str, Symbol] = {}
        self.children: list[SymbolTable] = []
        if parent:
            parent.children.append(self)

    def define(
        self,
        name: str,
        value: str,
        location: SourceLocation,
        value_type: str = "Unknown",
        aliases: Optional[set[str]] = None,
    ) -> Symbol:
        """Define a new symbol in the current scope or update if reassigned."""
        if name in self.symbols:
            # Variable reassignment in the same scope
            sym = self.symbols[name]
            sym.current_value = value
            sym.value_type = value_type
            sym.is_reassigned = True
            sym.assignment_locations.append(location)
            if aliases:
                sym.aliases.update(aliases)
            return sym

        sym = Symbol(
            name=name,
            scope_name=self.scope_name,
            initial_location=location,
            current_value=value,
            value_type=value_type,
            aliases=set(aliases) if aliases else set(),
            assignment_locations=[location],
            is_reassigned=False,
        )
        self.symbols[name] = sym
        return sym

    def lookup(self, name: str, current_only: bool = False) -> Optional[Symbol]:
        """Look up a symbol by name in the current scope, searching parents hierarchically."""
        if name in self.symbols:
            return self.symbols[name]
        if not current_only and self.parent is not None:
            return self.parent.lookup(name)
        return None

    def get_symbols(self) -> dict[str, Symbol]:
        """Return all symbols directly defined in this scope."""
        return self.symbols

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope_name": self.scope_name,
            "symbols": {k: v.to_dict() for k, v in self.symbols.items()},
            "children": [c.to_dict() for c in self.children],
        }
