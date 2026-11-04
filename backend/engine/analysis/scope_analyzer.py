"""Scope Analyzer for SecurePy.

Manages lexical scope lifecycles, symbol table hierarchies, and variable
visibility resolution across Python module and function boundaries.
"""

from __future__ import annotations

import ast
from typing import Optional

from backend.engine.analysis.symbol_table import Symbol, SymbolTable
from backend.engine.parser.parser_models import SourceLocation


class ScopeAnalyzer:
    """Manages active lexical scope stack and nested symbol resolution."""

    def __init__(self) -> None:
        self.root_table = SymbolTable("<module>")
        self.current_table = self.root_table
        self.table_map: dict[str, SymbolTable] = {"<module>": self.root_table}
        self.scope_stack: list[str] = ["<module>"]

    @property
    def current_scope_name(self) -> str:
        return ".".join(self.scope_stack)

    def enter_scope(self, scope_id: str) -> SymbolTable:
        """Create and enter a new child scope under the current scope."""
        self.scope_stack.append(scope_id)
        full_name = self.current_scope_name
        new_table = SymbolTable(scope_name=full_name, parent=self.current_table)
        self.table_map[full_name] = new_table
        self.current_table = new_table
        return new_table

    def exit_scope(self) -> None:
        """Exit the current scope back to the parent scope."""
        if len(self.scope_stack) > 1:
            self.scope_stack.pop()
            parent_name = self.current_scope_name
            self.current_table = self.table_map[parent_name]

    def register_parameter(
        self, param_name: str, location: SourceLocation
    ) -> Symbol:
        """Register a function parameter in the current scope."""
        return self.current_table.define(
            name=param_name,
            value=f"<param:{param_name}>",
            location=location,
            value_type="Parameter",
        )

    def register_variable(
        self,
        name: str,
        value: str,
        location: SourceLocation,
        value_type: str = "Unknown",
        aliases: Optional[set[str]] = None,
    ) -> Symbol:
        """Define or reassign a variable symbol in the active scope."""
        return self.current_table.define(
            name=name,
            value=value,
            location=location,
            value_type=value_type,
            aliases=aliases,
        )

    def resolve_symbol(self, name: str) -> Optional[Symbol]:
        """Resolve a symbol across the current scope and its enclosing parents."""
        return self.current_table.lookup(name)

    def get_table(self, scope_name: str) -> Optional[SymbolTable]:
        """Retrieve symbol table for a specific scope name."""
        return self.table_map.get(scope_name)
