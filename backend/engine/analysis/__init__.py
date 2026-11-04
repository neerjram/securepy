"""Intermediate Representation and Scope Analysis package for SecurePy."""

from backend.engine.analysis.ast_analyzer import ASTAnalyzer
from backend.engine.analysis.intermediate_representation import (
    IRAssignment,
    IRCall,
    IRModule,
    IROpType,
    IRScope,
    IRStatement,
    IRVariable,
)
from backend.engine.analysis.scope_analyzer import ScopeAnalyzer
from backend.engine.analysis.symbol_table import Symbol, SymbolTable

__all__ = [
    "ASTAnalyzer",
    "ScopeAnalyzer",
    "SymbolTable",
    "Symbol",
    "IRModule",
    "IRScope",
    "IRStatement",
    "IRAssignment",
    "IRCall",
    "IRVariable",
    "IROpType",
]
