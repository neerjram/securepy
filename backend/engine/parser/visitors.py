"""AST Node Visitors for SecurePy.

Traverses Python Abstract Syntax Trees without executing code and extracts:
- Imports (standard and from-imports with aliases)
- Function calls and their arguments
- Variable assignments (simple, multiple, annotated, and augmented)
- Function definitions and lexical scopes
- Precise source locations
"""

from __future__ import annotations

import ast
from typing import Any

from backend.engine.parser.parser_models import (
    ArgumentInfo,
    AssignmentInfo,
    CallInfo,
    FunctionDefInfo,
    ImportInfo,
    SourceLocation,
)


class SecurePyASTVisitor(ast.NodeVisitor):
    """Custom AST visitor collecting security-relevant structural syntax."""

    def __init__(self) -> None:
        super().__init__()
        self.imports: list[ImportInfo] = []
        self.function_defs: list[FunctionDefInfo] = []
        self.calls: list[CallInfo] = []
        self.assignments: list[AssignmentInfo] = []
        self.scope_stack: list[str] = ["<module>"]

    @property
    def current_scope(self) -> str:
        """Return the current hierarchical scope name."""
        return ".".join(self.scope_stack)

    def _extract_location(self, node: ast.AST) -> SourceLocation:
        """Extract line and column coordinate spans from an AST node."""
        line = getattr(node, "lineno", 1)
        col = getattr(node, "col_offset", 0)
        end_line = getattr(node, "end_lineno", line)
        end_col = getattr(node, "end_col_offset", None)
        return SourceLocation(
            line=line,
            col=col,
            end_line=end_line,
            end_col=end_col,
        )

    def _resolve_callable_name(self, node: ast.AST) -> str:
        """Recursively resolve the full string name of a callable node.

        Examples:
            - ast.Name -> 'input'
            - ast.Attribute -> 'os.system'
            - Nested -> 'sqlite3.connect().cursor().execute'
        """
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            prefix = self._resolve_callable_name(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        elif isinstance(node, ast.Call):
            # Chained call such as db.cursor().execute
            prefix = self._resolve_callable_name(node.func)
            return f"{prefix}()"
        else:
            return ast.unparse(node)

    def _extract_target_names(self, target: ast.AST) -> list[str]:
        """Extract variable names from an assignment target.

        Supports single names, attributes, subscripting, and tuple/list unpacking.
        """
        if isinstance(target, ast.Name):
            return [target.id]
        elif isinstance(target, ast.Attribute):
            return [self._resolve_callable_name(target)]
        elif isinstance(target, (ast.Tuple, ast.List)):
            names: list[str] = []
            for elt in target.elts:
                names.extend(self._extract_target_names(elt))
            return names
        elif isinstance(target, ast.Subscript):
            return [ast.unparse(target)]
        return [ast.unparse(target)]

    def _extract_argument(
        self, arg_node: ast.AST, name: str | None = None
    ) -> ArgumentInfo:
        """Extract structured argument metadata from an expression node."""
        return ArgumentInfo(
            name=name,
            value_repr=ast.unparse(arg_node),
            value_type=type(arg_node).__name__,
            location=self._extract_location(arg_node),
        )

    def visit_Import(self, node: ast.Import) -> None:
        """Extract standard import statements like 'import os, sys as system'."""
        location = self._extract_location(node)
        for alias in node.names:
            alias_map = {alias.name: alias.asname or alias.name}
            self.imports.append(
                ImportInfo(
                    module=alias.name,
                    names=[alias.name],
                    aliases=alias_map,
                    is_from_import=False,
                    location=location,
                )
            )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Extract from-import statements like 'from subprocess import Popen as proc'."""
        location = self._extract_location(node)
        module_name = node.module or ""
        imported_names: list[str] = []
        aliases: dict[str, str] = {}

        for alias in node.names:
            imported_names.append(alias.name)
            aliases[alias.name] = alias.asname or alias.name

        self.imports.append(
            ImportInfo(
                module=module_name,
                names=imported_names,
                aliases=aliases,
                is_from_import=True,
                location=location,
            )
        )
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Extract synchronous function definitions and trace nested scopes."""
        self._handle_function_definition(node, is_async=False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Extract asynchronous function definitions and trace nested scopes."""
        self._handle_function_definition(node, is_async=True)

    def _handle_function_definition(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, is_async: bool
    ) -> None:
        """Common extraction logic for sync and async functions."""
        args: list[str] = [arg.arg for arg in node.args.args]
        if node.args.vararg:
            args.append(f"*{node.args.vararg.arg}")
        if node.args.kwarg:
            args.append(f"**{node.args.kwarg.arg}")

        self.function_defs.append(
            FunctionDefInfo(
                name=node.name,
                args=args,
                is_async=is_async,
                location=self._extract_location(node),
                parent_scope=self.current_scope,
            )
        )

        # Enter child scope
        self.scope_stack.append(node.name)
        # Traverse inner body
        for stmt in node.body:
            self.visit(stmt)
        # Exit child scope
        self.scope_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        """Extract function invocations, positional/keyword arguments, and locations."""
        caller = self._resolve_callable_name(node.func)
        args: list[ArgumentInfo] = [
            self._extract_argument(arg_node) for arg_node in node.args
        ]
        kwargs: list[ArgumentInfo] = [
            self._extract_argument(keyword.value, name=keyword.arg)
            for keyword in node.keywords
        ]

        self.calls.append(
            CallInfo(
                caller=caller,
                args=args,
                kwargs=kwargs,
                location=self._extract_location(node),
                parent_scope=self.current_scope,
            )
        )

        # Traverse nested child nodes so nested calls in args are captured
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Extract standard assignments, multiple targets, and chained assignments."""
        all_targets: list[str] = []
        for target in node.targets:
            all_targets.extend(self._extract_target_names(target))

        self.assignments.append(
            AssignmentInfo(
                targets=all_targets,
                value_repr=ast.unparse(node.value),
                value_type=type(node.value).__name__,
                location=self._extract_location(node),
                is_augmented=False,
                aug_operator=None,
                parent_scope=self.current_scope,
            )
        )

        # Continue traversing expression tree (e.g. if assigning result of Call)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Extract annotated assignments (e.g. 'x: str = input()')."""
        targets = self._extract_target_names(node.target)
        val_repr = ast.unparse(node.value) if node.value is not None else ""
        val_type = type(node.value).__name__ if node.value is not None else "None"

        self.assignments.append(
            AssignmentInfo(
                targets=targets,
                value_repr=val_repr,
                value_type=val_type,
                location=self._extract_location(node),
                is_augmented=False,
                aug_operator=None,
                parent_scope=self.current_scope,
            )
        )

        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        """Extract augmented assignments (e.g. 'cmd += input()')."""
        targets = self._extract_target_names(node.target)
        val_repr = ast.unparse(node.value)
        val_type = type(node.value).__name__

        op_name = type(node.op).__name__

        self.assignments.append(
            AssignmentInfo(
                targets=targets,
                value_repr=val_repr,
                value_type=val_type,
                location=self._extract_location(node),
                is_augmented=True,
                aug_operator=op_name,
                parent_scope=self.current_scope,
            )
        )

        self.generic_visit(node)
