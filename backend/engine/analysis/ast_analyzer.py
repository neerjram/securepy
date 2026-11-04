"""AST Analyzer and IR Generator for SecurePy.

Transforms ParsedModule AST representations into structured Intermediate
Representation (IR) modules with scope hierarchies, symbol bindings,
call linkages, and alias tracking.
"""

from __future__ import annotations

import ast
from typing import Optional

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
from backend.engine.parser.parser_models import (
    ArgumentInfo,
    ParsedModule,
    SourceLocation,
)
from backend.engine.parser.python_parser import PythonParser


class ASTAnalyzer:
    """Translates Python AST structures into normalized SecurePy IR."""

    def __init__(self) -> None:
        self.parser = PythonParser()

    def analyze_code(
        self, source_code: str, file_path: Optional[str] = None
    ) -> IRModule:
        """Parse source code string and generate its IR module."""
        parsed = self.parser.parse_code(source_code, file_path=file_path)
        return self.analyze_parsed_module(parsed)

    def analyze_parsed_module(self, parsed: ParsedModule) -> IRModule:
        """Generate IR module from an existing ParsedModule without reparsing."""
        ir_mod = IRModule(file_path=parsed.file_path)
        if not parsed.is_valid or parsed.ast_root is None:
            return ir_mod

        scope_analyzer = ScopeAnalyzer()

        # Initialize global scope
        root_scope_name = "<module>"
        ir_mod.scopes[root_scope_name] = IRScope(
            name=root_scope_name,
            parent_name=None,
            symbol_table=scope_analyzer.root_table,
        )

        self._process_body(
            statements=parsed.ast_root.body,  # type: ignore[attr-defined]
            ir_mod=ir_mod,
            scope_analyzer=scope_analyzer,
        )

        return ir_mod

    def _extract_location(self, node: ast.AST) -> SourceLocation:
        """Extract line and column coordinates from an AST node."""
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
        """Resolve full caller string from an AST expression."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            prefix = self._resolve_callable_name(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        elif isinstance(node, ast.Call):
            prefix = self._resolve_callable_name(node.func)
            return f"{prefix}()"
        return ast.unparse(node)

    def _extract_referenced_variables(self, expr_node: ast.AST) -> list[str]:
        """Extract all loaded variable identifiers from an expression node."""
        names: list[str] = []
        for sub in ast.walk(expr_node):
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
                names.append(sub.id)
        # Deduplicate while preserving order
        return list(dict.fromkeys(names))

    def _create_ir_call(
        self, call_node: ast.Call, scope_name: str, assigned_to: Optional[str] = None
    ) -> IRCall:
        """Construct an IRCall instance from an ast.Call node."""
        caller = self._resolve_callable_name(call_node.func)
        loc = self._extract_location(call_node)

        args = [
            ArgumentInfo(
                value_repr=ast.unparse(a),
                value_type=type(a).__name__,
                location=self._extract_location(a),
            )
            for a in call_node.args
        ]

        kwargs = [
            ArgumentInfo(
                name=kw.arg,
                value_repr=ast.unparse(kw.value),
                value_type=type(kw.value).__name__,
                location=self._extract_location(kw.value),
            )
            for kw in call_node.keywords
        ]

        return IRCall(
            caller=caller,
            args=args,
            kwargs=kwargs,
            location=loc,
            scope=scope_name,
            assigned_to=assigned_to,
        )

    def _process_body(
        self,
        statements: list[ast.stmt],
        ir_mod: IRModule,
        scope_analyzer: ScopeAnalyzer,
    ) -> None:
        """Process a sequence of statements inside the active scope."""
        current_scope_name = scope_analyzer.current_scope_name
        current_ir_scope = ir_mod.scopes[current_scope_name]

        for stmt in statements:
            loc = self._extract_location(stmt)

            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # 1. Register function definition in current scope
                fn_name = stmt.name
                current_ir_scope.child_scopes.append(fn_name)

                # 2. Enter child scope
                child_table = scope_analyzer.enter_scope(fn_name)
                child_scope_name = scope_analyzer.current_scope_name

                child_ir_scope = IRScope(
                    name=child_scope_name,
                    parent_name=current_scope_name,
                    symbol_table=child_table,
                )
                ir_mod.scopes[child_scope_name] = child_ir_scope

                # Register parameters in child symbol table
                for arg in stmt.args.args:
                    arg_loc = self._extract_location(arg)
                    scope_analyzer.register_parameter(arg.arg, arg_loc)

                # Process function body statements
                self._process_body(stmt.body, ir_mod, scope_analyzer)

                # Exit child scope back to parent
                scope_analyzer.exit_scope()

                # Add statement to current scope
                ir_stmt = IRStatement(
                    op_type=IROpType.FUNCTION_DEF,
                    scope=current_scope_name,
                    location=loc,
                    raw_repr=f"def {fn_name}(...)",
                )
                current_ir_scope.statements.append(ir_stmt)

            elif isinstance(stmt, ast.Assign):
                self._handle_assign(
                    stmt=stmt,
                    ir_mod=ir_mod,
                    current_ir_scope=current_ir_scope,
                    scope_analyzer=scope_analyzer,
                )

            elif isinstance(stmt, ast.AnnAssign):
                self._handle_ann_assign(
                    stmt=stmt,
                    ir_mod=ir_mod,
                    current_ir_scope=current_ir_scope,
                    scope_analyzer=scope_analyzer,
                )

            elif isinstance(stmt, ast.AugAssign):
                self._handle_aug_assign(
                    stmt=stmt,
                    ir_mod=ir_mod,
                    current_ir_scope=current_ir_scope,
                    scope_analyzer=scope_analyzer,
                )

            elif isinstance(stmt, ast.Expr):
                # Standalone expression, commonly a function call like os.system(x)
                if isinstance(stmt.value, ast.Call):
                    ir_call = self._create_ir_call(
                        call_node=stmt.value,
                        scope_name=current_scope_name,
                        assigned_to=None,
                    )
                    ir_mod.all_calls.append(ir_call)
                    stmt_ir = IRStatement(
                        op_type=IROpType.CALL,
                        scope=current_scope_name,
                        location=loc,
                        call=ir_call,
                        raw_repr=ast.unparse(stmt),
                    )
                    current_ir_scope.statements.append(stmt_ir)
                else:
                    stmt_ir = IRStatement(
                        op_type=IROpType.EXPRESSION,
                        scope=current_scope_name,
                        location=loc,
                        raw_repr=ast.unparse(stmt),
                    )
                    current_ir_scope.statements.append(stmt_ir)

            elif isinstance(stmt, ast.Return):
                call_ir = None
                if isinstance(stmt.value, ast.Call):
                    call_ir = self._create_ir_call(
                        call_node=stmt.value,
                        scope_name=current_scope_name,
                        assigned_to=None,
                    )
                    ir_mod.all_calls.append(call_ir)

                stmt_ir = IRStatement(
                    op_type=IROpType.RETURN,
                    scope=current_scope_name,
                    location=loc,
                    call=call_ir,
                    raw_repr=ast.unparse(stmt),
                )
                current_ir_scope.statements.append(stmt_ir)

    def _handle_assign(
        self,
        stmt: ast.Assign,
        ir_mod: IRModule,
        current_ir_scope: IRScope,
        scope_analyzer: ScopeAnalyzer,
    ) -> None:
        """Handle standard assignments, multiple targets, and alias resolution."""
        loc = self._extract_location(stmt)
        val_repr = ast.unparse(stmt.value)
        val_type = type(stmt.value).__name__
        referenced_vars = self._extract_referenced_variables(stmt.value)

        # Check if right-hand side is a Call (e.g. a = input())
        linked_call: Optional[IRCall] = None
        if isinstance(stmt.value, ast.Call):
            linked_call = self._create_ir_call(
                call_node=stmt.value,
                scope_name=current_ir_scope.name,
                assigned_to=None,  # Will set to target
            )
            ir_mod.all_calls.append(linked_call)

        # Extract target variable names
        targets: list[str] = []
        for t in stmt.targets:
            if isinstance(t, ast.Name):
                targets.append(t.id)
            elif isinstance(t, (ast.Tuple, ast.List)):
                for elt in t.elts:
                    if isinstance(elt, ast.Name):
                        targets.append(elt.id)
                    else:
                        targets.append(ast.unparse(elt))
            else:
                targets.append(ast.unparse(t))

        # Check for direct variable alias (e.g. b = a where 'a' is an ast.Name)
        direct_alias = stmt.value.id if isinstance(stmt.value, ast.Name) else None

        for target in targets:
            # Set assigned target in linked call if not yet set
            if linked_call and not linked_call.assigned_to:
                linked_call.assigned_to = target

            aliases: list[str] = []
            if direct_alias:
                aliases.append(direct_alias)
                # Register bidirectional or forward alias in module alias map
                ir_mod.alias_map.setdefault(target, set()).add(direct_alias)
                # Propagate any existing aliases of direct_alias to target
                if direct_alias in ir_mod.alias_map:
                    for prev_alias in ir_mod.alias_map[direct_alias]:
                        ir_mod.alias_map[target].add(prev_alias)
                        aliases.append(prev_alias)

            # Check if this target is being reassigned in the current scope
            existing_sym = scope_analyzer.current_table.lookup(
                target, current_only=True
            )
            is_reassignment = existing_sym is not None

            # Register or update symbol table
            sym = scope_analyzer.register_variable(
                name=target,
                value=val_repr,
                location=loc,
                value_type=val_type,
                aliases=set(aliases) if aliases else None,
            )

            # Create IRAssignment
            ir_assign = IRAssignment(
                target=target,
                value_repr=val_repr,
                value_type=val_type,
                location=loc,
                scope=current_ir_scope.name,
                aliases=list(set(aliases)),
                referenced_vars=referenced_vars,
                call=linked_call,
                is_reassignment=is_reassignment,
            )
            ir_mod.all_assignments.append(ir_assign)

            # Create IRVariable record in current scope
            current_ir_scope.variables[target] = IRVariable(
                name=target,
                scope=current_ir_scope.name,
                origin_expr=val_repr,
                value_type=val_type,
                location=loc,
                aliases=list(set(aliases)),
                referenced_vars=referenced_vars,
            )

            # Add statement
            ir_stmt = IRStatement(
                op_type=IROpType.ASSIGNMENT,
                scope=current_ir_scope.name,
                location=loc,
                assignment=ir_assign,
                raw_repr=f"{target} = {val_repr}",
            )
            current_ir_scope.statements.append(ir_stmt)

    def _handle_ann_assign(
        self,
        stmt: ast.AnnAssign,
        ir_mod: IRModule,
        current_ir_scope: IRScope,
        scope_analyzer: ScopeAnalyzer,
    ) -> None:
        """Handle annotated assignments (e.g. 'token: str = input()')."""
        if not isinstance(stmt.target, ast.Name):
            return

        target = stmt.target.id
        loc = self._extract_location(stmt)
        val_repr = ast.unparse(stmt.value) if stmt.value else ""
        val_type = type(stmt.value).__name__ if stmt.value else "None"
        referenced_vars = (
            self._extract_referenced_variables(stmt.value) if stmt.value else []
        )

        linked_call: Optional[IRCall] = None
        if isinstance(stmt.value, ast.Call):
            linked_call = self._create_ir_call(
                call_node=stmt.value,
                scope_name=current_ir_scope.name,
                assigned_to=target,
            )
            ir_mod.all_calls.append(linked_call)

        aliases: list[str] = []
        if isinstance(stmt.value, ast.Name):
            alias_name = stmt.value.id
            aliases.append(alias_name)
            ir_mod.alias_map.setdefault(target, set()).add(alias_name)

        existing_sym = scope_analyzer.current_table.lookup(target, current_only=True)
        is_reassign = existing_sym is not None

        scope_analyzer.register_variable(
            name=target,
            value=val_repr,
            location=loc,
            value_type=val_type,
            aliases=set(aliases) if aliases else None,
        )

        ir_assign = IRAssignment(
            target=target,
            value_repr=val_repr,
            value_type=val_type,
            location=loc,
            scope=current_ir_scope.name,
            aliases=aliases,
            referenced_vars=referenced_vars,
            call=linked_call,
            is_reassignment=is_reassign,
        )
        ir_mod.all_assignments.append(ir_assign)

        ir_stmt = IRStatement(
            op_type=IROpType.ASSIGNMENT,
            scope=current_ir_scope.name,
            location=loc,
            assignment=ir_assign,
            raw_repr=ast.unparse(stmt),
        )
        current_ir_scope.statements.append(ir_stmt)

    def _handle_aug_assign(
        self,
        stmt: ast.AugAssign,
        ir_mod: IRModule,
        current_ir_scope: IRScope,
        scope_analyzer: ScopeAnalyzer,
    ) -> None:
        """Handle augmented assignments (e.g. 'cmd += input()')."""
        if not isinstance(stmt.target, ast.Name):
            return

        target = stmt.target.id
        loc = self._extract_location(stmt)
        val_repr = ast.unparse(stmt.value)
        val_type = type(stmt.value).__name__
        op_name = type(stmt.op).__name__
        referenced_vars = self._extract_referenced_variables(stmt.value)

        linked_call: Optional[IRCall] = None
        if isinstance(stmt.value, ast.Call):
            linked_call = self._create_ir_call(
                call_node=stmt.value,
                scope_name=current_ir_scope.name,
                assigned_to=target,
            )
            ir_mod.all_calls.append(linked_call)

        scope_analyzer.register_variable(
            name=target,
            value=f"{target} {op_name} {val_repr}",
            location=loc,
            value_type=val_type,
        )

        ir_assign = IRAssignment(
            target=target,
            value_repr=val_repr,
            value_type=val_type,
            location=loc,
            scope=current_ir_scope.name,
            referenced_vars=referenced_vars,
            call=linked_call,
            is_reassignment=True,
            is_augmented=True,
            aug_operator=op_name,
        )
        ir_mod.all_assignments.append(ir_assign)

        ir_stmt = IRStatement(
            op_type=IROpType.ASSIGNMENT,
            scope=current_ir_scope.name,
            location=loc,
            assignment=ir_assign,
            raw_repr=ast.unparse(stmt),
        )
        current_ir_scope.statements.append(ir_stmt)
