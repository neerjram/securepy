"""Python AST Parser for SecurePy.

Safe, non-executing AST parser that converts Python source code into
structured syntactic models for static security analysis.
"""

from __future__ import annotations

import ast
from pathlib import Path

from backend.engine.parser.parser_models import ParsedModule, ParserError
from backend.engine.parser.visitors import SecurePyASTVisitor


class PythonParser:
    """Safe static parser for Python source code using the standard AST library."""

    def parse_code(
        self, source_code: str, file_path: str | None = None
    ) -> ParsedModule:
        """Parse Python source code string into a structured ParsedModule.

        Args:
            source_code: The raw Python source code text to analyze.
            file_path: Optional identifier or filesystem path for the source.

        Returns:
            ParsedModule containing extracted AST components or syntax error details.
        """
        # Handle empty or whitespace-only code gracefully
        if not source_code or not source_code.strip():
            return ParsedModule(
                source_code=source_code,
                file_path=file_path,
                is_valid=True,
                error=None,
                imports=[],
                function_defs=[],
                calls=[],
                assignments=[],
                ast_root=ast.Module(body=[], type_ignores=[]),
            )

        try:
            # Parse syntax tree without executing untrusted code
            ast_root = ast.parse(source_code, filename=file_path or "<string>")
        except SyntaxError as exc:
            error = ParserError(
                message=exc.msg,
                line=exc.lineno,
                column=exc.offset,
                text=exc.text.strip() if exc.text else None,
            )
            return ParsedModule(
                source_code=source_code,
                file_path=file_path,
                is_valid=False,
                error=error,
                imports=[],
                function_defs=[],
                calls=[],
                assignments=[],
                ast_root=None,
            )

        # Traverse the AST with SecurePy visitor
        visitor = SecurePyASTVisitor()
        visitor.visit(ast_root)

        return ParsedModule(
            source_code=source_code,
            file_path=file_path,
            is_valid=True,
            error=None,
            imports=visitor.imports,
            function_defs=visitor.function_defs,
            calls=visitor.calls,
            assignments=visitor.assignments,
            ast_root=ast_root,
        )

    def parse_file(self, file_path: str | Path) -> ParsedModule:
        """Read a Python file from disk and parse its contents.

        Args:
            file_path: Filesystem path to the .py file.

        Returns:
            ParsedModule containing extracted AST components or error details.
        """
        path = Path(file_path)
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            # Fallback with error-replace for non-UTF8 scripts
            content = path.read_text(encoding="latin-1")
        except Exception as exc:
            return ParsedModule(
                source_code="",
                file_path=str(path),
                is_valid=False,
                error=ParserError(message=f"Failed to read file: {exc}"),
            )

        return self.parse_code(source_code=content, file_path=str(path))
