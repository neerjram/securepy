"""Unit tests for SecurePy AST parser module."""

from pathlib import Path
import pytest
from backend.engine.parser import (
    PythonParser,
    ParsedModule,
    SourceLocation,
    CallInfo,
    AssignmentInfo,
    ImportInfo,
    FunctionDefInfo,
)


@pytest.fixture
def parser() -> PythonParser:
    return PythonParser()


def test_empty_and_whitespace_code(parser: PythonParser):
    """Empty or whitespace code should parse cleanly without error."""
    result_empty = parser.parse_code("")
    assert result_empty.is_valid is True
    assert result_empty.error is None
    assert len(result_empty.calls) == 0
    assert len(result_empty.assignments) == 0
    assert len(result_empty.imports) == 0

    result_ws = parser.parse_code("   \n\t  \n")
    assert result_ws.is_valid is True
    assert result_ws.error is None


def test_syntax_error_handling(parser: PythonParser):
    """Syntax errors must be caught gracefully with line and column metadata."""
    broken_code = "def invalid_syntax(:\n    pass\n"
    result = parser.parse_code(broken_code, file_path="broken.py")

    assert result.is_valid is False
    assert result.error is not None
    assert result.error.line == 1
    assert result.error.column is not None
    assert "expected" in result.error.message.lower() or "invalid" in result.error.message.lower()
    assert result.ast_root is None


def test_simple_source_sink_example(parser: PythonParser):
    """Test the canonical SecurePy example:
    x = input()
    os.system(x)
    """
    code = (
        "x = input()\n"
        "os.system(x)\n"
    )
    result = parser.parse_code(code)

    assert result.is_valid is True
    assert len(result.assignments) == 1
    assignment = result.assignments[0]
    assert assignment.targets == ["x"]
    assert assignment.value_repr == "input()"
    assert assignment.location.line == 1

    # Calls should include both input() and os.system(x)
    callers = [c.caller for c in result.calls]
    assert "input" in callers
    assert "os.system" in callers

    os_call = next(c for c in result.calls if c.caller == "os.system")
    assert os_call.location.line == 2
    assert len(os_call.args) == 1
    assert os_call.args[0].value_repr == "x"
    assert os_call.args[0].value_type == "Name"


def test_nested_calls_and_expressions(parser: PythonParser):
    """Verify that nested calls such as eval(input()) are both extracted."""
    code = 'eval(input("Enter expression: "))\n'
    result = parser.parse_code(code)

    assert result.is_valid is True
    assert len(result.calls) == 2

    callers = [c.caller for c in result.calls]
    assert callers == ["eval", "input"]

    eval_call = result.calls[0]
    assert eval_call.caller == "eval"
    assert len(eval_call.args) == 1
    assert "input(" in eval_call.args[0].value_repr
    assert "Enter expression: " in eval_call.args[0].value_repr


def test_imports_extraction(parser: PythonParser):
    """Verify both standard imports and from-imports with aliases."""
    code = (
        "import os\n"
        "import sys as system, math\n"
        "from subprocess import Popen as proc, PIPE\n"
        "from os import *\n"
    )
    result = parser.parse_code(code)

    assert result.is_valid is True
    # 4 import statements producing import entries
    modules = [i.module for i in result.imports]
    assert "os" in modules
    assert "sys" in modules
    assert "math" in modules
    assert "subprocess" in modules

    # Check aliases
    sys_import = next(i for i in result.imports if i.module == "sys")
    assert sys_import.aliases["sys"] == "system"

    sub_import = next(i for i in result.imports if i.module == "subprocess")
    assert sub_import.is_from_import is True
    assert sub_import.aliases["Popen"] == "proc"
    assert sub_import.aliases["PIPE"] == "PIPE"


def test_assignment_varieties(parser: PythonParser):
    """Test multiple assignment, augmented assignment, and type-annotated assignment."""
    code = (
        "a = b = 100\n"
        "x, y = 1, 2\n"
        "cmd: str = 'ls'\n"
        "cmd += ' -la'\n"
    )
    result = parser.parse_code(code)

    assert result.is_valid is True
    assert len(result.assignments) == 4

    # Multiple targets
    assert result.assignments[0].targets == ["a", "b"]
    assert result.assignments[0].value_repr == "100"

    # Tuple unpack
    assert result.assignments[1].targets == ["x", "y"]

    # Annotated assignment
    assert result.assignments[2].targets == ["cmd"]
    assert result.assignments[2].value_repr == "'ls'"
    assert result.assignments[2].is_augmented is False

    # Augmented assignment
    assert result.assignments[3].targets == ["cmd"]
    assert result.assignments[3].is_augmented is True
    assert result.assignments[3].aug_operator == "Add"


def test_functions_and_scope_tracking(parser: PythonParser):
    """Verify function parameters, sync/async functions, and hierarchical scopes."""
    code = (
        "def outer(req, *args, **kwargs):\n"
        "    res = req.get('key')\n"
        "    def inner(param):\n"
        "        return param\n"
        "    return inner(res)\n"
        "\n"
        "async def handle_async(data):\n"
        "    pass\n"
    )
    result = parser.parse_code(code)

    assert result.is_valid is True
    assert len(result.function_defs) == 3

    # outer function
    outer_fn = result.function_defs[0]
    assert outer_fn.name == "outer"
    assert outer_fn.args == ["req", "*args", "**kwargs"]
    assert outer_fn.is_async is False
    assert outer_fn.parent_scope == "<module>"

    # inner function
    inner_fn = result.function_defs[1]
    assert inner_fn.name == "inner"
    assert inner_fn.args == ["param"]
    assert inner_fn.parent_scope == "<module>.outer"

    # async function
    async_fn = result.function_defs[2]
    assert async_fn.name == "handle_async"
    assert async_fn.is_async is True

    # Verify calls inside outer have proper scope
    req_call = next(c for c in result.calls if c.caller == "req.get")
    assert req_call.parent_scope == "<module>.outer"


def test_call_keyword_arguments(parser: PythonParser):
    """Verify positional and keyword arguments are preserved with names."""
    code = "subprocess.run(['ping', host], shell=True, check=False)\n"
    result = parser.parse_code(code)

    assert result.is_valid is True
    assert len(result.calls) == 1
    call = result.calls[0]
    assert call.caller == "subprocess.run"
    assert len(call.args) == 1
    assert "['ping', host]" in call.args[0].value_repr

    assert len(call.kwargs) == 2
    kw_dict = {kw.name: kw.value_repr for kw in call.kwargs}
    assert kw_dict["shell"] == "True"
    assert kw_dict["check"] == "False"


def test_parse_file_from_disk(tmp_path: Path, parser: PythonParser):
    """Verify parse_file reads and parses an actual file on disk."""
    sample_file = tmp_path / "sample.py"
    sample_file.write_text("import sqlite3\ndb = sqlite3.connect('test.db')\n", encoding="utf-8")

    result = parser.parse_file(sample_file)
    assert result.is_valid is True
    assert result.file_path == str(sample_file)
    assert len(result.imports) == 1
    assert len(result.calls) == 1
    assert result.calls[0].caller == "sqlite3.connect"


def test_parsed_module_to_dict_serialization(parser: PythonParser):
    """Verify ParsedModule and components serialize cleanly to dict."""
    code = "x = input()\n"
    result = parser.parse_code(code)
    data = result.to_dict()

    assert data["is_valid"] is True
    assert len(data["calls"]) == 1
    assert data["calls"][0]["caller"] == "input"
    assert len(data["assignments"]) == 1
    assert data["assignments"][0]["targets"] == ["x"]
