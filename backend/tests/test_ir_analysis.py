"""Unit tests for SecurePy Intermediate Representation and Scope Analysis."""

import pytest
from backend.engine.analysis import ASTAnalyzer, ScopeAnalyzer, SymbolTable
from backend.engine.analysis.intermediate_representation import IROpType


@pytest.fixture
def analyzer() -> ASTAnalyzer:
    return ASTAnalyzer()


def test_canonical_source_sink_alias_propagation(analyzer: ASTAnalyzer):
    """Verify the canonical example:
    a = input()
    b = a
    os.system(b)
    """
    code = (
        "a = input()\n"
        "b = a\n"
        "os.system(b)\n"
    )
    ir_mod = analyzer.analyze_code(code)

    assert "<module>" in ir_mod.scopes
    mod_scope = ir_mod.scopes["<module>"]

    # Check assignments
    assert len(ir_mod.all_assignments) == 2
    assign_a = ir_mod.all_assignments[0]
    assign_b = ir_mod.all_assignments[1]

    assert assign_a.target == "a"
    assert assign_a.call is not None
    assert assign_a.call.caller == "input"
    assert assign_a.call.assigned_to == "a"

    assert assign_b.target == "b"
    assert "a" in assign_b.aliases
    assert "a" in ir_mod.alias_map.get("b", set())

    # Check transitive alias resolution
    b_aliases = ir_mod.get_aliases_for("b")
    assert "a" in b_aliases
    assert "b" in b_aliases

    # Check calls
    assert len(ir_mod.all_calls) == 2  # input() and os.system(b)
    os_call = next(c for c in ir_mod.all_calls if c.caller == "os.system")
    assert len(os_call.args) == 1
    assert os_call.args[0].value_repr == "b"


def test_transitive_alias_chain(analyzer: ASTAnalyzer):
    """Test multi-hop alias chains: x -> y -> z."""
    code = (
        "x = input()\n"
        "y = x\n"
        "z = y\n"
    )
    ir_mod = analyzer.analyze_code(code)

    z_aliases = ir_mod.get_aliases_for("z")
    assert "y" in z_aliases
    assert "x" in z_aliases
    assert "z" in z_aliases


def test_scope_isolation_and_shadowing(analyzer: ASTAnalyzer):
    """Test that variables in nested function scopes shadow outer variables correctly."""
    code = (
        "x = 'global_val'\n"
        "def worker(arg1):\n"
        "    x = 'local_val'\n"
        "    return x\n"
    )
    ir_mod = analyzer.analyze_code(code)

    global_scope = ir_mod.scopes["<module>"]
    worker_scope = ir_mod.scopes["<module>.worker"]

    # Global symbol table should have x = 'global_val'
    global_sym = global_scope.symbol_table.lookup("x", current_only=True)
    assert global_sym is not None
    assert global_sym.current_value == "'global_val'"

    # Worker symbol table should have parameter arg1 and local x
    param_sym = worker_scope.symbol_table.lookup("arg1", current_only=True)
    assert param_sym is not None
    assert param_sym.value_type == "Parameter"

    local_sym = worker_scope.symbol_table.lookup("x", current_only=True)
    assert local_sym is not None
    assert local_sym.current_value == "'local_val'"

    # Outer scope is preserved
    assert global_sym.current_value == "'global_val'"


def test_variable_reassignment_tracking(analyzer: ASTAnalyzer):
    """Test tracking reassignment flag and multiple assignment locations."""
    code = (
        "cmd = 'safe_echo'\n"
        "cmd = input()\n"
    )
    ir_mod = analyzer.analyze_code(code)

    assert len(ir_mod.all_assignments) == 2
    first = ir_mod.all_assignments[0]
    second = ir_mod.all_assignments[1]

    assert first.is_reassignment is False
    assert second.is_reassignment is True

    sym = ir_mod.scopes["<module>"].symbol_table.lookup("cmd")
    assert sym is not None
    assert sym.is_reassigned is True
    assert len(sym.assignment_locations) == 2


def test_augmented_assignment(analyzer: ASTAnalyzer):
    """Test handling of augmented assignment like cmd += ' something'."""
    code = (
        "cmd = 'ping'\n"
        "cmd += ' 127.0.0.1'\n"
    )
    ir_mod = analyzer.analyze_code(code)

    assert len(ir_mod.all_assignments) == 2
    aug = ir_mod.all_assignments[1]
    assert aug.is_augmented is True
    assert aug.aug_operator == "Add"
    assert aug.is_reassignment is True


def test_referenced_variables_in_expressions(analyzer: ASTAnalyzer):
    """Verify that variables referenced within binary expressions are extracted."""
    code = (
        "host = input()\n"
        "flag = '-c 1'\n"
        "full_cmd = 'ping ' + host + ' ' + flag\n"
    )
    ir_mod = analyzer.analyze_code(code)

    full_cmd_assign = next(a for a in ir_mod.all_assignments if a.target == "full_cmd")
    assert "host" in full_cmd_assign.referenced_vars
    assert "flag" in full_cmd_assign.referenced_vars


def test_ir_module_serialization(analyzer: ASTAnalyzer):
    """Verify IRModule serializes cleanly to dict."""
    code = (
        "a = input()\n"
        "b = a\n"
        "os.system(b)\n"
    )
    ir_mod = analyzer.analyze_code(code)
    data = ir_mod.to_dict()

    assert "scopes" in data
    assert "<module>" in data["scopes"]
    assert len(data["all_assignments"]) == 2
    assert len(data["all_calls"]) == 2
    assert "b" in data["alias_map"]
    assert "a" in data["alias_map"]["b"]
