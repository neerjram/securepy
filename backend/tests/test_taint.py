"""Unit tests for SecurePy Taint Analysis Engine."""

import pytest
from backend.engine.models.finding import Confidence, Severity
from backend.engine.taint import (
    SinkCategory,
    SourceCategory,
    TaintAnalyzer,
    find_matching_sink,
    find_matching_source,
    is_neutralized,
)


@pytest.fixture
def analyzer() -> TaintAnalyzer:
    return TaintAnalyzer()


def test_sources_and_sinks_matching():
    """Verify built-in sources and sinks correctly identify standard targets."""
    src = find_matching_source("input")
    assert src is not None
    assert src.category == SourceCategory.USER_INPUT

    web_src = find_matching_source("request.args.get")
    assert web_src is not None
    assert web_src.category == SourceCategory.WEB_REQUEST

    snk = find_matching_sink("os.system")
    assert snk is not None
    assert snk.category == SinkCategory.COMMAND_INJECTION
    assert snk.cwe_id == "CWE-78"

    sql_snk = find_matching_sink("cursor.execute")
    assert sql_snk is not None
    assert sql_snk.category == SinkCategory.SQL_INJECTION


def test_sanitizer_effectiveness():
    """Verify sanitizers neutralize only their designated sink categories."""
    assert is_neutralized("shlex.quote", SinkCategory.COMMAND_INJECTION) is True
    assert is_neutralized("shlex.quote", SinkCategory.SQL_INJECTION) is False

    assert is_neutralized("int", SinkCategory.COMMAND_INJECTION) is True
    assert is_neutralized("int", SinkCategory.SQL_INJECTION) is True


def test_canonical_multi_hop_taint_propagation(analyzer: TaintAnalyzer):
    """Verify the canonical SecurePy example:
    x = input()
    y = x
    z = "ping " + y
    os.system(z)
    """
    code = (
        "x = input()\n"
        "y = x\n"
        "z = 'ping ' + y\n"
        "os.system(z)\n"
    )
    findings = analyzer.analyze_code(code)

    assert len(findings) == 1
    finding = findings[0]

    assert finding.cwe_id == "CWE-78"
    assert finding.severity == Severity.CRITICAL
    assert finding.confidence == Confidence.HIGH
    assert finding.line_number == 4

    # Verify flow steps for visualizer
    assert len(finding.flow_steps) == 4

    step1 = finding.flow_steps[0]
    assert step1["type"] == "SOURCE"
    assert step1["line"] == 1
    assert "input" in step1["code"]

    step2 = finding.flow_steps[1]
    assert step2["type"] == "PROPAGATION"
    assert step2["line"] == 2
    assert "y = x" in step2["code"]

    step3 = finding.flow_steps[2]
    assert step3["type"] == "PROPAGATION"
    assert step3["line"] == 3
    assert "z = 'ping ' + y" in step3["code"]

    step4 = finding.flow_steps[3]
    assert step4["type"] == "SINK"
    assert step4["line"] == 4
    assert "os.system(z)" in step4["code"]


def test_direct_source_to_sink(analyzer: TaintAnalyzer):
    """Direct source to sink without intermediate variables: eval(x)."""
    code = (
        "x = input()\n"
        "eval(x)\n"
    )
    findings = analyzer.analyze_code(code)

    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-95"
    assert findings[0].line_number == 2
    assert len(findings[0].flow_steps) == 2


def test_reassignment_clears_taint(analyzer: TaintAnalyzer):
    """Overwriting a tainted variable with a safe constant clears its taint."""
    code = (
        "cmd = input()\n"
        "cmd = 'ls -la'\n"
        "os.system(cmd)\n"
    )
    findings = analyzer.analyze_code(code)
    # Taint was cleared before os.system, so no proven taint flow should exist
    assert len(findings) == 0


def test_sanitizer_neutralizes_taint_flow(analyzer: TaintAnalyzer):
    """Using shlex.quote neutralizes command injection."""
    code = (
        "import shlex\n"
        "x = input()\n"
        "clean = shlex.quote(x)\n"
        "os.system('echo ' + clean)\n"
    )
    findings = analyzer.analyze_code(code)
    assert len(findings) == 0


def test_type_cast_sanitizer(analyzer: TaintAnalyzer):
    """Casting untrusted input to int() prevents SQL and command injection."""
    code = (
        "raw_id = input()\n"
        "clean_id = int(raw_id)\n"
        "cursor.execute('SELECT * FROM users WHERE id = ' + clean_id)\n"
    )
    findings = analyzer.analyze_code(code)
    assert len(findings) == 0


def test_unrelated_variable_no_false_positive(analyzer: TaintAnalyzer):
    """Tainted variable present in scope should not taint unrelated variables."""
    code = (
        "untrusted = input()\n"
        "safe_target = '127.0.0.1'\n"
        "os.system('ping ' + safe_target)\n"
    )
    findings = analyzer.analyze_code(code)
    assert len(findings) == 0


def test_sql_injection_taint_flow(analyzer: TaintAnalyzer):
    """Test source-to-sink flow into SQL execution."""
    code = (
        "name = input()\n"
        "query = 'SELECT * FROM users WHERE name = ' + name\n"
        "cursor.execute(query)\n"
    )
    findings = analyzer.analyze_code(code)
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-89"
    assert findings[0].line_number == 3


def test_deserialization_taint_flow(analyzer: TaintAnalyzer):
    """Test untrusted input reaching pickle.loads."""
    code = (
        "import pickle\n"
        "raw_bytes = input()\n"
        "pickle.loads(raw_bytes)\n"
    )
    findings = analyzer.analyze_code(code)
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-502"
    assert findings[0].line_number == 3
