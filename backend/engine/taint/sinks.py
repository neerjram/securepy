"""Taint Sinks Definitions for SecurePy.

Defines security-sensitive functions and methods where untrusted tainted data
can trigger vulnerabilities.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Optional

from backend.engine.models.finding import Severity


class SinkCategory(str, Enum):
    """Vulnerability category for security sinks."""

    COMMAND_INJECTION = "COMMAND_INJECTION"
    SQL_INJECTION = "SQL_INJECTION"
    CODE_EXECUTION = "CODE_EXECUTION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    DESERIALIZATION = "DESERIALIZATION"


@dataclass(slots=True)
class TaintSink:
    """Specification of a dangerous security sink."""

    sink_id: str
    pattern: str  # Regex or exact caller name
    category: SinkCategory
    cwe_id: str
    title: str
    severity: Severity
    sensitive_arg_indices: list[int] = field(default_factory=lambda: [0])
    description: str = ""
    remediation: str = ""
    is_regex: bool = False

    def matches(self, caller: str) -> bool:
        if self.is_regex:
            return bool(re.search(self.pattern, caller))
        return self.pattern == caller


DEFAULT_SINKS: list[TaintSink] = [
    # Command Injection Sinks
    TaintSink(
        sink_id="SNK-OS-SYSTEM",
        pattern=r"^os\.(system|popen)$",
        category=SinkCategory.COMMAND_INJECTION,
        cwe_id="CWE-78",
        title="Command Injection via OS Shell",
        severity=Severity.CRITICAL,
        sensitive_arg_indices=[0],
        description="Untrusted data flows into a system shell execution call.",
        remediation="Avoid invoking the shell. Use subprocess.run() with a list of arguments without shell=True.",
        is_regex=True,
    ),
    TaintSink(
        sink_id="SNK-SUBPROCESS",
        pattern=r"^subprocess\.(call|Popen|run|check_output|check_call)$",
        category=SinkCategory.COMMAND_INJECTION,
        cwe_id="CWE-78",
        title="Command Injection via Subprocess",
        severity=Severity.HIGH,
        sensitive_arg_indices=[0],
        description="Untrusted data reaches a subprocess execution call.",
        remediation="Pass command arguments as an explicit list of strings rather than a concatenated string, and avoid shell=True.",
        is_regex=True,
    ),
    # SQL Injection Sinks
    TaintSink(
        sink_id="SNK-SQL-EXECUTE",
        pattern=r"(\.execute|\.executemany)$|^execute$",
        category=SinkCategory.SQL_INJECTION,
        cwe_id="CWE-89",
        title="SQL Injection via Database Cursor",
        severity=Severity.HIGH,
        sensitive_arg_indices=[0],
        description="Untrusted data reaches a dynamic database query execution call.",
        remediation="Use parameterized queries with placeholders (? or %s) and pass parameters in a tuple or sequence.",
        is_regex=True,
    ),
    # Code Execution Sinks
    TaintSink(
        sink_id="SNK-EVAL-EXEC",
        pattern=r"^(eval|exec)$",
        category=SinkCategory.CODE_EXECUTION,
        cwe_id="CWE-95",
        title="Code Execution via eval/exec",
        severity=Severity.CRITICAL,
        sensitive_arg_indices=[0],
        description="Untrusted data is dynamically evaluated as Python code.",
        remediation="Avoid eval() and exec(). Use ast.literal_eval() for safe literal evaluation.",
        is_regex=True,
    ),
    # Insecure Deserialization Sinks
    TaintSink(
        sink_id="SNK-DESER",
        pattern=r"^(_?pickle\.(loads|load)|yaml\.load)$",
        category=SinkCategory.DESERIALIZATION,
        cwe_id="CWE-502",
        title="Insecure Deserialization",
        severity=Severity.HIGH,
        sensitive_arg_indices=[0],
        description="Untrusted data is deserialized into Python objects.",
        remediation="Never unpickle untrusted bytes. Use safe data exchange formats such as JSON or Protocol Buffers.",
        is_regex=True,
    ),
    # Path Traversal Sinks
    TaintSink(
        sink_id="SNK-OPEN",
        pattern="open",
        category=SinkCategory.PATH_TRAVERSAL,
        cwe_id="CWE-22",
        title="Potential Path Traversal in File Access",
        severity=Severity.MEDIUM,
        sensitive_arg_indices=[0],
        description="Untrusted data influences the file path in open().",
        remediation="Validate file paths against an allowed base directory using os.path.abspath and os.path.commonpath.",
    ),
]


def find_matching_sink(caller: str) -> Optional[TaintSink]:
    """Find matching taint sink specification for a given caller string."""
    for sink in DEFAULT_SINKS:
        if sink.matches(caller):
            return sink
    return None
