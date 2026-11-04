"""Sanitizers and Neutralizers for SecurePy Taint Engine.

Identifies validation, escaping, and type-coercion operations that neutralize
taint for specific vulnerability contexts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Optional

from backend.engine.taint.sinks import SinkCategory


@dataclass(slots=True)
class Sanitizer:
    """Specification of a sanitization or validation operation."""

    name: str
    pattern: str
    effective_for: list[SinkCategory] = field(default_factory=list)
    description: str = ""
    is_regex: bool = False

    def matches(self, caller: str) -> bool:
        if self.is_regex:
            return bool(re.search(self.pattern, caller))
        return self.pattern == caller


DEFAULT_SANITIZERS: list[Sanitizer] = [
    # Shell Sanitizers
    Sanitizer(
        name="shlex.quote",
        pattern=r"^shlex\.quote$",
        effective_for=[SinkCategory.COMMAND_INJECTION],
        description="Escapes shell metacharacters for POSIX shells",
        is_regex=True,
    ),
    # Type Cast Sanitizers (Primitive integers and numbers cannot inject arbitrary shell or SQL syntax)
    Sanitizer(
        name="int",
        pattern=r"^int$",
        effective_for=[
            SinkCategory.COMMAND_INJECTION,
            SinkCategory.SQL_INJECTION,
            SinkCategory.PATH_TRAVERSAL,
            SinkCategory.CODE_EXECUTION,
        ],
        description="Coerces input to integer, neutralizing string-based injections",
        is_regex=True,
    ),
    Sanitizer(
        name="float",
        pattern=r"^float$",
        effective_for=[
            SinkCategory.COMMAND_INJECTION,
            SinkCategory.SQL_INJECTION,
            SinkCategory.PATH_TRAVERSAL,
            SinkCategory.CODE_EXECUTION,
        ],
        description="Coerces input to floating point number",
        is_regex=True,
    ),
    Sanitizer(
        name="bool",
        pattern=r"^bool$",
        effective_for=[
            SinkCategory.COMMAND_INJECTION,
            SinkCategory.SQL_INJECTION,
            SinkCategory.PATH_TRAVERSAL,
            SinkCategory.CODE_EXECUTION,
        ],
        description="Coerces input to boolean",
        is_regex=True,
    ),
    # Path Sanitizers
    Sanitizer(
        name="os.path.basename",
        pattern=r"^(os\.path\.basename|pathlib\.Path\.name)$",
        effective_for=[SinkCategory.PATH_TRAVERSAL],
        description="Strips directory traversal sequences (../) leaving only filename",
        is_regex=True,
    ),
]


def find_sanitizer(caller: str) -> Optional[Sanitizer]:
    """Find a sanitizer matching the given callable expression."""
    for s in DEFAULT_SANITIZERS:
        if s.matches(caller):
            return s
    return None


def is_neutralized(caller: str, sink_cat: SinkCategory) -> bool:
    """Check if the given callable neutralizes taint for the specified sink category."""
    san = find_sanitizer(caller)
    if san and sink_cat in san.effective_for:
        return True
    return False
