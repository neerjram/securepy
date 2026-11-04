"""Taint Sources Definitions for SecurePy.

Defines untrusted input origins such as CLI inputs, web request parameters,
and environment variables.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Optional


class SourceCategory(str, Enum):
    """Classification of the untrusted source."""

    USER_INPUT = "USER_INPUT"
    WEB_REQUEST = "WEB_REQUEST"
    ENVIRONMENT = "ENVIRONMENT"
    FILE_INPUT = "FILE_INPUT"


@dataclass(slots=True)
class TaintSource:
    """Specification of an untrusted source pattern."""

    source_id: str
    pattern: str  # Regex or exact function/method name
    category: SourceCategory
    description: str
    is_regex: bool = False

    def matches(self, caller: str) -> bool:
        if self.is_regex:
            return bool(re.search(self.pattern, caller))
        return self.pattern == caller


# Standard library and common framework sources
DEFAULT_SOURCES: list[TaintSource] = [
    # Built-in input
    TaintSource(
        source_id="SRC-INPUT",
        pattern="input",
        category=SourceCategory.USER_INPUT,
        description="Standard CLI console input via input()",
    ),
    # Standard I/O
    TaintSource(
        source_id="SRC-STDIN",
        pattern=r"^sys\.stdin\.(read|readline|readlines)$",
        category=SourceCategory.USER_INPUT,
        description="Standard input read stream",
        is_regex=True,
    ),
    # Web Frameworks (Flask, Django, FastAPI request inputs)
    TaintSource(
        source_id="SRC-FLASK-REQ",
        pattern=r"^request\.(args|form|values|json|get_json|data|files)(\.get)?$",
        category=SourceCategory.WEB_REQUEST,
        description="Flask HTTP request parameter or payload",
        is_regex=True,
    ),
    TaintSource(
        source_id="SRC-DJANGO-REQ",
        pattern=r"^request\.(GET|POST|body|data)(\.get)?$",
        category=SourceCategory.WEB_REQUEST,
        description="Django HTTP request parameter or body",
        is_regex=True,
    ),
    TaintSource(
        source_id="SRC-FASTAPI-REQ",
        pattern=r"^request\.(query_params|path_params)(\.get)?$",
        category=SourceCategory.WEB_REQUEST,
        description="FastAPI/Starlette request parameters",
        is_regex=True,
    ),
    # Environment variables
    TaintSource(
        source_id="SRC-ENV",
        pattern=r"^(os\.getenv|os\.environ\.get)$",
        category=SourceCategory.ENVIRONMENT,
        description="Environment variable lookup",
        is_regex=True,
    ),
]


def find_matching_source(caller: str) -> Optional[TaintSource]:
    """Find matching taint source specification for a given caller string."""
    for src in DEFAULT_SOURCES:
        if src.matches(caller):
            return src
    return None
