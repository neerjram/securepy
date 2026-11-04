"""Taint Analysis Engine package for SecurePy."""

from backend.engine.taint.evidence_builder import EvidenceBuilder
from backend.engine.taint.propagation import TaintPropagator
from backend.engine.taint.sanitizers import (
    DEFAULT_SANITIZERS,
    Sanitizer,
    find_sanitizer,
    is_neutralized,
)
from backend.engine.taint.sinks import (
    DEFAULT_SINKS,
    SinkCategory,
    TaintSink,
    find_matching_sink,
)
from backend.engine.taint.sources import (
    DEFAULT_SOURCES,
    SourceCategory,
    TaintSource,
    find_matching_source,
)
from backend.engine.taint.taint_analyzer import TaintAnalyzer
from backend.engine.taint.taint_state import PropagationStep, TaintState, TaintTag

__all__ = [
    "TaintAnalyzer",
    "TaintState",
    "TaintTag",
    "PropagationStep",
    "TaintPropagator",
    "EvidenceBuilder",
    "TaintSource",
    "SourceCategory",
    "DEFAULT_SOURCES",
    "find_matching_source",
    "TaintSink",
    "SinkCategory",
    "DEFAULT_SINKS",
    "find_matching_sink",
    "Sanitizer",
    "DEFAULT_SANITIZERS",
    "find_sanitizer",
    "is_neutralized",
]
