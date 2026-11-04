"""Taint State tracking for SecurePy.

Maintains taint status, origin source tags, propagation chains, and
sanitization records for program variables.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from backend.engine.parser.parser_models import SourceLocation
from backend.engine.taint.sanitizers import is_neutralized
from backend.engine.taint.sinks import SinkCategory
from backend.engine.taint.sources import SourceCategory


@dataclass(slots=True)
class TaintTag:
    """Metadata describing the origin of a tainted value."""

    source_id: str
    source_name: str
    category: SourceCategory
    location: SourceLocation
    origin_repr: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "source_name": self.source_name,
            "category": self.category.value,
            "location": self.location.to_dict(),
            "origin_repr": self.origin_repr,
        }


@dataclass(slots=True)
class PropagationStep:
    """An individual step in a taint propagation path."""

    step_number: int
    from_name: str
    to_name: str
    expression: str
    location: SourceLocation
    description: str
    is_sanitizer: bool = False
    sanitizer_name: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_number": self.step_number,
            "from_name": self.from_name,
            "to_name": self.to_name,
            "expression": self.expression,
            "location": self.location.to_dict(),
            "description": self.description,
            "is_sanitizer": self.is_sanitizer,
            "sanitizer_name": self.sanitizer_name,
        }


class TaintState:
    """Tracks active variable taint status and data-flow histories."""

    def __init__(self) -> None:
        # Maps variable name -> active origin TaintTag
        self.tainted_vars: dict[str, TaintTag] = {}
        # Maps variable name -> sequence of propagation steps from origin
        self.propagation_chains: dict[str, list[PropagationStep]] = {}
        # Maps variable name -> set of applied sanitizer names
        self.applied_sanitizers: dict[str, set[str]] = {}

    def mark_tainted(
        self,
        var_name: str,
        tag: TaintTag,
        location: SourceLocation,
        expression: str,
    ) -> None:
        """Mark a variable as directly tainted by a source."""
        self.tainted_vars[var_name] = tag
        step = PropagationStep(
            step_number=1,
            from_name=tag.source_name,
            to_name=var_name,
            expression=expression,
            location=location,
            description=f"Received untrusted input from source '{tag.source_name}()'",
        )
        self.propagation_chains[var_name] = [step]
        self.applied_sanitizers[var_name] = set()

    def propagate(
        self,
        source_var: str,
        target_var: str,
        expression: str,
        location: SourceLocation,
        description: str,
    ) -> None:
        """Propagate taint from source_var to target_var."""
        if source_var not in self.tainted_vars:
            return

        tag = self.tainted_vars[source_var]
        self.tainted_vars[target_var] = tag

        prior_steps = self.propagation_chains.get(source_var, [])
        new_step = PropagationStep(
            step_number=len(prior_steps) + 1,
            from_name=source_var,
            to_name=target_var,
            expression=expression,
            location=location,
            description=description,
        )
        self.propagation_chains[target_var] = prior_steps + [new_step]
        # Propagate any existing sanitizers
        self.applied_sanitizers[target_var] = set(
            self.applied_sanitizers.get(source_var, set())
        )

    def apply_sanitizer(
        self,
        source_var: str,
        target_var: str,
        sanitizer_name: str,
        expression: str,
        location: SourceLocation,
    ) -> None:
        """Record sanitization operation on target_var."""
        tag = self.tainted_vars.get(source_var)
        if tag:
            self.tainted_vars[target_var] = tag
            prior_steps = self.propagation_chains.get(source_var, [])
            step = PropagationStep(
                step_number=len(prior_steps) + 1,
                from_name=source_var,
                to_name=target_var,
                expression=expression,
                location=location,
                description=f"Sanitized via '{sanitizer_name}()'",
                is_sanitizer=True,
                sanitizer_name=sanitizer_name,
            )
            self.propagation_chains[target_var] = prior_steps + [step]

        sanitizers = self.applied_sanitizers.setdefault(target_var, set())
        sanitizers.add(sanitizer_name)

    def clear_taint(self, var_name: str) -> None:
        """Clear taint on a variable (e.g. when overwritten with a constant)."""
        self.tainted_vars.pop(var_name, None)
        self.propagation_chains.pop(var_name, None)
        self.applied_sanitizers.pop(var_name, None)

    def is_tainted(
        self, var_name: str, sink_cat: Optional[SinkCategory] = None
    ) -> bool:
        """Check if var_name is tainted and not neutralized for the given sink category."""
        if var_name not in self.tainted_vars:
            return False

        if sink_cat is not None:
            # Check if any applied sanitizer neutralizes this sink category
            applied = self.applied_sanitizers.get(var_name, set())
            for san_name in applied:
                if is_neutralized(san_name, sink_cat):
                    return False

        return True

    def get_tag(self, var_name: str) -> Optional[TaintTag]:
        return self.tainted_vars.get(var_name)

    def get_chain(self, var_name: str) -> list[PropagationStep]:
        return self.propagation_chains.get(var_name, [])
