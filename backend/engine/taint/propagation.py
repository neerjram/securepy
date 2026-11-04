"""Taint Propagation Logic for SecurePy.

Tracks data flow sequentially across variable assignments, aliases, binary
expressions, string formatting, and sanitizer invocations within a scope.
"""

from __future__ import annotations

from typing import Optional

from backend.engine.analysis.intermediate_representation import (
    IRAssignment,
    IRScope,
)
from backend.engine.taint.sanitizers import find_sanitizer
from backend.engine.taint.sources import TaintSource, find_matching_source
from backend.engine.taint.taint_state import TaintState, TaintTag


class TaintPropagator:
    """Executes sequential data-flow and taint propagation rules."""

    def __init__(self, state: Optional[TaintState] = None) -> None:
        self.state = state or TaintState()

    def process_assignment(self, assignment: IRAssignment) -> None:
        """Evaluate an assignment statement and update taint state."""
        target = assignment.target
        loc = assignment.location

        # 1. Check if the value is a direct call to a Taint Source
        if assignment.call:
            src = find_matching_source(assignment.call.caller)
            if src:
                tag = TaintTag(
                    source_id=src.source_id,
                    source_name=assignment.call.caller,
                    category=src.category,
                    location=assignment.call.location,
                    origin_repr=f"{target} = {assignment.value_repr}",
                )
                self.state.mark_tainted(
                    var_name=target,
                    tag=tag,
                    location=loc,
                    expression=f"{target} = {assignment.value_repr}",
                )
                return

            # Check if calling a Sanitizer function (e.g. clean = shlex.quote(x))
            san = find_sanitizer(assignment.call.caller)
            if san and assignment.call.args:
                first_arg = assignment.call.args[0].value_repr
                if self.state.is_tainted(first_arg):
                    self.state.apply_sanitizer(
                        source_var=first_arg,
                        target_var=target,
                        sanitizer_name=san.name,
                        expression=f"{target} = {assignment.value_repr}",
                        location=loc,
                    )
                    return

        # 2. Check if assignment is a direct alias (e.g. y = x)
        if len(assignment.aliases) == 1:
            source_var = assignment.aliases[0]
            if self.state.is_tainted(source_var):
                self.state.propagate(
                    source_var=source_var,
                    target_var=target,
                    expression=f"{target} = {source_var}",
                    location=loc,
                    description=f"Assigned directly from variable '{source_var}'",
                )
                return

        # 3. Check if expression references any tainted variable (e.g. z = "ping " + y)
        tainted_ref = None
        for ref_var in assignment.referenced_vars:
            if self.state.is_tainted(ref_var):
                tainted_ref = ref_var
                break

        if tainted_ref:
            self.state.propagate(
                source_var=tainted_ref,
                target_var=target,
                expression=f"{target} = {assignment.value_repr}",
                location=loc,
                description=(
                    f"Propagated through expression containing tainted variable '{tainted_ref}'"
                ),
            )
            return

        # 4. If target is reassigned to a constant/safe value without tainted inputs, clear taint!
        if assignment.is_reassignment and not assignment.referenced_vars and not assignment.is_augmented:
            self.state.clear_taint(target)

    def process_scope(self, scope: IRScope) -> None:
        """Process all assignments within an IRScope in sequential order."""
        for stmt in scope.statements:
            if stmt.assignment:
                self.process_assignment(stmt.assignment)
