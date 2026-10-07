"""Recognize structured statements backed by proven register overwrites.

Layer: Types/Lowering.
Responsibility: consume direct stack-move facts to prove that a structured
initializer overwrites a physical register before later structured uses.
Consumes alias, widening, and typed facts; it does not infer storage identity.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from angr.analyses.decompiler.structured_codegen.c import CAssignment, CForLoop, CStatements, CVariable
from angr.sim_variable import SimStackVariable

__all__ = ["stack_initializer_overwrites_register_8616"]


class StackMoveRegisterOverwriteFact8616(Protocol):
    """Direct stack-move fields required for register-overwrite proof."""

    dst_offset: int
    width: int
    ins_addr: int
    source_register_offset: int | None


def _single_initializer_assignment_8616(statement: object) -> CAssignment | None:
    """Return the assignment that executes first in a bounded initializer."""
    initializer = statement.initializer if isinstance(statement, CForLoop) else statement
    while isinstance(initializer, CStatements) and len(initializer.statements) == 1:
        initializer = initializer.statements[0]
    return initializer if isinstance(initializer, CAssignment) else None


def stack_initializer_overwrites_register_8616(
    statement: object,
    *,
    register_offset: int,
    register_width: int,
    facts: Sequence[StackMoveRegisterOverwriteFact8616],
) -> bool:
    """Return whether the first initializer has an exact register-load fact."""
    assignment = _single_initializer_assignment_8616(statement)
    if assignment is None or not isinstance(assignment.lhs, CVariable):
        return False
    variable = assignment.lhs.variable
    if not isinstance(variable, SimStackVariable) or variable.base != "bp":
        return False
    ins_addr = assignment.tags.get("ins_addr")
    if not isinstance(ins_addr, int):
        return False
    return any(
        fact.source_register_offset == register_offset
        and fact.width == register_width
        and fact.dst_offset == variable.offset
        and fact.ins_addr == ins_addr
        for fact in facts
    )
