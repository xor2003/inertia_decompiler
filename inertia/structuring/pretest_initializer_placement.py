"""Preserve execution order when placing proven pretest-loop initializers.

Layer: Structuring.
Responsibility: retain existing unconditional pre-loop placement or relocate an
already-classified initializer. Do not infer storage identity or assignment values.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from angr.analyses.decompiler.structured_codegen import c as structured_c

if TYPE_CHECKING:
    from .direct_stack_move_loop_sites import DirectStackMoveAssignmentLocation8616
    from .direct_stack_move_pretest_initializers import DirectStackMovePretestInitializerSite8616


def _contains_unconditional_location(
    statements: list[object],
    location: DirectStackMoveAssignmentLocation8616,
    seen: set[int],
) -> bool:
    """Follow only sequence containers, never conditional or repeated bodies."""
    if statements is location.statements:
        return True
    if id(statements) in seen:
        return False
    seen.add(id(statements))
    return any(
        isinstance(statement, structured_c.CStatements)
        and _contains_unconditional_location(statement.statements, location, seen)
        for statement in statements
    )


def place_pretest_initializer_8616(
    site: DirectStackMovePretestInitializerSite8616,
    assignment: structured_c.CAssignment,
    location: DirectStackMoveAssignmentLocation8616 | None,
) -> tuple[bool, bool]:
    """Return (placed, already placed) without moving an initializer past reads."""
    try:
        loop_index = next(index for index, statement in enumerate(site.statements) if statement is site.loop)
    except StopIteration:
        return False, False
    if location is not None:
        if not 0 <= location.index < len(location.statements):
            return False, False
        if location.statements[location.index] is not assignment:
            return False, False
        same_sequence_prefix = location.statements is site.statements and location.index < loop_index
        nested_sequence_prefix = _contains_unconditional_location(
            site.statements[:loop_index], location, set(),
        )
        # Adjacency is not required: moving past a header read changes behavior.
        if same_sequence_prefix or nested_sequence_prefix:
            return True, True
        del location.statements[location.index]
    site.statements.insert(loop_index, assignment)
    return True, False
