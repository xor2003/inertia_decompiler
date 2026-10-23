"""Layer: Types/Lowering.

Responsibility: keep consumed argument PUSH storage while structured reads still
observe its typed stack range. This is a conservative DCE veto, not an alias
producer or a proof that unknown memory reads cannot alias the stack.
"""
from __future__ import annotations

from enum import StrEnum

from angr.analyses.decompiler.structured_codegen.c import CAssignment, CVariable
from angr.sim_variable import SimStackVariable

from .c_ast_utils import _iter_c_node_children_8616, _structured_slot_names_8616
from .stack_variable_coordinates import machine_bp_offset_for_stack_variable_8616


class PushStackReadVerdict8616(StrEnum):
    """Whether a typed stack-store carrier has an outstanding structured read."""

    NOT_APPLICABLE = "not_applicable"
    OBSERVED = "observed"
    NO_TYPED_READ = "no_typed_read"
    UNKNOWN_REFUSE = "unknown_refuse"


def _read_overlap_8616(
    node: object, variable: SimStackVariable, offset: int, *, codegen: object,
) -> PushStackReadVerdict8616 | None:
    """Compare independently materialized stack views using owned BP coordinates."""
    if not isinstance(node, CVariable) or not isinstance(node.variable, SimStackVariable):
        return None
    other = node.variable
    if other.region != variable.region:
        return None
    other_offset = machine_bp_offset_for_stack_variable_8616(codegen, other)
    if other_offset is None or not isinstance(other.size, int) or other.size <= 0:
        return PushStackReadVerdict8616.UNKNOWN_REFUSE
    if offset < other_offset + other.size and other_offset < offset + variable.size:
        return PushStackReadVerdict8616.OBSERVED
    return None


def consumed_push_stack_read_verdict_8616(
    root: object, assignment: CAssignment, *, codegen: object,
) -> PushStackReadVerdict8616:
    """Veto erasing a stack definition used anywhere in the retained AST.

    Direct assignment lvalues are writes. Address-taking and byte subranges are
    observations. No branch ordering or kill inference is attempted, so earlier
    reads can conservatively retain a store. Other carrier kinds retain their
    existing independent proof obligations.
    """
    lhs = assignment.lhs
    if not isinstance(lhs, CVariable) or not isinstance(lhs.variable, SimStackVariable):
        return PushStackReadVerdict8616.NOT_APPLICABLE
    variable = lhs.variable
    offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
    if offset is None or not isinstance(variable.size, int) or variable.size <= 0:
        return PushStackReadVerdict8616.UNKNOWN_REFUSE
    pending = [root]
    seen: set[int] = set()
    while pending:
        node = pending.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        if len(seen) > 8192:
            return PushStackReadVerdict8616.UNKNOWN_REFUSE
        overlap = _read_overlap_8616(node, variable, offset, codegen=codegen)
        if overlap is not None:
            return overlap
        if isinstance(node, CAssignment):
            pending.append(node.rhs)
            if not isinstance(node.lhs, CVariable):
                pending.append(node.lhs)
            continue
        for slot in _structured_slot_names_8616(node):
            # Dynamic third-party angr AST boundary: syntax owner selects child slots.
            pending.extend(_iter_c_node_children_8616(getattr(node, slot)))
    return PushStackReadVerdict8616.NO_TYPED_READ
