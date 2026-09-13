"""Materialize exact byte and word views of proven scalar stack arguments.

Layer: Types/Lowering.
Responsibility: replace narrow structured-C reads contained by one authoritative
16/32-bit BP argument with projections of that argument. The owner and range come
from the stack-prototype contract; rendered names and source text are not
evidence. Writes and ambiguous ranges remain explicit refusals.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeInt, SimTypeLong, SimTypeShort
from angr.sim_variable import SimStackVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616, _replace_c_children_8616
from ..pipeline.errors import PipelineHardError
from .condition_stack_operands import project_contained_stack_integer_view_8616
from .stack_variable_coordinates import machine_bp_offset_for_stack_variable_8616

_WORD_BYTES = 2
_WIDE_BYTES = 4


@dataclass(frozen=True, slots=True)
class WideStackArgumentOwner8616:
    """One authoritative wide argument and its machine-BP range."""

    bp_offset: int
    width: int
    cvar: structured_c.CVariable


@dataclass(frozen=True, slots=True)
class WideStackArgumentSubviewResult8616:
    """Closed evidence and variables that unsafe projections must retain."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    retained_variables: tuple[SimStackVariable, ...]

    @property
    def changed(self) -> bool:
        """Return whether at least one proven subview was materialized."""
        return self.materialized_count > 0


class _CFunction8616(Protocol):
    """Required third-party structured-C function boundary."""

    statements: object


class _Codegen8616(Protocol):
    """Required third-party codegen boundary plus owned result publication."""

    cfunc: _CFunction8616 | None
    _inertia_wide_stack_argument_subview_result_8616: WideStackArgumentSubviewResult8616


def _signed_view_8616(cvar: structured_c.CVariable) -> bool:
    """Return signedness from supported integer views only."""
    type_ = cvar.variable_type
    if isinstance(type_, (SimTypeChar, SimTypeShort, SimTypeInt, SimTypeLong)):
        return bool(type_.signed)
    return False


def _matching_view_8616(
    codegen: object, active_owners: tuple[WideStackArgumentOwner8616, ...], node: object,
) -> tuple[int, SimStackVariable, tuple[WideStackArgumentOwner8616, ...]] | None:
    """Return exact owner candidates for one structured stack variable."""
    if not isinstance(node, structured_c.CVariable):
        return None
    variable = node.variable
    if not isinstance(variable, SimStackVariable) or not isinstance(variable.size, int):
        return None
    if any(variable is owner.cvar.variable for owner in active_owners):
        return None
    offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
    if not isinstance(offset, int):
        return None
    candidates = tuple(
        owner for owner in active_owners
        if owner.bp_offset <= offset and offset + variable.size <= owner.bp_offset + owner.width
    )
    return (offset, variable, candidates) if candidates else None


def _protected_view_nodes_8616(
    codegen: object, owners: tuple[WideStackArgumentOwner8616, ...], root: object,
) -> set[int]:
    """Keep storage locations and escaped addresses outside value projection."""
    protected_ids: set[int] = set()
    for node in _iter_c_nodes_deep_8616(root):
        if isinstance(node, structured_c.CAssignment):
            protected = node.lhs
        elif isinstance(node, structured_c.CUnaryOp) and node.op in {"Reference", "AddressOf"}:
            protected = node.operand
        else:
            continue
        for child in _iter_c_nodes_deep_8616(protected):
            if _matching_view_8616(codegen, owners, child) is not None:
                protected_ids.add(id(child))
    return protected_ids


def materialize_wide_stack_argument_subviews_8616(
    codegen: object,
    owners: tuple[WideStackArgumentOwner8616, ...],
) -> WideStackArgumentSubviewResult8616:
    """Project exact contained scalar reads and retain every unproven variable."""
    typed_codegen = cast(_Codegen8616, codegen)
    active_owners = tuple(owner for owner in owners if owner.width >= _WORD_BYTES)
    if not active_owners:
        result = WideStackArgumentSubviewResult8616(0, 0, 0, 0, 0, ())
        typed_codegen._inertia_wide_stack_argument_subview_result_8616 = result
        return result
    cfunc = typed_codegen.cfunc
    root = cfunc.statements if cfunc is not None else None
    raw_count = 0
    normalized_count = 0
    classified_count = 0
    materialized_count = 0
    failure_count = 0

    lvalue_ids = _protected_view_nodes_8616(codegen, active_owners, root) if root is not None else set()

    def transform(node: object) -> object:
        """Replace one exact read while preserving unproven C AST nodes."""
        nonlocal classified_count, failure_count, materialized_count
        nonlocal normalized_count, raw_count
        match = _matching_view_8616(codegen, active_owners, node)
        if match is None:
            return node
        raw_count += 1
        offset, variable, candidates = match
        if id(node) in lvalue_ids or len(candidates) != 1:
            failure_count += 1
            return node
        normalized_count += 1
        owner = candidates[0]
        supported_size = variable.size in {1, _WORD_BYTES}
        aligned_view = supported_size and (offset - owner.bp_offset) % variable.size == 0
        supported_owner = owner.width == _WIDE_BYTES or (
            owner.width == _WORD_BYTES
            and isinstance(owner.cvar.variable_type, (SimTypeShort, SimTypeInt))
        )
        if not aligned_view or not supported_owner:
            failure_count += 1
            return node
        classified_count += 1
        assert isinstance(node, structured_c.CVariable)
        projected = project_contained_stack_integer_view_8616(
            codegen,
            owner.cvar,
            owner_bp_offset=owner.bp_offset,
            offset=offset,
            size=variable.size,
            signed=_signed_view_8616(node),
            tags=node.tags,
        )
        if projected is None:
            failure_count += 1
            return node
        materialized_count += 1
        return projected

    if root is not None:
        _replace_c_children_8616(root, transform)
    retained = {
        match[1]
        for node in _iter_c_nodes_deep_8616(root)
        if (match := _matching_view_8616(codegen, active_owners, node)) is not None
    } if root is not None else set()
    result = WideStackArgumentSubviewResult8616(
        raw_fact_count=raw_count,
        normalized_fact_count=normalized_count,
        classified_fact_count=classified_count,
        materialized_count=materialized_count,
        failure_count=failure_count,
        retained_variables=tuple(sorted(retained, key=lambda variable: (variable.offset, variable.size))),
    )
    typed_codegen._inertia_wide_stack_argument_subview_result_8616 = result
    if result.classified_fact_count > 0 and result.materialized_count == 0:
        raise PipelineHardError(
            "wide stack argument subviews were classified without materialization"
        )
    return result


__all__ = [
    "WideStackArgumentOwner8616",
    "WideStackArgumentSubviewResult8616",
    "materialize_wide_stack_argument_subviews_8616",
]
