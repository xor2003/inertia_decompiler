"""Normalize proven scalar assignment destinations into valid C lvalues.

Layer: Types/Lowering.
Responsibility: remove structured-C casts from direct scalar assignment
destinations only when every cast and the owning variable have the same proven
integer width. Signedness-only views do not change the stored bit pattern.
Pointer, aggregate, unknown-width, and width-changing destinations are refused.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeInt, SimTypeLong, SimTypeShort

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.lowering.structured_tags import copy_structured_tags_8616


class AssignmentLvalueCastStatus8616(StrEnum):
    """Typed outcome for one cast-wrapped assignment destination."""

    MATERIALIZED = "materialized"
    NON_VARIABLE = "non-variable"
    NON_SCALAR_INTEGER = "non-scalar-integer"
    UNKNOWN_WIDTH = "unknown-width"
    WIDTH_MISMATCH = "width-mismatch"


@dataclass(frozen=True, slots=True)
class AssignmentLvalueCastDecision8616:
    """Classification of one cast-wrapped assignment destination."""

    status: AssignmentLvalueCastStatus8616

    @property
    def materialized(self) -> bool:
        """Return whether the destination can become a direct C lvalue."""
        return self.status is AssignmentLvalueCastStatus8616.MATERIALIZED


@dataclass(frozen=True, slots=True)
class AssignmentLvalueCastStats8616:
    """Closed evidence counters for assignment-lvalue cast normalization."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


class _CFunctionBoundary8616(Protocol):
    """Third-party function field consumed by this lowering pass."""

    statements: object


class _CodegenBoundary8616(Protocol):
    """Third-party codegen fields read and published by this pass."""

    cfunc: _CFunctionBoundary8616 | None
    _inertia_assignment_lvalue_cast_decisions_8616: tuple[AssignmentLvalueCastDecision8616, ...]
    _inertia_assignment_lvalue_cast_stats_8616: AssignmentLvalueCastStats8616


_SCALAR_INTEGER_TYPES_8616 = (SimTypeChar, SimTypeShort, SimTypeInt, SimTypeLong)


def _integer_width_bits_8616(type_: object) -> int | None:
    """Return one supported scalar integer width in bits."""
    if not isinstance(type_, _SCALAR_INTEGER_TYPES_8616):
        return None
    size = type_.size
    return size if isinstance(size, int) and size > 0 else None


def _classify_lvalue_cast_8616(
    lhs: structured_c.CTypeCast,
) -> tuple[AssignmentLvalueCastDecision8616, structured_c.CVariable | None]:
    """Classify one cast chain and return its direct variable when proven safe."""
    widths: list[int] = []
    node: structured_c.CExpression = lhs
    while isinstance(node, structured_c.CTypeCast):
        width = _integer_width_bits_8616(node.dst_type)
        if width is None:
            status = (
                AssignmentLvalueCastStatus8616.UNKNOWN_WIDTH
                if isinstance(node.dst_type, _SCALAR_INTEGER_TYPES_8616)
                else AssignmentLvalueCastStatus8616.NON_SCALAR_INTEGER
            )
            return AssignmentLvalueCastDecision8616(status), None
        widths.append(width)
        node = node.expr
    if not isinstance(node, structured_c.CVariable):
        return AssignmentLvalueCastDecision8616(AssignmentLvalueCastStatus8616.NON_VARIABLE), None
    if not isinstance(node.variable_type, _SCALAR_INTEGER_TYPES_8616):
        return (
            AssignmentLvalueCastDecision8616(
                AssignmentLvalueCastStatus8616.NON_SCALAR_INTEGER
            ),
            None,
        )
    variable_size = node.variable.size
    storage_width = variable_size * 8 if isinstance(variable_size, int) and variable_size > 0 else None
    if storage_width is None:
        storage_width = _integer_width_bits_8616(node.variable_type)
    if storage_width is None:
        status = (
            AssignmentLvalueCastStatus8616.UNKNOWN_WIDTH
            if isinstance(node.variable_type, _SCALAR_INTEGER_TYPES_8616)
            else AssignmentLvalueCastStatus8616.NON_SCALAR_INTEGER
        )
        return AssignmentLvalueCastDecision8616(status), None
    if any(width != storage_width for width in widths):
        return AssignmentLvalueCastDecision8616(AssignmentLvalueCastStatus8616.WIDTH_MISMATCH), None
    return AssignmentLvalueCastDecision8616(AssignmentLvalueCastStatus8616.MATERIALIZED), node


def normalize_scalar_assignment_lvalues_8616(codegen: object) -> bool:
    """Replace proven signedness-only assignment casts with direct C lvalues."""
    boundary = cast(_CodegenBoundary8616, codegen)
    cfunc = boundary.cfunc
    root = cfunc.statements if cfunc is not None else None
    decisions: list[AssignmentLvalueCastDecision8616] = []
    changed = False
    if root is not None:
        for node in _iter_c_nodes_deep_8616(root):
            if not isinstance(node, structured_c.CAssignment):
                continue
            lhs = node.lhs
            if not isinstance(lhs, structured_c.CTypeCast):
                continue
            decision, variable = _classify_lvalue_cast_8616(lhs)
            decisions.append(decision)
            if not decision.materialized or variable is None:
                continue
            assignment_tags = copy_structured_tags_8616(node.tags) or {}
            cast_tags = copy_structured_tags_8616(lhs.tags) or {}
            node.tags = {**cast_tags, **assignment_tags}
            node.lhs = variable
            changed = True
    materialized_count = sum(decision.materialized for decision in decisions)
    boundary._inertia_assignment_lvalue_cast_decisions_8616 = tuple(decisions)
    boundary._inertia_assignment_lvalue_cast_stats_8616 = AssignmentLvalueCastStats8616(
        raw_fact_count=len(decisions),
        normalized_fact_count=len(decisions),
        classified_fact_count=len(decisions),
        materialized_count=materialized_count,
        failure_count=len(decisions) - materialized_count,
    )
    return changed


__all__ = [
    "AssignmentLvalueCastDecision8616",
    "AssignmentLvalueCastStats8616",
    "AssignmentLvalueCastStatus8616",
    "normalize_scalar_assignment_lvalues_8616",
]
