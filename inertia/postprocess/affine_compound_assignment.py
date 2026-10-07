"""Restore rendering identity for proven affine ``for`` iterators.

Layer: Rewrite/Postprocess cleanup
Responsibility: preserve the proven lvalue identity needed by angr to render
``i = i + step`` as ``i += step`` after late AST regeneration.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control
flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CForLoop,
    CStatement,
    CVariable,
)

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616, _same_c_expression_8616

__all__ = [
    "AffineCompoundAssignmentStats8616",
    "apply_affine_compound_assignment_identity_8616",
    "restore_affine_compound_assignment_identity_8616",
]

_COMPOUND_ASSIGNMENT_OPS_8616 = frozenset(
    {"Add", "Sub", "Mul", "Div", "And", "Xor", "Or", "Shr", "Shl", "Sar"}
)
_COMMUTATIVE_COMPOUND_ASSIGNMENT_OPS_8616 = frozenset(
    {"Add", "Mul", "And", "Xor", "Or"}
)


class _CFunctionBoundary8616(Protocol):
    """Owned C-function root consumed at the dynamic angr boundary."""

    statements: CStatement


class _CodegenBoundary8616(Protocol):
    """Owned codegen fields read and written by this cleanup pass."""

    cfunc: _CFunctionBoundary8616
    _inertia_affine_compound_assignment_stats_8616: AffineCompoundAssignmentStats8616


@dataclass(frozen=True, slots=True)
class AffineCompoundAssignmentStats8616:
    """Closed accounting for affine iterator rendering identities."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    changed_count: int = 0
    failure_count: int = 0

    @property
    def changed(self) -> bool:
        """Return whether at least one iterator identity was restored."""
        return self.changed_count > 0


def _self_update_operand_8616(
    lhs: CVariable,
    rhs: CBinaryOp,
) -> CVariable | None:
    """Return the exact lvalue operand of one supported affine update."""
    if rhs.op not in _COMPOUND_ASSIGNMENT_OPS_8616:
        return None
    if isinstance(rhs.lhs, CVariable) and _same_c_expression_8616(lhs, rhs.lhs):
        return rhs.lhs
    if (
        rhs.op in _COMMUTATIVE_COMPOUND_ASSIGNMENT_OPS_8616
        and isinstance(rhs.rhs, CVariable)
        and _same_c_expression_8616(lhs, rhs.rhs)
    ):
        return rhs.rhs
    return None


def restore_affine_compound_assignment_identity_8616(
    codegen: _CodegenBoundary8616,
) -> AffineCompoundAssignmentStats8616:
    """Restore shared render identity on exact affine ``CForLoop`` iterators."""
    root = codegen.cfunc.statements
    raw_count = 0
    normalized_count = 0
    classified_count = 0
    materialized_count = 0
    changed_count = 0
    failure_count = 0
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CForLoop) or not isinstance(node.iterator, CAssignment):
            continue
        raw_count += 1
        assignment = node.iterator
        if not isinstance(assignment.lhs, CVariable) or not isinstance(assignment.rhs, CBinaryOp):
            continue
        self_operand = _self_update_operand_8616(assignment.lhs, assignment.rhs)
        if self_operand is None:
            continue
        normalized_count += 1
        owners = tuple(
            owner
            for owner in (
                assignment.lhs.unified_variable,
                self_operand.unified_variable,
            )
            if owner is not None
        )
        if owners and any(owner != owners[0] for owner in owners[1:]):
            failure_count += 1
            continue
        classified_count += 1
        owner = owners[0] if owners else assignment.lhs.variable
        if assignment.lhs.unified_variable is None:
            assignment.lhs.unified_variable = owner
            changed_count += 1
        if self_operand.unified_variable is None:
            self_operand.unified_variable = owner
            changed_count += 1
        if (
            assignment.lhs.unified_variable == owner
            and self_operand.unified_variable == owner
        ):
            materialized_count += 1
        else:
            failure_count += 1
    stats = AffineCompoundAssignmentStats8616(
        raw_fact_count=raw_count,
        normalized_fact_count=normalized_count,
        classified_fact_count=classified_count,
        materialized_count=materialized_count,
        changed_count=changed_count,
        failure_count=failure_count,
    )
    codegen._inertia_affine_compound_assignment_stats_8616 = stats
    if classified_count > 0 and materialized_count == 0:
        raise RuntimeError("classified affine iterator identities were not materialized")
    return stats


def apply_affine_compound_assignment_identity_8616(
    codegen: _CodegenBoundary8616,
) -> bool:
    """Apply the render-identity pass through the postprocess driver."""
    return restore_affine_compound_assignment_identity_8616(codegen).changed
