# cython: language_level=3, infer_types=True
"""Compare structured conditions through typed memory storage identities.

Layer: Structuring.
Responsibility: bridge equivalent structured condition operands only when
Widening or angr variables provide exact segmented storage identities.
Forbidden: rendered text matching, alias recovery, or condition invention.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Callable
from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CTypeCast,
    CVariable,
)
from angr.sim_variable import SimMemoryVariable, SimStackVariable

from inertia.ir.core import MemSpace
from inertia.widening.segmented_load_identity import segmented_load_identity_8616
import dataclasses
import operator


@dataclasses.dataclass(frozen=True, )
class _MemoryOperandIdentity8616:
    """Exact segmented storage selected by one condition operand."""

    space: MemSpace
    offset: cython.longlong
    width: cython.longlong


@cython.ccall
def _strip_casts_8616(node: object) -> object:
    """Remove representation-only casts from one structured operand."""
    while isinstance(node, CTypeCast):
        node = node.expr
    return node


@cython.ccall
def _memory_operand_identity_8616(
    node: object,
) -> _MemoryOperandIdentity8616 | None:
    """Return exact segmented storage without inferring an unknown segment."""
    identity: object
    node = _strip_casts_8616(node)
    identity = segmented_load_identity_8616(node)
    if identity is not None:
        return _MemoryOperandIdentity8616(
            space=identity.space,
            offset=identity.offset,
            width=identity.width,
        )
    if not isinstance(node, CVariable):
        return None
    variable = node.unified_variable
    if not isinstance(variable, SimMemoryVariable):
        variable = node.variable
    if isinstance(variable, SimStackVariable):
        # Stack variables inherit SimMemoryVariable, but their numeric addr
        # is a frame-relative offset, not a DS address. Keep the frame/base
        # comparison in the caller's exact C-variable identity resolver.
        return None
    if (
        not isinstance(variable, SimMemoryVariable)
        or not isinstance(variable.addr, int)
        or variable.addr < 0
        or not isinstance(variable.size, int)
        or variable.size <= 0
    ):
        return None
    return _MemoryOperandIdentity8616(
        space=MemSpace.DS,
        offset=variable.addr,
        width=variable.size,
    )


@cython.ccall
def same_condition_storage_identity_8616(
    left: object,
    right: object,
    *,
    same_expression: Callable[[object, object], cython.bint],
) -> cython.bint:
    """Match comparisons whose corresponding operands select exact storage."""
    left_identity: object
    right_identity: object
    left_operand: object
    right_operand: object
    left = _strip_casts_8616(left)
    right = _strip_casts_8616(right)
    comparison_ops = {"CmpEQ", "CmpNE", "CmpLT", "CmpLE", "CmpGT", "CmpGE"}
    if (
        not isinstance(left, CBinaryOp)
        or not isinstance(right, CBinaryOp)
        or operator.ne(left.op, right.op)
        or left.op not in comparison_ops
    ):
        return False
    for left_operand, right_operand in (
        (left.lhs, right.lhs),
        (left.rhs, right.rhs),
    ):
        left_identity = _memory_operand_identity_8616(left_operand)
        right_identity = _memory_operand_identity_8616(right_operand)
        if left_identity is not None or right_identity is not None:
            if operator.ne(left_identity, right_identity):
                return False
        elif not same_expression(left_operand, right_operand):
            return False
    return True


__all__ = ["same_condition_storage_identity_8616"]
