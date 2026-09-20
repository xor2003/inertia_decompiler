"""Typed condition identity bridge for final semantic validation.

Layer: Tail validation.
Responsibility: compare proven ConditionIR storage with its final lowered C AST
identity without recovering or rewriting semantics.
Forbidden: semantic recovery, AST mutation, or source/COD/assembly/rendered-C
inspection.
"""

from __future__ import annotations

from collections.abc import Callable
from copy import copy
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CVariable
from angr.sim_type import SimTypeChar, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeShort

from .ir.condition_ir import ConditionIR
from .ir.core import IRBinaryValue, IRValue, MemSpace
from .lowering.semantic_cast import (
    CSemanticCast8616,
    declared_variable_type_8616,
    is_identity_semantic_variable_cast_8616,
)
from .structuring.condition_materialization import materialize_condition_ir_expression_8616
from .tail_validation_fingerprint import _expr_fingerprint


class _IntegerTypeBoundary8616(Protocol):
    """Third-party integer type metadata used by Validation."""

    size: int | None
    signed: bool | None


def condition_precision_view_fingerprint_8616(
    expression: object,
    fingerprint: Callable[[object], str],
) -> str:
    """Preserve integer views across explicit casts and declaration refinement.

    A same-width variable cast and a variable declared with that destination
    type have identical value interpretations. Keep the width and signedness
    in the immutable token; removing a non-identity cast must not match.
    Other casts retain their original fingerprint, including narrowing casts.
    """
    if isinstance(expression, CBinaryOp):
        lhs = condition_precision_view_fingerprint_8616(expression.lhs, fingerprint)
        rhs = condition_precision_view_fingerprint_8616(expression.rhs, fingerprint)
        return f"{expression.op}({lhs},{rhs})"
    integer_types = (SimTypeChar, SimTypeShort, SimTypeInt, SimTypeLong, SimTypeLongLong)
    variable = expression
    type_ = None
    if isinstance(expression, CSemanticCast8616) and isinstance(expression.expr, CVariable):
        source = expression.src_type
        destination = expression.dst_type
        if not isinstance(source, integer_types) or not isinstance(destination, integer_types):
            return fingerprint(expression)
        try:
            if source.size != destination.size:
                return fingerprint(expression)
        except ValueError:
            return fingerprint(expression)
        variable = expression.expr
        type_ = destination
    elif isinstance(expression, CVariable):
        type_ = declared_variable_type_8616(expression)
    if not isinstance(type_, integer_types):
        return fingerprint(expression)
    try:
        width = type_.size
    except ValueError:
        return fingerprint(expression)
    if not isinstance(width, int) or width <= 0 or not isinstance(type_.signed, bool):
        return fingerprint(expression)
    signedness = "signed" if type_.signed else "unsigned"
    return f"IntegerView({width},{signedness},{fingerprint(variable)})"


def _typed_operand_fingerprint_8616(
    operand: object,
    expression: object,
    project: object,
) -> str:
    """Fingerprint one typed operand through final lowering evidence."""
    if isinstance(operand, IRBinaryValue) and isinstance(expression, CBinaryOp):
        lhs = _typed_operand_fingerprint_8616(operand.lhs, expression.lhs, project)
        rhs = _typed_operand_fingerprint_8616(operand.rhs, expression.rhs, project)
        return f"{expression.op}({lhs},{rhs})"
    if isinstance(operand, IRValue):
        direct_global = (
            operand.space is MemSpace.DS
            and operand.expr is None
            and operand.index is None
            and operand.name is None
            and operand.offset >= 0
        )
        if direct_global:
            return f"global:{operand.offset:#x}"
    if isinstance(operand, IRValue) and operand.space is not MemSpace.CONST:
        return str(_expr_fingerprint(expression, project))
    return str(_expr_fingerprint(expression, project))


def condition_ir_semantic_fingerprint_8616(
    project: object,
    codegen: object,
    condition: ConditionIR,
) -> str | None:
    """Fingerprint proven ConditionIR using a detached current-type view.

    Redundant casts may compare equal here without removing their proof from
    the live AST, whose declarations can still be refined before emission.
    """
    expression = materialize_condition_ir_expression_8616(project, codegen, condition)
    signedness = condition.is_signed if condition.is_signed or condition.is_unsigned else None
    expression = project_identity_semantic_casts_8616(expression, required_signedness=signedness)
    if not isinstance(expression, CBinaryOp):
        return None
    lhs = _typed_operand_fingerprint_8616(condition.lhs, expression.lhs, project)
    rhs = _typed_operand_fingerprint_8616(condition.rhs, expression.rhs, project)
    return f"{expression.op}({lhs},{rhs})"


def project_identity_semantic_casts_8616(
    expression: object,
    *,
    required_signedness: bool | None = None,
) -> object:
    """Project proven cast identities for comparison without mutating live AST.

    This is a current-declaration comparison view, not a rewrite or historical
    fingerprint normalization. Non-identity casts and all operators survive.
    """
    if isinstance(expression, CSemanticCast8616):
        if not is_identity_semantic_variable_cast_8616(expression):
            operand = project_identity_semantic_casts_8616(
                expression.expr, required_signedness=required_signedness,
            )
            if operand is expression.expr:
                return expression
            # Preserve the outer conversion and all metadata; only its proven
            # identity children differ in this detached comparison view.
            projected_cast = copy(expression)
            projected_cast.expr = operand
            return projected_cast
        destination = cast(_IntegerTypeBoundary8616, expression.dst_type)
        if required_signedness is not None and destination.signed is not required_signedness:
            return expression
        return expression.expr
    if not isinstance(expression, CBinaryOp):
        return expression
    lhs = project_identity_semantic_casts_8616(expression.lhs, required_signedness=required_signedness)
    rhs = project_identity_semantic_casts_8616(expression.rhs, required_signedness=required_signedness)
    if lhs is expression.lhs and rhs is expression.rhs:
        return expression
    projected = copy(expression)
    projected.lhs = lhs
    projected.rhs = rhs
    return projected


def condition_semantic_view_projection_fingerprint_8616(
    condition: ConditionIR,
    candidate: object,
    *,
    condition_fingerprint: Callable[[object], str],
) -> str | None:
    """Fingerprint a C predicate after proving its explicit casts match typed IR.

    A same-width semantic cast is a typed view of unchanged machine bits.  It
    may therefore be compared with the storage-domain ConditionIR fingerprint,
    but only when its destination signedness agrees with the proven comparison.
    """
    if not isinstance(candidate, CBinaryOp):
        return None
    if condition.op not in {
        "eq", "ne", "slt", "sle", "sgt", "sge", "ult", "ule", "ugt", "uge",
    }:
        return None
    required_signedness = (
        condition.op.startswith("s")
        if condition.op not in {"eq", "ne"}
        else None
    )
    identity_projection = cast(CBinaryOp, project_identity_semantic_casts_8616(
        candidate, required_signedness=required_signedness,
    ))
    if identity_projection is not candidate:
        return condition_fingerprint(identity_projection)
    if not isinstance(candidate.lhs, CSemanticCast8616) and not isinstance(
        candidate.rhs,
        CSemanticCast8616,
    ):
        return None
    projected: list[str] = []
    for operand, expression in (
        (condition.lhs, candidate.lhs),
        (condition.rhs, candidate.rhs),
    ):
        if not isinstance(expression, CSemanticCast8616):
            projected.append(condition_fingerprint(expression))
            continue
        if not isinstance(operand, (IRValue, IRBinaryValue)):
            return None
        width_bits = operand.size * 8
        source = cast(_IntegerTypeBoundary8616, expression.src_type)
        destination = cast(_IntegerTypeBoundary8616, expression.dst_type)
        try:
            cast_matches = (
                width_bits > 0
                and source.size == width_bits
                and destination.size == width_bits
                and (
                    required_signedness is None
                    or destination.signed is required_signedness
                )
            )
        except AttributeError:
            cast_matches = False
        if not cast_matches:
            return None
        projected.append(condition_fingerprint(expression.expr))
    return f"{candidate.op}({projected[0]},{projected[1]})"
