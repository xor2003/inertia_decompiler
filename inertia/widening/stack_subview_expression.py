"""Build structured-C expressions for Widening-proven stack subviews.

Layer: Widening.
Responsibility: materialize one accepted scalar stack-object view with exact
width, offset, mask, and shift operations after storage identity is proven.
Consumes only ``StackObjectViewProof8616``; it does not discover ownership.
Consumes alias-proven storage identity through the typed Widening proof.
Do not join values from rendered text, cosmetic shape, postprocess, or
CLI/reporting evidence.

This module is a structured-C materialization boundary. Never infer a view from
rendered C, assembly text, variable names, or expression shape here. A call-bearing
write is materializable only when its exact callsite has an owner-preserving typed
effect in the consumed Widening proof; all other side effects remain unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimType, SimTypeChar, SimTypeLong, SimTypeShort

from inertia.lowering.c_ast_utils import _clone_c_ast_tree_8616

from .stack_subview_proof import StackObjectViewProof8616


def _unsigned_scalar_type_8616(size: int) -> SimType | None:
    """Return the exact supported unsigned scalar type for a byte width."""
    scalar_types: dict[int, SimType] = {
        1: SimTypeChar(signed=False),
        2: SimTypeShort(signed=False),
        4: SimTypeLong(signed=False),
    }
    return scalar_types.get(size)


def _matching_view_type_8616(proof: StackObjectViewProof8616) -> SimType | None:
    """Keep an existing scalar view type only when its width is exact."""
    view_type = proof.view.variable_type
    expected_types: dict[int, type[SimType]] = {
        1: SimTypeChar,
        2: SimTypeShort,
        4: SimTypeLong,
    }
    expected = expected_types.get(proof.view_size)
    return view_type if expected is not None and isinstance(view_type, expected) else None


def scalar_subview_proof_8616(
    proof: StackObjectViewProof8616 | None,
) -> StackObjectViewProof8616 | None:
    """Accept one strict scalar subrange of a supported scalar owner."""
    if proof is None or proof.owner_size not in {2, 4} or proof.view_size not in {1, 2}:
        return None
    if proof.view_size >= proof.owner_size or proof.relative_offset < 0:
        return None
    if proof.relative_offset + proof.view_size > proof.owner_size:
        return None
    return proof


class StackSubviewRhsEffectKind8616(StrEnum):
    """Typed evaluation requirement for one scalar-view write value."""

    PURE = "pure"
    OWNER_PRESERVING_CALLS = "owner_preserving_calls"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class StackSubviewRhsEffect8616:
    """Structured RHS classification plus exact callsites requiring proof."""

    kind: StackSubviewRhsEffectKind8616
    callsite_addrs: tuple[int, ...] = ()


def _combine_rhs_effects_8616(
    effects: tuple[StackSubviewRhsEffect8616, ...],
) -> StackSubviewRhsEffect8616:
    """Combine child evaluations without losing exact callsite identity."""
    if any(effect.kind is StackSubviewRhsEffectKind8616.UNSUPPORTED for effect in effects):
        return StackSubviewRhsEffect8616(StackSubviewRhsEffectKind8616.UNSUPPORTED)
    callsites = tuple(addr for effect in effects for addr in effect.callsite_addrs)
    kind = (
        StackSubviewRhsEffectKind8616.OWNER_PRESERVING_CALLS
        if callsites
        else StackSubviewRhsEffectKind8616.PURE
    )
    return StackSubviewRhsEffect8616(kind, callsites)


def classify_subview_rhs_8616(node: object) -> StackSubviewRhsEffect8616:
    """Classify values that are pure or contain exactly tagged function calls."""
    if isinstance(node, (structured_c.CConstant, structured_c.CVariable)):
        return StackSubviewRhsEffect8616(StackSubviewRhsEffectKind8616.PURE)
    if isinstance(node, structured_c.CTypeCast):
        return classify_subview_rhs_8616(node.expr)
    if isinstance(node, structured_c.CBinaryOp):
        return _combine_rhs_effects_8616(
            (classify_subview_rhs_8616(node.lhs), classify_subview_rhs_8616(node.rhs))
        )
    if isinstance(node, structured_c.CFunctionCall):
        tags = node.tags
        callsite_addr = tags.get("ins_addr") if isinstance(tags, dict) else None
        if not isinstance(callsite_addr, int):
            return StackSubviewRhsEffect8616(StackSubviewRhsEffectKind8616.UNSUPPORTED)
        children = tuple(node.args or ())
        if isinstance(node.callee_target, structured_c.CExpression):
            children = (node.callee_target, *children)
        combined = _combine_rhs_effects_8616(
            tuple(classify_subview_rhs_8616(child) for child in children)
        )
        if combined.kind is StackSubviewRhsEffectKind8616.UNSUPPORTED:
            return combined
        return StackSubviewRhsEffect8616(
            StackSubviewRhsEffectKind8616.OWNER_PRESERVING_CALLS,
            (*combined.callsite_addrs, callsite_addr),
        )
    return StackSubviewRhsEffect8616(StackSubviewRhsEffectKind8616.UNSUPPORTED)


def _expression_type_or_width_8616(expr: structured_c.CExpression, size: int) -> SimType:
    """Return a concrete boundary type for an optionally untyped expression."""
    expr_type = expr.type
    fallback = _unsigned_scalar_type_8616(size)
    if fallback is None:
        raise ValueError(f"unsupported scalar stack width {size}")
    return expr_type if isinstance(expr_type, SimType) else fallback


def make_scalar_subview_read_expr_8616(
    codegen: object,
    proof: StackObjectViewProof8616,
) -> structured_c.CExpression:
    """Project one proven scalar rvalue from its unsigned containing owner."""
    owner_type = _unsigned_scalar_type_8616(proof.owner_size)
    if owner_type is None:
        raise ValueError(f"unsupported scalar stack owner width {proof.owner_size}")
    owner = cast(structured_c.CExpression, _clone_c_ast_tree_8616(proof.owner))
    value: structured_c.CExpression = structured_c.CTypeCast(
        _expression_type_or_width_8616(owner, proof.owner_size),
        owner_type,
        owner,
        codegen=codegen,
    )
    shift_bits = proof.relative_offset * 8
    if shift_bits:
        value = structured_c.CBinaryOp(
            "Shr",
            value,
            structured_c.CConstant(shift_bits, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
    view_mask = (1 << (proof.view_size * 8)) - 1
    value = structured_c.CBinaryOp(
        "And",
        value,
        structured_c.CConstant(view_mask, owner_type, codegen=codegen),
        codegen=codegen,
    )
    view_type = _matching_view_type_8616(proof)
    if view_type is not None:
        return structured_c.CTypeCast(owner_type, view_type, value, codegen=codegen)
    return value


def make_scalar_subview_write_assignment_8616(
    codegen: object,
    assignment: structured_c.CAssignment,
    proof: StackObjectViewProof8616,
) -> structured_c.CAssignment:
    """Project one proven scalar-view write as a containing-owner update."""
    owner_type = _unsigned_scalar_type_8616(proof.owner_size)
    if owner_type is None:
        raise ValueError(f"unsupported scalar stack owner width {proof.owner_size}")
    owner_read = cast(structured_c.CExpression, _clone_c_ast_tree_8616(proof.owner))
    owner_value = structured_c.CTypeCast(
        _expression_type_or_width_8616(owner_read, proof.owner_size),
        owner_type,
        owner_read,
        codegen=codegen,
    )
    shift_bits = proof.relative_offset * 8
    view_mask = (1 << (proof.view_size * 8)) - 1
    owner_mask = (1 << (proof.owner_size * 8)) - 1
    preserved_mask = owner_mask ^ (view_mask << shift_bits)
    preserved = structured_c.CBinaryOp(
        "And",
        owner_value,
        structured_c.CConstant(preserved_mask, owner_type, codegen=codegen),
        codegen=codegen,
    )
    rhs = cast(structured_c.CExpression, _clone_c_ast_tree_8616(assignment.rhs))
    inserted: structured_c.CExpression = structured_c.CBinaryOp(
        "And",
        structured_c.CTypeCast(
            _expression_type_or_width_8616(rhs, proof.view_size),
            owner_type,
            rhs,
            codegen=codegen,
        ),
        structured_c.CConstant(view_mask, owner_type, codegen=codegen),
        codegen=codegen,
    )
    if shift_bits:
        inserted = structured_c.CBinaryOp(
            "Shl",
            inserted,
            structured_c.CConstant(shift_bits, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
    replacement = cast(structured_c.CAssignment, _clone_c_ast_tree_8616(assignment))
    replacement.lhs = cast(structured_c.CExpression, _clone_c_ast_tree_8616(proof.owner))
    replacement.rhs = structured_c.CBinaryOp("Or", preserved, inserted, codegen=codegen)
    return replacement


__all__ = [
    "StackSubviewRhsEffect8616",
    "StackSubviewRhsEffectKind8616",
    "classify_subview_rhs_8616",
    "make_scalar_subview_read_expr_8616",
    "make_scalar_subview_write_assignment_8616",
    "scalar_subview_proof_8616",
]
