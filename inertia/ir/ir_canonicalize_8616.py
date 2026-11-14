# cython: language_level=3, infer_types=True
"""Lossless local algebraic normalization for IR expressions.

Layer: IR.
Responsibility: owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import dataclasses
import typing
import cython

# Equivalent to LLVM: tiny subset of InstCombine/Reassociate.
from dataclasses import dataclass
from typing import Protocol, cast

from .condition_fingerprint_masks import is_proven_full_width_mask_8616
import operator

__all__ = [
    "_ir_canonicalize_expr_8616",
    "canonicalize_expr_8616",
]


@dataclasses.dataclass(frozen=True)
class _ConstReassoc:
    terms: object
    const: cython.longlong


class _CExprBoundary(Protocol):
    """External C-AST attributes consumed by local expression canonicalization."""

    op: object
    lhs: object
    rhs: object
    value: object
    constant: object
    type: object
    codegen: object
    variable: object


class _CVariableBoundary(Protocol):
    """External C-variable attributes used to preserve machine width."""

    size: object


@cython.ccall
def _c_op(expr: object) -> str:
    try:
        op = cast(_CExprBoundary, expr).op
    except AttributeError:
        return ""
    return str(op or "")


@cython.ccall
def _c_lhs(expr: object) -> object:
    return cast(_CExprBoundary, expr).lhs


@cython.ccall
def _c_rhs(expr: object) -> object:
    return cast(_CExprBoundary, expr).rhs


@cython.ccall
def _c_codegen(expr: object) -> object | None:
    if expr is None:
        return None
    try:
        return cast(_CExprBoundary, expr).codegen
    except AttributeError:
        return None


@cython.ccall
def _c_type(expr: object) -> object | None:
    if expr is None:
        return None
    try:
        return cast(_CExprBoundary, expr).type
    except AttributeError:
        return None


@cython.ccall
def _c_width_bytes(expr: object) -> int | None:
    try:
        size = cast(_CVariableBoundary, cast(_CExprBoundary, expr).variable).size
    except AttributeError:
        return None
    return size if isinstance(size, int) and size > 0 else None


@cython.ccall
def canonicalize_expr_8616(expr: object, *, max_rounds: cython.longlong = 4) -> object:
    """Canonicalize a local expression until fixed point."""
    current = expr
    for _ in range(max_rounds):
        new = _ir_canonicalize_expr_once_8616(current)
        if _same_c_expr_8616(new, current):
            return new
        current = new
    return current


@cython.ccall
def _ir_canonicalize_expr_8616(expr: object) -> object:
    """Backward-compatible public entry point."""
    return canonicalize_expr_8616(expr)


@cython.ccall
def _canonicalize_binop_dispatch_8616(op: object, lhs: object, rhs: object, expr: object) -> object | None:
    """Dispatch to the per-op canonicalizer."""
    if op in {"Add", "Sub"}:
        return _canonicalize_add_sub_8616(lhs, rhs, op, expr)
    if op == "Mul":
        return _canonicalize_mul_8616(lhs, rhs, expr)
    if op in {"And", "Or"}:
        return _canonicalize_bitwise_assoc_8616(lhs, rhs, op, expr)
    if op == "Xor":
        return _canonicalize_xor_8616(lhs, rhs, expr)
    return None


@cython.ccall
def __ir_canonicalize_expr_once_8616___impl(expr: object) -> object:
    """Single canonicalization pass over one binary expression."""
    folded: object
    out: object
    from angr.analyses.decompiler.structured_codegen import c as structured_c

    if not isinstance(expr, structured_c.CBinaryOp):
        return expr

    lhs = canonicalize_expr_8616(_c_lhs(expr))
    rhs = canonicalize_expr_8616(_c_rhs(expr))
    op = _c_op(expr)

    lhs_val = _c_constant_value(lhs)
    rhs_val = _c_constant_value(rhs)
    folded = _fold_binary_constants_8616(op, lhs_val, rhs_val, expr)
    if folded is not None:
        return folded

    out = _canonicalize_binop_dispatch_8616(op, lhs, rhs, expr)
    if out is not None:
        return out

    if op in {"Shl", "Shr", "Sar"} and rhs_val == 0:
        return lhs

    return _rebuild_binary_8616(expr, op, lhs, rhs)


@cython.ccall
def _ir_canonicalize_expr_once_8616(expr: object) -> object:
    return __ir_canonicalize_expr_once_8616___impl(expr)


def _canonicalize_add_sub_8616(lhs: object, rhs: object, op: object, template: object) -> object | None:
    def _impl() -> object | None:
        flattened: object
        rhs_val = _c_constant_value(rhs)
        lhs_val = _c_constant_value(lhs)

        if op == "Add" and rhs_val == 0:
            return lhs
        if op == "Add" and lhs_val == 0:
            return rhs
        if op == "Sub" and rhs_val == 0:
            return lhs
        if op == "Sub" and _same_c_expr_8616(lhs, rhs):
            return _make_const_8616(0, template)

        flattened = _flatten_add_sub_8616(lhs, rhs, op)
        if flattened is None:
            return None

        terms, const = flattened.terms, flattened.const

        if not terms:
            return _make_const_8616(const, template)

        base = _rebuild_left_assoc_8616(terms, "Add", template)

        if const == 0:
            return base
        if const > 0:
            return _make_binop_8616("Add", base, _make_const_8616(const, template), template)
        return _make_binop_8616("Sub", base, _make_const_8616(-const, template), template)

    return _impl()


def _flatten_add_sub_8616(lhs: object, rhs: object, op: object) -> _ConstReassoc | None:
    terms: list[object] = []
    const = 0

    def walk(node: object, sign: cython.longlong) -> None:
        nonlocal const
        value = _c_constant_value(node)
        if isinstance(value, int):
            const += sign * value
            return

        from angr.analyses.decompiler.structured_codegen import c as structured_c

        if isinstance(node, structured_c.CBinaryOp):
            node_op = _c_op(node)
            if node_op == "Add":
                walk(_c_lhs(node), sign)
                walk(_c_rhs(node), sign)
                return
            if node_op == "Sub":
                walk(_c_lhs(node), sign)
                walk(_c_rhs(node), -sign)
                return

        if sign == 1:
            terms.append(node)
        else:
            terms.append(_make_binop_8616("Sub", _make_const_8616(0, node), node, node))

    walk(lhs, 1)
    walk(rhs, 1 if op == "Add" else -1)

    return _ConstReassoc(tuple(terms), const)


def _canonicalize_mul_8616(lhs: object, rhs: object, template: object) -> object | None:
    lhs_val = _c_constant_value(lhs)
    rhs_val = _c_constant_value(rhs)

    if rhs_val == 1:
        return lhs
    if lhs_val == 1:
        return rhs
    if rhs_val == 0 or lhs_val == 0:
        return _make_const_8616(0, template)

    terms: list[object] = []
    const = 1

    def walk(node: object) -> None:
        nonlocal const
        value = _c_constant_value(node)
        if isinstance(value, int):
            const *= value
            return

        from angr.analyses.decompiler.structured_codegen import c as structured_c

        if isinstance(node, structured_c.CBinaryOp) and _c_op(node) == "Mul":
            walk(_c_lhs(node))
            walk(_c_rhs(node))
            return

        terms.append(node)

    walk(lhs)
    walk(rhs)

    if const == 0:
        return _make_const_8616(0, template)

    if not terms:
        return _make_const_8616(const, template)

    base = _rebuild_left_assoc_8616(tuple(terms), "Mul", template)

    if const == 1:
        return base
    return _make_binop_8616("Mul", base, _make_const_8616(const, template), template)


@cython.ccall
def _assoc_combine_8616(op: object, a: cython.longlong, b: cython.longlong) -> cython.longlong:
    """Fold ``a`` and ``b`` with the associative ``op``."""
    if op == "And":
        return a & b
    if op == "Or":
        return a | b
    raise AssertionError(op)


@cython.ccall
def _assoc_walk_8616(node: object, op: object, terms: object, const: object) -> int | None:
    """Flatten ``op``-chained binops; return the folded constant accumulator."""
    value = _c_constant_value(node)
    if isinstance(value, int):
        return value if const is None else _assoc_combine_8616(op, const, value)
    from angr.analyses.decompiler.structured_codegen import c as structured_c

    if isinstance(node, structured_c.CBinaryOp) and operator.eq(_c_op(node), op):
        const = _assoc_walk_8616(_c_lhs(node), op, terms, const)
        return _assoc_walk_8616(_c_rhs(node), op, terms, const)
    terms.append(node)
    return const


@cython.ccall
def _assoc_const_gate_8616(lhs: object, rhs: object, op: object, template: object) -> object | None:
    """Constant-elimination gates for ``And``/``Or``; None means flatten."""
    lhs_val = _c_constant_value(lhs)
    rhs_val = _c_constant_value(rhs)
    if op == "And":
        if isinstance(rhs_val, int) and is_proven_full_width_mask_8616(rhs_val, _c_width_bytes(lhs)):
            return lhs
        if isinstance(lhs_val, int) and is_proven_full_width_mask_8616(lhs_val, _c_width_bytes(rhs)):
            return rhs
        if rhs_val == 0 or lhs_val == 0:
            return _make_const_8616(0, template)
    if op == "Or":
        if rhs_val == 0:
            return lhs
        if lhs_val == 0:
            return rhs
    return None


@cython.ccall
def _assoc_rebuild_8616(terms: object, const: cython.longlong, op: object, template: object) -> object:
    """Rebuild the flattened ``terms`` plus folded ``const`` under ``op``."""
    if not terms:
        return _make_const_8616(const, template)
    base = _rebuild_left_assoc_8616(tuple(terms), op, template)
    if op == "Or" and const == 0:
        return base
    if op == "And" and is_proven_full_width_mask_8616(const, _c_width_bytes(base)):
        return base
    return _make_binop_8616(op, base, _make_const_8616(const, template), template)


@cython.ccall
def __canonicalize_bitwise_assoc_8616___impl(
    lhs: object, rhs: object, op: object, template: object
) -> object | None:
    """Canonicalize an ``And``/``Or``-assoc expression."""
    const: object
    gated: object
    gated = _assoc_const_gate_8616(lhs, rhs, op, template)
    if gated is not None:
        return gated
    terms: list[object] = []
    const = _assoc_walk_8616(rhs, op, terms, _assoc_walk_8616(lhs, op, terms, None))
    if const is None:
        return None
    if op == "And" and const == 0:
        return _make_const_8616(0, template)
    return _assoc_rebuild_8616(terms, const, op, template)


@cython.ccall
def _canonicalize_bitwise_assoc_8616(lhs: object, rhs: object, op: object, template: object) -> object | None:
    return __canonicalize_bitwise_assoc_8616___impl(lhs, rhs, op, template)


@cython.ccall
def _xor_walk_8616(node: object, terms: object, const: cython.longlong) -> cython.longlong:
    """Flatten ``Xor``-chains; remove same-expr pairs; return folded const."""
    existing: object
    idx: object
    value = _c_constant_value(node)
    if isinstance(value, int):
        return const ^ value

    from angr.analyses.decompiler.structured_codegen import c as structured_c

    if isinstance(node, structured_c.CBinaryOp) and _c_op(node) == "Xor":
        const = _xor_walk_8616(_c_lhs(node), terms, const)
        return _xor_walk_8616(_c_rhs(node), terms, const)

    for idx, existing in enumerate(terms):
        if _same_c_expr_8616(existing, node):
            del terms[idx]
            return const
    terms.append(node)
    return const


@cython.ccall
def _canonicalize_xor_8616(lhs: object, rhs: object, template: object) -> object | None:
    lhs_val = _c_constant_value(lhs)
    rhs_val = _c_constant_value(rhs)

    if rhs_val == 0:
        return lhs
    if lhs_val == 0:
        return rhs
    if _same_c_expr_8616(lhs, rhs):
        return _make_const_8616(0, template)

    terms: list[object] = []
    const = _xor_walk_8616(rhs, terms, _xor_walk_8616(lhs, terms, 0))

    if not terms:
        return _make_const_8616(const, template)

    base = _rebuild_left_assoc_8616(tuple(terms), "Xor", template)

    if const == 0:
        return base

    return _make_binop_8616("Xor", base, _make_const_8616(const, template), template)


_CONST_FOLD_TABLE_8616 = {
    "Add": int.__add__,
    "Sub": int.__sub__,
    "Mul": int.__mul__,
    "And": int.__and__,
    "Or": int.__or__,
    "Xor": int.__xor__,
    "Shl": int.__lshift__,
}


@cython.ccall
def _fold_const_pair_8616(op: object, lhs_val: cython.longlong, rhs_val: cython.longlong) -> int | None:
    """Compute ``lhs_val OP rhs_val``; return None when unsafe or unknown."""
    if op in _CONST_FOLD_TABLE_8616:
        return int(_CONST_FOLD_TABLE_8616[op](lhs_val, rhs_val))
    if op in {"Shr", "Sar"}:
        if rhs_val < 0:
            return None
        return lhs_val >> rhs_val
    if op in {"Div", "Mod"}:
        if rhs_val == 0:
            return None
        return lhs_val // rhs_val if op == "Div" else lhs_val % rhs_val
    return None


@cython.ccall
def __fold_binary_constants_8616___impl(
    op: object, lhs_val: int | None, rhs_val: int | None, template: object
) -> object | None:
    """Fold a binary op when both operands are constants."""
    value: object
    if not isinstance(lhs_val, int) or not isinstance(rhs_val, int):
        return None
    try:
        value = _fold_const_pair_8616(op, lhs_val, rhs_val)
    except (ArithmeticError, TypeError, ValueError):
        return None
    if value is None:
        return None
    return _make_const_8616(value, template)


@cython.ccall
def _fold_binary_constants_8616(op: object, lhs_val: int | None, rhs_val: int | None, template: object) -> object | None:
    return __fold_binary_constants_8616___impl(op, lhs_val, rhs_val, template)


@cython.ccall
def _rebuild_left_assoc_8616(terms: object, op: object, template: object) -> object:
    term: object
    if not terms:
        return _make_const_8616(0, template)

    current = terms[0]
    for term in terms[1:]:
        current = _make_binop_8616(op, current, term, template)
    return current


@cython.ccall
def _make_binop_8616(op: object, lhs: object, rhs: object, template: object) -> object:
    from angr.analyses.decompiler.structured_codegen import c as structured_c

    return structured_c.CBinaryOp(
        op,
        lhs,
        rhs,
        codegen=_c_codegen(template),
    )


@cython.ccall
def _rebuild_binary_8616(template: object, op: object, lhs: object, rhs: object) -> object:
    if lhs is _c_lhs(template) and rhs is _c_rhs(template):
        return template
    return _make_binop_8616(op, lhs, rhs, template)


@cython.ccall
def _make_const_8616(value: cython.longlong, template: object | None = None) -> object:
    from angr.analyses.decompiler.structured_codegen import c as structured_c
    from angr.sim_type import SimType, SimTypeInt

    type_ = _c_type(template)
    if not isinstance(type_, SimType):
        type_ = SimTypeInt(signed=False, label="int")

    return structured_c.CConstant(
        value,
        type_,
        codegen=_c_codegen(template),
    )


@cython.ccall
def _c_constant_value(expr: object) -> int | None:
    try:
        value = cast(_CExprBoundary, expr).value
    except AttributeError:
        value = None
    if isinstance(value, int):
        return value

    try:
        value = cast(_CExprBoundary, expr).constant
    except AttributeError:
        value = None
    if isinstance(value, int):
        return value

    return None


@cython.ccall
def _same_c_expr_8616(lhs: object, rhs: object) -> cython.bint:
    if lhs is rhs:
        return True
    if type(lhs) is not type(rhs):
        return False

    if _c_constant_value(lhs) is not None or _c_constant_value(rhs) is not None:
        return operator.eq(_c_constant_value(lhs), _c_constant_value(rhs))

    return operator.eq(repr(lhs), repr(rhs))
