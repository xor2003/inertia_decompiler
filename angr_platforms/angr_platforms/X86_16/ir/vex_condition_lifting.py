"""Lift VEX condition and flag expressions into typed IR conditions.

Layer: IR.
Responsibility: owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Any, Protocol, cast

from .condition_ir import build_condition_ir_8616, harmonize_condition_args_8616, normalize_condition_op_8616
from .core import IRCondition, IRValue
from .regs import register_name_from_offset

__all__ = (
    "build_condition_from_binop",
    "expr_to_condition",
)

_TmpValues = dict[int, IRValue]
_TmpConditions = dict[int, IRCondition]
_TmpExprs = dict[int, object]
_ExprToValue = Callable[[object, _TmpValues, _TmpConditions], IRValue]


class _VexConstBoundary(Protocol):
    """Minimal pyvex constant surface consumed by condition lifting."""

    value: object


class _VexResultSizeBoundary(Protocol):
    """Minimal pyvex result-size surface consumed by condition lifting."""

    value: object


class _VexExprBoundary(Protocol):
    """Minimal pyvex expression surface consumed by condition lifting."""

    tag: object
    tmp: object
    offset: object
    op: object
    args: object
    con: _VexConstBoundary | None
    cond: object
    iftrue: object
    iffalse: object
    result_size: _VexResultSizeBoundary | None
    ty: object


def _expr_tag(expr: object | None) -> str:
    """Return a VEX expression tag from the pyvex boundary."""
    if expr is None:
        return ""
    try:
        return str(cast(_VexExprBoundary, expr).tag)
    except AttributeError:
        return ""


def _expr_tmp(expr: object) -> int:
    """Return a VEX temporary id from the pyvex boundary."""
    return _external_int(cast(_VexExprBoundary, expr).tmp)


def _expr_offset(expr: object, default: int = -1) -> int:
    """Return a VEX register offset from the pyvex boundary."""
    try:
        return _external_int(cast(_VexExprBoundary, expr).offset)
    except AttributeError:
        return default


def _expr_op(expr: object | None, default: str = "") -> str:
    """Return a VEX expression operation name from the pyvex boundary."""
    if expr is None:
        return default
    try:
        return str(cast(_VexExprBoundary, expr).op)
    except AttributeError:
        return default


def _expr_args(expr: object | None) -> tuple[object, ...]:
    """Return VEX expression arguments as a stable tuple."""
    if expr is None:
        return ()
    try:
        args = cast(_VexExprBoundary, expr).args
    except AttributeError:
        return ()
    if args is None:
        return ()
    return tuple(cast(Iterable[object], args))


def _expr_const(expr: object | None) -> _VexConstBoundary | None:
    """Return a VEX constant boundary object when present."""
    if expr is None:
        return None
    try:
        return cast(_VexExprBoundary, expr).con
    except AttributeError:
        return None


def _expr_cond(expr: object) -> object | None:
    """Return the condition expression from a VEX ITE boundary."""
    try:
        return cast(_VexExprBoundary, expr).cond
    except AttributeError:
        return None


def _expr_iftrue(expr: object) -> object | None:
    """Return the true expression from a VEX ITE boundary."""
    try:
        return cast(_VexExprBoundary, expr).iftrue
    except AttributeError:
        return None


def _expr_iffalse(expr: object) -> object | None:
    """Return the false expression from a VEX ITE boundary."""
    try:
        return cast(_VexExprBoundary, expr).iffalse
    except AttributeError:
        return None


def _external_int(value: object) -> int:
    """Coerce pyvex integer-like boundary values without owning their type."""
    return int(cast(Any, value))


class _FlagBit(IntEnum):
    """x86 flags word bit masks used by VEX flag formulas."""

    CF = 0x0001
    ZF = 0x0040
    SF = 0x0080
    OF = 0x0800


class _FlagPredicateKind(Enum):
    """Typed flag predicate families recovered from VEX formulas."""

    BIT_SET = "bit_set"
    BIT_CLEAR = "bit_clear"
    BITS_EQUAL = "bits_equal"
    BITS_NOT_EQUAL = "bits_not_equal"
    AND = "and"
    OR = "or"


@dataclass(frozen=True, slots=True)
class _FlagPredicate:
    """Structured predicate over one or more x86 flag bits."""

    kind: _FlagPredicateKind
    bit: _FlagBit | None = None
    left_bit: _FlagBit | None = None
    right_bit: _FlagBit | None = None
    left: _FlagPredicate | None = None
    right: _FlagPredicate | None = None


_INVERT_CONDITION_OPS = {
    "eq": "ne",
    "ne": "eq",
    "zero": "nonzero",
    "nonzero": "zero",
    "ult": "uge",
    "uge": "ult",
    "ule": "ugt",
    "ugt": "ule",
    "slt": "sge",
    "sge": "slt",
    "sle": "sgt",
    "sgt": "sle",
}


def _zero_fold(cond_op: str, left: IRValue, right: IRValue) -> IRCondition | None:
    if cond_op not in {"eq", "ne"}:
        return None
    if right.const == 0:
        return build_condition_ir_8616("zero" if cond_op == "eq" else "nonzero", left, expr=("zero_fold",))
    if left.const == 0:
        return build_condition_ir_8616("zero" if cond_op == "eq" else "nonzero", right, expr=("zero_fold",))
    return None


def _compare_size_bytes(op: str) -> int:
    match = re.search(r"(\d+)(?:[SU])?$", op)
    if match is None:
        return 0
    bits = int(match.group(1))
    return 0 if bits <= 0 else max(1, bits // 8)


def build_condition_from_binop(op: str, left: IRValue, right: IRValue) -> IRCondition | None:
    """Recover a typed IR condition from a two-argument VEX comparison op."""
    folded = op.lower()
    left, right = harmonize_condition_args_8616(left, right, size=_compare_size_bytes(op))
    variants = {
        "cmpeq": "eq",
        "cmpne": "ne",
        "cmplt": "lt",
        "cmple": "le",
        "cmpgt": "gt",
        "cmpge": "ge",
        "cascmp": "eq",
    }
    for needle, cond_op in variants.items():
        if needle not in folded:
            continue
        zero_fold = _zero_fold(cond_op, left, right)
        if zero_fold is not None:
            return zero_fold
        if folded.endswith("s"):
            return build_condition_ir_8616(normalize_condition_op_8616(f"s{cond_op}"), left, right, expr=(op,))
        if folded.endswith("u"):
            return build_condition_ir_8616(normalize_condition_op_8616(f"u{cond_op}"), left, right, expr=(op,))
        return build_condition_ir_8616(normalize_condition_op_8616(cond_op), left, right, expr=(op,))
    return None


def _nonzero_condition(value: IRValue, *, source: str) -> IRCondition:
    return build_condition_ir_8616("nonzero", value, expr=(source,))


def _masked_nonzero_condition(left: IRValue, right: IRValue, *, source: str) -> IRCondition:
    return IRCondition(op="masked_nonzero", args=(left, right), expr=(source,))


def _const_value(expr: object | None) -> int | None:
    con = _expr_const(expr)
    if con is None:
        return None
    value = con.value
    return None if value is None else _external_int(value)


def _invert_condition(cond: IRCondition) -> IRCondition:
    def _impl() -> IRCondition:
        inverted_op = _INVERT_CONDITION_OPS.get(cond.op)
        if inverted_op is not None:
            args = cond.args
            if all(isinstance(arg, IRValue) for arg in args):
                value_args = cast(tuple[IRValue, ...], args)
                return build_condition_ir_8616(normalize_condition_op_8616(inverted_op), *value_args, expr=cond.expr)
        if cond.op == "not" and len(cond.args) == 1 and isinstance(cond.args[0], IRCondition):
            return cond.args[0]
        if cond.op == "and" and len(cond.args) == 2 and all(isinstance(arg, IRCondition) for arg in cond.args):
            left = _invert_condition(cast(IRCondition, cond.args[0]))
            right = _invert_condition(cast(IRCondition, cond.args[1]))
            return IRCondition(op="or", args=(left, right), expr=cond.expr)
        if cond.op == "or" and len(cond.args) == 2 and all(isinstance(arg, IRCondition) for arg in cond.args):
            left = _invert_condition(cast(IRCondition, cond.args[0]))
            right = _invert_condition(cast(IRCondition, cond.args[1]))
            return IRCondition(op="and", args=(left, right), expr=cond.expr)
        return IRCondition(op="not", args=(cond,), expr=cond.expr)

    return _impl()


def _resolve_tmp_expr(expr: object, tmp_exprs: _TmpExprs | None, seen: set[int] | None = None) -> object:
    if _expr_tag(expr) != "Iex_RdTmp" or tmp_exprs is None:
        return expr
    tmp_id = _expr_tmp(expr)
    if seen is None:
        seen = set()
    if tmp_id in seen:
        return expr
    resolved = tmp_exprs.get(tmp_id)
    if resolved is None:
        return expr
    seen.add(tmp_id)
    return _resolve_tmp_expr(resolved, tmp_exprs, seen)


def _is_flags_expr(expr: object, tmp_exprs: _TmpExprs | None) -> bool:
    resolved = _resolve_tmp_expr(expr, tmp_exprs)
    tag = _expr_tag(resolved)
    if tag == "Iex_Get":
        return bool(register_name_from_offset(_expr_offset(resolved)) == "flags")
    if tag == "Iex_Unop":
        args = _expr_args(resolved)
        return bool(args) and _is_flags_expr(args[0], tmp_exprs)
    return False


def _flag_bit_from_mask(mask: int | None) -> _FlagBit | None:
    if mask is None:
        return None
    try:
        return _FlagBit(int(mask))
    except ValueError:
        return None


def _extract_flag_bit_expr(expr: object, tmp_exprs: _TmpExprs | None) -> _FlagBit | None:
    resolved = _resolve_tmp_expr(expr, tmp_exprs)
    if _expr_tag(resolved) != "Iex_Binop":
        return None
    op = _expr_op(resolved).lower()
    if "and" not in op:
        return None
    args = _expr_args(resolved)
    if len(args) != 2:
        return None
    left, right = args
    if _is_flags_expr(left, tmp_exprs):
        return _flag_bit_from_mask(_const_value(_resolve_tmp_expr(right, tmp_exprs)))
    if _is_flags_expr(right, tmp_exprs):
        return _flag_bit_from_mask(_const_value(_resolve_tmp_expr(left, tmp_exprs)))
    return None


def _extract_boolean_flag_test(expr: object, tmp_exprs: _TmpExprs | None) -> tuple[_FlagBit, bool] | None:
    resolved = _resolve_tmp_expr(expr, tmp_exprs)
    if _expr_tag(resolved) != "Iex_Binop":
        return None
    op = _expr_op(resolved).lower()
    args = _expr_args(resolved)
    if len(args) != 2:
        return None
    left, right = args
    left_bit = _extract_flag_bit_expr(left, tmp_exprs)
    right_bit = _extract_flag_bit_expr(right, tmp_exprs)
    left_const = _const_value(_resolve_tmp_expr(left, tmp_exprs))
    right_const = _const_value(_resolve_tmp_expr(right, tmp_exprs))
    if left_bit is not None and right_const == 0:
        return left_bit, "cmpne" in op
    if right_bit is not None and left_const == 0:
        return right_bit, "cmpne" in op
    return None


def _extract_masked_flag_pair_test(
    lhs: object,
    rhs: object,
    tmp_exprs: _TmpExprs | None,
) -> tuple[_FlagBit, _FlagBit] | None:
    left_bit = _extract_flag_bit_expr(lhs, tmp_exprs)
    right_bit = _extract_flag_bit_expr(rhs, tmp_exprs)
    if left_bit is None or right_bit is None:
        return None
    return left_bit, right_bit


def _invert_flag_predicate_8616(pred: _FlagPredicate) -> _FlagPredicate | None:
    def _impl() -> _FlagPredicate | None:
        if pred.kind == _FlagPredicateKind.BIT_SET:
            return _FlagPredicate(_FlagPredicateKind.BIT_CLEAR, bit=pred.bit)
        if pred.kind == _FlagPredicateKind.BIT_CLEAR:
            return _FlagPredicate(_FlagPredicateKind.BIT_SET, bit=pred.bit)
        if pred.kind == _FlagPredicateKind.BITS_EQUAL:
            return _FlagPredicate(
                _FlagPredicateKind.BITS_NOT_EQUAL,
                left_bit=pred.left_bit,
                right_bit=pred.right_bit,
            )
        if pred.kind == _FlagPredicateKind.BITS_NOT_EQUAL:
            return _FlagPredicate(
                _FlagPredicateKind.BITS_EQUAL,
                left_bit=pred.left_bit,
                right_bit=pred.right_bit,
            )
        if pred.kind == _FlagPredicateKind.AND and pred.left is not None and pred.right is not None:
            left_pred = _invert_flag_predicate_8616(pred.left)
            right_pred = _invert_flag_predicate_8616(pred.right)
            if left_pred is None or right_pred is None:
                return None
            return _FlagPredicate(_FlagPredicateKind.OR, left=left_pred, right=right_pred)
        if pred.kind == _FlagPredicateKind.OR and pred.left is not None and pred.right is not None:
            left_pred = _invert_flag_predicate_8616(pred.left)
            right_pred = _invert_flag_predicate_8616(pred.right)
            if left_pred is None or right_pred is None:
                return None
            return _FlagPredicate(_FlagPredicateKind.AND, left=left_pred, right=right_pred)
        return None

    return _impl()


def _flag_predicate_from_expr(expr: object, tmp_exprs: _TmpExprs | None) -> _FlagPredicate | None:
    return _flag_predicate_impl_8616(expr, tmp_exprs)


def _flag_predicate_cmp_8616(
    op: str,
    left: object,
    right: object,
    tmp_exprs: _TmpExprs | None,
) -> _FlagPredicate | None:
    """Lift one flag-compare Binop arm to a bit-equality predicate."""
    if "cmpeq" not in op and "cmpne" not in op:
        return None
    left_test = _extract_boolean_flag_test(left, tmp_exprs)
    right_test = _extract_boolean_flag_test(right, tmp_exprs)
    if left_test is not None and right_test is not None:
        left_bit, left_set = left_test
        right_bit, right_set = right_test
        same_truth = left_set == right_set
        if "cmpeq" in op:
            return _FlagPredicate(
                _FlagPredicateKind.BITS_EQUAL if same_truth else _FlagPredicateKind.BITS_NOT_EQUAL,
                left_bit=left_bit,
                right_bit=right_bit,
            )
        return _FlagPredicate(
            _FlagPredicateKind.BITS_NOT_EQUAL if same_truth else _FlagPredicateKind.BITS_EQUAL,
            left_bit=left_bit,
            right_bit=right_bit,
        )

    masked_bits = _extract_masked_flag_pair_test(left, right, tmp_exprs)
    if masked_bits is None:
        return None
    left_bit, right_bit = masked_bits
    if "cmpeq" in op:
        return _FlagPredicate(
            _FlagPredicateKind.BITS_EQUAL,
            left_bit=left_bit,
            right_bit=right_bit,
        )
    return _FlagPredicate(
        _FlagPredicateKind.BITS_NOT_EQUAL,
        left_bit=left_bit,
        right_bit=right_bit,
    )


def _flag_predicate_binop_8616(
    resolved: object,
    op: str,
    left: object,
    right: object,
    tmp_exprs: _TmpExprs | None,
) -> _FlagPredicate | None:
    """Lift one Binop expression to a flag predicate."""
    flag_test = _extract_boolean_flag_test(resolved, tmp_exprs)
    if flag_test is not None:
        bit, is_set = flag_test
        return _FlagPredicate(_FlagPredicateKind.BIT_SET if is_set else _FlagPredicateKind.BIT_CLEAR, bit=bit)
    if "and" in op:
        left_pred = _flag_predicate_from_expr(left, tmp_exprs)
        right_pred = _flag_predicate_from_expr(right, tmp_exprs)
        if left_pred is not None and right_pred is not None:
            return _FlagPredicate(_FlagPredicateKind.AND, left=left_pred, right=right_pred)
    if "or" in op:
        left_pred = _flag_predicate_from_expr(left, tmp_exprs)
        right_pred = _flag_predicate_from_expr(right, tmp_exprs)
        if left_pred is not None and right_pred is not None:
            return _FlagPredicate(_FlagPredicateKind.OR, left=left_pred, right=right_pred)
    return _flag_predicate_cmp_8616(op, left, right, tmp_exprs)


def _flag_predicate_impl_8616(expr: object, tmp_exprs: _TmpExprs | None) -> _FlagPredicate | None:
    resolved = _resolve_tmp_expr(expr, tmp_exprs)
    tag = _expr_tag(resolved)
    if tag == "Iex_Unop":
        op = _expr_op(resolved).lower()
        args = _expr_args(resolved)
        if len(args) != 1:
            return None
        if "not" not in op:
            return None
        inner = _flag_predicate_from_expr(args[0], tmp_exprs)
        if inner is None:
            return None
        return _invert_flag_predicate_8616(inner)
    if tag == "Iex_Binop":
        op = _expr_op(resolved).lower()
        args = _expr_args(resolved)
        if len(args) != 2:
            return None
        left, right = args
        return _flag_predicate_binop_8616(resolved, op, left, right, tmp_exprs)
    return None


def _looks_like_flag_compare(cond: IRCondition) -> bool:
    for arg in cond.args:
        if not isinstance(arg, IRValue):
            continue
        if arg.space.name == "REG" and arg.name == "flags":
            return True
        if (arg.name or "").startswith("mask:flags"):
            return True
    return False


def _latest_nonflag_compare(conditions: dict[int, IRCondition]) -> IRCondition | None:
    for cond in reversed(tuple(conditions.values())):
        if cond.op not in {"eq", "ne", "ult", "ule", "ugt", "uge", "slt", "sle", "sgt", "sge"}:
            continue
        if len(cond.args) != 2:
            continue
        if _looks_like_flag_compare(cond):
            continue
        return cond
    return None


def _simple_flag_ops_8616(pred: _FlagPredicate) -> str | None:
    """Map single-bit and bit-pair predicates to their condition op."""
    if pred.kind == _FlagPredicateKind.BIT_SET and pred.bit == _FlagBit.ZF:
        return "eq"
    if pred.kind == _FlagPredicateKind.BIT_CLEAR and pred.bit == _FlagBit.ZF:
        return "ne"
    if pred.kind == _FlagPredicateKind.BIT_SET and pred.bit == _FlagBit.CF:
        return "ult"
    if pred.kind == _FlagPredicateKind.BIT_CLEAR and pred.bit == _FlagBit.CF:
        return "uge"
    if pred.kind == _FlagPredicateKind.BITS_NOT_EQUAL and {pred.left_bit, pred.right_bit} == {
        _FlagBit.SF,
        _FlagBit.OF,
    }:
        return "slt"
    if pred.kind == _FlagPredicateKind.BITS_EQUAL and {pred.left_bit, pred.right_bit} == {_FlagBit.SF, _FlagBit.OF}:
        return "sge"
    return None


def _compound_flag_ops_8616(pred: _FlagPredicate) -> str | None:
    """Map compound AND/OR flag predicates to their condition op."""
    if pred.kind == _FlagPredicateKind.OR and pred.left is not None and pred.right is not None:
        if {
            (pred.left.kind, pred.left.bit),
            (pred.right.kind, pred.right.bit),
        } == {
            (_FlagPredicateKind.BIT_SET, _FlagBit.CF),
            (_FlagPredicateKind.BIT_SET, _FlagBit.ZF),
        }:
            return "ule"
        if {pred.left.kind, pred.right.kind} == {_FlagPredicateKind.BIT_SET, _FlagPredicateKind.BITS_NOT_EQUAL}:
            bit_pred = pred.left if pred.left.kind == _FlagPredicateKind.BIT_SET else pred.right
            cmp_pred = pred.right if bit_pred is pred.left else pred.left
            if bit_pred.bit == _FlagBit.ZF and {cmp_pred.left_bit, cmp_pred.right_bit} == {
                _FlagBit.SF,
                _FlagBit.OF,
            }:
                return "sle"
    if pred.kind == _FlagPredicateKind.AND and pred.left is not None and pred.right is not None:
        if {
            (pred.left.kind, pred.left.bit),
            (pred.right.kind, pred.right.bit),
        } == {
            (_FlagPredicateKind.BIT_CLEAR, _FlagBit.CF),
            (_FlagPredicateKind.BIT_CLEAR, _FlagBit.ZF),
        }:
            return "ugt"
        if {pred.left.kind, pred.right.kind} == {_FlagPredicateKind.BIT_CLEAR, _FlagPredicateKind.BITS_EQUAL}:
            bit_pred = pred.left if pred.left.kind == _FlagPredicateKind.BIT_CLEAR else pred.right
            cmp_pred = pred.right if bit_pred is pred.left else pred.left
            if bit_pred.bit == _FlagBit.ZF and {cmp_pred.left_bit, cmp_pred.right_bit} == {
                _FlagBit.SF,
                _FlagBit.OF,
            }:
                return "sgt"
    return None


def _condition_op_from_flag_predicate(pred: _FlagPredicate) -> str | None:
    simple = _simple_flag_ops_8616(pred)
    if simple is not None:
        return simple
    return _compound_flag_ops_8616(pred)


def _flag_formula_condition(expr: object, conditions: _TmpConditions, tmp_exprs: _TmpExprs | None) -> IRCondition | None:
    pred = _flag_predicate_from_expr(expr, tmp_exprs)
    if pred is None:
        return None
    cond_op = _condition_op_from_flag_predicate(pred)
    if cond_op is None:
        return None
    compare = _latest_nonflag_compare(conditions)
    if compare is None:
        return None
    lhs, rhs = compare.args
    if not isinstance(lhs, IRValue) or not isinstance(rhs, IRValue):
        return None
    return build_condition_ir_8616(normalize_condition_op_8616(cond_op), lhs, rhs, expr=("flag_jcc_formula", cond_op))


def _try_expr_to_condition(
    expr: object,
    tmps: _TmpValues,
    conditions: _TmpConditions,
    *,
    expr_to_value: _ExprToValue,
    tmp_exprs: _TmpExprs | None = None,
) -> IRCondition | None:
    return _try_expr_to_condition_impl_8616(
        expr, tmps, conditions, expr_to_value=expr_to_value, tmp_exprs=tmp_exprs
    )


def _try_binop_condition_8616(
    expr: object,
    tmps: _TmpValues,
    conditions: _TmpConditions,
    *,
    expr_to_value: _ExprToValue,
    tmp_exprs: _TmpExprs | None,
) -> IRCondition | None:
    """Lift one Binop expression to a logical or comparison condition."""
    formula_cond = _flag_formula_condition(expr, conditions, tmp_exprs)
    if formula_cond is not None:
        return formula_cond
    op = _expr_op(expr)
    args = _expr_args(expr)
    if len(args) != 2:
        return None
    lowered = op.lower()
    if "and" in lowered:
        return _logical_condition(
            "and",
            args[0],
            args[1],
            tmps,
            conditions,
            expr_to_value=expr_to_value,
            source=op,
            tmp_exprs=tmp_exprs,
        )
    if "or" in lowered:
        return _logical_condition(
            "or",
            args[0],
            args[1],
            tmps,
            conditions,
            expr_to_value=expr_to_value,
            source=op,
            tmp_exprs=tmp_exprs,
        )
    left = expr_to_value(args[0], tmps, conditions)
    right = expr_to_value(args[1], tmps, conditions)
    return build_condition_from_binop(op, left, right)


def _try_ite_condition_8616(
    expr: object,
    tmps: _TmpValues,
    conditions: _TmpConditions,
    *,
    expr_to_value: _ExprToValue,
    tmp_exprs: _TmpExprs | None,
) -> IRCondition | None:
    """Lift one ITE 1/0 arm to its branch condition, possibly inverted."""
    cond_expr = _expr_cond(expr)
    iftrue = _expr_iftrue(expr)
    iffalse = _expr_iffalse(expr)
    cond = _try_expr_to_condition(cond_expr, tmps, conditions, expr_to_value=expr_to_value, tmp_exprs=tmp_exprs)
    if cond is None:
        return None
    iftrue_const = _const_value(iftrue)
    iffalse_const = _const_value(iffalse)
    if (iftrue_const, iffalse_const) == (1, 0):
        return cond
    if (iftrue_const, iffalse_const) == (0, 1):
        return _invert_condition(cond)
    return None


def _try_expr_to_condition_impl_8616(
    expr: object,
    tmps: _TmpValues,
    conditions: _TmpConditions,
    *,
    expr_to_value: _ExprToValue,
    tmp_exprs: _TmpExprs | None,
) -> IRCondition | None:
    tag = _expr_tag(expr)
    if tag == "Iex_RdTmp":
        tmp_id = _expr_tmp(expr)
        cond = conditions.get(tmp_id)
        if cond is not None:
            return cond
        if tmp_exprs is not None and tmp_id in tmp_exprs:
            return _try_expr_to_condition(
                tmp_exprs[tmp_id], tmps, conditions, expr_to_value=expr_to_value, tmp_exprs=tmp_exprs
            )
        return None
    if tag == "Iex_Binop":
        return _try_binop_condition_8616(
            expr, tmps, conditions, expr_to_value=expr_to_value, tmp_exprs=tmp_exprs
        )
    if tag == "Iex_ITE":
        return _try_ite_condition_8616(
            expr, tmps, conditions, expr_to_value=expr_to_value, tmp_exprs=tmp_exprs
        )
    return None


def _logical_condition(
    op: str,
    lhs: object,
    rhs: object,
    tmps: _TmpValues,
    conditions: _TmpConditions,
    *,
    expr_to_value: _ExprToValue,
    source: str,
    tmp_exprs: _TmpExprs | None = None,
) -> IRCondition | None:
    lhs_cond = _try_expr_to_condition(lhs, tmps, conditions, expr_to_value=expr_to_value, tmp_exprs=tmp_exprs)
    rhs_cond = _try_expr_to_condition(rhs, tmps, conditions, expr_to_value=expr_to_value, tmp_exprs=tmp_exprs)
    if lhs_cond is None or rhs_cond is None:
        return None
    return IRCondition(op=op, args=(lhs_cond, rhs_cond), expr=(source,))


def expr_to_condition(
    expr: object,
    tmps: _TmpValues,
    conditions: _TmpConditions,
    *,
    expr_to_value: _ExprToValue,
    tmp_exprs: _TmpExprs | None = None,
) -> IRCondition:
    """Recover a typed IR condition from a VEX expression boundary."""
    return _expr_to_condition_impl_8616(
        expr, tmps, conditions, expr_to_value=expr_to_value, tmp_exprs=tmp_exprs
    )


def _binop_expr_condition_8616(
    expr: object,
    tmps: _TmpValues,
    conditions: _TmpConditions,
    *,
    expr_to_value: _ExprToValue,
    tmp_exprs: _TmpExprs | None,
) -> IRCondition | None:
    """Recover a formula, comparison, logical, or masked condition from a Binop."""
    op = _expr_op(expr)
    args = _expr_args(expr)
    if len(args) != 2:
        return None
    formula_cond = _flag_formula_condition(expr, conditions, tmp_exprs)
    if formula_cond is not None:
        return formula_cond
    left = expr_to_value(args[0], tmps, conditions)
    right = expr_to_value(args[1], tmps, conditions)
    cond = build_condition_from_binop(op, left, right)
    if cond is not None:
        return cond
    logical = _try_expr_to_condition(
        expr, tmps, conditions, expr_to_value=expr_to_value, tmp_exprs=tmp_exprs
    )
    if logical is not None:
        return logical
    if "And" in op:
        return _masked_nonzero_condition(left, right, source=op)
    return None


def _expr_to_condition_impl_8616(
    expr: object,
    tmps: _TmpValues,
    conditions: _TmpConditions,
    *,
    expr_to_value: _ExprToValue,
    tmp_exprs: _TmpExprs | None,
) -> IRCondition:
    tag = _expr_tag(expr)
    if tag == "Iex_RdTmp":
        tmp_id = _expr_tmp(expr)
        if tmp_id in conditions:
            return conditions[tmp_id]
        return _nonzero_condition(expr_to_value(expr, tmps, conditions), source=f"rdtmp:{tmp_id}")
    if tag == "Iex_Binop":
        binop_cond = _binop_expr_condition_8616(
            expr, tmps, conditions, expr_to_value=expr_to_value, tmp_exprs=tmp_exprs
        )
        if binop_cond is not None:
            return binop_cond
    if tag == "Iex_ITE":
        cond = _try_expr_to_condition(expr, tmps, conditions, expr_to_value=expr_to_value, tmp_exprs=tmp_exprs)
        if cond is not None:
            return cond
    return _nonzero_condition(expr_to_value(expr, tmps, conditions), source=tag or "expr")
