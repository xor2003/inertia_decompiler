# cython: language_level=3, infer_types=True
"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Callable, Sequence

from inertia.lowering.segmented_lowering import _SegmentedAccess
import operator

ClassifySegmentedAddrExpr = typing.TypeAliasType("ClassifySegmentedAddrExpr", Callable[[object, object], _SegmentedAccess | None])


@cython.ccall
def _split_expr_const_offset(
    node: object,
    *,
    flatten_c_add_terms: Callable[[object], Sequence[object]],
    unwrap_c_casts: Callable[[object], object],
    c_constant_value: Callable[[object], int | None],
) -> tuple[list[object], cython.longlong]:
    constant: object
    term: object
    terms = flatten_c_add_terms(node)
    const_sum = 0
    others = []
    for term in terms:
        constant = c_constant_value(unwrap_c_casts(term))
        if constant is not None:
            const_sum += constant
        else:
            others.append(term)
    return others, const_sum


@cython.ccall
def _same_expression_list(
    lhs_terms: Sequence[object],
    rhs_terms: Sequence[object],
    *,
    same_c_expression: Callable[[object, object], cython.bint],
) -> cython.bint:
    idx: object
    lhs: object
    rhs: object
    if operator.ne(len(lhs_terms), len(rhs_terms)):
        return False

    used = [False] * len(rhs_terms)
    for lhs in lhs_terms:
        matched = False
        for idx, rhs in enumerate(rhs_terms):
            if used[idx]:
                continue
            if same_c_expression(lhs, rhs):
                used[idx] = True
                matched = True
                break
        if not matched:
            return False
    return True


def _addr_exprs_are_same(
    low_addr_expr: object,
    high_addr_expr: object,
    project: object,
    *,
    classify_segmented_addr_expr: ClassifySegmentedAddrExpr,
    same_c_expression: Callable[[object, object], cython.bint],
    split_expr_const_offset: Callable[[object], tuple[Sequence[object], cython.longlong]],
    same_expression_list: Callable[[Sequence[object], Sequence[object]], cython.bint],
) -> cython.bint:
    def _impl() -> cython.bint:
        high_class: object
        low_class: object
        low_class = classify_segmented_addr_expr(low_addr_expr, project)
        high_class = classify_segmented_addr_expr(high_addr_expr, project)

        if low_class is not None and high_class is not None:  # noqa: SIM102
            if operator.eq(low_class.kind, high_class.kind) and operator.eq(low_class.seg_name, high_class.seg_name):
                if low_class.kind == "stack" and low_class.cvar is not None and high_class.cvar is not None:  # noqa: SIM102
                    if same_c_expression(low_class.cvar, high_class.cvar):
                        return bool(operator.eq(low_class.extra_offset, high_class.extra_offset))
                if low_class.kind in {"extra", "segment_const"}:
                    return bool(operator.eq(low_class.linear, high_class.linear))

        low_terms, low_const = split_expr_const_offset(low_addr_expr)
        high_terms, high_const = split_expr_const_offset(high_addr_expr)
        return low_const == high_const and same_expression_list(low_terms, high_terms)

    return _impl()


@cython.ccall
def _strip_zero_segment_scale_terms_8616(
    terms: Sequence[object],
    project: object,
    classify_segmented_addr_expr: ClassifySegmentedAddrExpr,
) -> Sequence[object]:
    """Drop terms that classify as a zero-linear segment scale."""
    classified: object
    term: object
    if project is None:
        return terms
    kept = []
    for term in terms:
        classified = classify_segmented_addr_expr(term, project)
        if classified is not None and classified.kind in {"segment_const", "extra"} and classified.linear == 0:
            continue
        kept.append(term)
    return kept


@cython.ccall
def _classified_byte_pair_8616(
    low_addr_expr: object,
    high_addr_expr: object,
    project: object,
    classify_segmented_addr_expr: ClassifySegmentedAddrExpr,
    stack_slot_identity_can_join_var: Callable[[object, object], cython.bint],
) -> bool | None:
    """Decide a byte-pair match from segmented classification, or defer (None)."""
    high_class: object
    low_class: object
    low_class = classify_segmented_addr_expr(low_addr_expr, project)
    high_class = classify_segmented_addr_expr(high_addr_expr, project)
    if low_class is None or high_class is None:
        return None
    if operator.ne(low_class.kind, high_class.kind) or operator.ne(low_class.seg_name, high_class.seg_name):
        return False
    if (
        low_class.kind == "stack"
        and low_class.stack_var is not None
        and high_class.stack_var is not None
    ) and stack_slot_identity_can_join_var(low_class.stack_var, high_class.stack_var):
        return bool(operator.eq(high_class.extra_offset, low_class.extra_offset + 1))
    if low_class.kind in {"extra", "segment_const"}:  # noqa: SIM102
        if low_class.linear is not None and high_class.linear is not None:
            return bool(operator.eq(high_class.linear, low_class.linear + 1))
    return None


def _addr_exprs_are_byte_pair(
    low_addr_expr: object,
    high_addr_expr: object,
    project: object | None = None,
    *,
    classify_segmented_addr_expr: ClassifySegmentedAddrExpr,
    stack_slot_identity_can_join_var: Callable[[object, object], cython.bint],
    split_expr_const_offset: Callable[[object], tuple[Sequence[object], cython.longlong]],
    same_expression_list: Callable[[Sequence[object], Sequence[object]], cython.bint],
) -> cython.bint:
    classified: object
    if project is not None:
        classified = _classified_byte_pair_8616(
            low_addr_expr,
            high_addr_expr,
            project,
            classify_segmented_addr_expr,
            stack_slot_identity_can_join_var,
        )
        if classified is not None:
            return classified

    low_terms, low_const = split_expr_const_offset(low_addr_expr)
    high_terms, high_const = split_expr_const_offset(high_addr_expr)
    low_terms = _strip_zero_segment_scale_terms_8616(low_terms, project, classify_segmented_addr_expr)
    high_terms = _strip_zero_segment_scale_terms_8616(high_terms, project, classify_segmented_addr_expr)
    return same_expression_list(low_terms, high_terms) and operator.eq(high_const, low_const + 1)

