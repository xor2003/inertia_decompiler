# cython: language_level=3, infer_types=True
"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Callable


@cython.ccall
def _carry_base_rewrite_plan(
    carry_base: object,
    *,
    expr_contains_dereference: Callable[[object], cython.bint],
    extract_linear_delta: Callable[[object], tuple[object | None, object]],
) -> object:
    base_expr: object
    if carry_base is None:
        return None
    if not expr_contains_dereference(carry_base):
        return None
    base_expr, delta = extract_linear_delta(carry_base)
    if base_expr is None:
        return {"replacement": carry_base, "linear": None}
    return {"replacement": carry_base, "linear": (base_expr, delta)}


@cython.ccall
def _should_commit_linear_rewrite(
    original_expr: object,
    rewritten_expr: object,
    *,
    expr_contains_dereference: Callable[[object], cython.bint],
    same_c_expression: Callable[[object, object], cython.bint],
) -> cython.bint:
    if same_c_expression(original_expr, rewritten_expr):
        return False
    return expr_contains_dereference(rewritten_expr)
