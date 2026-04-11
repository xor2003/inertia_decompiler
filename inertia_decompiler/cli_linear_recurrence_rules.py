from __future__ import annotations


def _carry_base_rewrite_plan(carry_base, *, expr_contains_dereference, extract_linear_delta):
    if carry_base is None:
        return None
    if not expr_contains_dereference(carry_base):
        return None
    base_expr, delta = extract_linear_delta(carry_base)
    if base_expr is None:
        return {"replacement": carry_base, "linear": None}
    return {"replacement": carry_base, "linear": (base_expr, delta)}


def _should_commit_linear_rewrite(original_expr, rewritten_expr, *, expr_contains_dereference, same_c_expression):
    if same_c_expression(original_expr, rewritten_expr):
        return False
    return expr_contains_dereference(rewritten_expr)
