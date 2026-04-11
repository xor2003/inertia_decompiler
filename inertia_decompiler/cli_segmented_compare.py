from __future__ import annotations


def _split_expr_const_offset(node, *, flatten_c_add_terms, unwrap_c_casts, c_constant_value):
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


def _same_expression_list(lhs_terms, rhs_terms, *, same_c_expression) -> bool:
    if len(lhs_terms) != len(rhs_terms):
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
    low_addr_expr,
    high_addr_expr,
    project,
    *,
    classify_segmented_addr_expr,
    same_c_expression,
    split_expr_const_offset,
    same_expression_list,
):
    low_class = classify_segmented_addr_expr(low_addr_expr, project)
    high_class = classify_segmented_addr_expr(high_addr_expr, project)

    if low_class is not None and high_class is not None:
        if low_class.kind == high_class.kind and low_class.seg_name == high_class.seg_name:
            if low_class.kind == "stack" and low_class.cvar is not None and high_class.cvar is not None:
                if same_c_expression(low_class.cvar, high_class.cvar):
                    return low_class.extra_offset == high_class.extra_offset
            if low_class.kind in {"extra", "segment_const"}:
                return low_class.linear == high_class.linear

    low_terms, low_const = split_expr_const_offset(low_addr_expr)
    high_terms, high_const = split_expr_const_offset(high_addr_expr)
    return low_const == high_const and same_expression_list(low_terms, high_terms)


def _addr_exprs_are_byte_pair(
    low_addr_expr,
    high_addr_expr,
    project=None,
    *,
    classify_segmented_addr_expr,
    stack_slot_identity_can_join_var,
    split_expr_const_offset,
    same_expression_list,
):
    if project is not None:
        low_class = classify_segmented_addr_expr(low_addr_expr, project)
        high_class = classify_segmented_addr_expr(high_addr_expr, project)
        if low_class is not None and high_class is not None:
            if low_class.kind == high_class.kind and low_class.seg_name == high_class.seg_name:
                if low_class.kind == "stack" and low_class.stack_var is not None and high_class.stack_var is not None:
                    if stack_slot_identity_can_join_var(low_class.stack_var, high_class.stack_var):
                        return high_class.extra_offset == low_class.extra_offset + 1
                if low_class.kind in {"extra", "segment_const"}:
                    if low_class.linear is not None and high_class.linear is not None:
                        return high_class.linear == low_class.linear + 1

    low_terms, low_const = split_expr_const_offset(low_addr_expr)
    high_terms, high_const = split_expr_const_offset(high_addr_expr)
    return same_expression_list(low_terms, high_terms) and high_const == low_const + 1
