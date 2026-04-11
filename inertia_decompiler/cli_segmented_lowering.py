from __future__ import annotations

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimRegisterVariable


def _match_segment_register_based_dereference(
    node,
    project,
    *,
    classify_segmented_dereference,
    flatten_c_add_terms,
    unwrap_c_casts,
    c_constant_value,
    segment_reg_name,
):
    classified = classify_segmented_dereference(node, project)
    if classified is None or classified.addr_expr is None or classified.seg_name not in {"ds", "es"}:
        return None
    if not classified.allows_object_rewrite():
        return None

    addr_expr = classified.addr_expr
    base_terms = []
    for term in flatten_c_add_terms(addr_expr):
        inner = unwrap_c_casts(term)
        if isinstance(inner, structured_c.CBinaryOp) and inner.op == "Mul":
            segment_scale = False
            for maybe_seg, maybe_scale in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
                if c_constant_value(unwrap_c_casts(maybe_scale)) != 16:
                    continue
                if segment_reg_name(unwrap_c_casts(maybe_seg), project) is not None:
                    segment_scale = True
                    break
            if segment_scale:
                continue

        if c_constant_value(inner) is not None:
            continue

        if isinstance(inner, structured_c.CVariable) and isinstance(getattr(inner, "variable", None), SimRegisterVariable):
            base_terms.append(inner)
            continue

        return None

    if len(base_terms) != 1:
        return None
    return classified, base_terms[0]


def _strip_segment_scale_from_addr_expr(
    addr_expr,
    project,
    *,
    flatten_c_add_terms,
    unwrap_c_casts,
    c_constant_value,
    segment_reg_name,
):
    kept_terms = []
    for term in flatten_c_add_terms(addr_expr):
        inner = unwrap_c_casts(term)
        if isinstance(inner, structured_c.CBinaryOp) and inner.op == "Mul":
            segment_scale = False
            for maybe_seg, maybe_scale in ((inner.lhs, inner.rhs), (inner.rhs, inner.lhs)):
                if c_constant_value(unwrap_c_casts(maybe_scale)) != 16:
                    continue
                if segment_reg_name(unwrap_c_casts(maybe_seg), project) is not None:
                    segment_scale = True
                    break
            if segment_scale:
                continue
        kept_terms.append(term)

    if not kept_terms:
        return None
    result = kept_terms[0]
    for term in kept_terms[1:]:
        result = structured_c.CBinaryOp("Add", result, term, codegen=getattr(term, "codegen", None))
    return result


def _match_ss_stack_reference(node, project, *, project_rewrite_cache, classify_segmented_dereference):
    cache = project_rewrite_cache(project).setdefault("ss_stack_reference", {})
    key = id(node)
    if key in cache:
        return cache[key]

    classified = classify_segmented_dereference(node, project)
    if classified is not None and classified.kind == "stack" and classified.stack_var is not None and classified.cvar is not None:
        result = (classified.stack_var, classified.cvar, classified.extra_offset)
        cache[key] = result
        return result

    cache[key] = None
    return None
