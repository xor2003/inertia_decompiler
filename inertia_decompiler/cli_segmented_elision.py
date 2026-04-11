from __future__ import annotations

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable


def _elide_redundant_segment_pointer_dereferences(
    project,
    codegen,
    *,
    iter_c_nodes_deep,
    classify_segmented_dereference,
    flatten_c_add_terms,
    unwrap_c_casts,
    c_constant_value,
    segment_reg_name,
    match_segment_register_based_dereference,
    strip_segment_scale_from_addr_expr,
    same_c_storage,
    replace_c_children,
):
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False
    eligible_bases: dict[int, tuple[structured_c.CVariable, set[int]]] = {}

    def collect_candidate_bases() -> None:
        for node in iter_c_nodes_deep(codegen.cfunc.statements):
            classified = classify_segmented_dereference(node, project)
            if classified is None or classified.addr_expr is None or classified.seg_name not in {"ds", "es"}:
                continue

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

                base_terms = []
                break

            if len(base_terms) != 1:
                continue
            base_var = getattr(base_terms[0], "variable", None)
            if not isinstance(base_var, SimRegisterVariable):
                continue
            entry = eligible_bases.get(id(base_var))
            if entry is None:
                eligible_bases[id(base_var)] = (base_terms[0], {classified.extra_offset})
            else:
                entry[1].add(classified.extra_offset)

    def _addr_expr_is_safe_projection(addr_expr) -> bool:
        allowed_ops = {"Add", "Sub", "Mul", "And", "Or", "Xor", "Shl", "Shr", "Div"}

        def _check(node) -> bool:
            node = unwrap_c_casts(node)
            if c_constant_value(node) is not None:
                return True
            if isinstance(node, structured_c.CVariable) and isinstance(getattr(node, "variable", None), SimRegisterVariable):
                return True
            if isinstance(node, structured_c.CUnaryOp) and node.op in {"Neg", "BitNot"}:
                return _check(node.operand)
            if isinstance(node, structured_c.CBinaryOp) and node.op in allowed_ops:
                return _check(node.lhs) and _check(node.rhs)
            return False

        return _check(addr_expr)

    def make_deref(base_expr, bits: int):
        element_type = SimTypeChar(False) if bits == 8 else SimTypeShort(False)
        ptr_type = SimTypePointer(element_type).with_arch(project.arch)
        return structured_c.CUnaryOp(
            "Dereference",
            structured_c.CTypeCast(None, ptr_type, base_expr, codegen=codegen),
            codegen=codegen,
        )

    def transform(node):
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            return node
        match = match_segment_register_based_dereference(node, project)
        if match is None:
            classified = classify_segmented_dereference(node, project)
            if classified is None or classified.seg_name not in {"ds", "es"} or classified.addr_expr is None:
                return node
            base_expr = strip_segment_scale_from_addr_expr(classified.addr_expr, project)
            if base_expr is None or not _addr_expr_is_safe_projection(base_expr):
                return node
            if classified.cvar is None or not isinstance(base_expr, structured_c.CVariable):
                return node
            if not same_c_storage(base_expr, classified.cvar):
                return node
        else:
            classified, base_expr = match
            base_var = getattr(getattr(base_expr, "variable", None), "reg", None)
            if base_var is None:
                return node
            eligible = eligible_bases.get(id(getattr(base_expr, "variable", None)))
            if eligible is None or eligible[1] != {0}:
                return node
        type_ = getattr(node, "type", None)
        bits = getattr(type_, "size", None)
        if bits != 8:
            return node
        return make_deref(base_expr, bits)

    collect_candidate_bases()
    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    if replace_c_children(root, transform):
        changed = True
    return changed
