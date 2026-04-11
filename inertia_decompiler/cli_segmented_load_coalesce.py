from __future__ import annotations

from angr.analyses.decompiler.structured_codegen import c as structured_c


def _coalesce_segmented_word_load_expressions(
    project,
    codegen,
    *,
    unwrap_c_casts,
    iter_c_nodes_deep,
    replace_c_children,
    structured_codegen_node,
    match_byte_load_addr_expr,
    match_shifted_high_byte_addr_expr,
    addr_exprs_are_byte_pair,
    classify_segmented_addr_expr,
    resolve_stack_cvar_from_addr_expr,
    make_word_dereference_from_addr_expr,
    describe_alias_storage,
):
    if getattr(codegen, "cfunc", None) is None:
        return False

    dereferenced_variable_ids: set[int] = set()

    def _collect_variable_ids(expr, ids: set[int]) -> None:
        expr = unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CVariable):
            variable = getattr(expr, "variable", None)
            if variable is not None:
                ids.add(id(variable))
            return
        for attr in ("lhs", "rhs", "operand", "expr"):
            if not hasattr(expr, attr):
                continue
            try:
                value = getattr(expr, attr)
            except Exception:
                continue
            if structured_codegen_node(value):
                _collect_variable_ids(value, ids)
        for attr in ("args", "operands", "statements"):
            if not hasattr(expr, attr):
                continue
            try:
                items = getattr(expr, attr)
            except Exception:
                continue
            for item in items or ():
                if structured_codegen_node(item):
                    _collect_variable_ids(item, ids)

    for walk_node in iter_c_nodes_deep(codegen.cfunc.statements):
        if isinstance(walk_node, structured_c.CUnaryOp) and walk_node.op == "Dereference":
            _collect_variable_ids(getattr(walk_node, "operand", None), dereferenced_variable_ids)

    def transform(node):
        if not isinstance(node, structured_c.CBinaryOp) or node.op not in {"Or", "Add"}:
            return node

        for low_expr, high_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            low_addr_expr = match_byte_load_addr_expr(unwrap_c_casts(low_expr))
            if low_addr_expr is None:
                continue

            high_addr_expr = match_shifted_high_byte_addr_expr(high_expr)
            if high_addr_expr is None:
                continue

            low_facts = describe_alias_storage(low_addr_expr)
            high_facts = describe_alias_storage(high_addr_expr)
            if low_facts.identity is None or high_facts.identity is None:
                continue
            if not low_facts.can_join(high_facts):
                continue

            low_addr_ids: set[int] = set()
            high_addr_ids: set[int] = set()
            _collect_variable_ids(low_addr_expr, low_addr_ids)
            _collect_variable_ids(high_addr_expr, high_addr_ids)
            if low_addr_ids & dereferenced_variable_ids or high_addr_ids & dereferenced_variable_ids:
                continue

            if addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, project):
                resolved_lhs = resolve_stack_cvar_from_addr_expr(project, codegen, low_addr_expr)
                low_class = classify_segmented_addr_expr(low_addr_expr, project)
                if resolved_lhs is not None and (low_class is None or low_class.kind != "stack"):
                    return resolved_lhs
                return make_word_dereference_from_addr_expr(codegen, project, low_addr_expr)

        return node

    root = codegen.cfunc.statements
    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
        changed = True
    else:
        changed = False

    if replace_c_children(root, transform):
        changed = True
    return changed
