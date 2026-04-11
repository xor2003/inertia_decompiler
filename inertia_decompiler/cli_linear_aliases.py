from __future__ import annotations

from collections import Counter

from angr.analyses.decompiler.structured_codegen import c as structured_c


def _seed_adjacent_byte_pair_aliases(
    project,
    codegen,
    *,
    structured_codegen_node,
    unwrap_c_casts,
    iter_c_nodes_deep,
    match_byte_load_addr_expr,
    addr_exprs_are_byte_pair,
    make_word_dereference_from_addr_expr,
):
    if getattr(codegen, "cfunc", None) is None:
        return {}

    statements = getattr(codegen.cfunc, "statements", None)
    if not structured_codegen_node(statements):
        return {}

    aliases: dict[int, object] = {}

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

    def _count_variable_ids(expr, counts: Counter[int]) -> None:
        expr = unwrap_c_casts(expr)
        if isinstance(expr, structured_c.CVariable):
            variable = getattr(expr, "variable", None)
            if variable is not None:
                counts[id(variable)] += 1
            return
        for attr in ("lhs", "rhs", "operand", "expr"):
            if not hasattr(expr, attr):
                continue
            try:
                value = getattr(expr, attr)
            except Exception:
                continue
            if structured_codegen_node(value):
                _count_variable_ids(value, counts)
        for attr in ("args", "operands", "statements"):
            if not hasattr(expr, attr):
                continue
            try:
                items = getattr(expr, attr)
            except Exception:
                continue
            for item in items or ():
                if structured_codegen_node(item):
                    _count_variable_ids(item, counts)

    dereference_counts: Counter[int] = Counter()
    for node in iter_c_nodes_deep(statements):
        if isinstance(node, structured_c.CUnaryOp) and node.op == "Dereference":
            _count_variable_ids(getattr(node, "operand", None), dereference_counts)

    def _record_alias(lhs, expr) -> None:
        variable = getattr(lhs, "variable", None)
        if variable is None:
            return
        aliases[id(variable)] = expr

    def visit(node) -> None:
        if isinstance(node, structured_c.CStatements):
            stmt_list = getattr(node, "statements", None)
            if isinstance(stmt_list, list):
                for index in range(len(stmt_list) - 1):
                    low_stmt = stmt_list[index]
                    high_stmt = stmt_list[index + 1]
                    if not (
                        isinstance(low_stmt, structured_c.CAssignment)
                        and isinstance(high_stmt, structured_c.CAssignment)
                        and isinstance(low_stmt.lhs, structured_c.CVariable)
                        and isinstance(high_stmt.lhs, structured_c.CVariable)
                    ):
                        continue

                    low_addr_expr = match_byte_load_addr_expr(unwrap_c_casts(low_stmt.rhs))
                    high_addr_expr = match_byte_load_addr_expr(unwrap_c_casts(high_stmt.rhs))
                    if low_addr_expr is None or high_addr_expr is None:
                        continue
                    if not addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, project):
                        continue

                    pair_counts: Counter[int] = Counter()
                    _count_variable_ids(low_addr_expr, pair_counts)
                    _count_variable_ids(high_addr_expr, pair_counts)
                    if any(dereference_counts[var_id] > pair_counts[var_id] for var_id in pair_counts):
                        continue

                    word_expr = make_word_dereference_from_addr_expr(codegen, project, low_addr_expr)
                    _record_alias(low_stmt.lhs, word_expr)
                    _record_alias(high_stmt.lhs, word_expr)
            for stmt in getattr(node, "statements", ()) or ():
                visit(stmt)
            return

        if isinstance(node, structured_c.CIfElse):
            for cond, body in getattr(node, "condition_and_nodes", ()) or ():
                visit(cond)
                visit(body)
            else_node = getattr(node, "else_node", None)
            if else_node is not None:
                visit(else_node)
            return

        if isinstance(node, structured_c.CWhileLoop):
            visit(getattr(node, "condition", None))
            visit(getattr(node, "body", None))
            return

        if hasattr(structured_c, "CDoWhileLoop") and isinstance(node, getattr(structured_c, "CDoWhileLoop")):
            visit(getattr(node, "condition", None))
            visit(getattr(node, "body", None))
            return

        if hasattr(structured_c, "CForLoop") and isinstance(node, getattr(structured_c, "CForLoop")):
            visit(getattr(node, "init", None))
            visit(getattr(node, "condition", None))
            visit(getattr(node, "iteration", None))
            visit(getattr(node, "body", None))
            return

    visit(statements)
    return aliases
