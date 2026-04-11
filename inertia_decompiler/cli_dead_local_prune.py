from __future__ import annotations

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable


def _expr_has_side_effects(node, *, iter_c_nodes_deep) -> bool:
    return any(isinstance(subnode, structured_c.CFunctionCall) for subnode in iter_c_nodes_deep(node))


def _prune_dead_local_assignments(
    codegen,
    *,
    structured_codegen_node,
    iter_c_nodes_deep,
    unwrap_c_casts,
    describe_alias_storage,
) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False
    root = getattr(codegen.cfunc, "statements", None)
    if not structured_codegen_node(root):
        return False

    def collect_storage_read_keys(
        node,
        keys: set[tuple[object, ...]],
        seen: set[int] | None = None,
        *,
        allow_variable_read: bool = True,
    ) -> None:
        if not structured_codegen_node(node):
            return
        if seen is None:
            seen = set()
        node_id = id(node)
        if node_id in seen:
            return
        seen.add(node_id)
        try:
            if isinstance(node, structured_c.CVariable):
                if allow_variable_read:
                    variable = getattr(node, "variable", None)
                    if variable is not None:
                        keys.add(("var", id(variable)))
                        unified = getattr(node, "unified_variable", None)
                        if unified is not None:
                            keys.add(("unified", id(unified)))
                        storage_key = describe_alias_storage(node).identity
                        if storage_key is not None:
                            keys.add(("storage", storage_key))
                return

            if isinstance(node, structured_c.CAssignment):
                if structured_codegen_node(node.lhs):
                    collect_storage_read_keys(node.lhs, keys, seen, allow_variable_read=False)
                if structured_codegen_node(node.rhs):
                    collect_storage_read_keys(node.rhs, keys, seen, allow_variable_read=True)
                return

            for attr in ("lhs", "rhs", "expr", "operand", "condition", "cond", "body", "iffalse", "iftrue", "else_node", "retval"):
                if not hasattr(node, attr):
                    continue
                try:
                    value = getattr(node, attr)
                except Exception:
                    continue
                if structured_codegen_node(value):
                    collect_storage_read_keys(value, keys, seen)

            for attr in ("args", "operands", "statements"):
                if not hasattr(node, attr):
                    continue
                try:
                    items = getattr(node, attr)
                except Exception:
                    continue
                if not items:
                    continue
                for item in items:
                    if structured_codegen_node(item):
                        collect_storage_read_keys(item, keys, seen)

            if hasattr(node, "condition_and_nodes"):
                try:
                    pairs = getattr(node, "condition_and_nodes")
                except Exception:
                    pairs = None
                if pairs:
                    for cond, body in pairs:
                        if structured_codegen_node(cond):
                            collect_storage_read_keys(cond, keys, seen)
                        if structured_codegen_node(body):
                            collect_storage_read_keys(body, keys, seen)
        finally:
            seen.remove(node_id)

    reads: set[tuple[object, ...]] = set()
    collect_storage_read_keys(root, reads)

    def is_local_variable(variable) -> bool:
        return isinstance(variable, (SimRegisterVariable, SimStackVariable))

    def collect_stmt_reads(stmt) -> set[tuple[object, ...]]:
        stmt_reads: set[tuple[object, ...]] = set()
        collect_storage_read_keys(stmt, stmt_reads)
        return stmt_reads

    def call_callee_key(call_expr):
        callee_target = getattr(call_expr, "callee_target", None)
        if callee_target is not None:
            return ("target", callee_target)

        callee_func = getattr(call_expr, "callee_func", None)
        if callee_func is not None:
            callee_addr = getattr(callee_func, "addr", None)
            if callee_addr is not None:
                return ("func_addr", callee_addr)
            callee_name = getattr(callee_func, "name", None)
            if callee_name is not None:
                return ("func_name", callee_name)
            return ("func_id", id(callee_func))

        callee = getattr(call_expr, "callee", None)
        if isinstance(callee, str):
            return ("callee", callee)
        return None

    def normalized_call_arg_key(expr):
        expr = unwrap_c_casts(expr)
        storage_key = describe_alias_storage(expr).identity
        if storage_key is not None:
            return ("storage", storage_key)
        if isinstance(expr, structured_c.CConstant):
            return ("const", expr.value)
        if isinstance(expr, structured_c.CVariable):
            variable = getattr(expr, "variable", None)
            if isinstance(variable, SimRegisterVariable):
                return ("reg", getattr(variable, "reg", None), getattr(variable, "size", None))
            if isinstance(variable, SimStackVariable):
                return ("stack", getattr(variable, "base", None), getattr(variable, "offset", None), getattr(variable, "size", None))
            if isinstance(variable, SimMemoryVariable):
                return ("mem", getattr(variable, "addr", None), getattr(variable, "size", None))
            return ("var", id(variable))
        if isinstance(expr, structured_c.CUnaryOp):
            return ("unary", expr.op, normalized_call_arg_key(expr.operand))
        if isinstance(expr, structured_c.CBinaryOp):
            return ("binary", expr.op, normalized_call_arg_key(expr.lhs), normalized_call_arg_key(expr.rhs))
        if isinstance(expr, structured_c.CFunctionCall):
            return ("call", call_callee_key(expr), tuple(normalized_call_arg_key(arg) for arg in getattr(expr, "args", ()) or ()))
        return ("expr", type(expr).__name__)

    def same_call_signature(lhs, rhs) -> bool:
        lhs_call = unwrap_c_casts(lhs)
        rhs_call = unwrap_c_casts(rhs)
        if not isinstance(lhs_call, structured_c.CFunctionCall) or not isinstance(rhs_call, structured_c.CFunctionCall):
            return False
        lhs_key = call_callee_key(lhs_call)
        rhs_key = call_callee_key(rhs_call)
        if lhs_key is None or rhs_key is None or lhs_key != rhs_key:
            return False
        lhs_args = tuple(normalized_call_arg_key(arg) for arg in getattr(lhs_call, "args", ()) or ())
        rhs_args = tuple(normalized_call_arg_key(arg) for arg in getattr(rhs_call, "args", ()) or ())
        return lhs_args == rhs_args

    changed = False

    def prune(node) -> None:
        nonlocal changed
        if not structured_codegen_node(node):
            return

        if isinstance(node, structured_c.CStatements):
            new_statements = []
            pending_assignment_indices: dict[tuple[object, ...], int] = {}
            statements = list(node.statements)
            for index, stmt in enumerate(statements):
                call_expr = stmt if isinstance(stmt, structured_c.CFunctionCall) else getattr(stmt, "expr", None)
                if isinstance(call_expr, structured_c.CFunctionCall):
                    next_stmt = statements[index + 1] if index + 1 < len(statements) else None
                    if (
                        isinstance(next_stmt, structured_c.CReturn)
                        and isinstance(getattr(next_stmt, "retval", None), structured_c.CFunctionCall)
                        and same_call_signature(call_expr, next_stmt.retval)
                    ):
                        changed = True
                        continue
                stmt_reads = collect_stmt_reads(stmt)
                if stmt_reads:
                    for key in list(pending_assignment_indices):
                        if key in stmt_reads:
                            pending_assignment_indices.pop(key, None)
                if (
                    isinstance(stmt, structured_c.CAssignment)
                    and isinstance(stmt.lhs, structured_c.CVariable)
                    and is_local_variable(getattr(stmt.lhs, "variable", None))
                    and not _expr_has_side_effects(getattr(stmt, "rhs", None), iter_c_nodes_deep=iter_c_nodes_deep)
                ):
                    lhs_variable = getattr(stmt.lhs, "variable", None)
                    lhs_unified = getattr(stmt.lhs, "unified_variable", None)
                    lhs_keys: set[tuple[object, ...]] = set()
                    if lhs_variable is not None:
                        lhs_keys.add(("var", id(lhs_variable)))
                    if lhs_unified is not None:
                        lhs_keys.add(("unified", id(lhs_unified)))
                    storage_key = describe_alias_storage(stmt.lhs).identity
                    if storage_key is not None:
                        lhs_keys.add(("storage", storage_key))
                    if lhs_keys.isdisjoint(reads):
                        changed = True
                        continue
                    for key in lhs_keys:
                        if key in pending_assignment_indices:
                            new_statements[pending_assignment_indices[key]] = None
                            changed = True
                        pending_assignment_indices[key] = len(new_statements)
                prune(stmt)
                new_statements.append(stmt)
            if new_statements != list(node.statements):
                node.statements = [stmt for stmt in new_statements if stmt is not None]
                changed = True
            return

        for attr in ("lhs", "rhs", "expr", "operand", "condition", "cond", "body", "iffalse", "iftrue", "else_node", "retval"):
            if not hasattr(node, attr):
                continue
            try:
                value = getattr(node, attr)
            except Exception:
                continue
            if structured_codegen_node(value):
                prune(value)

        for attr in ("args", "operands", "statements"):
            if not hasattr(node, attr):
                continue
            try:
                items = getattr(node, attr)
            except Exception:
                continue
            if not items:
                continue
            for item in items:
                if structured_codegen_node(item):
                    prune(item)

        if hasattr(node, "condition_and_nodes"):
            try:
                pairs = getattr(node, "condition_and_nodes")
            except Exception:
                pairs = None
            if pairs:
                for cond, body in pairs:
                    if structured_codegen_node(cond):
                        prune(cond)
                    if structured_codegen_node(body):
                        prune(body)

    prune(root)
    return changed
