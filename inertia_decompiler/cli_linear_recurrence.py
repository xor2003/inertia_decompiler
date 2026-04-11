from __future__ import annotations

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable

from inertia_decompiler.cli_linear_recurrence_state import LinearRecurrenceState


def _rewrite_linear_condition(node, state, *, structured_codegen_node, same_c_expression, rules) -> None:
    candidate = None
    current = getattr(node, "condition", None)
    if structured_codegen_node(current):
        candidate = state.resolve_known_copy_alias_expr(current)
        candidate = state.inline_known_linear_defs(candidate)
        if candidate is not current and rules._should_commit_linear_rewrite(
            current,
            candidate,
            expr_contains_dereference=state.expr_contains_dereference,
            same_c_expression=same_c_expression,
        ):
            node.condition = candidate
            state.changed = True


def _coalesce_linear_recurrence_statements(
    project,
    codegen,
    *,
    unwrap_c_casts,
    structured_codegen_node,
    iter_c_nodes_deep,
    same_c_expression,
    c_constant_value,
    canonicalize_stack_cvar_expr,
    seed_adjacent_byte_pair_aliases,
    describe_alias_storage,
    analyze_widening_expr,
    match_high_byte_projection_base,
    match_duplicate_word_base_expr,
    match_duplicate_word_increment_shift_expr,
    same_stack_slot_identity_var,
    rules,
):
    if getattr(codegen, "cfunc", None) is None:
        return False
    state = LinearRecurrenceState(
        project=project,
        codegen=codegen,
        unwrap_c_casts=unwrap_c_casts,
        structured_codegen_node=structured_codegen_node,
        iter_c_nodes_deep=iter_c_nodes_deep,
        same_c_expression=same_c_expression,
        c_constant_value=c_constant_value,
        canonicalize_stack_cvar_expr=canonicalize_stack_cvar_expr,
        seed_adjacent_byte_pair_aliases=seed_adjacent_byte_pair_aliases,
        describe_alias_storage=describe_alias_storage,
        analyze_widening_expr=analyze_widening_expr,
        match_high_byte_projection_base=match_high_byte_projection_base,
        match_duplicate_word_base_expr=match_duplicate_word_base_expr,
        match_duplicate_word_increment_shift_expr=match_duplicate_word_increment_shift_expr,
        same_stack_slot_identity_var=same_stack_slot_identity_var,
    )
    state.prepare()

    def visit(node):
        if isinstance(node, structured_c.CStatements):
            new_statements = []
            i = 0
            while i < len(node.statements):
                stmt = node.statements[i]
                next_stmt = node.statements[i + 1] if i + 1 < len(node.statements) else None
                if isinstance(stmt, structured_c.CAssignment) and isinstance(stmt.lhs, structured_c.CVariable):
                    stmt_var = getattr(stmt.lhs, "variable", None)
                    if stmt_var is not None and id(stmt_var) in state.dereferenced_variable_ids:
                        visit(stmt)
                        new_statements.append(stmt)
                        i += 1
                        continue
                    carry_base = match_duplicate_word_increment_shift_expr(stmt.rhs, state.resolve_known_copy_alias_expr, codegen)
                    carry_rewrite = rules._carry_base_rewrite_plan(
                        carry_base,
                        expr_contains_dereference=state.expr_contains_dereference,
                        extract_linear_delta=state.extract_linear_delta,
                    )
                    if carry_rewrite is not None:
                        if stmt_var is not None and carry_rewrite["linear"] is not None:
                            state.linear_defs[id(stmt_var)] = carry_rewrite["linear"]
                        new_statements.append(structured_c.CAssignment(stmt.lhs, carry_rewrite["replacement"], codegen=codegen))
                        state.changed = True
                        i += 1
                        continue
                if (
                    isinstance(stmt, structured_c.CAssignment)
                    and isinstance(stmt.lhs, structured_c.CVariable)
                    and isinstance(next_stmt, structured_c.CAssignment)
                    and isinstance(next_stmt.lhs, structured_c.CVariable)
                ):
                    temp_var = getattr(stmt.lhs, "variable", None)
                    next_var = getattr(next_stmt.lhs, "variable", None)
                    temp_use_count = state.variable_use_counts.get(id(temp_var), 0) if temp_var is not None else 0
                    if (
                        (temp_var is not None and id(temp_var) in state.dereferenced_variable_ids)
                        or (next_var is not None and id(next_var) in state.dereferenced_variable_ids)
                        or (temp_var is not None and id(temp_var) in state.protected_linear_alias_ids)
                        or (next_var is not None and id(next_var) in state.protected_linear_alias_ids)
                    ):
                        visit(stmt)
                        new_statements.append(stmt)
                        i += 1
                        continue
                    if temp_use_count >= 2 and state.is_linear_register_temp(stmt.lhs) and state.is_linear_register_temp(next_stmt.lhs):
                        stmt_base, stmt_delta = state.extract_linear_delta(stmt.rhs)
                        next_rhs = unwrap_c_casts(next_stmt.rhs)
                        if isinstance(next_rhs, structured_c.CBinaryOp) and next_rhs.op in {"Add", "Sub"}:
                            if same_c_expression(unwrap_c_casts(next_rhs.lhs), stmt.lhs):
                                next_delta = c_constant_value(unwrap_c_casts(next_rhs.rhs))
                                next_base = stmt_base
                            elif same_c_expression(unwrap_c_casts(next_rhs.rhs), stmt.lhs):
                                next_delta = c_constant_value(unwrap_c_casts(next_rhs.lhs))
                                next_base = stmt_base
                            else:
                                next_delta = None
                                next_base = None
                            if next_base is not None and isinstance(next_delta, int):
                                combined = stmt_delta + next_delta if next_rhs.op == "Add" else stmt_delta - next_delta
                                new_statements.append(structured_c.CAssignment(next_stmt.lhs, state.build_linear_expr(next_base, combined), codegen=codegen))
                                state.changed = True
                                i += 2
                                continue
                    if temp_use_count >= 2 and state.is_linear_register_temp(stmt.lhs) and state.is_linear_register_temp(next_stmt.lhs):
                        stmt_shift_base, stmt_shift_count = state.extract_shift_delta(stmt.rhs)
                        next_shift_rhs = unwrap_c_casts(next_stmt.rhs)
                        if isinstance(next_shift_rhs, structured_c.CBinaryOp) and next_shift_rhs.op == "Shr":
                            if same_c_expression(unwrap_c_casts(next_shift_rhs.lhs), stmt.lhs):
                                next_shift_count = c_constant_value(unwrap_c_casts(next_shift_rhs.rhs))
                                if isinstance(next_shift_count, int) and stmt_shift_count >= 0:
                                    combined_shift = stmt_shift_count + next_shift_count
                                    shift_repl = structured_c.CAssignment(next_stmt.lhs, state.build_shift_expr(stmt_shift_base, combined_shift), codegen=codegen)
                                    shift_var = getattr(next_stmt.lhs, "variable", None)
                                    if shift_var is not None:
                                        state.shift_defs[id(shift_var)] = (stmt_shift_base, combined_shift)
                                    new_statements.append(shift_repl)
                                    state.changed = True
                                    i += 2
                                    continue
                    if state.is_linear_register_temp(stmt.lhs):
                        stmt_base, stmt_delta = state.extract_linear_delta(stmt.rhs)
                        if stmt_base is not None:
                            base_var = getattr(stmt_base, "variable", None) if isinstance(stmt_base, structured_c.CVariable) else None
                            if base_var is not None and (id(base_var) in state.dereferenced_variable_ids or id(base_var) in state.protected_linear_alias_ids):
                                visit(stmt)
                                new_statements.append(stmt)
                                i += 1
                                continue
                            state.linear_defs[id(temp_var)] = (stmt_base, stmt_delta)
                            resolved_base = state.resolve_known_copy_alias_expr(stmt_base)
                            if isinstance(resolved_base, structured_c.CVariable) and isinstance(getattr(resolved_base, "variable", None), SimStackVariable):
                                state.protected_linear_defs.add(id(temp_var))
                            canonical_rhs = state.build_linear_expr(stmt_base, stmt_delta)
                            if not same_c_expression(stmt.rhs, canonical_rhs):
                                stmt = structured_c.CAssignment(stmt.lhs, canonical_rhs, codegen=codegen)
                                state.changed = True
                        rhs = state.inline_known_linear_defs(stmt.rhs)
                        inlined_base, inlined_delta = state.extract_linear_delta(rhs)
                        if inlined_base is not None and not same_c_expression(rhs, stmt.rhs):
                            stmt = structured_c.CAssignment(stmt.lhs, state.build_linear_expr(inlined_base, inlined_delta), codegen=codegen)
                            rhs = stmt.rhs
                            state.changed = True
                        current_linear = state.linear_defs.get(id(temp_var)) if temp_var is not None else None
                        if current_linear is not None and isinstance(rhs, structured_c.CBinaryOp) and rhs.op in {"Add", "Sub"}:
                            if same_c_expression(unwrap_c_casts(rhs.lhs), stmt.lhs) or same_c_expression(unwrap_c_casts(rhs.rhs), stmt.lhs):
                                current_delta = c_constant_value(unwrap_c_casts(rhs.lhs))
                                if current_delta is None:
                                    current_delta = c_constant_value(unwrap_c_casts(rhs.rhs))
                                if isinstance(current_delta, int):
                                    base_expr, base_delta = current_linear
                                    resolved_base = state.resolve_known_copy_alias_expr(base_expr)
                                    if isinstance(resolved_base, structured_c.CVariable) and isinstance(getattr(resolved_base, "variable", None), SimStackVariable):
                                        state.protected_linear_defs.add(id(temp_var))
                                    combined = base_delta + current_delta if rhs.op == "Add" else base_delta - current_delta
                                    stmt = structured_c.CAssignment(stmt.lhs, state.build_linear_expr(base_expr, combined), codegen=codegen)
                                    state.changed = True
                        if temp_var is not None and state.is_copy_alias_candidate(stmt.rhs):
                            alias = unwrap_c_casts(stmt.rhs)
                            alias_var = getattr(alias, "variable", None)
                            if alias_var is not None and alias_var is not temp_var:
                                state.expr_aliases[id(temp_var)] = alias
                                storage_key = state.alias_storage_key(stmt.lhs)
                                if storage_key is not None:
                                    state.expr_aliases[storage_key] = alias
                        if isinstance(temp_var, SimStackVariable) and state.is_copy_alias_candidate(stmt.rhs):
                            alias = unwrap_c_casts(stmt.rhs)
                            alias_var = getattr(alias, "variable", None)
                            if isinstance(alias_var, SimStackVariable) and alias_var is not temp_var and same_stack_slot_identity_var(temp_var, alias_var):
                                state.expr_aliases[id(temp_var)] = alias
                                storage_key = state.alias_storage_key(stmt.lhs)
                                if storage_key is not None:
                                    state.expr_aliases[storage_key] = alias
                visit(stmt)
                new_statements.append(stmt)
                i += 1
            if state.changed or new_statements != node.statements:
                node.statements = new_statements
        elif isinstance(node, structured_c.CIfElse):
            new_pairs = []
            pair_changed = False
            for cond, body in node.condition_and_nodes:
                new_cond = cond
                if structured_codegen_node(cond):
                    candidate_cond = state.resolve_known_copy_alias_expr(new_cond)
                    candidate_cond = state.inline_known_linear_defs(candidate_cond)
                    if rules._should_commit_linear_rewrite(cond, candidate_cond, expr_contains_dereference=state.expr_contains_dereference, same_c_expression=same_c_expression):
                        new_cond = candidate_cond
                if new_cond is not cond:
                    pair_changed = True
                visit(body)
                new_pairs.append((new_cond, body))
            if pair_changed:
                node.condition_and_nodes = new_pairs
                state.changed = True
            if node.else_node is not None:
                visit(node.else_node)
        elif isinstance(node, structured_c.CWhileLoop):
            _rewrite_linear_condition(node, state, structured_codegen_node=structured_codegen_node, same_c_expression=same_c_expression, rules=rules)
            visit(getattr(node, "condition", None))
            visit(getattr(node, "body", None))
        elif hasattr(structured_c, "CDoWhileLoop") and isinstance(node, getattr(structured_c, "CDoWhileLoop")):
            _rewrite_linear_condition(node, state, structured_codegen_node=structured_codegen_node, same_c_expression=same_c_expression, rules=rules)
            visit(getattr(node, "condition", None))
            visit(getattr(node, "body", None))
        elif hasattr(structured_c, "CForLoop") and isinstance(node, getattr(structured_c, "CForLoop")):
            for attr in ("init", "condition", "iteration"):
                current = getattr(node, attr, None)
                if structured_codegen_node(current):
                    candidate = state.resolve_known_copy_alias_expr(current)
                    candidate = state.inline_known_linear_defs(candidate)
                    if candidate is not current and rules._should_commit_linear_rewrite(current, candidate, expr_contains_dereference=state.expr_contains_dereference, same_c_expression=same_c_expression):
                        setattr(node, attr, candidate)
                        state.changed = True
            visit(getattr(node, "init", None))
            visit(getattr(node, "condition", None))
            visit(getattr(node, "iteration", None))
            visit(getattr(node, "body", None))

    visit(codegen.cfunc.statements)
    return state.changed
