from __future__ import annotations

from angr.analyses.decompiler.structured_codegen import c as structured_c


def _coalesce_segmented_word_store_statements(
    project,
    codegen,
    *,
    match_ss_local_plus_const,
    match_word_rhs_from_byte_pair,
    promote_direct_stack_cvariable,
    stack_type_for_size,
    stack_slot_identity_can_join,
    canonicalize_stack_cvar_expr,
    match_byte_store_addr_expr,
    addr_exprs_are_byte_pair,
    resolve_stack_cvar_from_addr_expr,
    make_word_dereference_from_addr_expr,
    classify_segmented_addr_expr,
    describe_alias_storage,
):
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False
    target_type = stack_type_for_size(2)

    def visit(node):
        nonlocal changed

        if isinstance(node, structured_c.CStatements):
            new_statements = []
            i = 0
            while i < len(node.statements):
                stmt = node.statements[i]
                next_stmt = node.statements[i + 1] if i + 1 < len(node.statements) else None

                if isinstance(stmt, structured_c.CAssignment) and isinstance(next_stmt, structured_c.CAssignment):
                    replacement = None

                    if isinstance(stmt.lhs, structured_c.CVariable):
                        matched = match_ss_local_plus_const(next_stmt.lhs, project)
                        if matched is not None:
                            target_cvar, extra_offset = matched
                            rhs_word = match_word_rhs_from_byte_pair(stmt.rhs, next_stmt.rhs, codegen, project)
                            if (
                                extra_offset == 1
                                and isinstance(target_cvar, structured_c.CVariable)
                                and target_cvar is not None
                                and rhs_word is not None
                                and stack_slot_identity_can_join(target_cvar, stmt.lhs)
                            ):
                                replacement_lhs = canonicalize_stack_cvar_expr(stmt.lhs, codegen)
                                rhs_word = canonicalize_stack_cvar_expr(rhs_word, codegen)
                                if promote_direct_stack_cvariable(codegen, replacement_lhs, 2, target_type):
                                    changed = True
                                replacement = structured_c.CAssignment(replacement_lhs, rhs_word, codegen=codegen)

                    if replacement is None:
                        low_addr_expr = match_byte_store_addr_expr(stmt.lhs)
                        high_addr_expr = match_byte_store_addr_expr(next_stmt.lhs)
                        rhs_word = match_word_rhs_from_byte_pair(stmt.rhs, next_stmt.rhs, codegen, project)
                        if (
                            low_addr_expr is not None
                            and high_addr_expr is not None
                            and rhs_word is not None
                            and addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, project)
                        ):
                            low_facts = describe_alias_storage(low_addr_expr)
                            high_facts = describe_alias_storage(high_addr_expr)
                            if low_facts.identity is None or high_facts.identity is None or not low_facts.can_join(high_facts):
                                visit(stmt)
                                new_statements.append(stmt)
                                i += 1
                                continue
                            low_class = classify_segmented_addr_expr(low_addr_expr, project)
                            if low_class is not None and low_class.kind == "stack":
                                resolved_lhs = resolve_stack_cvar_from_addr_expr(project, codegen, low_addr_expr)
                                if resolved_lhs is None:
                                    visit(stmt)
                                    new_statements.append(stmt)
                                    i += 1
                                    continue
                                replacement_lhs = canonicalize_stack_cvar_expr(resolved_lhs, codegen)
                                rhs_word = canonicalize_stack_cvar_expr(rhs_word, codegen)
                                if promote_direct_stack_cvariable(codegen, replacement_lhs, 2, target_type):
                                    changed = True
                                replacement = structured_c.CAssignment(replacement_lhs, rhs_word, codegen=codegen)
                            else:
                                resolved_lhs = resolve_stack_cvar_from_addr_expr(project, codegen, low_addr_expr)
                                replacement = structured_c.CAssignment(
                                    resolved_lhs if resolved_lhs is not None else make_word_dereference_from_addr_expr(codegen, project, low_addr_expr),
                                    rhs_word,
                                    codegen=codegen,
                                )

                    if replacement is not None:
                        new_statements.append(replacement)
                        changed = True
                        i += 2
                        continue

                visit(stmt)
                new_statements.append(stmt)
                i += 1

            if changed or new_statements != node.statements:
                node.statements = new_statements

        elif isinstance(node, structured_c.CIfElse):
            for _cond, body in node.condition_and_nodes:
                visit(body)
            if node.else_node is not None:
                visit(node.else_node)

    visit(codegen.cfunc.statements)
    return changed
