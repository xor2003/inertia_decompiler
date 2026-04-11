from __future__ import annotations

from angr.analyses.decompiler.structured_codegen import c as structured_c


def _coalesce_direct_ss_local_word_statements(
    project,
    codegen,
    *,
    match_ss_local_plus_const,
    match_shift_right_8_expr,
    stack_slot_identity_can_join,
    same_c_expression,
    unwrap_c_casts,
    promote_direct_stack_cvariable,
    stack_type_for_size,
):
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False

    def visit(node):
        nonlocal changed

        if isinstance(node, structured_c.CStatements):
            new_statements = []
            i = 0
            while i < len(node.statements):
                stmt = node.statements[i]
                if (
                    i + 1 < len(node.statements)
                    and isinstance(stmt, structured_c.CAssignment)
                    and isinstance(stmt.lhs, structured_c.CVariable)
                    and isinstance(node.statements[i + 1], structured_c.CAssignment)
                ):
                    next_stmt = node.statements[i + 1]
                    matched = match_ss_local_plus_const(next_stmt.lhs, project)
                    if matched is not None:
                        target_cvar, extra_offset = matched
                        high_expr = match_shift_right_8_expr(next_stmt.rhs)
                        if (
                            extra_offset == 1
                            and stack_slot_identity_can_join(target_cvar, stmt.lhs)
                            and high_expr is not None
                            and same_c_expression(unwrap_c_casts(high_expr), unwrap_c_casts(stmt.rhs))
                        ):
                            if promote_direct_stack_cvariable(codegen, stmt.lhs, 2, stack_type_for_size(2)):
                                changed = True
                            new_statements.append(stmt)
                            changed = True
                            i += 2
                            continue

                visit(stmt)
                new_statements.append(stmt)
                i += 1

            if changed or new_statements != node.statements:
                node.statements = new_statements

    visit(codegen.cfunc.statements)
    return changed
