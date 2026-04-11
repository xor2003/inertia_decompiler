from __future__ import annotations

from typing import Any, Callable

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort


def _coalesce_cod_word_global_statements(
    project: Any,
    codegen: Any,
    synthetic_globals: Any,
    *,
    global_memory_addr: Callable[[Any], int | None],
    high_byte_store_addr: Callable[[Any, Any], int | None],
    synthetic_word_global_variable: Callable[[Any, Any, int], structured_c.CVariable | None],
) -> bool:
    if not synthetic_globals or getattr(codegen, "cfunc", None) is None:
        return False

    changed = False

    def visit(node: Any) -> None:
        nonlocal changed

        if isinstance(node, structured_c.CStatements):
            new_statements = []
            i = 0
            while i < len(node.statements):
                stmt = node.statements[i]

                if (
                    i + 1 < len(node.statements)
                    and isinstance(stmt, structured_c.CAssignment)
                    and isinstance(node.statements[i + 1], structured_c.CAssignment)
                ):
                    next_stmt = node.statements[i + 1]
                    base_addr = global_memory_addr(stmt.lhs)
                    next_addr = high_byte_store_addr(next_stmt.lhs, project)
                    word_global = synthetic_word_global_variable(codegen, synthetic_globals, base_addr) if base_addr is not None else None

                    if base_addr is not None and next_addr == base_addr + 1 and word_global is not None:
                        if isinstance(stmt.rhs, structured_c.CConstant) and isinstance(next_stmt.rhs, structured_c.CConstant):
                            value = (stmt.rhs.value & 0xFF) | ((next_stmt.rhs.value & 0xFF) << 8)
                            new_statements.append(
                                structured_c.CAssignment(
                                    word_global,
                                    structured_c.CConstant(value, SimTypeShort(False), codegen=codegen),
                                    codegen=codegen,
                                )
                            )
                            changed = True
                            i += 2
                            continue
                        changed = True
                        new_statements.append(stmt)
                        i += 2
                        continue

                visit(stmt)
                new_statements.append(stmt)
                i += 1

            if len(new_statements) != len(node.statements):
                node.statements = new_statements

        elif isinstance(node, structured_c.CIfElse):
            for _, body in node.condition_and_nodes:
                visit(body)
            if node.else_node is not None:
                visit(node.else_node)

    visit(codegen.cfunc.statements)
    return changed
