"""Preserve an existing register SSA value when replacing a switch ladder.

Layer: Structuring.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.
Responsibility: consume AIL register identities and transparent sequence order
to retain the last exact definition before a proven switch region. No register
storage, call ABI, case values, or source-level types are inferred here.
Missing definitions, overlapping writes, calls, and non-sequential predecessors
refuse binding. Never invent an unbound raw register as a replacement selector.
"""

from __future__ import annotations

from angr import ailment
from angr.analyses.decompiler.structurer_nodes import ConditionNode, MultiNode, SequenceNode


def _statement_clobbers_8616(statement: ailment.Stmt.Statement | ailment.Expr.Expression) -> bool:
    """Observe opaque effects through the third-party AIL visitor boundary."""
    clobbers = False

    def observe(
        expr_idx: int, expr: ailment.Expr.Expression, stmt_idx: int,
        stmt: ailment.Stmt.Statement | None, block: ailment.Block | None,
    ) -> None:
        """Refuse an intervening call or opaque effect without guessing its ABI."""
        nonlocal clobbers
        clobbers = True

    observer = ailment.AILBlockViewer()
    for kind in (ailment.Expr.Call, ailment.Expr.DirtyExpression, ailment.Expr.FunctionLikeMacro):
        observer.expr_handlers[kind] = observe
    if isinstance(statement, ailment.Expr.Expression):
        observer.walk_expression(statement)
    else:
        observer.walk_statement(statement)
    return clobbers


def _blocks_8616(node: object) -> tuple[ailment.Block, ...] | None:
    """Flatten only third-party nodes with unconditional sequential children."""
    if isinstance(node, ailment.Block):
        return (node,)
    if not isinstance(node, (SequenceNode, MultiNode)):
        return None
    result: list[ailment.Block] = []
    for child in node.nodes:
        blocks = _blocks_8616(child)
        if blocks is None:
            return None
        result.extend(blocks)
    return tuple(result)


def _prefix_blocks_8616(
    sequence: object, path: tuple[int, ...],
) -> tuple[ailment.Block, ...] | None:
    """Collect only predecessors guaranteed to execute before the replacement."""
    current = sequence
    prefix: list[ailment.Block] = []
    for index in path:
        if not isinstance(current, (SequenceNode, MultiNode)):
            return None
        if index < 0 or index >= len(current.nodes):
            return None
        for child in current.nodes[:index]:
            blocks = _blocks_8616(child)
            if blocks is None:
                return None
            prefix.extend(blocks)
        current = current.nodes[index]
    return tuple(prefix)


def _selector_read_8616(
    sequence: object, path: tuple[int, ...], definition: ailment.Expr.Expression,
) -> ailment.Expr.Expression | None:
    """Require the entry predicate to read the same SSA version, not just AX.

    CMP followed by MOV can leave flags describing an older register version.
    Reusing the latest physical register definition alone would then be wrong.
    """
    node = sequence
    for index in path:
        if not isinstance(node, (SequenceNode, MultiNode)):
            return None
        node = node.nodes[index]
    while isinstance(node, (SequenceNode, MultiNode)) and node.nodes:
        node = node.nodes[0]
    if not isinstance(node, ConditionNode) or not isinstance(node.condition, ailment.Expr.Expression):
        return None
    if _statement_clobbers_8616(node.condition):
        return None
    reads: list[ailment.Expr.Expression] = []

    def collect(
        expr_idx: int, expr: ailment.Expr.Expression, stmt_idx: int,
        stmt: ailment.Stmt.Statement | None, block: ailment.Block | None,
    ) -> None:
        """Collect exact register-view reads from the existing predicate."""
        if (isinstance(expr, ailment.Expr.Register) or expr.was_reg) and (
            expr.reg_offset == definition.reg_offset and expr.size == definition.size
        ):
            reads.append(expr)

    walker = ailment.AILBlockViewer()
    walker.expr_handlers[ailment.Expr.VirtualVariable] = collect
    walker.expr_handlers[ailment.Expr.Register] = collect
    walker.walk_expression(node.condition)
    if reads and all(
        isinstance(read, ailment.Expr.VirtualVariable) and read.varid == definition.varid
        for read in reads
    ):
        return reads[0]
    return None


def bind_switch_selector_value_8616(
    sequence: object, path: tuple[int, ...], *, register_offset: int, size: int,
) -> ailment.Expr.Expression | None:
    """Return the exact reaching SSA atom, refusing ambiguous execution paths.

    The caller supplies the register view of the already proven normalized
    switch. This function preserves the existing AIL atom and its variable-map
    key; it does not recover storage from names or construct a new variable.
    """
    blocks = _prefix_blocks_8616(sequence, path)
    if blocks is None:
        return None
    candidate: ailment.Expr.Expression | None = None
    for block in blocks:
        for statement in block.statements:
            if not isinstance(statement, (ailment.Stmt.Assignment, ailment.Stmt.Store,
                                          ailment.Stmt.NoOp, ailment.Stmt.SideEffectStatement,
                                          ailment.Expr.Call)):
                return None
            if isinstance(statement, ailment.Stmt.SideEffectStatement) or _statement_clobbers_8616(statement):
                candidate = None
            if not isinstance(statement, ailment.Stmt.Assignment):
                continue
            dst = statement.dst
            if isinstance(dst, ailment.Expr.Register) or (isinstance(dst, ailment.Expr.VirtualVariable) and dst.was_reg):
                offset = dst.reg_offset
            else:
                continue
            if offset < register_offset + size and register_offset < offset + dst.size:
                candidate = (
                    dst if isinstance(dst, ailment.Expr.VirtualVariable)
                    and offset == register_offset and dst.size == size else None
                )
    return _selector_read_8616(sequence, path, candidate) if candidate is not None else None
