"""Check SSA definition survival before replacing a switch decision ladder.

Layer: Structuring.
Responsibility: refuse removal of dispatcher definitions still read by retained
case/default bodies or the surrounding function. This is a loss check, not a
reaching-definition, liveness, storage-recovery or switch-equivalence proof.
Do not infer replacement values or repair statements in Rewrite or the CLI.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from angr import ailment


@dataclass(slots=True)
class _VariableInventory8616:
    """Exact SSA IDs defined and read by a bounded pre-codegen surface."""

    definitions: set[int] = field(default_factory=set)
    reads: set[int] = field(default_factory=set)

    def observe_read(
        self, expr_idx: int, expr: ailment.Expr.Expression, stmt_idx: int,
        stmt: ailment.Stmt.Statement | None, block: ailment.Block | None,
    ) -> None:
        """Record an atom through angr's standard AIL expression visitor."""
        if isinstance(expr, ailment.Expr.VirtualVariable):
            self.reads.add(expr.varid)

    def statement(self, statement: ailment.Stmt.Statement, walker: ailment.AILBlockViewer) -> None:
        """Separate assignment destinations from uses of their source values."""
        if isinstance(statement, ailment.Stmt.Assignment) and isinstance(
            statement.dst, ailment.Expr.VirtualVariable,
        ):
            self.definitions.add(statement.dst.varid)
            walker.walk_expression(statement.src)
        else:
            walker.walk_statement(statement)


def _inventory_8616(
    roots: tuple[object, ...],
    children: Callable[[object], tuple[object, ...]],
    *,
    excluded: object | None = None,
) -> _VariableInventory8616:
    """Collect retained SSA facts without crossing the excluded subtree.

    Dynamic attributes below belong to third-party angr structurer nodes.
    The caller supplies its authoritative child traversal, including cases.
    """
    result = _VariableInventory8616()
    walker = ailment.AILBlockViewer()
    walker.expr_handlers[ailment.Expr.VirtualVariable] = result.observe_read
    pending = list(roots)
    visited: set[int] = set()
    while pending:
        node = pending.pop()
        if node is excluded or id(node) in visited:
            continue
        visited.add(id(node))
        if isinstance(node, ailment.Expr.Expression):
            walker.walk_expression(node)
        elif isinstance(node, ailment.Block):
            for statement in node.statements:
                result.statement(statement, walker)
        else:
            for name in ("condition", "switch_expr"):
                expression = getattr(node, name, None)
                if isinstance(expression, ailment.Expr.Expression):
                    walker.walk_expression(expression)
            arms = getattr(node, "condition_and_nodes", ())
            for expression, _body in arms:
                if isinstance(expression, ailment.Expr.Expression):
                    walker.walk_expression(expression)
            pending.extend(children(node))
    return result


def missing_switch_definition_ids_8616(
    sequence: object,
    replaced: object,
    retained: tuple[object, ...],
    *,
    children: Callable[[object], tuple[object, ...]],
) -> tuple[int, ...]:
    """Return discarded SSA definitions still referenced after replacement.

    Include the surrounding function, not just cases: loop tails and shared
    epilogues may consume dispatcher outputs. Values defined outside the
    replaced subtree are not invented or reclassified by this check.
    """
    source = _inventory_8616((replaced,), children)
    surviving = _inventory_8616((sequence, *retained), children, excluded=replaced)
    removed = source.definitions - surviving.definitions
    return tuple(sorted(removed & surviving.reads))
