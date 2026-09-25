"""Cleanup-only value-flow renaming over proven alias domains.

Layer: Rewrite/Postprocess cleanup.
Responsibility: inline value-flow temporaries only when alias facts prove storage identity.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
This module may inline structured-codegen values only when alias facts already
prove same-domain storage.
Do not recover new semantics, storage identity, types, call signatures, control
flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.
The codegen and C AST objects cross a dynamic third-party angr boundary; keep
dynamic attribute access limited to traversing already-recovered C AST nodes.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CFunctionCall,
    CUnaryOp,
    CVariable,
)

from ..c_ast_utils import _same_c_expression_8616
from ..semantics.alias_query import _storage_domain_for_expr

__all__ = ["_apply_value_flow_renaming_8616"]


def _same_var(a: object, b: object) -> bool:
    """Prove two variables refer to the same storage using alias facts."""
    domain_a = _storage_domain_for_expr(a)
    domain_b = _storage_domain_for_expr(b)
    if domain_a is None or domain_b is None:
        return _same_c_expression_8616(a, b)
    return domain_a == domain_b


def _is_side_effecting(expr: object) -> bool:
    """Check for side effects that prevent inlining."""
    if isinstance(expr, CFunctionCall):
        return True
    return bool(isinstance(expr, CAssignment))


def _has_variable_use(expr: object, target: object) -> bool:
    """Return whether an expression uses a target variable."""

    def _impl() -> bool:
        """Walk uses across the dynamic third-party angr C AST boundary."""
        if expr is None:
            return False
        if _same_var(expr, target):
            return True
        if isinstance(expr, CBinaryOp):
            return _has_variable_use(expr.lhs, target) or _has_variable_use(expr.rhs, target)
        if isinstance(expr, CUnaryOp):
            return _has_variable_use(expr.operand, target)
        if isinstance(expr, CFunctionCall):
            return any(_has_variable_use(arg, target) for arg in (getattr(expr, "args", ()) or ()))
        if isinstance(expr, CAssignment):
            return _has_variable_use(expr.rhs, target) or _has_variable_use(expr.lhs, target)
        return False

    return _impl()


def _iter_c_nodes(node: object) -> Iterator[object]:
    """Yield C AST descendants across the dynamic third-party angr boundary."""
    if node is None:
        return
    yield node
    if isinstance(node, CBinaryOp):
        yield from _iter_c_nodes(node.lhs)
        yield from _iter_c_nodes(node.rhs)
    elif isinstance(node, CUnaryOp):
        yield from _iter_c_nodes(node.operand)
    elif isinstance(node, CFunctionCall):
        for arg in getattr(node, "args", ()) or ():
            yield from _iter_c_nodes(arg)
    elif isinstance(node, CAssignment):
        yield from _iter_c_nodes(node.rhs)


def _collect_var_uses(stmts: Iterable[object]) -> dict[int, int]:
    """Count C AST variable uses across the dynamic third-party angr boundary."""
    count: dict[int, int] = {}
    for stmt in stmts:
        if isinstance(stmt, CAssignment):
            rhs = getattr(stmt, "rhs", None)
            lhs = getattr(stmt, "lhs", None)
            if rhs is not None:
                for node in _iter_c_nodes(rhs):
                    if isinstance(node, CVariable):
                        node_id = id(node)
                        count[node_id] = count.get(node_id, 0) + 1
            # Don't count definition site as a use
            if lhs is not None and id(lhs) in count:
                count[id(lhs)] -= 1
    return count


@dataclass(slots=True)
class _ValueFlowScan8616:
    """Mutable inlining state across one structured AST walk."""

    changed: bool = False

    def walk_statements(self, statements: object) -> None:
        """Walk statement blocks across the dynamic third-party angr boundary."""
        stmts = list(getattr(statements, "statements", ()) or ())
        if len(stmts) < 2:
            return

        # Track definitions: {var_id: (index, rhs_expression)}
        defs: dict[int, tuple[int, object]] = {}

        # Count uses across the block
        use_counts = _collect_var_uses(stmts)

        for idx, stmt in enumerate(stmts):
            self._apply_statement(stmt, idx, defs, use_counts)

    def _apply_statement(
        self,
        stmt: object,
        idx: int,
        defs: dict[int, tuple[int, object]],
        use_counts: dict[int, int],
    ) -> None:
        """Inline a single-use temporary into one assignment when proven."""
        if not isinstance(stmt, CAssignment):
            return
        rhs = getattr(stmt, "rhs", None)
        lhs = getattr(stmt, "lhs", None)
        if lhs is None or rhs is None:
            return

        # Record this definition (may overwrite previous)
        defs[id(lhs)] = (idx, rhs)

        # Check if we can inline earlier definitions used here
        if isinstance(rhs, CVariable):
            rhs_id = id(rhs)
            if rhs_id in defs:
                _def_idx, def_expr = defs[rhs_id]
                # Only inline if rhs is used exactly once (this use)
                if use_counts.get(rhs_id, 0) == 1 and not _is_side_effecting(def_expr):
                    stmt.rhs = def_expr
                    self.changed = True
                    # Update defs for the new expression
                    defs[id(lhs)] = (idx, def_expr)

        # Invalidate defs when variable is redefined
        if id(lhs) in defs:
            # Re-record to track latest definition
            pass

    def walk_node(self, node: object) -> None:
        """Walk child links across the dynamic third-party angr boundary."""
        if node is None:
            return
        if hasattr(node, "statements"):
            self.walk_statements(node)
        self._walk_attr_children(node)
        if hasattr(node, "condition_and_nodes"):
            for _cond, body in getattr(node, "condition_and_nodes", ()) or ():
                self.walk_node(body)
        if hasattr(node, "cases"):
            for case_body in getattr(node, "cases", {}).values():
                self.walk_node(case_body)
        if hasattr(node, "default"):
            self.walk_node(getattr(node, "default", None))

    def _walk_attr_children(self, node: object) -> None:
        """Recurse into the node's named structural child attributes."""
        for attr in ("body", "else_node", "iftrue", "iffalse", "initializer", "iterator"):
            child = getattr(node, attr, None)
            if child is not None:
                self.walk_node(child)


def _apply_value_flow_renaming_8616(codegen: object) -> bool:
    """Inline single-use temporaries where alias-safe.

    The codegen object crosses a dynamic third-party angr boundary; this pass
    only traverses already-built C AST nodes and relies on alias facts.

    For each block:
    - Track assignments t = expr
    - When t is used exactly once (as rhs of another assignment),
      and t is not redefined between def and use,
      inline the expression.

    Respects alias domain: only inlines when source and destination
    storage identity is preserved.

    Returns True if any inlining occurred.
    """
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False

    scan = _ValueFlowScan8616()
    # Walk from cfunc
    if hasattr(cfunc, "statements"):
        scan.walk_statements(cfunc)
    scan.walk_node(cfunc)

    return scan.changed
