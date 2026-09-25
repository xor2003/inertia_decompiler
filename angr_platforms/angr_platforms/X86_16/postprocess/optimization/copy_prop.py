"""Layer: Rewrite/Postprocess cleanup.

Responsibility: propagate copies only when alias storage facts prove the same storage.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.
The codegen and C AST objects cross a dynamic third-party angr boundary; keep
dynamic attribute access limited to traversing already-recovered C AST nodes.
"""

from __future__ import annotations

from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CVariable,
)

from ...semantics.alias_query import _storage_domain_for_expr

__all__ = ["_copy_propagation_8616"]


def _same_storage_domain(lhs: object, rhs: object) -> bool:
    """Prove two expressions refer to the same storage using alias facts."""
    lhs_domain = _storage_domain_for_expr(lhs)
    rhs_domain = _storage_domain_for_expr(rhs)
    if lhs_domain is None or rhs_domain is None:
        return False
    return lhs_domain == rhs_domain


@dataclass(slots=True)
class _CopyPropScan8616:
    """Mutable copy-propagation state across one structured AST walk."""

    changed: bool = False

    def walk_statements(self, statements: object) -> None:
        """Walk statement blocks across the dynamic third-party angr boundary."""
        stmts = tuple(getattr(statements, "statements", ()) or ())
        # Track last assignment per storage domain within this block
        block_defs: dict[str, object] = {}

        for stmt in stmts:
            if isinstance(stmt, CAssignment):
                self._apply_assignment(stmt, block_defs)
            self.walk_node(stmt)

    def _apply_assignment(
        self,
        stmt: CAssignment,
        block_defs: dict[str, object],
    ) -> None:
        """Propagate a proven copy source and record this definition."""
        rhs = stmt.rhs
        lhs = stmt.lhs
        if isinstance(rhs, CVariable):
            rhs_domain = _storage_domain_for_expr(rhs)
            rhs_domain_key = str(rhs_domain) if rhs_domain is not None else None
            if rhs_domain_key is not None and rhs_domain_key in block_defs:
                replacement = block_defs[rhs_domain_key]
                if replacement is not None:
                    stmt.rhs = replacement
                    self.changed = True

        # Record this definition
        if lhs is not None:
            lhs_domain = _storage_domain_for_expr(lhs)
            lhs_domain_key = str(lhs_domain) if lhs_domain is not None else None
            if lhs_domain_key is not None:
                block_defs[lhs_domain_key] = rhs

    def walk_node(self, node: object) -> None:
        """Walk C AST child links across the dynamic third-party angr boundary."""
        if node is None:
            return
        if hasattr(node, "statements"):
            self.walk_statements(node)
        self._walk_attr_children(node)
        if hasattr(node, "condition_and_nodes"):
            for cond, body in getattr(node, "condition_and_nodes", ()) or ():
                self.walk_node(cond)
                self.walk_node(body)
        if hasattr(node, "cases"):
            for case_body in getattr(node, "cases", {}).values():
                self.walk_node(case_body)
        if hasattr(node, "default"):
            self.walk_node(getattr(node, "default", None))

    def _walk_attr_children(self, node: object) -> None:
        """Recurse into the node's named structural child attributes."""
        for attr in (
            "condition",
            "cond",
            "body",
            "else_node",
            "iftrue",
            "iffalse",
            "retval",
            "expr",
            "switch",
            "initializer",
            "iterator",
        ):
            child = getattr(node, attr, None)
            if child is not None:
                self.walk_node(child)


def _copy_propagation_8616(codegen: object) -> bool:
    """Propagate copies: t2 = t1 becomes t2 = original_source when alias-provable.

    The codegen object crosses a dynamic third-party angr boundary; dynamic
    access here is limited to the already-built C AST surface.

    Returns True if any copy was propagated.
    """
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False

    scan = _CopyPropScan8616()
    scan.walk_statements(cfunc)
    return scan.changed
