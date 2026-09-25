"""Store-to-load forwarding within proven alias storage domains.

Layer: Widening.
Responsibility: owns store-to-load forwarding within proven alias storage domains.
Consumes alias-proven storage identity to forward values only when no
intervening write invalidates the storage domain.
Do not join values from rendered text, cosmetic shape, postprocess, or
CLI/reporting evidence.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..alias.alias_model_impl import AliasStorageFacts
from ..c_ast_utils import _unwrap_statements_8616
from ..semantics.alias_query import describe_alias_storage
from ..semantics.expression_analysis import _unwrap_c_casts

__all__ = ["_widening_store_to_load_forwarding_8616"]


def _iter_switch_case_bodies_8616(cases: object) -> tuple[object, ...]:
    """Read switch cases through the dynamic third-party angr C AST boundary."""
    if cases is None:
        return ()
    if isinstance(cases, dict):
        return tuple(cases.values())
    bodies: list[object] = []
    if isinstance(cases, (list, tuple)):
        for case in cases:
            if isinstance(case, (list, tuple)) and len(case) >= 2:
                bodies.append(case[1])
            else:
                bodies.append(case)
    return tuple(bodies)


def _addr_expr_from_deref(expr: object) -> object:
    """Extract address expressions through the dynamic third-party angr C AST boundary."""
    from angr.analyses.decompiler.structured_codegen import c as structured_c

    # Pattern: CBinaryOp('Mul', CVariable(seg), CConstant(16)) → seg reg
    if isinstance(expr, structured_c.CBinaryOp) and expr.op == "Add":
        return expr
    # Reference through a dereference: *(addr)
    if isinstance(expr, structured_c.CUnaryOp):
        return _addr_expr_from_deref(expr.operand)
    return expr


def _is_deref_write(stmt: object) -> bool:
    """Check pointer stores through the dynamic third-party angr C AST boundary."""
    from angr.analyses.decompiler.structured_codegen import c as structured_c

    if not isinstance(stmt, structured_c.CAssignment):
        return False
    lhs = getattr(stmt, "lhs", None)
    # The lhs is typically a CUnaryOp('Reference') or similar for pointer stores
    return bool(isinstance(lhs, structured_c.CUnaryOp))


def _is_deref_read(rhs: object) -> bool:
    """Check pointer loads through the dynamic third-party angr C AST boundary."""
    from angr.analyses.decompiler.structured_codegen import c as structured_c

    return bool(isinstance(rhs, structured_c.CUnaryOp))


def _structural_hash(expr: object) -> str:
    """Create a structural hash across the dynamic third-party angr C AST boundary."""
    from angr.analyses.decompiler.structured_codegen import c as structured_c

    if isinstance(expr, structured_c.CVariable):
        var = getattr(expr, "variable", None)
        off = getattr(expr, "offset", None)
        return f"v:{id(var)}:{off}"
    if isinstance(expr, structured_c.CConstant):
        return f"c:{getattr(expr, 'value', None)}"
    if isinstance(expr, structured_c.CBinaryOp):
        return f"b:{expr.op}:{_structural_hash(expr.lhs)}:{_structural_hash(expr.rhs)}"
    if isinstance(expr, structured_c.CUnaryOp):
        return f"u:{expr.op}:{_structural_hash(expr.operand)}"
    return str(id(expr))


def _addr_key(addr_expr: object) -> str | None:
    """Create an alias key across a dynamic compatibility boundary."""
    facts: AliasStorageFacts = describe_alias_storage(addr_expr)
    domain = facts.domain
    identity = facts.identity
    if domain is None:
        return None
    domain_repr = getattr(domain, "_repr", None) or str(domain)
    identity_repr = str(identity) if identity is not None else ""
    # Include structural hash for disambiguation
    structural = _structural_hash(addr_expr)
    return f"{domain_repr}:{identity_repr}:{structural}"


@dataclass(slots=True)
class _ForwardingScan8616:
    """Mutable store-to-load forwarding state across one structured AST walk."""

    changed: bool = False

    def walk_statements(self, statements_obj: object) -> None:
        """Walk statements through the dynamic third-party angr C AST boundary."""
        stmts = _unwrap_statements_8616(statements_obj)
        # Map addr_key → stored_value for pending stores
        pending_stores: dict[str, object] = {}

        for stmt in stmts:
            # Kill pending stores on side effects
            if _has_side_effects_stmt(stmt):
                pending_stores.clear()

            self._forward_assignment(stmt, pending_stores)

            self.walk_node(stmt)

    def _forward_assignment(
        self,
        stmt: object,
        pending_stores: dict[str, object],
    ) -> None:
        """Forward proven stores into reads and record new pointer stores."""
        from angr.analyses.decompiler.structured_codegen import c as structured_c

        if not isinstance(stmt, structured_c.CAssignment):
            return
        rhs = getattr(stmt, "rhs", None)
        lhs = getattr(stmt, "lhs", None)

        # Forward: if reading from a stored-to address
        if rhs is not None and _is_deref_read(rhs):
            addr_expr = _addr_expr_from_deref(rhs)
            key = _addr_key(addr_expr)
            if key is not None and key in pending_stores:
                replacement = pending_stores[key]
                if replacement is not None and not _is_same_expr(replacement, rhs):
                    stmt.rhs = _unwrap_c_casts(replacement)
                    self.changed = True

        # Record: if this is a store through a pointer, record it
        if lhs is not None and _is_deref_write(stmt):
            addr_expr = _addr_expr_from_deref(lhs)
            key = _addr_key(addr_expr)
            if key is not None and rhs is not None:
                pending_stores[key] = _unwrap_c_casts(rhs)

    def walk_node(self, node: object) -> None:
        """Walk nested nodes through the dynamic third-party angr C AST boundary."""
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
            for case_body in _iter_switch_case_bodies_8616(getattr(node, "cases", None)):
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


def _widening_store_to_load_forwarding_8616(codegen: object) -> bool:
    """Forward stored values to subsequent loads within the same block.

    Pattern:
        *(addr) = value;
        ...
        use = *(addr);   →  use = value;

    Only forwards when the address expressions have identical alias storage
    domains and there is no intervening side-effecting operation.

    Returns True if any load was forwarded.
    The codegen and C AST nodes cross a dynamic third-party angr boundary.
    """
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False

    scan = _ForwardingScan8616()
    scan.walk_statements(cfunc)
    return scan.changed


def _has_side_effects_stmt(stmt: object) -> bool:
    """Check if a statement has side effects that invalidate memory forwarding."""
    from angr.analyses.decompiler.structured_codegen import c as structured_c

    if isinstance(stmt, structured_c.CFunctionCall):
        return True
    return bool(isinstance(stmt, structured_c.CReturn))


def _is_same_expr(a: object, b: object) -> bool:
    """Check if two expressions are structurally identical across the dynamic third-party angr boundary."""
    from angr.analyses.decompiler.structured_codegen import c as structured_c

    if type(a) is not type(b):
        return False
    if isinstance(a, structured_c.CVariable):
        return getattr(a, "variable", None) is getattr(b, "variable", None) and getattr(a, "offset", None) == getattr(
            b, "offset", None
        )
    if isinstance(a, structured_c.CConstant):
        return getattr(a, "value", None) == getattr(b, "value", None)
    if isinstance(a, structured_c.CBinaryOp):
        rhs_binary = b
        return (
            a.op == getattr(rhs_binary, "op", None)
            and _is_same_expr(a.lhs, getattr(rhs_binary, "lhs", None))
            and _is_same_expr(a.rhs, getattr(rhs_binary, "rhs", None))
        )
    if isinstance(a, structured_c.CUnaryOp):
        rhs_unary = b
        return a.op == getattr(rhs_unary, "op", None) and _is_same_expr(
            a.operand, getattr(rhs_unary, "operand", None)
        )
    return a is b
