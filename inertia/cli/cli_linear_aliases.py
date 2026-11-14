# cython: language_level=3, infer_types=True
"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations
import typing
import cython

from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Protocol

from angr.analyses.decompiler.structured_codegen import c as structured_c
import dataclasses


class _CFunctionLike(Protocol):
    """Structured C function surface needed by adjacent byte-pair alias seeding."""

    statements: object


class _CodegenLike(Protocol):
    """Codegen surface needed by adjacent byte-pair alias seeding."""

    cfunc: _CFunctionLike | None

_ATTR_MISSING_8616 = object()


@cython.ccall
def _safe_child_attr_8616(expr: object, attr: object) -> object:
    """Read one optional angr C AST child attribute."""
    if not hasattr(expr, attr):
        return _ATTR_MISSING_8616
    try:
        # Dynamic codegen boundary: child field names vary across angr C AST nodes.
        return getattr(expr, attr)
    except Exception:
        return _ATTR_MISSING_8616


@cython.ccall
def _count_variable_ids_8616(
    unwrap_c_casts: Callable[[object], object],
    structured_codegen_node: Callable[[object], cython.bint],
    expr: object,
    counts: Counter[cython.longlong],
) -> None:
    """Count variable identities under one expression."""
    variable: object
    attr: object
    item: object
    expr = unwrap_c_casts(expr)
    if isinstance(expr, structured_c.CVariable):
        # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
        variable = getattr(expr, "variable", None)
        if variable is not None:
            counts[id(variable)] += 1
        return
    for attr in ("lhs", "rhs", "operand", "expr"):
        value = _safe_child_attr_8616(expr, attr)
        if value is _ATTR_MISSING_8616 or not structured_codegen_node(value):
            continue
        _count_variable_ids_8616(
            unwrap_c_casts, structured_codegen_node, value, counts
        )
    for attr in ("args", "operands", "statements"):
        items = _safe_child_attr_8616(expr, attr)
        if items is _ATTR_MISSING_8616 or not isinstance(items, Iterable):
            continue
        for item in items:
            if structured_codegen_node(item):
                _count_variable_ids_8616(
                    unwrap_c_casts, structured_codegen_node, item, counts
                )


@cython.dataclasses.dataclass()
class _BytePairSeedVisitor:
    """Seed word aliases for adjacent byte-pair load assignments."""

    project: object
    codegen: _CodegenLike
    structured_codegen_node: Callable[[object], cython.bint]
    unwrap_c_casts: Callable[[object], object]
    match_byte_load_addr_expr: Callable[[object], object | None]
    addr_exprs_are_byte_pair: Callable[[object, object, object], cython.bint]
    make_word_dereference_from_addr_expr: Callable[
        [_CodegenLike, object, object], object
    ]
    dereference_counts: Counter[cython.longlong]
    aliases: object = field(default_factory=dict)

    @cython.ccall
    def visit(self, node: object) -> None:
        """Dispatch one structured-C node to the matching traversal arm."""
        else_node: object
        body: object
        cond: object
        if isinstance(node, structured_c.CStatements):
            self.visit_statements(node)
            return

        if isinstance(node, structured_c.CIfElse):
            # Dynamic codegen boundary: CIfElse condition/body pairs are angr codegen metadata.
            for cond, body in getattr(node, "condition_and_nodes", ()) or ():
                self.visit(cond)
                self.visit(body)
            # Dynamic codegen boundary: CIfElse else payload is optional.
            else_node = getattr(node, "else_node", None)
            if else_node is not None:
                self.visit(else_node)
            return

        if isinstance(node, structured_c.CWhileLoop):
            self.visit(node.condition)
            self.visit(node.body)
            return

        self.visit_loop_variant(node)

    @cython.ccall
    def visit_loop_variant(self, node: object) -> None:
        """Visit angr-version-dependent loop payload fields."""
        do_while_type: object
        for_loop_type: object
        attr: object
        # Dynamic codegen boundary: older/newer angr versions differ on loop node classes.
        do_while_type = getattr(structured_c, "CDoWhileLoop", None)
        if do_while_type is not None and isinstance(node, do_while_type):
            # Dynamic codegen boundary: loop payload fields vary across angr C AST nodes.
            self.visit(getattr(node, "condition", None))
            # Dynamic codegen boundary: loop payload fields vary across angr C AST nodes.
            self.visit(getattr(node, "body", None))
            return

        # Dynamic codegen boundary: older/newer angr versions differ on loop node classes.
        for_loop_type = getattr(structured_c, "CForLoop", None)
        if for_loop_type is not None and isinstance(node, for_loop_type):
            for attr in ("init", "condition", "iteration", "body"):
                # Dynamic codegen boundary: for-loop payload fields vary across angr C AST nodes.
                self.visit(getattr(node, attr, None))

    @cython.ccall
    def visit_statements(self, node: structured_c.CStatements) -> None:
        """Scan adjacent assignment pairs, then recurse into each statement."""
        stmt: object
        stmt_list = node.statements
        if isinstance(stmt_list, list):
            for index in range(len(stmt_list) - 1):
                self.visit_assignment_pair(stmt_list[index], stmt_list[index + 1])
        for stmt in node.statements:
            self.visit(stmt)

    def visit_assignment_pair(self, low_stmt: object, high_stmt: object) -> None:
        """Seed word aliases for one adjacent byte-load assignment pair."""
        high_addr_expr: object
        low_addr_expr: object
        if not (
            isinstance(low_stmt, structured_c.CAssignment)
            and isinstance(high_stmt, structured_c.CAssignment)
            and isinstance(low_stmt.lhs, structured_c.CVariable)
            and isinstance(high_stmt.lhs, structured_c.CVariable)
        ):
            return

        low_addr_expr = self.match_byte_load_addr_expr(
            self.unwrap_c_casts(low_stmt.rhs)
        )
        high_addr_expr = self.match_byte_load_addr_expr(
            self.unwrap_c_casts(high_stmt.rhs)
        )
        if low_addr_expr is None or high_addr_expr is None:
            return
        if not self.addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, self.project):
            return

        pair_counts: Counter[cython.longlong] = Counter()
        _count_variable_ids_8616(
            self.unwrap_c_casts, self.structured_codegen_node, low_addr_expr, pair_counts
        )
        _count_variable_ids_8616(
            self.unwrap_c_casts, self.structured_codegen_node, high_addr_expr, pair_counts
        )
        if any(
            self.dereference_counts[var_id] > pair_counts[var_id]
            for var_id in iter(pair_counts)
        ):
            return

        word_expr = self.make_word_dereference_from_addr_expr(
            self.codegen, self.project, low_addr_expr
        )
        self.record_alias(low_stmt.lhs, word_expr)
        self.record_alias(high_stmt.lhs, word_expr)

    @cython.ccall
    def record_alias(self, lhs: object, expr: object) -> None:
        """Record the word alias for one assignment lhs variable."""
        variable: object
        # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
        variable = getattr(lhs, "variable", None)
        if variable is None:
            return
        self.aliases[id(variable)] = expr


@cython.ccall
def _seed_adjacent_byte_pair_aliases(
    project: object,
    codegen: _CodegenLike,
    *,
    structured_codegen_node: Callable[[object], cython.bint],
    unwrap_c_casts: Callable[[object], object],
    iter_c_nodes_deep: Callable[[object], Iterable[object]],
    match_byte_load_addr_expr: Callable[[object], object | None],
    addr_exprs_are_byte_pair: Callable[[object, object, object], cython.bint],
    make_word_dereference_from_addr_expr: Callable[[_CodegenLike, object, object], object],
) -> object:
    """Seed aliases mapping adjacent byte-load pairs to their word view."""
    cfunc: object
    node: object
    cfunc = codegen.cfunc
    if cfunc is None:
        return {}

    statements = cfunc.statements
    if not structured_codegen_node(statements):
        return {}

    dereference_counts: Counter[cython.longlong] = Counter()
    for node in iter_c_nodes_deep(statements):
        if isinstance(node, structured_c.CUnaryOp) and node.op == "Dereference":
            _count_variable_ids_8616(
                unwrap_c_casts,
                structured_codegen_node,
                # Dynamic codegen boundary: CUnaryOp operand is supplied by angr structured codegen.
                getattr(node, "operand", None),
                dereference_counts,
            )

    visitor = _BytePairSeedVisitor(
        project=project,
        codegen=codegen,
        structured_codegen_node=structured_codegen_node,
        unwrap_c_casts=unwrap_c_casts,
        match_byte_load_addr_expr=match_byte_load_addr_expr,
        addr_exprs_are_byte_pair=addr_exprs_are_byte_pair,
        make_word_dereference_from_addr_expr=make_word_dereference_from_addr_expr,
        dereference_counts=dereference_counts,
    )
    visitor.visit(statements)
    return visitor.aliases
