# cython: language_level=3, infer_types=True
"""Distinguish native stack-relative address bases from numeric operands.

Layer: Frontend/angr compatibility.
Responsibility: guard native propagation by exact SSA operand roles. A memory
address permits a single positive affine base, not arbitrary arithmetic on the
numeric stack register. This is not Alias recovery or permission for DCE.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Callable
from enum import Enum

from angr.ailment.block import Block
from angr.ailment.block_walker import AILBlockViewer
from angr.ailment.expression import BinaryOp, Const, Convert, Expression, Load, VirtualVariable
from angr.ailment.statement import Assignment, Statement, Store

_ExpressionVisitor8616 = Callable[[int, Expression, int, Statement | None, Block | None], None]


class StackValueUse8616(Enum):
    """Distinguish address-only operands from numeric or unlocated SSA uses."""

    UNKNOWN = "unknown"
    ADDRESS_ONLY = "address_only"
    VALUE = "value"


@cython.cclass
class _StackValueUses8616:
    """Collect roles independently for each memory-address evaluation."""
    address = cython.declare(object, visibility = "public")
    address_counts = cython.declare(object, visibility = "public")
    uses = cython.declare(dict, visibility = "public")
    walker = cython.declare(object, visibility = "public")

    def __init__(self) -> None:
        handler: object
        kind: object
        self.address: cython.bint = False
        self.address_counts: dict[cython.longlong, cython.longlong] = {}
        self.uses: dict[cython.longlong, set[cython.bint]] = {}
        self.walker = AILBlockViewer()
        for kind, handler in tuple(self.walker.expr_handlers.items()):
            if kind not in (VirtualVariable, BinaryOp, Convert, Const, Load):
                self.walker.expr_handlers[kind] = self._value_handler(handler)
        self.walker.expr_handlers[VirtualVariable] = self._handle_VirtualVariable
        self.walker.expr_handlers[BinaryOp] = self._handle_BinaryOp
        self.walker.expr_handlers[Load] = self._handle_Load
        self.walker.stmt_handlers[Assignment] = self._handle_Assignment
        self.walker.stmt_handlers[Store] = self._handle_Store

    def _value_handler(self, handler: _ExpressionVisitor8616) -> _ExpressionVisitor8616:
        """Keep opaque operands numeric, even inside an enclosing address."""
        def visit(
            expr_idx: cython.longlong, expr: Expression, stmt_idx: cython.longlong, stmt: Statement | None, block: Block | None,
        ) -> None:
            """Visit opaque operands and restore the enclosing role."""
            saved = self.address
            self.address = False
            handler(expr_idx, expr, stmt_idx, stmt, block)
            self.address = saved
        return visit

    @cython.ccall
    def _handle_expr(
        self, expr_idx: cython.longlong, expr: Expression, stmt_idx: cython.longlong, stmt: Statement | None, block: Block | None,
    ) -> None:
        """Delegate through the native visitor's registered handlers."""
        self.walker.walk_expression(expr, stmt_idx=stmt_idx, stmt=stmt, block=block)

    @cython.ccall
    def _address_operand(
        self, expr: Expression, stmt_idx: cython.longlong, stmt: Statement | None, block: Block | None,
    ) -> None:
        """Require at most one positive occurrence of each base per address."""
        count: object
        varid: object
        saved_address, saved_counts = self.address, self.address_counts
        self.address, self.address_counts = True, {}
        self._handle_expr(0, expr, stmt_idx, stmt, block)
        for varid, count in self.address_counts.items():
            if count > 1:
                self.uses[varid].add(False)
        self.address, self.address_counts = saved_address, saved_counts

    @cython.ccall
    def _handle_Assignment(self, stmt_idx: cython.longlong, stmt: Assignment, block: Block | None) -> None:
        """Visit the source, not the definition of an SSA value."""
        self._handle_expr(1, stmt.src, stmt_idx, stmt, block)

    @cython.ccall
    def _handle_VirtualVariable(
        self, expr_idx: cython.longlong, expr: VirtualVariable, stmt_idx: cython.longlong, stmt: Statement | None, block: Block | None,
    ) -> None:
        """Record occurrences, including mixed address and data uses."""
        self.uses.setdefault(expr.varid, set()).add(self.address)
        if self.address:
            self.address_counts[expr.varid] = self.address_counts.get(expr.varid, 0) + 1

    @cython.ccall
    def _handle_BinaryOp(
        self, expr_idx: cython.longlong, expr: BinaryOp, stmt_idx: cython.longlong, stmt: Statement | None, block: Block | None,
    ) -> None:
        """Only addition and a subtraction's left operand retain base roles."""
        index: object
        operand: object
        saved = self.address
        if expr.op not in {"Add", "Sub"}:
            self.address = False
        for index, operand in enumerate(expr.operands):
            if expr.op == "Sub" and index > 0:
                self.address = False
            self._handle_expr(index, operand, stmt_idx, stmt, block)
        self.address = saved

    @cython.ccall
    def _handle_Load(
        self, expr_idx: cython.longlong, expr: Load, stmt_idx: cython.longlong, stmt: Statement | None, block: Block | None,
    ) -> None:
        """Only the load address is an address; guards and alternatives are values."""
        saved = self.address
        self._address_operand(expr.addr, stmt_idx, stmt, block)
        self.address = False
        if expr.guard is not None:
            self._handle_expr(1, expr.guard, stmt_idx, stmt, block)
        if expr.alt is not None:
            self._handle_expr(2, expr.alt, stmt_idx, stmt, block)
        self.address = saved

    @cython.ccall
    def _handle_Store(self, stmt_idx: cython.longlong, stmt: Store, block: Block | None) -> None:
        """Separate stored values and guards from the destination address."""
        self._address_operand(stmt.addr, stmt_idx, stmt, block)
        self.address = False
        self._handle_expr(1, stmt.data, stmt_idx, stmt, block)
        if stmt.guard is not None:
            self._handle_expr(2, stmt.guard, stmt_idx, stmt, block)


@cython.ccall
def classify_stack_value_use_8616(statement: object, varid: cython.longlong) -> StackValueUse8616:
    """Classify one native AIL statement's use of an exact SSA value identity."""
    roles: object
    if statement is None:
        return StackValueUse8616.UNKNOWN
    visitor = _StackValueUses8616()
    visitor.walker.walk_statement(statement)
    roles = visitor.uses.get(varid)
    if roles == {True}:
        return StackValueUse8616.ADDRESS_ONLY
    return StackValueUse8616.VALUE if roles else StackValueUse8616.UNKNOWN
