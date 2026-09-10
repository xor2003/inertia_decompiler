"""Normalize constant displacements on native integer register values.

Layer: IR/native AIL adapter.
Responsibility: reassociate only same-width integer Add/Sub chains with one
register base. Preserve evaluation, source tags and bit-vector wrapping. This
does not prove stack ownership, infer addresses or delete statements.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import cast

import networkx as nx
from angr.ailment.block import Block
from angr.ailment.block_walker import AILBlockRewriter
from angr.ailment.expression import BinaryOp, Const, Expression, Register, VirtualVariable, VirtualVariableCategory
from angr.ailment.manager import Manager
from angr.ailment.statement import Statement

_MIN_FOLD_TERMS: int = 2


@dataclass(frozen=True, slots=True)
class RegisterDisplacementFact8616:
    """One bit-vector identity, including the source and fresh output atoms."""

    source_indices: tuple[int | None, ...]
    result_index: int | None
    width_bits: int
    displacement: int


@dataclass(frozen=True, slots=True)
class RegisterDisplacementReport8616:
    """Closed census of local arithmetic folds, not dead-code consumption."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    facts: tuple[RegisterDisplacementFact8616, ...]


def _fold_8616(
    expression: BinaryOp, manager: Manager,
) -> tuple[Expression, RegisterDisplacementFact8616] | None:
    """Fold a same-width integer chain with exactly one register evaluation."""
    bits = expression.bits
    if bits not in {8, 16, 32}:
        return None
    base: Expression = expression
    displacement = 0
    indices: list[int | None] = []
    while isinstance(base, BinaryOp) and base.op in {"Add", "Sub"}:
        left, constant = base.operands
        if not (
            not base.floating_point and isinstance(constant, Const)
            and type(constant.value) is int
            and base.bits == left.bits == constant.bits == bits
        ):
            return None
        indices.append(base.idx)
        displacement += constant.value if base.op == "Add" else -constant.value
        base = left
    if len(indices) < _MIN_FOLD_TERMS or not (
        isinstance(base, Register)
        or (isinstance(base, VirtualVariable) and base.category is VirtualVariableCategory.REGISTER)
    ):
        return None
    displacement %= 1 << bits
    result = base
    if displacement:
        negative = displacement >= 1 << (bits - 1)
        # Fresh atoms are mandatory: reusing an expression ID for a constant
        # can attach stale variable-recovery bindings to the new value.
        constant = Const(manager.next_atom(), (1 << bits) - displacement if negative else displacement, bits)
        result = BinaryOp(
            manager.next_atom(), "Sub" if negative else "Add", (base, constant),
            expression.signed, bits=bits, **expression.tags,
        )
    return result, RegisterDisplacementFact8616(tuple(indices), result.idx, bits, displacement)


class _DisplacementWalker8616:
    """Normalize bottom-up with the native copy-on-change expression walker."""

    def __init__(self, manager: Manager) -> None:
        self.manager = manager
        self.raw: int = 0
        self.facts: list[RegisterDisplacementFact8616] = []
        self.native = AILBlockRewriter()
        self._native_binary = cast(
            Callable[[int, BinaryOp, int, Statement | None, Block | None], Expression],
            self.native.expr_handlers[BinaryOp],
        )
        self.native.expr_handlers[BinaryOp] = self._handle_BinaryOp

    def _handle_BinaryOp(
        self, expr_idx: int, expr: BinaryOp, stmt_idx: int,
        stmt: Statement | None, block: Block | None,
    ) -> Expression:
        """Visit children, then consider only a nested Add/Sub candidate."""
        rewritten = self._native_binary(expr_idx, expr, stmt_idx, stmt, block)
        if not (
            isinstance(rewritten, BinaryOp) and rewritten.op in {"Add", "Sub"}
            and isinstance(rewritten.operands[0], BinaryOp)
            and rewritten.operands[0].op in {"Add", "Sub"}
        ):
            return rewritten
        self.raw += 1
        result = _fold_8616(rewritten, self.manager)
        if result is None:
            return rewritten
        normalized, fact = result
        self.facts.append(fact)
        return normalized


def normalize_register_displacements_8616(
    graph: nx.DiGraph[Block], manager: Manager,
) -> RegisterDisplacementReport8616:
    """Fold native register arithmetic without changing statements or CFG edges."""
    walker = _DisplacementWalker8616(manager)
    for block in sorted(graph, key=lambda node: (node.addr, -1 if node.idx is None else node.idx)):
        walker.native.walk(block)
    count = len(walker.facts)
    return RegisterDisplacementReport8616(walker.raw, count, count, count, walker.raw - count, tuple(walker.facts))
