"""Project a selected VEX bit through proven neutral bitwise operands.

Layer: IR.
Responsibility: retain an equivalent source for one selected bit, not an
equivalent whole value. Consumers must extract only that bit. Captured temporaries
stay captured; this pass never moves a register or memory read across a write.
Unknown operators, malformed definitions and exhausted bounds retain the input.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from pyvex.block import IRTypeEnv
from pyvex.expr import Binop, Const, IRExpr, RdTmp
from pyvex.stmt import IRStmt, WrTmp

_MAX_DEFINITION_DEPTH: int = 64
_MAX_PROOF_STEPS: int = 1024


@dataclass(frozen=True, slots=True)
class BitSourceProjection8616:
    """Closed proof of a selected bit; other output bits are unspecified."""

    source: IRExpr
    bit: int
    width_bits: int
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(slots=True)
class _BitSourceQuery:
    """Share a bounded proof budget across definition and constant-bit queries."""

    source: IRExpr
    definitions: dict[int, IRExpr]
    tyenv: IRTypeEnv
    bit: int
    width: int
    and_op: str
    or_op: str
    exhausted: bool = False
    remaining: int = _MAX_PROOF_STEPS

    def resolve(self, expression: IRExpr) -> IRExpr:
        """Inspect definitions without replacing a captured atom by a live read."""
        seen: set[int] = set()
        for _ in range(_MAX_DEFINITION_DEPTH):
            self.remaining -= 1
            if self.remaining < 0 or (isinstance(expression, RdTmp) and expression.tmp in seen):
                self.exhausted = True
                return expression
            if not isinstance(expression, RdTmp) or expression.tmp not in self.definitions:
                return expression
            seen.add(expression.tmp)
            expression = self.definitions[expression.tmp]
        self.exhausted = True
        return self.source

    def known(self, expression: IRExpr, depth: int = 0) -> int | None:
        """Prove one constant bit, short-circuiting annihilating operands."""
        if depth >= _MAX_DEFINITION_DEPTH or self.exhausted:
            self.exhausted = True
            return None
        value = self.resolve(expression)
        if isinstance(value, Const) and value.result_size(self.tyenv) == self.width:
            number = value.con.value
            return (number >> self.bit) & 1 if isinstance(number, int) else None
        if not isinstance(value, Binop) or value.op not in {self.and_op, self.or_op}:
            return None
        if any(arg.result_size(self.tyenv) != self.width for arg in value.args):
            return None
        annihilator = 0 if value.op == self.and_op else 1
        right = self.known(value.args[1], depth + 1)
        if right == annihilator:
            return annihilator
        left = self.known(value.args[0], depth + 1)
        if left == annihilator:
            return annihilator
        return left if left is not None and left == right else None

    def select(self) -> IRExpr:
        """Select captured neutral operands, rolling back any exhausted proof."""
        selected = self.source
        visited: set[int] = set()
        for _ in range(_MAX_DEFINITION_DEPTH):
            if isinstance(selected, RdTmp):
                if selected.tmp in visited:
                    self.exhausted = True
                    break
                visited.add(selected.tmp)
            value = self.resolve(selected)
            if not isinstance(value, Binop) or value.op not in {self.and_op, self.or_op}:
                break
            if any(arg.result_size(self.tyenv) != self.width for arg in value.args):
                break
            neutral = 1 if value.op == self.and_op else 0
            left, right = value.args
            candidate = left if self.known(right) == neutral else right if self.known(left) == neutral else None
            if not isinstance(candidate, (RdTmp, Const)) or candidate.result_size(self.tyenv) != self.width:
                break
            selected = candidate
        else:
            self.exhausted = True
        return self.source if self.exhausted else selected


def project_bit_source_8616(
    source: IRExpr, statements: Sequence[IRStmt], tyenv: IRTypeEnv, *, bit: int,
) -> BitSourceProjection8616:
    """Remove neutral AND/OR inputs for one bit using bounded SSA definitions."""
    width = source.result_size(tyenv)
    definitions: dict[int, IRExpr] = {}
    for statement in statements:
        if isinstance(statement, WrTmp):
            if statement.tmp in definitions:
                return BitSourceProjection8616(source, bit, width, 1, 0, 0, 0, 1)
            definitions[statement.tmp] = statement.data
    if width not in {8, 16, 32} or not 0 <= bit < width:
        return BitSourceProjection8616(source, bit, width, 1, 0, 0, 0, 1)
    query = _BitSourceQuery(source, definitions, tyenv, bit, width, f"Iop_And{width}", f"Iop_Or{width}")
    selected = query.select()
    changed = int(selected is not source)
    return BitSourceProjection8616(selected, bit, width, 1, changed, changed, changed, 1 - changed)
