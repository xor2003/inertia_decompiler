"""Project a selected VEX bit through proven neutral bitwise operands.

Layer: IR.
Responsibility: retain an equivalent source for one selected bit, not an
equivalent whole value. Consumers must extract only that bit. Captured temporaries
stay captured; this pass never moves a register or memory read across a write.
Unknown operators, malformed definitions and exhausted bounds retain the input.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from pyvex.block import IRTypeEnv
from pyvex.expr import Binop, Const, IRExpr, RdTmp
from pyvex.stmt import IRStmt, WrTmp


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
    and_op, or_op = f"Iop_And{width}", f"Iop_Or{width}"
    exhausted = False
    remaining = 1024

    def resolve(expression: IRExpr) -> IRExpr:
        """Inspect definitions without replacing a captured atom by a live read."""
        nonlocal exhausted, remaining
        seen: set[int] = set()
        for _ in range(64):
            remaining -= 1
            if remaining < 0 or (isinstance(expression, RdTmp) and expression.tmp in seen):
                exhausted = True
                return expression
            if not isinstance(expression, RdTmp) or expression.tmp not in definitions:
                return expression
            seen.add(expression.tmp)
            expression = definitions[expression.tmp]
        exhausted = True
        return source

    def known(expression: IRExpr, depth: int = 0) -> int | None:
        """Prove one constant bit, short-circuiting annihilating operands."""
        nonlocal exhausted
        if depth >= 64 or exhausted:
            exhausted = True
            return None
        value = resolve(expression)
        if isinstance(value, Const) and value.result_size(tyenv) == width:
            number = value.con.value
            return (number >> bit) & 1 if isinstance(number, int) else None
        if not isinstance(value, Binop) or value.op not in {and_op, or_op}:
            return None
        if any(arg.result_size(tyenv) != width for arg in value.args):
            return None
        annihilator = 0 if value.op == and_op else 1
        right = known(value.args[1], depth + 1)
        if right == annihilator:
            return annihilator
        left = known(value.args[0], depth + 1)
        if left == annihilator:
            return annihilator
        return left if left is not None and left == right else None

    selected = source
    visited: set[int] = set()
    for _ in range(64):
        if isinstance(selected, RdTmp):
            if selected.tmp in visited:
                exhausted = True
                break
            visited.add(selected.tmp)
        value = resolve(selected)
        if not isinstance(value, Binop) or value.op not in {and_op, or_op}:
            break
        if any(arg.result_size(tyenv) != width for arg in value.args):
            break
        neutral = 1 if value.op == and_op else 0
        left, right = value.args
        candidate = left if known(right) == neutral else right if known(left) == neutral else None
        if not isinstance(candidate, (RdTmp, Const)) or candidate.result_size(tyenv) != width:
            break
        selected = candidate
    else:
        exhausted = True
    if exhausted:
        selected = source
    changed = int(selected is not source)
    return BitSourceProjection8616(selected, bit, width, 1, changed, changed, changed, 1 - changed)
