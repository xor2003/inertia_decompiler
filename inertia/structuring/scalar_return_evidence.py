# cython: language_level=3, infer_types=True
"""Preserve typed scalar return leaves across Structuring regeneration.

Layer: Structuring.
Responsibility: Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.

This module changes only expression types and equivalent 16-bit constant
representations. It does not infer function prototypes, branch conditions, or
return values. Types/Lowering owns the later prototype materialization.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import TypeGuard

from angr.analyses.decompiler.structured_codegen.c import CConstant, CExpression, CReturn
from angr.errors import SimEngineError
from angr.sim_type import SimTypeInt, SimTypeShort

from inertia.lowering.c_ast_utils import _same_c_expression_8616

from .branch_return_expressions import sole_return_statement_8616
import dataclasses
import operator

__all__ = [
    "ScalarReturnLeafResult8616",
    "ScalarReturnLeafStats8616",
    "materialize_complete_scalar_return_leaves_8616",
]


@dataclasses.dataclass(frozen=True, )
class ScalarReturnLeafStats8616:
    """Closed evidence counts for one structured scalar return chain."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0


@dataclasses.dataclass(frozen=True, )
class ScalarReturnLeafResult8616:
    """Atomic scalar return-leaf materialization result."""

    changed: cython.bint
    expressions: object
    stats: ScalarReturnLeafStats8616

    @property
    def complete(self) -> cython.bint:
        """Return whether every structured body received one typed leaf fact."""
        count = len(self.expressions)
        return (
            count > 0
            and operator.eq(self.stats.raw_fact_count, count)
            and operator.eq(self.stats.normalized_fact_count, count)
            and operator.eq(self.stats.classified_fact_count, count)
            and operator.eq(self.stats.materialized_count, count)
            and self.stats.failure_count == 0
        )


@cython.ccall
def _is_signed_word_expression_8616(expression: object) -> TypeGuard[CExpression]:
    """Return whether one CFG expression carries a signed 16-bit scalar type."""
    if not isinstance(expression, CExpression):
        return False
    type_ = expression.type
    return (
        isinstance(type_, (SimTypeInt, SimTypeShort))
        and type_.size == 16
        and type_.signed is True
    )


@cython.ccall
def _same_word_return_value_8616(lhs: CExpression, rhs: CExpression) -> cython.bint:
    """Compare exact 16-bit values while ignoring signed constant rendering."""
    if isinstance(lhs, CConstant) and isinstance(rhs, CConstant):
        try:
            return operator.eq((int(lhs.value) & 0xFFFF), (int(rhs.value) & 0xFFFF))
        except (TypeError, ValueError):
            return False
    return _same_c_expression_8616(lhs, rhs)


def _recovered_signed_word_returns_8616(
    cfg_addresses: Iterable[cython.longlong],
    recover_return: Callable[[int], CExpression | None],
) -> object:
    """Collect unique signed-word return expressions proven by the CFG."""
    address: object
    recovered: list[CExpression] = []
    for address in sorted(tuple(set(cfg_addresses))):
        try:
            expression = recover_return(address)
        except (KeyError, SimEngineError):
            continue
        if not _is_signed_word_expression_8616(expression):
            continue
        if not any(_same_word_return_value_8616(expression, prior) for prior in iter(recovered)):
            recovered.append(expression)
    return recovered


def _selected_scalar_return_leaves_8616(
    current: object,
    recovered: object,
    raw_count: cython.longlong,
) -> object:
    """Match each current leaf to exactly one recovered expression."""
    expression: object
    selected: list[CExpression] = []
    for expression in current:
        matches = tuple(
            candidate
            for candidate in iter(recovered)
            if _same_word_return_value_8616(expression, candidate)
        )
        if len(matches) != 1:
            return ScalarReturnLeafResult8616(
                False,
                (),
                ScalarReturnLeafStats8616(raw_count, raw_count, failure_count=1),
            )
        selected.append(matches[0])
    return selected


@cython.ccall
def _apply_scalar_return_leaves_8616(
    body_returns: object,
    selected: object,
) -> cython.bint:
    """Rewrite each non-signed-word leaf to its proven expression."""
    statement: object
    expression: object
    changed = False
    for statement, expression in zip(body_returns, selected, strict=True):
        if statement is None:
            raise AssertionError("complete scalar return proof lost its return statement")
        if not _is_signed_word_expression_8616(statement.retval):
            statement.retval = expression
            changed = True
    return changed


def materialize_complete_scalar_return_leaves_8616(
    bodies: Sequence[object],
    cfg_addresses: Iterable[cython.longlong],
    recover_return: Callable[[int], CExpression | None],
) -> ScalarReturnLeafResult8616:
    """Apply signed CFG return expressions only when every body is covered."""
    raw_count = len(bodies)
    body_returns = tuple(sole_return_statement_8616(body) for body in iter(bodies))
    current = tuple(
        statement.retval
        for statement in iter(body_returns)
        if statement is not None and isinstance(statement.retval, CExpression)
    )
    if raw_count == 0 or operator.ne(len(current), raw_count):
        return ScalarReturnLeafResult8616(
            False,
            (),
            ScalarReturnLeafStats8616(raw_count, len(current), failure_count=1),
        )

    recovered = _recovered_signed_word_returns_8616(cfg_addresses, recover_return)
    selected = _selected_scalar_return_leaves_8616(current, recovered, raw_count)
    if isinstance(selected, ScalarReturnLeafResult8616):
        return selected
    changed = _apply_scalar_return_leaves_8616(body_returns, selected)
    count = len(selected)
    return ScalarReturnLeafResult8616(
        changed,
        tuple(selected),
        ScalarReturnLeafStats8616(count, count, count, count, 0),
    )
