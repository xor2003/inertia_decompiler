"""Collapse return guards whose alternatives are proved identical.

Layer: Structuring.
Responsibility: remove a structured condition only when its bounded C-AST
expression is side-effect-free and every represented path returns the same
expression.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.

Calls, dereferences, division, unknown nodes, and unequal returns force a typed
refusal. Accepted collapse exposes dead condition carriers to existing
evidence-aware DCE; it never repairs or reinterprets those carriers.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import cast

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CBinaryOp,
    CConstant,
    CIfElse,
    CReturn,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
)

from ..c_ast_utils import _iter_c_nodes_deep_8616, _same_c_expression_8616

_PURE_BINARY_OPS_8616 = frozenset(
    {
        "Add",
        "And",
        "CmpEQ",
        "CmpGE",
        "CmpGT",
        "CmpLE",
        "CmpLT",
        "CmpNE",
        "LogicalAnd",
        "LogicalOr",
        "Mul",
        "Or",
        "Sar",
        "Shl",
        "Shr",
        "Sub",
        "Xor",
    }
)
_PURE_UNARY_OPS_8616 = frozenset({"BitwiseNeg", "Neg", "Not", "Reference"})


class IdenticalReturnGuardRefusalReason8616(Enum):
    """Typed reason why one return guard was retained."""

    MULTIPLE_CONDITION_ARMS = "multiple_condition_arms"
    BRANCH_IS_NOT_ONE_RETURN = "branch_is_not_one_return"
    CONDITION_PURITY_UNPROVEN = "condition_purity_unproven"
    RETURN_EXPRESSION_MISMATCH = "return_expression_mismatch"


class IdenticalReturnGuardShape8616(Enum):
    """Structured representation consumed by one accepted collapse."""

    ELSE_RETURN = "else_return"
    FALLTHROUGH_RETURN = "fallthrough_return"


@dataclass(frozen=True, slots=True)
class IdenticalReturnGuardRefusal8616:
    """One conservatively retained guard and alternate path."""

    statement_index: int
    reason: IdenticalReturnGuardRefusalReason8616


@dataclass(frozen=True, slots=True)
class IdenticalReturnGuardMaterialization8616:
    """Durable shape evidence for one removed return guard."""

    statement_index: int
    shape: IdenticalReturnGuardShape8616


@dataclass(frozen=True, slots=True)
class IdenticalReturnGuardCollapseStats8616:
    """Closed evidence accounting for pure identical-return guard collapse."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every raw candidate reached acceptance or refusal."""
        return bool(
            self.raw_fact_count == self.materialized_count + self.failure_count
            and self.classified_fact_count == self.materialized_count
            and self.raw_fact_count >= self.normalized_fact_count
            and self.normalized_fact_count >= self.classified_fact_count
        )


@dataclass(frozen=True, slots=True)
class IdenticalReturnGuardCollapseResult8616:
    """Typed mutation result for pure identical-return guard collapse."""

    collapsed_guard_count: int = 0
    stats: IdenticalReturnGuardCollapseStats8616 = (
        IdenticalReturnGuardCollapseStats8616()
    )
    materializations: tuple[IdenticalReturnGuardMaterialization8616, ...] = ()
    refusals: tuple[IdenticalReturnGuardRefusal8616, ...] = ()

    @property
    def changed(self) -> bool:
        """Return whether at least one redundant guard was removed."""
        return self.collapsed_guard_count > 0


def _condition_is_proven_pure_8616(condition: object) -> bool:
    """Accept only a bounded C-expression subset with no observable effects."""
    for node in _iter_c_nodes_deep_8616(condition):
        if isinstance(node, (CConstant, CVariable, CTypeCast, CITE)):
            continue
        if isinstance(node, CUnaryOp) and node.op in _PURE_UNARY_OPS_8616:
            continue
        if isinstance(node, CBinaryOp) and node.op in _PURE_BINARY_OPS_8616:
            continue
        return False
    return True


def _single_return_8616(node: object) -> CReturn | None:
    """Unwrap statement containers only when they contain one exact return."""
    current = node
    while isinstance(current, CStatements):
        statements = tuple(cast(Iterable[object], current.statements or ()))
        if len(statements) != 1:
            return None
        current = statements[0]
    return current if isinstance(current, CReturn) else None


@dataclass(slots=True)
class _GuardCandidate8616:
    """One resolved identical-return guard shape awaiting collapse."""

    alternate_node: object
    alternate_return: CReturn
    consumed_count: int
    shape: IdenticalReturnGuardShape8616


def _guard_candidate_8616(
    statements: list[object],
    index: int,
    guard: CIfElse,
) -> _GuardCandidate8616 | None:
    """Resolve the else/fallthrough alternate return shape or skip."""
    else_node = guard.else_node
    alternate_return = _single_return_8616(else_node)
    if alternate_return is not None and else_node is not None:
        return _GuardCandidate8616(
            else_node, alternate_return, 1, IdenticalReturnGuardShape8616.ELSE_RETURN
        )
    if index + 1 >= len(statements):
        return None
    alternate_node = statements[index + 1]
    alternate_return = _single_return_8616(alternate_node)
    if alternate_return is None or else_node is not None:
        return None
    return _GuardCandidate8616(
        alternate_node,
        alternate_return,
        2,
        IdenticalReturnGuardShape8616.FALLTHROUGH_RETURN,
    )


def _collapse_one_guard_8616(
    statements: list[object],
    index: int,
    guard: CIfElse,
    candidate: _GuardCandidate8616,
    refusals: list[IdenticalReturnGuardRefusal8616],
) -> tuple[int, int, int, int]:
    """Validate one guard and splice it, returning index and count deltas."""
    arms = tuple(guard.condition_and_nodes or ())
    if len(arms) != 1:
        refusals.append(
            IdenticalReturnGuardRefusal8616(
                index,
                IdenticalReturnGuardRefusalReason8616.MULTIPLE_CONDITION_ARMS,
            )
        )
        return index + 1, 0, 0, 0
    condition, body = arms[0]
    branch_return = _single_return_8616(body)
    if branch_return is None:
        refusals.append(
            IdenticalReturnGuardRefusal8616(
                index,
                IdenticalReturnGuardRefusalReason8616.BRANCH_IS_NOT_ONE_RETURN,
            )
        )
        return index + 1, 0, 0, 0
    if not _condition_is_proven_pure_8616(condition):
        refusals.append(
            IdenticalReturnGuardRefusal8616(
                index,
                IdenticalReturnGuardRefusalReason8616.CONDITION_PURITY_UNPROVEN,
            )
        )
        return index + 1, 1, 0, 0
    if not _same_c_expression_8616(
        branch_return.retval,
        candidate.alternate_return.retval,
    ):
        refusals.append(
            IdenticalReturnGuardRefusal8616(
                index,
                IdenticalReturnGuardRefusalReason8616.RETURN_EXPRESSION_MISMATCH,
            )
        )
        return index + 1, 1, 0, 0
    statements[index : index + candidate.consumed_count] = [candidate.alternate_node]
    return max(0, index - 1), 1, 1, 1


def collapse_pure_identical_return_guards_8616(
    root: object,
) -> IdenticalReturnGuardCollapseResult8616:
    """Collapse identical pure-guard return paths without semantic recovery."""
    raw_count = normalized_count = classified_count = materialized_count = 0
    materializations: list[IdenticalReturnGuardMaterialization8616] = []
    refusals: list[IdenticalReturnGuardRefusal8616] = []
    containers = tuple(
        node
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, CStatements)
    )

    for container in reversed(containers):
        statements = list(cast(Iterable[object], container.statements or ()))
        index = 0
        while index < len(statements):
            guard = statements[index]
            if not isinstance(guard, CIfElse):
                index += 1
                continue
            candidate = _guard_candidate_8616(statements, index, guard)
            if candidate is None:
                index += 1
                continue
            raw_count += 1
            next_index, normalized, classified, materialized = _collapse_one_guard_8616(
                statements, index, guard, candidate, refusals
            )
            normalized_count += normalized
            classified_count += classified
            materialized_count += materialized
            if materialized:
                materializations.append(
                    IdenticalReturnGuardMaterialization8616(index, candidate.shape)
                )
                container.statements = statements
            index = next_index

    stats = IdenticalReturnGuardCollapseStats8616(
        raw_fact_count=raw_count,
        normalized_fact_count=normalized_count,
        classified_fact_count=classified_count,
        materialized_count=materialized_count,
        failure_count=len(refusals),
    )
    return IdenticalReturnGuardCollapseResult8616(
        collapsed_guard_count=materialized_count,
        stats=stats,
        materializations=tuple(materializations),
        refusals=tuple(refusals),
    )
