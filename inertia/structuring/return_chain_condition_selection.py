"""Select CFG return-chain conditions without losing branch polarity.

Layer: Structuring.
Responsibility: reconcile an exact-tagged structured zero test with the
machine-decoded JCC zero test used to pair a branch with its return target.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.
Forbidden: CFG discovery, condition recovery, AST rendering, or validation
suppression.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CBinaryOp,
    CConstant,
    CExpression,
    CFunctionCall,
    CTypeCast,
    CUnaryOp,
)

__all__ = (
    "ReturnChainConditionSelectionResult8616",
    "ReturnChainConditionSelectionStats8616",
    "ReturnChainConditionSelectionVerdict8616",
    "select_cfg_return_condition_8616",
)


class ReturnChainConditionSelectionVerdict8616(StrEnum):
    """Typed outcome of reconciling structured and decoded conditions."""

    BRANCH_IDENTITY_UNPROVEN = "branch_identity_unproven"
    NO_COMPARABLE_ZERO_TEST = "no_comparable_zero_test"
    STRUCTURED_POLARITY_MATCH = "structured_polarity_match"
    DECODED_POLARITY_CONFLICT = "decoded_polarity_conflict"


@dataclass(slots=True)
class ReturnChainConditionSelectionStats8616:
    """Closed evidence-loop counters for comparable zero-test conditions."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class ReturnChainConditionSelectionResult8616:
    """Selected condition and the evidence-backed reason for that choice."""

    condition: CExpression
    verdict: ReturnChainConditionSelectionVerdict8616


class _ConditionSelectionCodegen8616(Protocol):
    """Dynamic angr codegen boundary carrying selection diagnostics."""

    _inertia_return_chain_condition_selection_stats_8616: ReturnChainConditionSelectionStats8616
    _inertia_return_chain_condition_selection_result_8616: ReturnChainConditionSelectionResult8616


def _zero_test_equal_orientation_8616(expression: object) -> bool | None:
    """Return whether a call truth test means equality with zero after wrappers."""
    node = expression
    inverted = False
    while True:
        if isinstance(node, CTypeCast):
            node = node.expr
            continue
        if isinstance(node, CUnaryOp) and node.op == "Not":
            inverted = not inverted
            node = node.operand
            continue
        if isinstance(node, CITE):
            true_value = node.iftrue.value if isinstance(node.iftrue, CConstant) else None
            false_value = node.iffalse.value if isinstance(node.iffalse, CConstant) else None
            if (true_value, false_value) == (0, 1):
                inverted = not inverted
                node = node.cond
                continue
            if (true_value, false_value) == (1, 0):
                node = node.cond
                continue
        break
    if isinstance(node, CFunctionCall):
        return inverted
    if not isinstance(node, CBinaryOp) or node.op not in {"CmpEQ", "CmpNE"}:
        return None
    zero_count = sum(
        isinstance(operand, CConstant) and operand.value == 0
        for operand in (node.lhs, node.rhs)
    )
    if zero_count != 1:
        return None
    equal = node.op == "CmpEQ"
    return not equal if inverted else equal


def _selection_stats_8616(codegen: object) -> ReturnChainConditionSelectionStats8616:
    """Return the owned aggregate stats on a dynamic angr codegen boundary."""
    boundary = cast(_ConditionSelectionCodegen8616, codegen)
    try:
        stats = boundary._inertia_return_chain_condition_selection_stats_8616
    except AttributeError:
        stats = ReturnChainConditionSelectionStats8616()
        boundary._inertia_return_chain_condition_selection_stats_8616 = stats
    if not isinstance(stats, ReturnChainConditionSelectionStats8616):
        raise TypeError("return-chain condition-selection stats have an invalid owned contract")
    return stats


def select_cfg_return_condition_8616(
    codegen: object,
    structured_condition: CExpression,
    decoded_condition: CExpression,
    *,
    same_branch_proven: bool,
) -> ReturnChainConditionSelectionResult8616:
    """Prefer decoded JCC evidence only for a proven same-branch polarity conflict."""
    stats = _selection_stats_8616(codegen)
    stats.raw_fact_count += 1
    structured_equal = _zero_test_equal_orientation_8616(structured_condition)
    decoded_equal = _zero_test_equal_orientation_8616(decoded_condition)
    if not same_branch_proven:
        stats.failure_count += 1
        result = ReturnChainConditionSelectionResult8616(
            structured_condition,
            ReturnChainConditionSelectionVerdict8616.BRANCH_IDENTITY_UNPROVEN,
        )
    elif structured_equal is None or decoded_equal is None:
        result = ReturnChainConditionSelectionResult8616(
            structured_condition,
            ReturnChainConditionSelectionVerdict8616.NO_COMPARABLE_ZERO_TEST,
        )
    else:
        stats.normalized_fact_count += 1
        stats.classified_fact_count += 1
        stats.materialized_count += 1
        if structured_equal == decoded_equal:
            result = ReturnChainConditionSelectionResult8616(
                structured_condition,
                ReturnChainConditionSelectionVerdict8616.STRUCTURED_POLARITY_MATCH,
            )
        else:
            result = ReturnChainConditionSelectionResult8616(
                decoded_condition,
                ReturnChainConditionSelectionVerdict8616.DECODED_POLARITY_CONFLICT,
            )
    cast(_ConditionSelectionCodegen8616, codegen)._inertia_return_chain_condition_selection_result_8616 = result
    return result
