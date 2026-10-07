"""Resolve duplicate typed-condition evidence before C materialization.

Layer: Types/Lowering.
Responsibility: normalize competing ``ConditionIR`` facts at the transfer
boundary and refuse operand ambiguity before Structuring consumes the facts.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.

This module does not decode instructions, infer branch semantics, or inspect
rendered C. It only arbitrates already-owned typed facts for the same exact CFG
branch identity. A stale self-comparison may be discarded only when one unique
non-self fact exists; multiple non-self alternatives are refused as ambiguous.
When one alternative has uniquely replaced more register/TMP carriers with
segmented or constant identities, that bound fact is stronger; equally bound
alternatives remain ambiguous.
"""

from __future__ import annotations

from dataclasses import dataclass

from inertia.ir.condition_ir import ConditionIR, deduplicate_conditions_8616
from inertia.ir.core import IRBinaryValue, IRValue, MemSpace

type _BranchIdentity8616 = tuple[
    object,
    int,
    tuple[str, ...],
    int | None,
    int | None,
    int | None,
    int | None,
    int | None,
    int | None,
]


@dataclass(frozen=True, slots=True)
class ConditionFactResolution8616:
    """Report deterministic condition-fact arbitration and refusals."""

    conditions: tuple[ConditionIR, ...]
    raw_fact_count: int
    normalized_fact_count: int
    failure_count: int


def _branch_identity_8616(condition: ConditionIR) -> _BranchIdentity8616:
    """Return the operand-independent identity of one typed CFG branch."""
    return (
        condition.op,
        condition.width_bits,
        condition.source,
        condition.src_insn,
        condition.block_addr,
        condition.producer_insn,
        condition.taken_target,
        condition.fallthrough_target,
        condition.operand_bind_insn,
    )


def _same_operands_8616(left: ConditionIR, right: ConditionIR) -> bool:
    """Compare owned ConditionIR operands without rendered-text fingerprints."""
    return left.lhs == right.lhs and left.rhs == right.rhs


def _is_self_comparison_8616(condition: ConditionIR) -> bool:
    """Return whether a binary comparison has identical owned operands."""
    return condition.is_comparison and condition.rhs is not None and condition.lhs == condition.rhs


def _bound_value_count_8616(value: object) -> int:
    """Count concrete storage and literal leaves in one owned IR value tree."""
    bound_spaces = {MemSpace.SS, MemSpace.DS, MemSpace.ES, MemSpace.CONST}
    if isinstance(value, IRValue):
        return int(value.space in bound_spaces)
    if isinstance(value, IRBinaryValue):
        return _bound_value_count_8616(value.lhs) + _bound_value_count_8616(value.rhs)
    return 0


def _bound_operand_count_8616(condition: ConditionIR) -> int:
    """Count concrete leaves across scalar or composite condition operands."""
    return _bound_value_count_8616(condition.lhs) + _bound_value_count_8616(condition.rhs)


def resolve_condition_fact_conflicts_8616(
    conditions: list[ConditionIR] | tuple[ConditionIR, ...],
) -> ConditionFactResolution8616:
    """Resolve exact-branch duplicates and refuse unresolved operand conflicts.

    Duplicate lifter cache entries can carry stale register state. For one
    exact branch, a unique non-self comparison outranks stale self-comparison
    alternatives. A uniquely more-bound non-self fact outranks register/TMP
    carrier alternatives. Equal-strength operand conflicts are refused.
    """
    deduplicated = deduplicate_conditions_8616(list(conditions))
    grouped: dict[_BranchIdentity8616, list[ConditionIR]] = {}
    for condition in deduplicated:
        grouped.setdefault(_branch_identity_8616(condition), []).append(condition)

    resolved: list[ConditionIR] = []
    failures = 0
    for candidates in grouped.values():
        distinct: list[ConditionIR] = []
        for candidate in candidates:
            if not any(_same_operands_8616(candidate, prior) for prior in distinct):
                distinct.append(candidate)
        if len(distinct) == 1:
            resolved.append(distinct[0])
            continue

        non_self = [candidate for candidate in distinct if not _is_self_comparison_8616(candidate)]
        if len(non_self) == 1:
            resolved.append(non_self[0])
            failures += len(distinct) - 1
            continue

        if non_self:
            strongest_score = max(_bound_operand_count_8616(candidate) for candidate in non_self)
            strongest = [
                candidate
                for candidate in non_self
                if _bound_operand_count_8616(candidate) == strongest_score
            ]
            if len(strongest) == 1:
                resolved.append(strongest[0])
                failures += len(distinct) - 1
                continue

        failures += len(distinct)

    resolved.sort(
        key=lambda condition: (
            condition.block_addr if isinstance(condition.block_addr, int) else -1,
            condition.src_insn if isinstance(condition.src_insn, int) else -1,
            condition.op,
        )
    )
    return ConditionFactResolution8616(
        conditions=tuple(resolved),
        raw_fact_count=len(conditions),
        normalized_fact_count=len(resolved),
        failure_count=failures,
    )
