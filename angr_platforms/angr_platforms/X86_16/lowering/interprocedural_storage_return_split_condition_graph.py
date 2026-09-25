"""Prove exact decision graphs that consume split DX:AX returns.

Layer: Types/Lowering.
Responsibility: normalize Alias-owned output-piece operands and prove strict,
non-strict, equality, or inequality wide relations through authoritative SSA
CFG edges. Consumes alias, widening, and typed facts. This module does not
materialize trials, inspect assembly or rendered C, or mutate code generation.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from ..alias.domains import register_domain_for_name, register_view_for_name
from ..ir import IRValue, MemSpace
from ..ir.condition_ir import ConditionIR, ConditionOp
from ..ir.ssa_function import SSAFunctionArtifact
from .interprocedural_storage_contracts import (
    StorageIdentity8616,
    StorageTrialSignedness8616,
)
from .interprocedural_storage_return_type_contracts import (
    ReturnStorageTypeFailure8616,
    SplitReturnRelation8616,
)

__all__ = [
    "SplitReturnConditionCandidate8616",
    "select_split_return_condition_8616",
    "split_return_register_matches_8616",
]


@dataclass(frozen=True, slots=True)
class _OrderingPattern8616:
    """One normalized wide ordering relation and its branch topology."""

    first_high_op: ConditionOp
    second_high_op: ConditionOp
    low_op: ConditionOp
    relation: SplitReturnRelation8616
    strict: bool


@dataclass(frozen=True, slots=True)
class SplitReturnConditionCandidate8616:
    """One closed split-return decision-graph interpretation."""

    relation: SplitReturnRelation8616
    conditions: tuple[ConditionIR, ...]
    high_condition: ConditionIR
    low_condition: ConditionIR
    signedness: StorageTrialSignedness8616
    true_sink_addr: int
    false_sink_addr: int
    transparent_block_addrs: tuple[int, ...]


_ORDERING_PATTERNS_8616 = (
    _OrderingPattern8616("sle", "sge", "ule", SplitReturnRelation8616.SLE, False),
    _OrderingPattern8616("sge", "sle", "uge", SplitReturnRelation8616.SGE, False),
    _OrderingPattern8616("ule", "uge", "ule", SplitReturnRelation8616.ULE, False),
    _OrderingPattern8616("uge", "ule", "uge", SplitReturnRelation8616.UGE, False),
    _OrderingPattern8616("slt", "sgt", "ult", SplitReturnRelation8616.SLT, True),
    _OrderingPattern8616("sgt", "slt", "ugt", SplitReturnRelation8616.SGT, True),
    _OrderingPattern8616("ult", "ugt", "ult", SplitReturnRelation8616.ULT, True),
    _OrderingPattern8616("ugt", "ult", "ugt", SplitReturnRelation8616.UGT, True),
)
_SWAPPED_OP_8616: dict[ConditionOp, ConditionOp] = {
    "eq": "eq", "ne": "ne", "slt": "sgt", "sle": "sge",
    "sgt": "slt", "sge": "sle", "ult": "ugt", "ule": "uge",
    "ugt": "ult", "uge": "ule", "zero": "zero", "nonzero": "nonzero",
}


def split_return_register_matches_8616(
    value: object,
    storage: StorageIdentity8616,
) -> bool:
    """Match one typed operand to one exact Alias-owned output view."""
    return bool(
        isinstance(value, IRValue)
        and value.space is MemSpace.REG
        and value.size == storage.width
        and register_domain_for_name(value.name)
        == register_domain_for_name(storage.register)
        and register_view_for_name(value.name)
        == register_view_for_name(storage.register)
    )


def _normalized_condition_8616(
    condition: ConditionIR,
    storage: StorageIdentity8616,
) -> tuple[ConditionOp, object] | None:
    """Place the selected output piece on the left of one comparison."""
    if not condition.is_comparison or condition.width_bits != storage.width * 8:
        return None
    lhs_matches = split_return_register_matches_8616(condition.lhs, storage)
    rhs_matches = split_return_register_matches_8616(condition.rhs, storage)
    if lhs_matches == rhs_matches:
        return None
    if lhs_matches:
        return condition.op, condition.rhs
    return _SWAPPED_OP_8616[condition.op], condition.lhs


def _other_pieces_compatible_8616(high: object, low: object) -> bool:
    """Prove comparison operands are adjacent pieces of one logical value."""
    if not isinstance(high, IRValue) or not isinstance(low, IRValue):
        return False
    if high.size != 2 or low.size != 2 or high.space is not low.space:
        return False
    if high.space is MemSpace.CONST:
        return bool(
            isinstance(high.const, int)
            and not isinstance(high.const, bool)
            and isinstance(low.const, int)
            and not isinstance(low.const, bool)
        )
    if high.space not in {MemSpace.SS, MemSpace.DS, MemSpace.ES}:
        return False
    return bool(
        high.name == low.name
        and high.offset == low.offset + low.size
        and high.index == low.index
        and high.index_shift == low.index_shift
        and high.expr == low.expr
    )


def _successors_8616(artifact: SSAFunctionArtifact, source_addr: int) -> tuple[int, ...]:
    """Return exact sorted successors retained by function SSA."""
    return tuple(
        sorted(
            target
            for target, predecessors in artifact.predecessor_map.items()
            if source_addr in predecessors
        )
    )


def _transparent_branch_path_8616(
    artifact: SSAFunctionArtifact,
    source_addr: int,
    branch_target: int,
    destination_addr: int,
) -> tuple[int, ...] | None:
    """Prove a branch reaches a destination through empty single-edge blocks."""
    if branch_target not in _successors_8616(artifact, source_addr):
        return None
    blocks = {block.addr: block for block in artifact.blocks}
    current = branch_target
    visited: list[int] = []
    while current != destination_addr:
        if current in visited or len(visited) >= len(blocks):
            return None
        block = blocks.get(current)
        if block is None or block.instrs or block.refusals:
            return None
        successors = _successors_8616(artifact, current)
        if len(successors) != 1:
            return None
        visited.append(current)
        current = successors[0]
    return tuple(visited)


def _condition_edges_8616(condition: ConditionIR) -> tuple[int, int, int] | None:
    """Project a known block and both branch targets without optional fields."""
    block, taken, fallthrough = condition.block_addr, condition.taken_target, condition.fallthrough_target
    if not isinstance(block, int) or not isinstance(taken, int) or not isinstance(fallthrough, int):
        return None
    return block, taken, fallthrough


def _ordering_candidate_8616(
    artifact: SSAFunctionArtifact,
    pattern: _OrderingPattern8616,
    first: ConditionIR,
    second: ConditionIR,
    low: ConditionIR,
    dx_storage: StorageIdentity8616,
    ax_storage: StorageIdentity8616,
) -> tuple[SplitReturnConditionCandidate8616 | None, ReturnStorageTypeFailure8616 | None]:
    """Validate one strict or non-strict three-condition ordering graph."""
    first_norm = _normalized_condition_8616(first, dx_storage)
    second_norm = _normalized_condition_8616(second, dx_storage)
    low_norm = _normalized_condition_8616(low, ax_storage)
    if first_norm is None or second_norm is None or low_norm is None:
        return None, None
    if first.producer_insn != second.producer_insn or first_norm[1] != second_norm[1]:
        return None, ReturnStorageTypeFailure8616.SPLIT_OPERAND_CONFLICT
    if not _other_pieces_compatible_8616(first_norm[1], low_norm[1]):
        return None, ReturnStorageTypeFailure8616.SPLIT_OPERAND_CONFLICT
    first_edges, second_edges, low_edges = map(_condition_edges_8616, (first, second, low))
    if first_edges is None or second_edges is None or low_edges is None:
        return None, ReturnStorageTypeFailure8616.SPLIT_CFG_INCOMPLETE
    first_block, first_taken, first_fallthrough = first_edges
    second_block, second_taken, second_fallthrough = second_edges
    low_block, true_sink, false_sink = low_edges
    if true_sink == false_sink:
        return None, ReturnStorageTypeFailure8616.SPLIT_CFG_INCOMPLETE
    if pattern.strict:
        paths = (
            _transparent_branch_path_8616(artifact, first_block, first_fallthrough, second_block),
            _transparent_branch_path_8616(artifact, second_block, second_fallthrough, low_block),
            _transparent_branch_path_8616(artifact, first_block, first_taken, true_sink),
            _transparent_branch_path_8616(artifact, second_block, second_taken, false_sink),
        )
    else:
        paths = (
            _transparent_branch_path_8616(artifact, first_block, first_taken, second_block),
            _transparent_branch_path_8616(artifact, second_block, second_taken, low_block),
            _transparent_branch_path_8616(artifact, second_block, second_fallthrough, true_sink),
            _transparent_branch_path_8616(artifact, first_block, first_fallthrough, false_sink),
        )
    low_paths = (
        _transparent_branch_path_8616(artifact, low_block, true_sink, true_sink),
        _transparent_branch_path_8616(artifact, low_block, false_sink, false_sink),
    )
    if any(path is None for path in (*paths, *low_paths)):
        return None, ReturnStorageTypeFailure8616.SPLIT_CFG_INCOMPLETE
    signed_relations = {
        SplitReturnRelation8616.SLT, SplitReturnRelation8616.SLE,
        SplitReturnRelation8616.SGT, SplitReturnRelation8616.SGE,
    }
    signedness = (
        StorageTrialSignedness8616.SIGNED
        if pattern.relation in signed_relations
        else StorageTrialSignedness8616.UNSIGNED
    )
    transparent = tuple(sorted({block for path in paths for block in path or ()}))
    return SplitReturnConditionCandidate8616(
        pattern.relation, (first, second, low), first, low, signedness,
        true_sink, false_sink, transparent,
    ), None


def _equality_candidate_8616(
    artifact: SSAFunctionArtifact,
    first: ConditionIR,
    low: ConditionIR,
    relation: SplitReturnRelation8616,
    dx_storage: StorageIdentity8616,
    ax_storage: StorageIdentity8616,
) -> tuple[SplitReturnConditionCandidate8616 | None, ReturnStorageTypeFailure8616 | None]:
    """Validate one sign-insensitive two-condition equality decision graph."""
    first_norm = _normalized_condition_8616(first, dx_storage)
    low_norm = _normalized_condition_8616(low, ax_storage)
    if first_norm is None or low_norm is None:
        return None, None
    if not _other_pieces_compatible_8616(first_norm[1], low_norm[1]):
        return None, ReturnStorageTypeFailure8616.SPLIT_OPERAND_CONFLICT
    first_edges, low_edges = map(_condition_edges_8616, (first, low))
    if first_edges is None or low_edges is None:
        return None, ReturnStorageTypeFailure8616.SPLIT_CFG_INCOMPLETE
    first_block, first_taken, first_fallthrough = first_edges
    low_block, true_sink, false_sink = low_edges
    if true_sink == false_sink:
        return None, ReturnStorageTypeFailure8616.SPLIT_CFG_INCOMPLETE
    first_is_equal = first_norm[0] == "eq"
    continue_target = first_taken if first_is_equal else first_fallthrough
    outside_target = first_fallthrough if first_is_equal else first_taken
    outside_sink = false_sink if relation is SplitReturnRelation8616.EQ else true_sink
    paths = (
        _transparent_branch_path_8616(artifact, first_block, continue_target, low_block),
        _transparent_branch_path_8616(artifact, first_block, outside_target, outside_sink),
        _transparent_branch_path_8616(artifact, low_block, true_sink, true_sink),
        _transparent_branch_path_8616(artifact, low_block, false_sink, false_sink),
    )
    if any(path is None for path in paths):
        return None, ReturnStorageTypeFailure8616.SPLIT_CFG_INCOMPLETE
    transparent = tuple(sorted({block for path in paths for block in path or ()}))
    return SplitReturnConditionCandidate8616(
        relation, (first, low), first, low,
        StorageTrialSignedness8616.SIGN_INSENSITIVE,
        true_sink, false_sink, transparent,
    ), None


@dataclass(slots=True)
class _SplitCandidateCensus8616:
    """Collected split-condition candidates and first retained refusal."""

    structural_count: int = 0
    candidates: list[SplitReturnConditionCandidate8616] = field(default_factory=list)
    retained_failure: ReturnStorageTypeFailure8616 | None = None

    def record(
        self,
        candidate: SplitReturnConditionCandidate8616 | None,
        failure: ReturnStorageTypeFailure8616 | None,
    ) -> None:
        """Retain one unique candidate or remember the first refusal."""
        if candidate is not None and candidate not in self.candidates:
            self.candidates.append(candidate)
        self.retained_failure = failure or self.retained_failure


def _ordering_candidates_8616(
    artifact: SSAFunctionArtifact,
    unique: tuple[ConditionIR, ...],
    witness_addr: int,
    dx_storage: StorageIdentity8616,
    ax_storage: StorageIdentity8616,
    census: _SplitCandidateCensus8616,
) -> None:
    """Collect candidates matching each high/low ordering pattern."""
    for pattern in _ORDERING_PATTERNS_8616:
        for first in unique:
            first_norm = _normalized_condition_8616(first, dx_storage)
            if first.producer_insn != witness_addr or first_norm is None or first_norm[0] != pattern.first_high_op:
                continue
            for second in unique:
                second_norm = _normalized_condition_8616(second, dx_storage)
                if second is first or second_norm is None or second_norm[0] != pattern.second_high_op:
                    continue
                for low in unique:
                    low_norm = _normalized_condition_8616(low, ax_storage)
                    if low in {first, second} or low_norm is None or low_norm[0] != pattern.low_op:
                        continue
                    census.structural_count += 1
                    candidate, failure = _ordering_candidate_8616(
                        artifact, pattern, first, second, low, dx_storage, ax_storage,
                    )
                    census.record(candidate, failure)


def _equality_candidates_8616(
    artifact: SSAFunctionArtifact,
    unique: tuple[ConditionIR, ...],
    witness_addr: int,
    dx_storage: StorageIdentity8616,
    ax_storage: StorageIdentity8616,
    census: _SplitCandidateCensus8616,
) -> None:
    """Collect candidates matching each equality low-word pattern."""
    equality_patterns = (
        (SplitReturnRelation8616.EQ, "eq"),
        (SplitReturnRelation8616.NE, "ne"),
    )
    for relation, low_op in equality_patterns:
        for first in unique:
            first_norm = _normalized_condition_8616(first, dx_storage)
            if first.producer_insn != witness_addr or first_norm is None or first_norm[0] not in {"eq", "ne"}:
                continue
            for low in unique:
                low_norm = _normalized_condition_8616(low, ax_storage)
                if low is first or low_norm is None or low_norm[0] != low_op:
                    continue
                census.structural_count += 1
                candidate, failure = _equality_candidate_8616(
                    artifact, first, low, relation, dx_storage, ax_storage,
                )
                census.record(candidate, failure)


def select_split_return_condition_8616(
    artifact: SSAFunctionArtifact,
    witness_addr: int,
    conditions: Sequence[ConditionIR],
    dx_storage: StorageIdentity8616,
    ax_storage: StorageIdentity8616,
) -> tuple[SplitReturnConditionCandidate8616 | None, ReturnStorageTypeFailure8616 | None]:
    """Select exactly one evidence-complete split-return decision graph."""
    unique = tuple(dict.fromkeys(conditions))
    census = _SplitCandidateCensus8616()
    _ordering_candidates_8616(artifact, unique, witness_addr, dx_storage, ax_storage, census)
    _equality_candidates_8616(artifact, unique, witness_addr, dx_storage, ax_storage, census)
    if census.structural_count > 1 or len(census.candidates) > 1:
        return None, ReturnStorageTypeFailure8616.SPLIT_CONDITION_CONFLICT
    if len(census.candidates) == 1:
        return census.candidates[0], None
    return None, census.retained_failure or ReturnStorageTypeFailure8616.SPLIT_CONDITION_NOT_FOUND
