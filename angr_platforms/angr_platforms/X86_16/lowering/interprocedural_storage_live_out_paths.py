"""Prove caller CFG paths from one call output to one memory use.

Layer: Types/Lowering.
Responsibility: require every caller path reaching one candidate LOAD to
preserve the same CALL_OUTPUT. This module consumes canonical function SSA and
the Alias-owned segmented access relation; it does not infer storage, mutate
prototypes, structure control flow, or render C.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from ..alias.storage_fact_join import (
    SegmentedAccessRelation8616,
    segmented_access_relation_8616,
)
from ..ir import IRAddress
from ..ir.ssa import SSABlock
from ..ir.ssa_function import SSAFunctionArtifact
from .interprocedural_storage_contracts import (
    StorageIdentity8616,
    StorageReachingDefinition8616,
    StorageUseEvidence8616,
)
from .interprocedural_storage_live_out_contracts import MemoryLiveOutFailureKind8616
from .interprocedural_storage_return_defs import CallOutputDefinitionResult8616

__all__ = [
    "MemoryLiveOutPathResult8616",
    "MemoryLiveOutPathVerdict8616",
    "memory_live_out_path_failure_8616",
    "prove_memory_live_out_path_8616",
]


class MemoryLiveOutPathVerdict8616(StrEnum):
    """Universal result for paths that can reach one candidate memory use."""

    CLEAN = "clean"
    OVERWRITTEN = "overwritten"
    NOT_REACHED = "not_reached"
    UNKNOWN_REFUSE = "unknown_refuse"


@dataclass(frozen=True, slots=True)
class MemoryLiveOutPathResult8616:
    """One closed universal path verdict or its stable refusal reason."""

    verdict: MemoryLiveOutPathVerdict8616
    failure: MemoryLiveOutFailureKind8616 | None = None

    @property
    def complete(self) -> bool:
        """Return whether the verdict and refusal fields agree."""
        return (self.verdict is MemoryLiveOutPathVerdict8616.UNKNOWN_REFUSE) == (
            self.failure is not None
        )


_FAILURE_PRIORITY_8616 = (
    MemoryLiveOutFailureKind8616.INTERVENING_ALIAS,
    MemoryLiveOutFailureKind8616.INTERVENING_CALL,
    MemoryLiveOutFailureKind8616.INTERVENING_WRITE,
    MemoryLiveOutFailureKind8616.CFG_INCOMPLETE,
    MemoryLiveOutFailureKind8616.CFG_CYCLE,
)


def _validated_cfg_8616(
    artifact: SSAFunctionArtifact,
) -> tuple[dict[int, SSABlock], dict[int, tuple[int, ...]]] | None:
    """Return exact block and successor maps when the CFG census closes."""
    blocks = {block.addr: block for block in artifact.blocks}
    if len(blocks) != len(artifact.blocks) or set(artifact.predecessor_map) != set(blocks):
        return None
    successors: dict[int, set[int]] = {address: set() for address in blocks}
    for successor, predecessors in artifact.predecessor_map.items():
        if any(predecessor not in blocks for predecessor in predecessors):
            return None
        for predecessor in predecessors:
            successors[predecessor].add(successor)
    return blocks, {
        address: tuple(sorted(values)) for address, values in successors.items()
    }


def _target_reaching_blocks_8616(
    predecessor_map: dict[int, tuple[int, ...]],
    target_block_addr: int,
) -> frozenset[int]:
    """Return blocks on at least one reverse CFG path to the target block."""
    reaching = {target_block_addr}
    pending = [target_block_addr]
    while pending:
        block_addr = pending.pop()
        for predecessor in predecessor_map[block_addr]:
            if predecessor not in reaching:
                reaching.add(predecessor)
                pending.append(predecessor)
    return frozenset(reaching)


def memory_live_out_path_failure_8616(
    results: tuple[MemoryLiveOutPathResult8616, ...],
) -> MemoryLiveOutFailureKind8616 | None:
    """Select the deterministic highest-priority refusal from path results."""
    failures: set[MemoryLiveOutFailureKind8616] = {
        result.failure for result in results if result.failure is not None
    }
    prioritized = next(
        (failure for failure in _FAILURE_PRIORITY_8616 if failure in failures),
        None,
    )
    return prioritized or min(failures, key=lambda failure: failure.value, default=None)


def _aggregate_results_8616(
    results: tuple[MemoryLiveOutPathResult8616, ...],
) -> MemoryLiveOutPathResult8616:
    """Join all target-reaching successor results without short-circuiting."""
    failure = memory_live_out_path_failure_8616(results)
    if failure is not None:
        return MemoryLiveOutPathResult8616(
            MemoryLiveOutPathVerdict8616.UNKNOWN_REFUSE,
            failure,
        )
    verdicts = {result.verdict for result in results}
    if {
        MemoryLiveOutPathVerdict8616.CLEAN,
        MemoryLiveOutPathVerdict8616.OVERWRITTEN,
    } <= verdicts:
        return MemoryLiveOutPathResult8616(
            MemoryLiveOutPathVerdict8616.UNKNOWN_REFUSE,
            MemoryLiveOutFailureKind8616.INTERVENING_WRITE,
        )
    if MemoryLiveOutPathVerdict8616.CLEAN in verdicts:
        return MemoryLiveOutPathResult8616(MemoryLiveOutPathVerdict8616.CLEAN)
    if MemoryLiveOutPathVerdict8616.OVERWRITTEN in verdicts:
        return MemoryLiveOutPathResult8616(MemoryLiveOutPathVerdict8616.OVERWRITTEN)
    return MemoryLiveOutPathResult8616(MemoryLiveOutPathVerdict8616.NOT_REACHED)


def _closed_producer_8616(
    definition: CallOutputDefinitionResult8616,
    storage: StorageIdentity8616,
    target: StorageUseEvidence8616,
) -> StorageReachingDefinition8616 | None:
    """Return the single proven CALL_OUTPUT producer or None."""
    if not definition.complete or len(definition.definitions) != 1 or not storage.is_exact:
        return None
    producer = definition.definitions[0]
    if producer.source_storage != storage or producer.instr_addr != target.callsite_addr:
        return None
    return producer


def _target_load_proven_8616(
    blocks: dict[int, SSABlock],
    target: StorageUseEvidence8616,
) -> bool:
    """Return whether the target site names its exact LOAD instruction."""
    target_block = blocks.get(target.block_addr)
    target_instruction = (
        target_block.instrs[target.instr_index]
        if target_block is not None and 0 <= target.instr_index < len(target_block.instrs)
        else None
    )
    return bool(
        target_block is not None
        and target_instruction is not None
        and target_instruction.op == "LOAD"
        and target_instruction.addr == target.instr_addr
    )


@dataclass(slots=True)
class _LiveOutPathScan8616:
    """Memoized backward DFS from the producer to the target LOAD."""

    blocks: dict[int, SSABlock]
    successors: dict[int, tuple[int, ...]]
    target_site: tuple[int, int]
    storage: StorageIdentity8616
    target_reaching: frozenset[int]
    visiting: set[tuple[int, int]] = field(default_factory=set)
    memo: dict[tuple[int, int], MemoryLiveOutPathResult8616] = field(default_factory=dict)

    def visit(self, state: tuple[int, int]) -> MemoryLiveOutPathResult8616:
        """Return the joined verdict for all paths from one instruction state."""
        cached = self.memo.get(state)
        if cached is not None:
            return cached
        if state in self.visiting:
            return MemoryLiveOutPathResult8616(
                MemoryLiveOutPathVerdict8616.UNKNOWN_REFUSE,
                MemoryLiveOutFailureKind8616.CFG_CYCLE,
            )
        block = self.blocks.get(state[0])
        if block is None or not 0 <= state[1] <= len(block.instrs):
            return MemoryLiveOutPathResult8616(
                MemoryLiveOutPathVerdict8616.UNKNOWN_REFUSE,
                MemoryLiveOutFailureKind8616.CFG_INCOMPLETE,
            )
        self.visiting.add(state)
        result: MemoryLiveOutPathResult8616 | None = None
        for index in range(state[1], len(block.instrs)):
            result = self._instruction_verdict_8616(block, index)
            if result is not None:
                break
        if result is None:
            next_results = tuple(
                self.visit((successor, 0))
                for successor in self.successors[block.addr]
                if successor in self.target_reaching
            )
            result = _aggregate_results_8616(next_results)
        self.visiting.remove(state)
        self.memo[state] = result
        return result

    def _instruction_verdict_8616(
        self,
        block: SSABlock,
        index: int,
    ) -> MemoryLiveOutPathResult8616 | None:
        """Return a terminating verdict for one instruction, or None to proceed."""
        if (block.addr, index) == self.target_site:
            return MemoryLiveOutPathResult8616(MemoryLiveOutPathVerdict8616.CLEAN)
        instruction = block.instrs[index]
        if instruction.op == "CALL":
            return MemoryLiveOutPathResult8616(
                MemoryLiveOutPathVerdict8616.UNKNOWN_REFUSE,
                MemoryLiveOutFailureKind8616.INTERVENING_CALL,
            )
        if instruction.op not in {"LOAD", "STORE"}:
            return None
        address = instruction.args[0] if instruction.args else None
        target_address = self.storage.address
        relation = (
            segmented_access_relation_8616(address, target_address)
            if isinstance(address, IRAddress) and target_address is not None
            else SegmentedAccessRelation8616.UNKNOWN
        )
        if relation in {
            SegmentedAccessRelation8616.UNKNOWN,
            SegmentedAccessRelation8616.UNPROVEN,
        }:
            return MemoryLiveOutPathResult8616(
                MemoryLiveOutPathVerdict8616.UNKNOWN_REFUSE,
                MemoryLiveOutFailureKind8616.INTERVENING_ALIAS,
            )
        if instruction.op == "STORE" and relation in {
            SegmentedAccessRelation8616.CONTAINED,
            SegmentedAccessRelation8616.CONTAINS,
            SegmentedAccessRelation8616.CROSSING,
        }:
            return MemoryLiveOutPathResult8616(
                MemoryLiveOutPathVerdict8616.UNKNOWN_REFUSE,
                MemoryLiveOutFailureKind8616.INTERVENING_WRITE,
            )
        if instruction.op == "STORE" and relation is SegmentedAccessRelation8616.EXACT:
            return MemoryLiveOutPathResult8616(
                MemoryLiveOutPathVerdict8616.OVERWRITTEN
            )
        return None


def prove_memory_live_out_path_8616(
    artifact: SSAFunctionArtifact,
    definition: CallOutputDefinitionResult8616,
    storage: StorageIdentity8616,
    target: StorageUseEvidence8616,
) -> MemoryLiveOutPathResult8616:
    """Require every CFG path reaching ``target`` to preserve CALL_OUTPUT."""
    producer = _closed_producer_8616(definition, storage, target)
    if producer is None:
        return MemoryLiveOutPathResult8616(
            MemoryLiveOutPathVerdict8616.UNKNOWN_REFUSE,
            MemoryLiveOutFailureKind8616.CALL_OUTPUT_DEFINITION_REFUSED,
        )
    cfg = _validated_cfg_8616(artifact)
    if cfg is None or not _target_load_proven_8616(cfg[0], target):
        return MemoryLiveOutPathResult8616(
            MemoryLiveOutPathVerdict8616.UNKNOWN_REFUSE,
            MemoryLiveOutFailureKind8616.CFG_INCOMPLETE,
        )
    blocks, successors = cfg
    target_reaching = _target_reaching_blocks_8616(
        artifact.predecessor_map,
        target.block_addr,
    )
    if producer.block_addr not in target_reaching:
        return MemoryLiveOutPathResult8616(MemoryLiveOutPathVerdict8616.NOT_REACHED)
    scan = _LiveOutPathScan8616(
        blocks=blocks,
        successors=successors,
        target_site=(target.block_addr, target.instr_index),
        storage=storage,
        target_reaching=target_reaching,
    )
    return scan.visit((producer.block_addr, producer.instr_index + 1))
