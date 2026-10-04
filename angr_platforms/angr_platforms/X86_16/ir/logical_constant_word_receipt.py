"""Retain exact block-local values written by a logical word STORE.

Layer: IR.
Responsibility: consume the existing constant-flow owner at the exact physical
STORE sites, retaining enough source evidence to replay the value proof. This
proves written values only, not aliases, later byte stability, or caller ABI.
No source text, instruction spelling heuristics or generated C is consumed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .constant_flow import IRConstantFlow8616
from .core import IRAddress, IRValue
from .logical_memory_contracts import (
    IRLogicalMemoryAccess8616,
    IRMemoryAccessKind8616,
    logical_memory_execution_address_matches_8616,
)
from .ssa import SSABlock
from .ssa_function import SSAFunctionArtifact


class LogicalConstantWordFailure8616(StrEnum):
    """Why one logical word lacks an exact retained constant-value receipt."""

    ACCESS_UNPROVEN = "access_unproven"
    FOREIGN_ACCESS = "foreign_access"
    BLOCK_UNPROVEN = "block_unproven"
    STORE_MISMATCH = "store_mismatch"
    VALUE_UNKNOWN = "value_unknown"


@dataclass(frozen=True, slots=True)
class LogicalConstantWordStats8616:
    """Closed five-counter accounting for one requested logical word."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def complete(self) -> bool:
        """Require one normalized, classified and materialized value proof."""
        counts = (self.raw_fact_count, self.normalized_fact_count,
                  self.classified_fact_count, self.materialized_count, self.failure_count)
        return all(type(count) is int for count in counts) and (
            self.raw_fact_count, self.normalized_fact_count,
            self.classified_fact_count, self.materialized_count, self.failure_count,
        ) == (1, 1, 1, 1, 0)


@dataclass(frozen=True, slots=True)
class _WordEvidence8616:
    """Internal replay outcome retaining both byte values and their block."""

    block: SSABlock | None
    lanes: tuple[int, int] | None
    failure: LogicalConstantWordFailure8616 | None


def _owning_block_8616(
    artifact: SSAFunctionArtifact, access: IRLogicalMemoryAccess8616,
) -> _WordEvidence8616:
    """Bind a complete logical word to its exact current source artifact."""
    supported = (
        access.complete and access.kind is IRMemoryAccessKind8616.WRITE
        and access.address.size == 2
        and tuple(lane.source_byte_offset for lane in access.execution_slices) == (0, 1)
        and all(lane.block_addr == access.key.block_addr and lane.insn_addr == access.key.insn_addr
                for lane in access.execution_slices)
    )
    if not supported:
        return _WordEvidence8616(None, None, LogicalConstantWordFailure8616.ACCESS_UNPROVEN)
    memory = artifact.logical_memory
    owned = (
        memory is not None and memory.closed
        and access.key.function_addr == artifact.function_addr
        and sum(candidate is access for candidate in memory.accesses) == 1
    )
    if not owned:
        return _WordEvidence8616(None, None, LogicalConstantWordFailure8616.FOREIGN_ACCESS)
    blocks = tuple(block for block in artifact.blocks if block.addr == access.key.block_addr)
    if len(blocks) != 1 or blocks[0].refusals:
        return _WordEvidence8616(None, None, LogicalConstantWordFailure8616.BLOCK_UNPROVEN)
    return _WordEvidence8616(blocks[0], None, None)


def _word_evidence_8616(
    artifact: SSAFunctionArtifact, access: IRLogicalMemoryAccess8616,
) -> _WordEvidence8616:
    """Replay one exact block prefix; calls and register lanes use their owner."""
    owned = _owning_block_8616(artifact, access)
    block = owned.block
    if block is None:
        return owned
    slices = {lane.instr_index: lane for lane in access.execution_slices}
    if len(slices) != 2 or min(slices) < 0 or max(slices) >= len(block.instrs):
        return _WordEvidence8616(block, None, LogicalConstantWordFailure8616.STORE_MISMATCH)
    flow = IRConstantFlow8616()
    values: dict[int, int] = {}
    for index, instruction in enumerate(block.instrs[:max(slices) + 1]):
        lane = slices.get(index)
        if lane is not None:
            exact_store = (
                lane.block_addr == block.addr and lane.insn_addr == instruction.addr
                and instruction.op == "STORE" and instruction.size == 1
                and len(instruction.args) == 2
            )
            if not exact_store:
                return _WordEvidence8616(block, None, LogicalConstantWordFailure8616.STORE_MISMATCH)
            address, value = instruction.args
            byte_views = isinstance(address, IRAddress) and address.size == 1
            byte_views = byte_views and isinstance(value, IRValue) and value.size == 1
            if not byte_views or not isinstance(address, IRAddress) or not logical_memory_execution_address_matches_8616(
                address, access.address, lane.source_byte_offset, access.address_bits,
            ):
                return _WordEvidence8616(block, None, LogicalConstantWordFailure8616.STORE_MISMATCH)
            constant = flow.constant(value)
            if constant is None or not 0 <= constant <= 0xFF:
                return _WordEvidence8616(block, None, LogicalConstantWordFailure8616.VALUE_UNKNOWN)
            values[lane.source_byte_offset] = constant
        flow.observe(instruction)
    return _WordEvidence8616(block, (values[0], values[1]), None)


@dataclass(frozen=True, slots=True)
class LogicalConstantWordReceipt8616:
    """One replayable value theorem bound to the original artifact/access."""

    artifact: SSAFunctionArtifact
    access: IRLogicalMemoryAccess8616
    block: SSABlock | None
    constant: int | None
    lane_values: tuple[int, int] | None
    failure: LogicalConstantWordFailure8616 | None
    stats: LogicalConstantWordStats8616

    @property
    def complete(self) -> bool:
        """Recompute the value proof instead of trusting a cached verdict."""
        if self.failure is not None or not self.stats.complete:
            return False
        evidence = _word_evidence_8616(self.artifact, self.access)
        if evidence.failure is not None or evidence.lanes is None:
            return False
        value = evidence.lanes[0] | (evidence.lanes[1] << 8)
        return (
            evidence.block is self.block and evidence.lanes == self.lane_values
            and type(self.constant) is int and self.constant == value
        )

    def matches_access(self, access: IRLogicalMemoryAccess8616) -> bool:
        """Require the identical producer-owned access and a current proof."""
        return self.access is access and self.complete

    @property
    def stored_values(self) -> tuple[IRValue, IRValue] | None:
        """Return the identical raw byte sources only for a current receipt."""
        if not self.complete or self.block is None:
            return None
        low, high = (self.block.instrs[lane.instr_index].args[1]
                     for lane in self.access.execution_slices)
        if not isinstance(low, IRValue) or not isinstance(high, IRValue):
            return None
        return low, high


def prove_logical_constant_word_write_8616(
    artifact: SSAFunctionArtifact, access: IRLogicalMemoryAccess8616,
) -> LogicalConstantWordReceipt8616:
    """Retain a proven word value or an explicit unknown/refused result."""
    evidence = _word_evidence_8616(artifact, access)
    accepted = int(evidence.failure is None)
    lanes = evidence.lanes
    constant = None if lanes is None else lanes[0] | (lanes[1] << 8)
    return LogicalConstantWordReceipt8616(
        artifact, access, evidence.block, constant, lanes, evidence.failure,
        LogicalConstantWordStats8616(1, int(evidence.block is not None), accepted, accepted, 1 - accepted),
    )
