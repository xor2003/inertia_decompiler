"""Prove a block-local stack word survives until the selected CALL.

Layer: Alias.
Responsibility: retain an exact local STORE lifetime census using the shared
frame-coordinate and scalar-effect owners. This theorem is conditional on the
supplied IR coverage; it does not prove binary completeness, caller/callee ABI,
callee-load stability, or selector equality across functions. Coordinates are
relative to arbitrary block incoming SP, not function-entry SP.
Owns storage identity.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting
work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.ir.core import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.logical_constant_word_receipt import (
    LogicalConstantWordReceipt8616,
    LogicalConstantWordStats8616,
)
from inertia.ir.scalar_instruction_effects import (
    ScalarInstructionEffectKind8616,
    scalar_instruction_effect_8616,
)
from inertia.ir.ssa_function import build_x86_16_function_ssa

from .entry_stack_pointer_snapshots import EntryStackPointerSnapshots8616


class StackWordCallWindowFailure8616(StrEnum):
    """Why the selected local memory lifetime cannot be established."""

    SOURCE_UNPROVEN = "source_unproven"
    CALL_UNPROVEN = "call_unproven"
    EFFECT_UNPROVEN = "effect_unproven"
    SELECTOR_CHANGED = "selector_changed"
    ADDRESS_UNPROVEN = "address_unproven"
    OVERLAPPING_WRITE = "overlapping_write"


@dataclass(frozen=True, slots=True)
class _WindowEvidence8616:
    """Recomputed local census and exact stack coordinates."""

    offsets: tuple[int, int] | None
    stores: tuple[int, ...]
    failure: StackWordCallWindowFailure8616 | None


def stack_byte_store_coordinate_8616(
    snapshots: EntryStackPointerSnapshots8616, instruction: IRInstr,
) -> int | None:
    """Resolve an exact proven SS byte STORE using the shared frame owner."""
    if instruction.op != "STORE" or instruction.dst is not None or len(instruction.args) != 2:
        return None
    address, value = instruction.args
    if not isinstance(address, IRAddress) or not isinstance(value, IRValue):
        return None
    exact_byte = (instruction.size == address.size == value.size == 1
                  and address.status is AddressStatus.STABLE
                  and address.segment_origin in {SegmentOrigin.PROVEN, SegmentOrigin.DEFAULTED})
    if address.space is not MemSpace.SS or not exact_byte:
        return None
    base = snapshots.strict_address_base(address)
    return None if base is None else (base.entry_sp_offset + address.offset) & 0xFFFF


def _source_block_8616(
    source_ir: IRFunctionArtifact, receipt: LogicalConstantWordReceipt8616,
) -> IRBlock | None:
    """Require a current exact raw-to-SSA projection before using coordinates."""
    memory = source_ir.logical_memory
    if (not receipt.complete or source_ir.function_addr != receipt.artifact.function_addr
            or memory is None or not memory.closed or memory.function_addr != source_ir.function_addr):
        return None
    projected = build_x86_16_function_ssa(source_ir)
    blocks = tuple(block for block in source_ir.blocks if block.addr == receipt.access.key.block_addr)
    # Plain dataclass equality deliberately omits producer identities. Compare
    # the owned structured projection so source_tmp and access provenance count.
    projected_blocks = tuple(block.to_dict() for block in projected.blocks)
    retained_blocks = tuple(block.to_dict() for block in receipt.artifact.blocks)
    if projected_blocks != retained_blocks or len(blocks) != 1:
        return None
    return blocks[0]


def _window_evidence_8616(
    source_ir: IRFunctionArtifact, receipt: LogicalConstantWordReceipt8616, callsite_addr: int,
) -> _WindowEvidence8616:
    """Replay the prefix and refuse every unclassified lifetime effect."""
    block = _source_block_8616(source_ir, receipt)
    if block is None:
        return _WindowEvidence8616(None, (), StackWordCallWindowFailure8616.SOURCE_UNPROVEN)
    calls = tuple(index for index, item in enumerate(block.instrs)
                  if item.op == "CALL" and item.addr == callsite_addr)
    lanes = tuple(lane.instr_index for lane in receipt.access.execution_slices)
    if len(calls) != 1 or calls[0] <= max(lanes):
        return _WindowEvidence8616(None, (), StackWordCallWindowFailure8616.CALL_UNPROVEN)
    snapshots = EntryStackPointerSnapshots8616()
    coordinates: dict[int, int] = {}
    stores: list[int] = []
    for index, instruction in enumerate(block.instrs[:calls[0]]):
        # Register effects are classified by the IR owner, not by an Alias opcode table.
        failure = _instruction_failure_8616(instruction, index >= min(lanes))
        if failure is not None:
            return _WindowEvidence8616(None, tuple(stores), failure)
        if instruction.op == "STORE" and index >= min(lanes):
            coordinate = stack_byte_store_coordinate_8616(snapshots, instruction)
            if coordinate is None:
                return _WindowEvidence8616(None, tuple(stores), StackWordCallWindowFailure8616.ADDRESS_UNPROVEN)
            if index in lanes:
                coordinates[index] = coordinate
            else:
                stores.append(index)
                if coordinate in coordinates.values():
                    return _WindowEvidence8616(None, tuple(stores), StackWordCallWindowFailure8616.OVERLAPPING_WRITE)
        snapshots.observe_entry_instruction(instruction, index)
    stack = snapshots.current_sp
    if stack is None or len(coordinates) != 2:
        return _WindowEvidence8616(None, tuple(stores), StackWordCallWindowFailure8616.ADDRESS_UNPROVEN)
    offsets = tuple((coordinates[lane] - stack) & 0xFFFF for lane in lanes)
    return _WindowEvidence8616((offsets[0], offsets[1]), tuple(stores), None)


def _instruction_failure_8616(
    instruction: IRInstr, in_lifetime: bool,
) -> StackWordCallWindowFailure8616 | None:
    """Consume the scalar-effect owner and reject live SS selector writes."""
    effect = scalar_instruction_effect_8616(instruction)
    if effect.kind in {ScalarInstructionEffectKind8616.UNKNOWN,
                       ScalarInstructionEffectKind8616.INSTRUCTION_POINTER_WRITE}:
        return StackWordCallWindowFailure8616.EFFECT_UNPROVEN
    destination = instruction.dst
    if (in_lifetime and isinstance(destination, IRValue)
            and destination.space is MemSpace.REG and destination.name == "ss"):
        return StackWordCallWindowFailure8616.SELECTOR_CHANGED
    return None


@dataclass(frozen=True, slots=True)
class StackWordCallWindowReceipt8616:
    """Replayable local lifetime theorem, never a binary coverage certificate."""

    source_ir: IRFunctionArtifact
    source: LogicalConstantWordReceipt8616
    callsite_addr: int
    call_boundary_offsets: tuple[int, int] | None
    checked_store_indices: tuple[int, ...]
    failure: StackWordCallWindowFailure8616 | None
    stats: LogicalConstantWordStats8616

    @property
    def complete(self) -> bool:
        """Require current source, exact census and closed proof accounting."""
        if self.failure is not None or not self.stats.complete:
            return False
        current = _window_evidence_8616(self.source_ir, self.source, self.callsite_addr)
        return (current.failure is None and current.offsets == self.call_boundary_offsets
                and current.stores == self.checked_store_indices)

    @property
    def constant(self) -> int | None:
        """Expose the source value only while its full local lifetime holds."""
        return self.source.constant if self.complete else None


def prove_stack_word_call_window_8616(
    source_ir: IRFunctionArtifact, source: LogicalConstantWordReceipt8616, callsite_addr: int,
) -> StackWordCallWindowReceipt8616:
    """Retain a local theorem or a typed refusal without guessing preservation."""
    evidence = _window_evidence_8616(source_ir, source, callsite_addr)
    accepted = int(evidence.failure is None)
    return StackWordCallWindowReceipt8616(
        source_ir, source, callsite_addr, evidence.offsets, evidence.stores, evidence.failure,
        LogicalConstantWordStats8616(1, int(source.complete), accepted, accepted, 1 - accepted),
    )
