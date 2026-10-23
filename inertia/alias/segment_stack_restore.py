"""Prove segment-register restoration through exact SS stack fragments.

Layer: Alias.
Responsibility: track stack byte identity through typed IR stores, loads, and
lossless byte composition, then emit restore-source relations for IR consumers.
An explicit SS-selector write invalidates saved memory bytes; values already
loaded into temporaries retain their independently captured bit provenance.
Owns storage identity. Do not perform lowering, structuring, rewrite,
postprocess, or CLI/reporting work here. Never infer restoration from opcode
names, rendered assembly, or C shape.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final, Protocol, cast

from inertia.ir.constant_flow import IRConstantFlow8616
from inertia.ir.core import IRAddress, IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from inertia.ir.segment_state_transfer import SEGMENT_REGISTER_SET, SegmentRestoreSource

from .segment_stack_fragments import (
    SegmentStackByteOrigin8616,
    SegmentStackFragments8616,
    complete_stack_constant_8616,
    complete_stack_register_restore_8616,
    computed_stack_register_fragments_8616,
    register_value_fragments_8616,
    stack_load_fragments_8616,
    store_stack_fragments_8616,
)
from .stack_pointer_snapshots import StackPointerSnapshots8616
from .stack_restore_state import (
    StackRestoreState8616 as _SegmentStackAliasState8616,
)
from .stack_restore_state import (
    join_stack_restore_states_8616 as _join_stack_states,
)
from .stack_restore_state import (
    stack_restore_state_8616 as _stack_state,
)

__all__ = [
    "SegmentStackRestoreArtifact8616",
    "SegmentStackRestoreFact8616",
    "SegmentStackRestoreVerdict8616",
    "StackRegisterRestoreArtifact8616",
    "StackRegisterRestoreFact8616",
    "StackRegisterRestoreVerdict8616",
    "apply_x86_16_segment_stack_restore_artifact",
    "apply_x86_16_stack_register_restore_artifact_8616",
    "build_x86_16_segment_stack_restore_artifact",
    "build_x86_16_stack_register_restore_artifact_8616",
]


class _CodegenBoundary8616(Protocol):
    """Typed artifacts carried across the dynamic angr codegen boundary."""

    _inertia_vex_ir_artifact: object
    _inertia_segment_stack_restore_artifact: SegmentStackRestoreArtifact8616
    _inertia_stack_register_restore_artifact_8616: SegmentStackRestoreArtifact8616


class SegmentStackRestoreVerdict8616(StrEnum):
    """Proof verdict for one stack-composed segment-register write."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


@dataclass(frozen=True, slots=True)
class SegmentStackRestoreFact8616:
    """Exact stack-byte evidence for one segment-register write."""

    block_addr: int
    restore_instruction_addr: int
    restore_register: str
    saved_instruction_addr: int | None
    saved_register: str | None
    stack_offsets: tuple[int, ...]
    verdict: SegmentStackRestoreVerdict8616
    constant_value: int | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "block_addr": self.block_addr,
            "restore_instruction_addr": self.restore_instruction_addr,
            "restore_register": self.restore_register,
            "saved_instruction_addr": self.saved_instruction_addr,
            "saved_register": self.saved_register,
            "stack_offsets": list(self.stack_offsets),
            "verdict": self.verdict.value,
            "constant_value": self.constant_value,
        }


@dataclass(frozen=True, slots=True)
class SegmentStackRestoreArtifact8616:
    """Alias-proved stack restoration facts and IR restore relations.

    The artifact and each emitted ``SegmentRestoreSource`` retain the exact
    in-process IR object they were proved from. General-register facts retain
    this binding even when no segment restore relation is emitted. Serialized
    ``source_function_addr`` is diagnostic only; it never authorizes lineage.
    """

    facts: tuple[SegmentStackRestoreFact8616, ...] = ()
    restore_sources: tuple[SegmentRestoreSource, ...] = ()
    summary: dict[str, int] = field(default_factory=dict)
    source_artifact: IRFunctionArtifact | None = field(default=None, compare=False, repr=False)

    def is_bound_to(self, artifact: IRFunctionArtifact) -> bool:
        """Require the exact retained IR object, never merely equal addresses.

        This establishes provenance only, not whole-function preservation or
        binary CFG closure. Manually constructed unbound facts remain unbound.
        """
        return self.source_artifact is artifact

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "source_function_addr": (
                None if self.source_artifact is None else self.source_artifact.function_addr
            ),
            "facts": [fact.to_dict() for fact in self.facts],
            "restore_sources": [
                {
                    "block_addr": source.block_addr,
                    "restore_instruction_addr": source.restore_instruction_addr,
                    "restore_register": source.restore_register,
                    "saved_instruction_addr": source.saved_instruction_addr,
                    "saved_register": source.saved_register,
                    "source_function_addr": (
                        None
                        if source.source_artifact is None
                        else source.source_artifact.function_addr
                    ),
                }
                for source in self.restore_sources
            ],
            "summary": dict(self.summary),
        }


StackRegisterRestoreVerdict8616: Final[type[SegmentStackRestoreVerdict8616]] = SegmentStackRestoreVerdict8616
StackRegisterRestoreFact8616: Final[type[SegmentStackRestoreFact8616]] = SegmentStackRestoreFact8616
StackRegisterRestoreArtifact8616: Final[type[SegmentStackRestoreArtifact8616]] = SegmentStackRestoreArtifact8616


def _predecessor_map(artifact: IRFunctionArtifact) -> dict[int, tuple[int, ...]]:
    """Build deterministic in-function predecessors from typed IR edges."""
    block_addrs = {block.addr for block in artifact.blocks}
    predecessors: dict[int, list[int]] = {addr: [] for addr in block_addrs}
    for block in artifact.blocks:
        for successor in block.successor_addrs:
            if successor in predecessors:
                predecessors[successor].append(block.addr)
    return {addr: tuple(sorted(values)) for addr, values in predecessors.items()}


def _track_value_fragments_8616(
    instruction: IRInstr,
    values: dict[str | int, SegmentStackFragments8616],
    constants: IRConstantFlow8616 | None,
    stack_pointers: StackPointerSnapshots8616,
    stack_bytes: dict[int, SegmentStackByteOrigin8616],
    sp_delta: int | None,
    bp_delta: int | None,
    tracked_registers: frozenset[str],
    *,
    instruction_addr: int,
) -> None:
    """Record fragments at the exact address selected by the transfer owner."""
    if instruction.op == "LOAD" and isinstance(instruction.dst, IRValue) and instruction.args:
        address = instruction.args[0]
        if isinstance(address, IRAddress) and instruction.dst.name is not None:
            fragments = stack_load_fragments_8616(
                address, max(1, instruction.dst.size),
                stack_pointers.address_base(address, sp_delta, bp_delta), stack_bytes,
            )
            values[instruction.dst.name] = fragments
            values[f"load_{instruction.dst.name}"] = fragments
            if instruction.dst.source_tmp is not None:
                values[instruction.dst.source_tmp] = fragments
    elif instruction.op == "STORE" and len(instruction.args) >= 2:
        address, value = instruction.args[:2]
        if isinstance(address, IRAddress) and isinstance(value, IRValue):
            store_stack_fragments_8616(
                address,
                value,
                register_value_fragments_8616(
                    value,
                    instruction_addr,
                    values,
                    tracked_registers=tracked_registers,
                    constant_value=None if constants is None else constants.constant(value),
                ),
                stack_pointers.address_base(address, sp_delta, bp_delta),
                stack_bytes,
            )
    elif isinstance(instruction.dst, IRValue) and instruction.dst.space is MemSpace.TMP:
        fragments = computed_stack_register_fragments_8616(
            instruction,
            values,
            tracked_registers=tracked_registers,
        )
        if instruction.dst.name is not None:
            values[instruction.dst.name] = fragments
        if instruction.dst.source_tmp is not None:
            values[instruction.dst.source_tmp] = fragments
        if instruction.op != "MOV":
            values[f"expr:{instruction.op}"] = fragments


def _restore_fact_for_write_8616(
    block_addr: int,
    instruction: IRInstr,
    values: dict[str | int, SegmentStackFragments8616],
    tracked_registers: frozenset[str],
    *,
    instruction_addr: int,
) -> SegmentStackRestoreFact8616 | None:
    """Classify a register write at the transfer owner's known address."""
    dst = instruction.dst
    if not (
        isinstance(dst, IRValue)
        and dst.space is MemSpace.REG
        and dst.name in tracked_registers
    ):
        return None
    source = instruction.args[0] if instruction.args else None
    fragments = register_value_fragments_8616(
        source,
        instruction_addr,
        values,
        tracked_registers=tracked_registers,
    )
    complete = complete_stack_register_restore_8616(fragments)
    if complete is not None:
        saved_register, saved_addr, stack_offsets = complete
        saved_constant = complete_stack_constant_8616(fragments)
        return SegmentStackRestoreFact8616(
            block_addr, instruction_addr, dst.name, saved_addr, saved_register,
            stack_offsets, SegmentStackRestoreVerdict8616.PROVEN,
            constant_value=None if saved_constant is None else saved_constant[0],
        )
    if tracked_registers == SEGMENT_REGISTER_SET and (
        constant := complete_stack_constant_8616(fragments)
    ) is not None:
        constant_value, saved_addr, stack_offsets = constant
        return SegmentStackRestoreFact8616(
            block_addr,
            instruction_addr,
            dst.name,
            saved_addr,
            None,
            stack_offsets,
            SegmentStackRestoreVerdict8616.PROVEN,
            constant_value,
        )
    if isinstance(source, IRValue) and source.space is MemSpace.TMP and source.name is not None:
        return SegmentStackRestoreFact8616(
            block_addr, instruction_addr, dst.name, None, None, (),
            SegmentStackRestoreVerdict8616.UNKNOWN_REFUSE,
        )
    return None


def _call_effect_stack_state_8616(
    instruction: IRInstr,
    instruction_entry_state: _SegmentStackAliasState8616,
) -> tuple[int | None, dict[int, SegmentStackByteOrigin8616], int | None]:
    """Return (sp_delta, stack_bytes, bp_delta) after one CALL boundary."""
    effect = instruction.call_stack_effect
    bp_delta = (
        instruction_entry_state.bp_delta
        if effect is not None and effect.complete and effect.bp_preserved
        else None
    )
    if effect is None:
        return None, {}, bp_delta
    coordinates = effect.stack_coordinates
    if coordinates is not None:
        # A present coordinate record must authenticate its source CALL:
        # callsite identity, the bound target, and a proven delta consistent
        # with the owned net projection. No legacy fallback applies.
        target = instruction.args[0] if instruction.args else None
        target_bound = coordinates.source is not None and coordinates.source.matches_call(instruction)
        if isinstance(target, IRValue) and target.space is MemSpace.CONST and type(target.const) is int:
            target_bound = target_bound and coordinates.target_addr == target.const
        coordinate_delta = (
            coordinates.net_sp_delta
            if coordinates.callsite_addr == instruction.addr
            and coordinates.net_sp_delta is not None
            and coordinates.net_sp_delta == effect.net_stack_delta
            and target_bound
            and coordinates.has_proven_sp_delta
            else None
        )
        if coordinate_delta is None:
            return None, {}, bp_delta
    else:
        coordinate_delta = None
    if coordinate_delta is not None:
        # A proven per-call SP coordinate survives uncertain memory effects:
        # the machine delta applies even when the preservation census refused.
        # Byte identities still require their own proof and are dropped when
        # the preservation census is incomplete or reported escapes.
        call_entry_sp = instruction_entry_state.sp_delta
        sp_delta = None if call_entry_sp is None else call_entry_sp + coordinate_delta
        stack_bytes = (
            instruction_entry_state.byte_map()
            if effect.complete and not effect.escaped_ranges
            else {}
        )
        return sp_delta, stack_bytes, bp_delta
    if effect.complete and effect.net_stack_delta is not None:
        call_entry_sp = instruction_entry_state.sp_delta
        sp_delta = None if call_entry_sp is None else call_entry_sp + effect.net_stack_delta
        # A proven frame coordinate survives uncertain memory effects. Old
        # byte identities do not; subsequent stores establish fresh identities.
        stack_bytes = {} if effect.escaped_ranges else instruction_entry_state.byte_map()
        return sp_delta, stack_bytes, bp_delta
    return None, {}, bp_delta


def _ignore_call_positions(_instruction: IRInstr, _before: int | None, _entry: int | None) -> None:
    """Leave optional CALL-position observation disabled during ordinary transfer."""


_SNAPSHOT_WORD_REGISTERS: Final[tuple[str, ...]] = ("ax", "bx", "cx", "dx", "si", "di")


def _block_constant_flow_8616(
    entry_state: _SegmentStackAliasState8616,
    tracked_registers: frozenset[str],
    allow_constant_values: bool,
    persistent_constants: bool,
) -> IRConstantFlow8616 | None:
    """Create the per-block constant flow and seed persistent entry facts."""
    want = persistent_constants or (
        allow_constant_values and tracked_registers != SEGMENT_REGISTER_SET
    )
    if not want:
        return None
    constants = IRConstantFlow8616()
    if persistent_constants:
        constants.seed_register_constants_8616(entry_state.register_constant_map())
    return constants


def _call_exit_state_8616(
    instruction: IRInstr,
    instruction_entry_state: _SegmentStackAliasState8616,
    call_deltas: Mapping[int, int] | None,
) -> tuple[int | None, dict[int, SegmentStackByteOrigin8616], int | None]:
    """Apply one CALL's callee effect: scoped overlay or universal fields.

    A scoped caller-visible delta applies only to SP: the callee body's byte
    identities and BP coordinate stay unproven under scoped-only evidence.
    """
    overlay = (
        call_deltas.get(instruction.addr)
        if call_deltas is not None and isinstance(instruction.addr, int)
        else None
    )
    if overlay is not None:
        entry_sp = instruction_entry_state.sp_delta
        return (None if entry_sp is None else entry_sp + overlay), {}, None
    return _call_effect_stack_state_8616(instruction, instruction_entry_state)


def _transfer_block(
    block_addr: int,
    instructions: tuple[IRInstr, ...],
    entry_state: _SegmentStackAliasState8616,
    tracked_registers: frozenset[str] = SEGMENT_REGISTER_SET,
    *,
    allow_constant_values: bool = False,
    persistent_constants: bool = False,
    call_deltas: Mapping[int, int] | None = None,
    value_observer: Callable[[IRInstr, StackPointerSnapshots8616, int | None, int | None], None] | None = None,
    call_observer: Callable[[IRInstr, int | None, int | None], None] = _ignore_call_positions,
) -> tuple[list[SegmentStackRestoreFact8616], _SegmentStackAliasState8616]:
    """Transfer exact stack identities and classify restorations in one block.

    A CALL observer receives the instruction-entry SP and the current SP after
    physical frame preparation, before the authenticated callee transfer.
    When ``persistent_constants`` is set, numeric register constants seeded
    into the entry state and proven inside the block are threaded through the
    same constant-flow owner and published on the exit state; SP-relative
    coordinates remain a separate fact kind.
    """
    values: dict[str | int, SegmentStackFragments8616] = {}
    constants = _block_constant_flow_8616(
        entry_state, tracked_registers, allow_constant_values, persistent_constants,
    )
    stack_pointers = StackPointerSnapshots8616(register_offsets=entry_state.register_offset_map())
    stack_bytes = entry_state.byte_map()
    sp_delta = entry_state.sp_delta
    bp_delta = entry_state.bp_delta
    facts: list[SegmentStackRestoreFact8616] = []
    machine_instruction_addr: int | None = None
    instruction_entry_state = entry_state
    for instruction in instructions:
        instruction_addr = instruction.addr
        destination = instruction.dst
        changes_stack_selector = (
            destination is not None and destination.space is MemSpace.REG and destination.name == "ss"
        )
        if instruction_addr is None:
            if changes_stack_selector:
                stack_bytes.clear()
            continue
        if constants is not None:
            constants.observe(instruction)
        if instruction.addr != machine_instruction_addr:
            machine_instruction_addr = instruction.addr
            instruction_entry_state = _stack_state(sp_delta, stack_bytes, bp_delta, stack_pointers.register_offsets)
        stack_pointers.observe(instruction, sp_delta, bp_delta, constants=constants)
        if value_observer is not None:
            value_observer(instruction, stack_pointers, sp_delta, bp_delta)
        _track_value_fragments_8616(
            instruction,
            values,
            constants,
            stack_pointers,
            stack_bytes,
            sp_delta,
            bp_delta,
            tracked_registers,
            instruction_addr=instruction_addr,
        )
        if changes_stack_selector:
            # Entry-SP offsets alone cannot equate two SS memory selectors.
            # Captured LOAD values remain valid; only live storage is invalidated.
            stack_bytes.clear()
        restore_fact = _restore_fact_for_write_8616(
            block_addr,
            instruction,
            values,
            tracked_registers,
            instruction_addr=instruction_addr,
        )
        if restore_fact is not None:
            facts.append(restore_fact)
        next_sp = stack_pointers.updated_register("sp", instruction, sp_delta, bp_delta, constants=constants)
        bp_delta = stack_pointers.updated_register("bp", instruction, sp_delta, bp_delta, constants=constants)
        sp_delta = next_sp
        if instruction.op == "CALL":
            call_observer(instruction, instruction_entry_state.sp_delta, sp_delta)
            sp_delta, stack_bytes, bp_delta = _call_exit_state_8616(
                instruction, instruction_entry_state, call_deltas,
            )
    return facts, _block_exit_state_8616(
        sp_delta, stack_bytes, bp_delta, stack_pointers, constants, persistent_constants,
    )


def _block_exit_state_8616(
    sp_delta: int | None,
    stack_bytes: dict[int, SegmentStackByteOrigin8616],
    bp_delta: int | None,
    stack_pointers: StackPointerSnapshots8616,
    constants: IRConstantFlow8616 | None,
    persistent_constants: bool,
) -> _SegmentStackAliasState8616:
    """Freeze the block exit, publishing proven constants only when scoped."""
    out_constants = (
        constants.register_constants_8616(_SNAPSHOT_WORD_REGISTERS)
        if persistent_constants and constants is not None
        else None
    )
    return _stack_state(
        sp_delta, stack_bytes, bp_delta, stack_pointers.register_offsets, out_constants,
    )


def _scoped_predecessors_8616(
    block_addrs: frozenset[int], successors: Mapping[int, Sequence[int]],
) -> dict[int, tuple[int, ...]]:
    """Invert one scoped successor map restricted to the live block set."""
    predecessors: dict[int, list[int]] = {addr: [] for addr in block_addrs}
    for block_addr in block_addrs:
        for successor in successors.get(block_addr, ()):
            if successor in predecessors:
                predecessors[successor].append(block_addr)
    return {addr: tuple(sorted(values)) for addr, values in predecessors.items()}


def _solve_stack_states(
    artifact: IRFunctionArtifact,
    tracked_registers: frozenset[str] = SEGMENT_REGISTER_SET,
    *,
    entry_constants: Mapping[str, int] | None = None,
    scoped_blocks: tuple[IRBlock, ...] | None = None,
    scoped_successors: Mapping[int, Sequence[int]] | None = None,
    call_deltas: Mapping[int, int] | None = None,
) -> dict[int, _SegmentStackAliasState8616]:
    """Reach a deterministic must-state fixed point across typed IR edges.

    The optional scoped graph parameters restrict the solved surface to one
    authenticated projection without touching the shared artifact; the
    universal path supplies neither and keeps its original behavior.
    """
    if scoped_blocks is None or scoped_successors is None:
        blocks_by_addr = {block.addr: block for block in artifact.blocks}
        predecessors = _predecessor_map(artifact)
    else:
        blocks_by_addr = {block.addr: block for block in scoped_blocks}
        predecessors = _scoped_predecessors_8616(frozenset(blocks_by_addr), scoped_successors)
    complete_ir = not any(block.refusals for block in blocks_by_addr.values())
    persistent = entry_constants is not None
    entry_seed = (
        _SegmentStackAliasState8616(0)
        if entry_constants is None
        else _stack_state(0, {}, None, {}, dict(entry_constants))
    )
    unknown = _SegmentStackAliasState8616(None)
    # An unvisited edge is not an analyzed unknown value. Seeding loop edges
    # with unknown would erase entry evidence before the first back-edge visit.
    exit_states: dict[int, _SegmentStackAliasState8616] = {}
    changed = True
    while changed:
        changed = False
        for block_addr in sorted(blocks_by_addr):
            incoming = tuple(exit_states[pred] for pred in predecessors[block_addr] if pred in exit_states)
            if block_addr == artifact.function_addr:
                incoming = (entry_seed, *incoming)
            if not incoming:
                continue
            entry_state = _join_stack_states(incoming)
            new_exit = _transfer_block(
                block_addr,
                blocks_by_addr[block_addr].instrs,
                entry_state,
                tracked_registers,
                allow_constant_values=complete_ir,
                persistent_constants=persistent,
                call_deltas=call_deltas,
            )[1]
            if new_exit != exit_states.get(block_addr):
                exit_states[block_addr] = new_exit
                changed = True
    return {addr: exit_states.get(addr, unknown) for addr in blocks_by_addr}


def _facts_for_block_8616(
    block_addr: int,
    instructions: tuple[IRInstr, ...],
    entry_state: _SegmentStackAliasState8616,
    tracked_registers: frozenset[str] = SEGMENT_REGISTER_SET,
    *,
    allow_constant_values: bool = False,
) -> list[SegmentStackRestoreFact8616]:
    """Prove block-local stack bytes without publishing an arbitrary SP origin.

    An unknown incoming SP forbids cross-block byte identity, but an exact
    store/load pair within this block can still use a relative coordinate.
    The temporary coordinate starts with no inherited bytes and its exit state
    is discarded; the must-state solver continues to publish unknown SP.
    """
    fact_entry = (
        entry_state
        if entry_state.sp_delta is not None
        else _stack_state(0, {}, None)
    )
    return _transfer_block(
        block_addr,
        instructions,
        fact_entry,
        tracked_registers,
        allow_constant_values=allow_constant_values,
    )[0]


def build_x86_16_segment_stack_restore_artifact(artifact: IRFunctionArtifact) -> SegmentStackRestoreArtifact8616:
    """Build conservative cross-block segment save/restore evidence from typed IR."""
    exit_states = _solve_stack_states(artifact)
    predecessors = _predecessor_map(artifact)
    instruction_blocks = {
        instruction.addr: block.addr
        for block in artifact.blocks
        for instruction in block.instrs
        if instruction.addr is not None
    }
    facts = tuple(
        fact
        for block in artifact.blocks
        for fact in _facts_for_block_8616(
            block.addr,
            block.instrs,
            _join_stack_states(
                
                    ((_SegmentStackAliasState8616(0),) if block.addr == artifact.function_addr else ())
                    + tuple(exit_states[pred] for pred in predecessors[block.addr])
                
            ),
        )
    )
    proven = tuple(fact for fact in facts if fact.verdict is SegmentStackRestoreVerdict8616.PROVEN)
    restore_sources = tuple(
        SegmentRestoreSource(
            fact.block_addr,
            fact.restore_instruction_addr,
            fact.restore_register,
            fact.saved_instruction_addr,
            fact.saved_register,
            source_artifact=artifact,
        )
        for fact in proven
        if fact.saved_instruction_addr is not None and fact.saved_register is not None
    )
    return SegmentStackRestoreArtifact8616(
        source_artifact=artifact,
        facts=facts,
        restore_sources=restore_sources,
        summary={
            "raw_fact_count": len(facts),
            "normalized_fact_count": len(facts),
            "classified_fact_count": len(proven),
            "materialized_count": len(proven),
            "failure_count": len(facts) - len(proven),
            "cross_block_restore_count": sum(
                fact.saved_instruction_addr is not None
                and instruction_blocks.get(fact.saved_instruction_addr) != fact.block_addr
                for fact in proven
            ),
        },
    )


def build_x86_16_stack_register_restore_artifact_8616(
    artifact: IRFunctionArtifact,
    *,
    tracked_registers: frozenset[str],
) -> SegmentStackRestoreArtifact8616:
    """Build exact stack save/restore facts for selected 16-bit registers."""
    complete_ir = not any(block.refusals for block in artifact.blocks)
    exit_states = _solve_stack_states(artifact, tracked_registers)
    predecessors = _predecessor_map(artifact)
    instruction_blocks = {
        instruction.addr: block.addr
        for block in artifact.blocks
        for instruction in block.instrs
        if instruction.addr is not None
    }
    facts = tuple(
        fact
        for block in artifact.blocks
        for fact in _facts_for_block_8616(
            block.addr,
            block.instrs,
            _join_stack_states(
                ((_SegmentStackAliasState8616(0),) if block.addr == artifact.function_addr else ())
                + tuple(exit_states[pred] for pred in predecessors[block.addr])
            ),
            tracked_registers,
            allow_constant_values=complete_ir,
        )
    )
    proven = tuple(fact for fact in facts if fact.verdict is SegmentStackRestoreVerdict8616.PROVEN)
    return SegmentStackRestoreArtifact8616(
        source_artifact=artifact,
        facts=facts,
        summary={
            "raw_fact_count": len(facts),
            "normalized_fact_count": len(facts),
            "classified_fact_count": len(proven),
            "materialized_count": len(proven),
            "failure_count": len(facts) - len(proven),
            "cross_block_restore_count": sum(
                fact.saved_instruction_addr is not None
                and instruction_blocks.get(fact.saved_instruction_addr) != fact.block_addr
                for fact in proven
            ),
        },
    )


def apply_x86_16_segment_stack_restore_artifact(project: object, codegen: object) -> bool:
    """Attach Alias-proved segment stack restoration before segment-state transfer."""
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        artifact = boundary._inertia_vex_ir_artifact
    except AttributeError:
        return False
    if not isinstance(artifact, IRFunctionArtifact):
        return False
    boundary._inertia_segment_stack_restore_artifact = build_x86_16_segment_stack_restore_artifact(artifact)
    return False


def apply_x86_16_stack_register_restore_artifact_8616(project: object, codegen: object) -> bool:
    """Attach exact 16-bit GP save/restore evidence at the codegen boundary."""
    del project
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        artifact = boundary._inertia_vex_ir_artifact
    except AttributeError:
        return False
    if not isinstance(artifact, IRFunctionArtifact):
        return False
    restoration = (
        build_x86_16_stack_register_restore_artifact_8616(
            artifact,
            tracked_registers=frozenset({"ax", "bx", "cx", "di", "dx", "si"}),
        )
    )
    boundary._inertia_stack_register_restore_artifact_8616 = restoration
    if os.environ.get("INERTIA_DEBUG_GP_STACK_RESTORE"):
        logging.getLogger(__name__).warning(
            "[gp-stack-restore-alias] function=%#x blocks=%s summary=%s facts=%s",
            artifact.function_addr,
            tuple((block.addr, block.successor_addrs) for block in artifact.blocks),
            restoration.summary,
            restoration.facts,
        )
        for block in artifact.blocks:
            logging.getLogger(__name__).warning(
                "[gp-stack-restore-ir] block=%#x calls=%s",
                block.addr,
                tuple(
                    (instruction.addr, instruction.call_stack_effect)
                    for instruction in block.instrs
                    if instruction.op == "CALL"
                ),
            )
    return False
