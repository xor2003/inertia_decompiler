"""Prove segment-register restoration through exact SS stack fragments.

Layer: Alias.
Responsibility: track stack byte identity through typed IR stores, loads, and
lossless byte composition, then emit restore-source relations for IR consumers.
Owns storage identity. Do not perform lowering, structuring, rewrite,
postprocess, or CLI/reporting work here. Never infer restoration from opcode
names, rendered assembly, or C shape.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final, Protocol, cast

from ..ir.core import IRAddress, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from ..ir.segment_state_transfer import SEGMENT_REGISTER_SET, SegmentRestoreSource
from .segment_stack_fragments import (
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
    """Alias-proved stack restoration facts and IR restore relations."""

    facts: tuple[SegmentStackRestoreFact8616, ...] = ()
    restore_sources: tuple[SegmentRestoreSource, ...] = ()
    summary: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "facts": [fact.to_dict() for fact in self.facts],
            "restore_sources": [
                {
                    "block_addr": source.block_addr,
                    "restore_instruction_addr": source.restore_instruction_addr,
                    "restore_register": source.restore_register,
                    "saved_instruction_addr": source.saved_instruction_addr,
                    "saved_register": source.saved_register,
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


def _transfer_block(
    block_addr: int,
    instructions: tuple[IRInstr, ...],
    entry_state: _SegmentStackAliasState8616,
    tracked_registers: frozenset[str] = SEGMENT_REGISTER_SET,
) -> tuple[list[SegmentStackRestoreFact8616], _SegmentStackAliasState8616]:
    """Transfer exact stack identities and classify restorations in one block."""
    values: dict[str, SegmentStackFragments8616] = {}
    stack_pointers = StackPointerSnapshots8616()
    stack_bytes = entry_state.byte_map()
    sp_delta = entry_state.sp_delta
    bp_delta = entry_state.bp_delta
    facts: list[SegmentStackRestoreFact8616] = []
    machine_instruction_addr: int | None = None
    instruction_entry_state = entry_state
    for instruction in instructions:
        if instruction.addr is None:
            continue
        if instruction.addr != machine_instruction_addr:
            machine_instruction_addr = instruction.addr
            instruction_entry_state = _stack_state(sp_delta, stack_bytes, bp_delta)
        stack_pointers.observe(instruction, sp_delta, bp_delta)
        if instruction.op == "LOAD" and isinstance(instruction.dst, IRValue) and instruction.args:
            address = instruction.args[0]
            if isinstance(address, IRAddress) and instruction.dst.name is not None:
                fragments = stack_load_fragments_8616(
                    address, max(1, instruction.dst.size),
                    stack_pointers.address_base(address, sp_delta, bp_delta), stack_bytes,
                )
                values[instruction.dst.name] = fragments
                values[f"load_{instruction.dst.name}"] = fragments
        elif instruction.op == "STORE" and len(instruction.args) >= 2:
            address, value = instruction.args[:2]
            if isinstance(address, IRAddress) and isinstance(value, IRValue):
                store_stack_fragments_8616(
                    address,
                    value,
                    register_value_fragments_8616(
                        value,
                        instruction.addr,
                        values,
                        tracked_registers=tracked_registers,
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
            if instruction.op != "MOV":
                values[f"expr:{instruction.op}"] = fragments

        dst = instruction.dst
        if isinstance(dst, IRValue) and dst.space is MemSpace.REG and dst.name in tracked_registers:
            source = instruction.args[0] if instruction.args else None
            fragments = register_value_fragments_8616(
                source,
                instruction.addr,
                values,
                tracked_registers=tracked_registers,
            )
            complete = complete_stack_register_restore_8616(fragments)
            if complete is not None:
                saved_register, saved_addr, stack_offsets = complete
                facts.append(
                    SegmentStackRestoreFact8616(
                        block_addr, instruction.addr, dst.name, saved_addr, saved_register,
                        stack_offsets, SegmentStackRestoreVerdict8616.PROVEN,
                    )
                )
            elif tracked_registers == SEGMENT_REGISTER_SET and (
                constant := complete_stack_constant_8616(fragments)
            ) is not None:
                constant_value, saved_addr, stack_offsets = constant
                facts.append(
                    SegmentStackRestoreFact8616(
                        block_addr,
                        instruction.addr,
                        dst.name,
                        saved_addr,
                        None,
                        stack_offsets,
                        SegmentStackRestoreVerdict8616.PROVEN,
                        constant_value,
                    )
                )
            elif isinstance(source, IRValue) and source.space is MemSpace.TMP and source.name is not None:
                facts.append(
                    SegmentStackRestoreFact8616(
                        block_addr, instruction.addr, dst.name, None, None, (),
                        SegmentStackRestoreVerdict8616.UNKNOWN_REFUSE,
                    )
                )
        next_sp = stack_pointers.updated_register("sp", instruction, sp_delta, bp_delta)
        bp_delta = stack_pointers.updated_register("bp", instruction, sp_delta, bp_delta)
        sp_delta = next_sp
        if instruction.op == "CALL":
            effect = instruction.call_stack_effect
            bp_delta = (instruction_entry_state.bp_delta
                        if effect is not None and effect.complete and effect.bp_preserved else None)
            if (
                effect is not None
                and effect.complete
                and effect.net_stack_delta is not None
                and not effect.escaped_ranges
            ):
                call_entry_sp = instruction_entry_state.sp_delta
                sp_delta = None if call_entry_sp is None else call_entry_sp + effect.net_stack_delta
                stack_bytes = instruction_entry_state.byte_map()
            else:
                sp_delta = None
                stack_bytes.clear()
    return facts, _stack_state(sp_delta, stack_bytes, bp_delta)


def _solve_stack_states(
    artifact: IRFunctionArtifact,
    tracked_registers: frozenset[str] = SEGMENT_REGISTER_SET,
) -> dict[int, _SegmentStackAliasState8616]:
    """Reach a deterministic must-state fixed point across typed IR edges."""
    blocks_by_addr = {block.addr: block for block in artifact.blocks}
    predecessors = _predecessor_map(artifact)
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
                incoming = (_SegmentStackAliasState8616(0), *incoming)
            if not incoming:
                continue
            entry_state = _join_stack_states(incoming)
            new_exit = _transfer_block(
                block_addr,
                blocks_by_addr[block_addr].instrs,
                entry_state,
                tracked_registers,
            )[1]
            if new_exit != exit_states.get(block_addr):
                exit_states[block_addr] = new_exit
                changed = True
    return {addr: exit_states.get(addr, unknown) for addr in blocks_by_addr}


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
        for fact in _transfer_block(
            block.addr,
            block.instrs,
            _join_stack_states(
                
                    ((_SegmentStackAliasState8616(0),) if block.addr == artifact.function_addr else ())
                    + tuple(exit_states[pred] for pred in predecessors[block.addr])
                
            ),
        )[0]
    )
    proven = tuple(fact for fact in facts if fact.verdict is SegmentStackRestoreVerdict8616.PROVEN)
    restore_sources = tuple(
        SegmentRestoreSource(
            fact.block_addr,
            fact.restore_instruction_addr,
            fact.restore_register,
            fact.saved_instruction_addr,
            fact.saved_register,
        )
        for fact in proven
        if fact.saved_instruction_addr is not None and fact.saved_register is not None
    )
    return SegmentStackRestoreArtifact8616(
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
        for fact in _transfer_block(
            block.addr,
            block.instrs,
            _join_stack_states(
                ((_SegmentStackAliasState8616(0),) if block.addr == artifact.function_addr else ())
                + tuple(exit_states[pred] for pred in predecessors[block.addr])
            ),
            tracked_registers,
        )[0]
    )
    proven = tuple(fact for fact in facts if fact.verdict is SegmentStackRestoreVerdict8616.PROVEN)
    return SegmentStackRestoreArtifact8616(
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
