# cython: language_level=3, infer_types=True
"""Prove word-sized numeric frame-register assignments from source IR.

Layer: Alias.
Responsibility: consume the canonical CFG stack transfer and exact captured
operand views to publish entry-SP-relative scalar values. These are values,
not SS addresses, and do not authorize reading a mutable native ESP after CALL.
Consumers must reprove against current IR before materializing a saved result.
Owns storage identity
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here
"""
from __future__ import annotations
import typing
import cython

from dataclasses import dataclass, replace

from inertia.ir.core import IRFunctionArtifact, IRInstr, IRValue, MemSpace

from .segment_stack_restore import (
    _predecessor_map,
    _solve_stack_states,
    _transfer_block,
)
from .stack_pointer_snapshots import StackPointerSnapshots8616
from .stack_restore_state import StackRestoreState8616, join_stack_restore_states_8616
import dataclasses
import operator


@dataclasses.dataclass(frozen=True)
class NumericStackPointerAssignment8616:
    """One exact source assignment of a word scalar relative to entry SP."""

    function_addr: cython.longlong
    block_addr: cython.longlong
    instruction_index: cython.longlong
    instruction_addr: cython.longlong
    register: object
    entry_sp_offset: cython.longlong
    width_bits: cython.longlong = 16


@cython.ccall
def _plain_frame_read(value: IRValue) -> cython.bint:
    """Admit an undecorated architectural word read, never a retained view."""
    return (
        value.name in {"sp", "bp"}
        and operator.eq(value, IRValue(space=MemSpace.REG, name=value.name, size=2))
        and value.source_tmp is None
        and value.memory_access_insn is None
    )


@cython.cclass
class _AssignmentObserver:
    """Retain exact MOV capture views while the authoritative transfer runs."""
    captures = cython.declare(dict, visibility = "public")
    coordinate = cython.declare(object, visibility = "public")
    target = cython.declare(object, visibility = "public")

    def __init__(self, target: IRInstr) -> None:
        """Select one source instruction by object identity, not display text."""
        self.target = target
        self.captures: dict[cython.longlong, tuple[IRValue, cython.longlong]] = {}
        self.coordinate: int | None = None

    @cython.ccall
    def observe(
        self, instruction: IRInstr, snapshots: StackPointerSnapshots8616,
        sp: int | None, bp: int | None,
    ) -> None:
        """Consume a source read before the canonical register/call transfer."""
        coordinate: object
        tmp: object
        destination = instruction.dst
        source = instruction.args[0] if len(instruction.args) == 1 else None
        coordinate = None
        if instruction.op == "MOV" and isinstance(source, IRValue):
            if _plain_frame_read(source):
                coordinate = snapshots.value_offset(source, sp, bp)
            elif source.source_tmp in self.captures:
                view, captured = self.captures[source.source_tmp]
                if source == view and operator.eq(source.memory_access_insn, view.memory_access_insn):
                    coordinate = captured
        if instruction is self.target:
            self.coordinate = coordinate
        if isinstance(destination, IRValue) and destination.space is MemSpace.TMP:
            tmp = destination.source_tmp
            if tmp is not None:
                self.captures.pop(tmp, None)
                if (coordinate is not None and isinstance(source, IRValue)
                        and operator.eq(destination, IRValue(
                            space=MemSpace.TMP, name=destination.name, size=2, source_tmp=tmp,
                        )) and destination.memory_access_insn is None):
                    self.captures[tmp] = (replace(source, source_tmp=tmp), coordinate)


def prove_numeric_stack_pointer_assignment_8616(
    artifact: IRFunctionArtifact, block_addr: cython.longlong, instruction_index: cython.longlong,
) -> NumericStackPointerAssignment8616 | None:
    """Reprove an exact GP word assignment from the current complete CFG.

    The canonical must-state solver owns entry coordinates and call effects.
    Exact MOV captures preserve a value even when a later SP changes; decorated,
    partial, undefined, or redefined capture views refuse. No result here proves
    a return path, native projection ownership, or the lifetime of a C capture.
    """
    block: object
    blocks = {block.addr: block for block in iter(artifact.blocks)}
    if (artifact.refusals or operator.ne(len(blocks), len(artifact.blocks))
            or artifact.function_addr not in blocks
            or any(block.refusals for block in iter(artifact.blocks))):
        return None
    if any(successor not in blocks for block in iter(artifact.blocks) for successor in iter(block.successor_addrs)):
        return None
    block = blocks.get(block_addr)
    if block is None or not 0 <= instruction_index < len(block.instrs):
        return None
    target = block.instrs[instruction_index]
    destination = target.dst
    if target.op != "MOV" or target.addr is None or not isinstance(destination, IRValue):
        return None
    if (destination.name not in {"ax", "bx", "cx", "dx", "si", "di"}
            or operator.ne(destination, IRValue(space=MemSpace.REG, name=destination.name, size=2))
            or destination.source_tmp is not None or destination.memory_access_insn is not None):
        return None
    states = _solve_stack_states(artifact)
    predecessors = _predecessor_map(artifact)
    incoming = tuple(states[pred] for pred in iter(predecessors[block_addr]))
    if operator.eq(block_addr, artifact.function_addr):
        incoming = (StackRestoreState8616(0), *incoming)
    if not incoming:
        return None
    observer = _AssignmentObserver(target)
    _transfer_block(
        block_addr, block.instrs[:instruction_index + 1], join_stack_restore_states_8616(incoming),
        value_observer=observer.observe,
    )
    if observer.coordinate is None:
        return None
    return NumericStackPointerAssignment8616(
        artifact.function_addr, block_addr, instruction_index, target.addr,
        destination.name, observer.coordinate,
    )
