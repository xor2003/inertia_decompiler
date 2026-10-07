"""Recover binary loop-entry evidence for direct stack moves.

Layer: Structuring.
Responsibility: normalize instruction address domains and prove backward CFG
edges that repeat the exact binary sequence containing a direct stack move.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
This module reads dynamic angr/Capstone boundary objects but does not inspect
rendered C, source text, symbols, or variable names.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, cast

from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone.x86_const import X86_OP_IMM


@dataclass(frozen=True, slots=True)
class DirectStackMoveLoopEntryEdge8616:
    """One backward edge that repeats the instruction sequence containing a move."""

    move_addr: int
    entry_addr: int
    jump_addr: int


def _boundary_attr_8616(
    value: object | None,
    name: str,
    default: object | None = None,
) -> object | None:
    """Read one optional field from a heterogeneous angr/Capstone boundary object."""
    # Dynamic boundary: angr and Capstone expose shape-specific extension fields.
    return getattr(value, name, default)


def boundary_tuple_8616(value: object) -> tuple[Any, ...]:
    """Convert one dynamic angr collection to a stable tuple."""
    if value is None:
        return ()
    return tuple(cast(Iterable[Any], value))


def candidate_addresses_8616(project: object, address: int) -> frozenset[int]:
    """Return current and original address-domain candidates."""
    candidates = {address}
    delta = _boundary_attr_8616(project, "_inertia_original_linear_delta")
    if isinstance(delta, int) and delta:
        candidates.update((address + delta, address - delta))
    return frozenset(candidates)


def comparable_address_8616(
    project: object,
    address: int,
    reference_addr: int,
) -> int:
    """Normalize one dynamic address to the fact's coordinate domain."""
    return min(
        candidate_addresses_8616(project, address),
        key=lambda candidate: abs(candidate - reference_addr),
    )


def _function_instructions_8616(function: object) -> tuple[tuple[object, ...], ...]:
    """Return authoritative Capstone sequences from the function's binary blocks."""
    blocks = boundary_tuple_8616(_boundary_attr_8616(function, "blocks", ()) or ())
    sequences: list[tuple[object, ...]] = []
    for block in blocks:
        capstone = _boundary_attr_8616(block, "capstone")
        instructions = tuple(
            _boundary_attr_8616(wrapper, "insn", wrapper)
            for wrapper in boundary_tuple_8616(
                _boundary_attr_8616(capstone, "insns", ()) or ()
            )
        )
        if instructions:
            sequences.append(instructions)
    return tuple(sequences)


@dataclass(slots=True)
class _SequenceEdgeCensus8616:
    """Mutable census of sequence entries and jump instructions for one move."""

    project: object
    move_addr: int
    sequence_entries: set[int]
    jump_instructions: list[object]

    def collect(self, instructions: tuple[object, ...]) -> None:
        """Collect one instruction sequence's entries and jumps."""
        for index, instruction in enumerate(instructions):
            self._collect_one(instructions, index, instruction)

    def _collect_one(
        self,
        instructions: tuple[object, ...],
        index: int,
        instruction: object,
    ) -> None:
        """Record one instruction's jump membership and backward entries."""
        address = _boundary_attr_8616(instruction, "address")
        groups = frozenset(
            boundary_tuple_8616(_boundary_attr_8616(instruction, "groups", ()) or ())
        )
        if CS_GRP_JUMP in groups:
            self.jump_instructions.append(instruction)
        if (
            not isinstance(address, int)
            or comparable_address_8616(self.project, address, self.move_addr)
            != self.move_addr
        ):
            return
        self.sequence_entries.add(self.move_addr)
        self._extend_backward(instructions, index)

    def _extend_backward(
        self,
        instructions: tuple[object, ...],
        index: int,
    ) -> None:
        """Walk backward from the move until a control-flow boundary."""
        for previous_index in range(index - 1, -1, -1):
            previous = instructions[previous_index]
            previous_addr = _boundary_attr_8616(previous, "address")
            previous_groups = frozenset(
                boundary_tuple_8616(_boundary_attr_8616(previous, "groups", ()) or ())
            )
            if (
                not isinstance(previous_addr, int)
                or previous_groups & {CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET}
            ):
                break
            comparable_previous = comparable_address_8616(
                self.project,
                previous_addr,
                self.move_addr,
            )
            if self.move_addr - comparable_previous > 16:
                break
            self.sequence_entries.add(comparable_previous)


def _jump_edge_8616(
    project: object,
    instruction: object,
    move_addr: int,
    sequence_entries: set[int],
) -> DirectStackMoveLoopEntryEdge8616 | None:
    """Return the proven backward edge for one jump, if any."""
    jump_addr = _boundary_attr_8616(instruction, "address")
    operands = boundary_tuple_8616(
        _boundary_attr_8616(instruction, "operands", ()) or ()
    )
    if not isinstance(jump_addr, int) or len(operands) != 1:
        return None
    operand = operands[0]
    target = _boundary_attr_8616(operand, "imm")
    if _boundary_attr_8616(operand, "type") != X86_OP_IMM or not isinstance(
        target, int
    ):
        return None
    comparable_jump = comparable_address_8616(project, jump_addr, move_addr)
    comparable_target = comparable_address_8616(project, target, move_addr)
    if comparable_target not in sequence_entries:
        return None
    if comparable_jump <= move_addr or comparable_target >= comparable_jump:
        return None
    return DirectStackMoveLoopEntryEdge8616(
        move_addr,
        comparable_target,
        comparable_jump,
    )


def repeated_sequence_edges_8616(
    project: object,
    function: object,
    move_addr: int,
) -> tuple[DirectStackMoveLoopEntryEdge8616, ...]:
    """Recover exact backward edges whose target repeats one direct move."""
    census = _SequenceEdgeCensus8616(project, move_addr, set(), [])
    for instructions in _function_instructions_8616(function):
        census.collect(instructions)
    if not census.sequence_entries:
        return ()
    edges: list[DirectStackMoveLoopEntryEdge8616] = []
    for instruction in census.jump_instructions:
        edge = _jump_edge_8616(project, instruction, move_addr, census.sequence_entries)
        if edge is not None:
            edges.append(edge)
    return tuple(dict.fromkeys(edges))
