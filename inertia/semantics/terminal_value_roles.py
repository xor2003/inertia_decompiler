"""Classify how terminal AX values are consumed by decoded instructions.

Layer: Semantics.
Responsibility: publish typed AX lane and use-role facts from exact Capstone
operand effects without choosing a C return type or mutating prototypes.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum, IntFlag
from typing import Protocol, cast

from capstone import CS_AC_READ, CS_AC_WRITE, CsError
from capstone.x86_const import X86_OP_MEM, X86_OP_REG

__all__ = [
    "TerminalAxReturnEvidence8616",
    "TerminalAxReturnLane8616",
    "TerminalAxUse8616",
    "TerminalAxUseKind8616",
    "TerminalReturnStorageState8616",
    "terminal_ax_use_8616",
]


class TerminalAxReturnLane8616(IntFlag):
    """AX byte lanes defined or consumed along one binary path."""

    NONE = 0
    LOW = 1
    HIGH = 2
    WORD = LOW | HIGH


@dataclass(frozen=True, slots=True)
class TerminalReturnStorageState8616:
    """Return-carrier state proven along one entry-reachable terminal path."""

    ax_lanes: TerminalAxReturnLane8616
    dx_ax_pair_proven: bool
    call_output_lanes: TerminalAxReturnLane8616 = TerminalAxReturnLane8616.NONE
    local_pointer_output_lanes: TerminalAxReturnLane8616 = TerminalAxReturnLane8616.NONE

    @property
    def explicit_ax_lanes(self) -> TerminalAxReturnLane8616:
        """Return AX lanes explicitly written after the last call output."""
        return self.ax_lanes & ~self.call_output_lanes

    @property
    def call_output_only(self) -> bool:
        """Return whether every defined AX lane still comes only from a call."""
        return self.ax_lanes is not TerminalAxReturnLane8616.NONE and self.call_output_lanes == self.ax_lanes

    @property
    def local_pointer_output_carrier(self) -> bool:
        """Return whether every explicit AX lane carries a local pointer output."""
        explicit_lanes = self.explicit_ax_lanes
        return (
            bool(explicit_lanes)
            and not self.call_output_lanes
            and int(self.local_pointer_output_lanes & explicit_lanes)
            == int(explicit_lanes)
        )


@dataclass(frozen=True, slots=True)
class TerminalAxReturnEvidence8616:
    """Closed accounting for entry-reachable binary terminal AX paths."""

    storage_states: frozenset[TerminalReturnStorageState8616]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def states(self) -> frozenset[TerminalAxReturnLane8616]:
        """Derive the compatibility AX-lane projection from storage states."""
        return frozenset(state.ax_lanes for state in self.storage_states)

    @property
    def complete(self) -> bool:
        """Return whether every discovered terminal-path fact was classified."""
        return (
            self.raw_fact_count > 0
            and self.normalized_fact_count == self.raw_fact_count
            and self.classified_fact_count == self.raw_fact_count
            and self.materialized_count == self.classified_fact_count
            and self.failure_count == 0
        )

    @property
    def proves_missing_value_path(self) -> bool:
        """Return whether a complete census includes a path with no AX definition."""
        return self.complete and TerminalAxReturnLane8616.NONE in self.states

    @property
    def proves_wide_return(self) -> bool:
        """Return whether every terminal path proves the same DX:AX carrier pair."""
        return (
            self.complete
            and bool(self.storage_states)
            and all(state.dx_ax_pair_proven for state in self.storage_states)
        )

    @property
    def proves_local_pointer_output_carrier(self) -> bool:
        """Return whether all terminal AX values are proven local pointer outputs."""
        return (
            self.complete
            and bool(self.storage_states)
            and all(state.local_pointer_output_carrier for state in self.storage_states)
        )


class TerminalAxUseKind8616(Enum):
    """Typed relationship between one instruction and the live AX value."""

    NONE = "none"
    MEMORY_EFFECT = "memory_effect"
    OTHER = "other"
    UNKNOWN_REFUSE = "unknown_refuse"


@dataclass(frozen=True, slots=True)
class TerminalAxUse8616:
    """One decoded instruction's use of live AX lanes."""

    kind: TerminalAxUseKind8616
    lanes: TerminalAxReturnLane8616


class _Operand8616(Protocol):
    """Capstone operand fields used by terminal-value semantics."""

    type: int
    reg: int
    access: int
    mem: _MemoryOperand8616


class _MemoryOperand8616(Protocol):
    """Capstone addressing fields used to distinguish indirect writes."""

    base: int
    index: int


class _DecodedInstruction8616(Protocol):
    """Capstone detail fields used by terminal-value semantics."""

    operands: Sequence[_Operand8616]

    def reg_name(self, register_id: int) -> str:
        """Return the canonical name for one Capstone register id."""

    def regs_access(self) -> tuple[Sequence[int], Sequence[int]]:
        """Return implicit and explicit register reads and writes."""


class _InstructionWrapper8616(Protocol):
    """angr/direct-decoder wrapper around one Capstone instruction."""

    insn: _DecodedInstruction8616


def _decoded_instruction_8616(instruction: object) -> _DecodedInstruction8616:
    """Return the dynamic third-party Capstone detail surface."""
    wrapper = cast(_InstructionWrapper8616, instruction)
    try:
        return wrapper.insn
    except AttributeError:
        return cast(_DecodedInstruction8616, instruction)


def _register_lane_8616(name: str) -> TerminalAxReturnLane8616:
    """Map one exact Capstone register name to its AX lanes."""
    return {
        "ax": TerminalAxReturnLane8616.WORD,
        "al": TerminalAxReturnLane8616.LOW,
        "ah": TerminalAxReturnLane8616.HIGH,
    }.get(name.lower(), TerminalAxReturnLane8616.NONE)


def _register_lanes_8616(
    instruction: _DecodedInstruction8616,
    register_ids: Sequence[int],
) -> TerminalAxReturnLane8616:
    """Return the union of AX lanes named by Capstone register ids."""
    lanes = TerminalAxReturnLane8616.NONE
    for register_id in register_ids:
        try:
            name = instruction.reg_name(register_id)
        except (CsError, TypeError, ValueError):
            continue
        if isinstance(name, str):
            lanes |= _register_lane_8616(name)
    return lanes


def terminal_ax_use_8616(instruction: object) -> TerminalAxUse8616:
    """Classify whether one instruction consumes the current AX definition.

    A memory effect is proven only when Capstone identifies an explicit
    writable memory operand and an explicit read-only AX-family source
    operand. Implicit memory operations and read-modify-write AX operations
    refuse the side-effect-only classification.
    """
    decoded = _decoded_instruction_8616(instruction)
    try:
        read_ids, write_ids = decoded.regs_access()
        operands = tuple(decoded.operands)
    except (AttributeError, CsError, TypeError, ValueError):
        return TerminalAxUse8616(
            TerminalAxUseKind8616.UNKNOWN_REFUSE,
            TerminalAxReturnLane8616.WORD,
        )
    read_lanes = _register_lanes_8616(decoded, read_ids)
    if read_lanes == TerminalAxReturnLane8616.NONE:
        return TerminalAxUse8616(
            TerminalAxUseKind8616.NONE,
            TerminalAxReturnLane8616.NONE,
        )
    if _register_lanes_8616(decoded, write_ids) != TerminalAxReturnLane8616.NONE:
        return TerminalAxUse8616(TerminalAxUseKind8616.OTHER, read_lanes)

    indirect_memory_write = False
    source_lanes = TerminalAxReturnLane8616.NONE
    try:
        for operand in operands:
            access = int(operand.access)
            if operand.type == X86_OP_MEM and access & CS_AC_WRITE:
                indirect_memory_write = bool(operand.mem.base or operand.mem.index)
            elif operand.type == X86_OP_REG and access & CS_AC_READ:
                name = decoded.reg_name(operand.reg)
                if isinstance(name, str):
                    source_lanes |= _register_lane_8616(name)
    except (AttributeError, CsError, TypeError, ValueError):
        return TerminalAxUse8616(
            TerminalAxUseKind8616.UNKNOWN_REFUSE,
            read_lanes,
        )
    consumed = source_lanes & read_lanes
    if indirect_memory_write and bool(consumed):
        return TerminalAxUse8616(TerminalAxUseKind8616.MEMORY_EFFECT, consumed)
    return TerminalAxUse8616(TerminalAxUseKind8616.OTHER, read_lanes)
