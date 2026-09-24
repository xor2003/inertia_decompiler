"""Collect decoded register and storage facts for callsite provenance.

Layer: Recovery metadata.
Responsibility: translate exact Capstone instruction effects into typed sources
that the Alias layer can propagate across a function CFG.
Forbidden: CFG joining, argument materialization, structuring, or C rewriting.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final, Protocol

from capstone import CS_AC_WRITE
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from .alias.callsite_stack_merge import CallsiteSource8616
from .semantics.register_value_preservation import decoded_register_bit_effects_8616, register_value_projection_8616

__all__ = (
    "DecodedInstructionFactSurface8616",
    "instruction_writes_memory_8616",
    "instruction_writes_register_8616",
    "register_replacement_source_8616",
    "register_storage_snapshot_source_8616",
)


class _MemoryOperand8616(Protocol):
    """Capstone memory fields consumed at the decoded-instruction boundary."""

    base: int
    index: int
    segment: int
    disp: int


class _Operand8616(Protocol):
    """Capstone operand fields consumed by instruction fact collection."""

    type: int
    reg: int
    imm: int
    size: int
    access: int
    mem: _MemoryOperand8616


class _DecodedInstruction8616(Protocol):
    """Capstone instruction detail used by exact effect collection."""

    operands: Sequence[_Operand8616]

    def reg_name(self, reg_id: int) -> str:
        """Return the backend register name for ``reg_id``."""
        ...

    def regs_access(self) -> tuple[Sequence[int], Sequence[int]]:
        """Return registers read and written by this instruction."""
        ...


class DecodedInstructionFactSurface8616(Protocol):
    """angr Capstone wrapper fields used by this recovery-metadata module."""

    mnemonic: str
    address: int
    insn: _DecodedInstruction8616


def _register_name_8616(
    instruction: DecodedInstructionFactSurface8616,
    operand: _Operand8616,
) -> str | None:
    """Return one normalized register operand name."""
    if operand.type != X86_OP_REG:
        return None
    name = instruction.insn.reg_name(operand.reg)
    return name.lower() if isinstance(name, str) and name else None


def instruction_writes_register_8616(
    instruction: DecodedInstructionFactSurface8616,
    register: str,
) -> bool:
    """Return whether an overlapping write is possible; unknown detail clobbers."""
    effects = decoded_register_bit_effects_8616(instruction, register)
    return effects is None or effects[1] != 0


def instruction_writes_memory_8616(
    instruction: DecodedInstructionFactSurface8616,
) -> bool:
    """Return whether an explicit operand may write memory."""
    for operand in instruction.insn.operands:
        if operand.type != X86_OP_MEM:
            continue
        try:
            access = int(operand.access)
        except (AttributeError, TypeError, ValueError):
            return True
        if access & CS_AC_WRITE:
            return True
    return False


_BYTE_VIEW_PARENTS_8616: Final[dict[str, tuple[str, int]]] = {
    "al": ("ax", 0),
    "ah": ("ax", 8),
    "bl": ("bx", 0),
    "bh": ("bx", 8),
    "cl": ("cx", 0),
    "ch": ("cx", 8),
    "dl": ("dx", 0),
    "dh": ("dx", 8),
}


def _subview_replacement_source_8616(
    instruction: DecodedInstructionFactSurface8616,
    register: str,
    destination_name: str,
    mnemonic: str,
    rhs: _Operand8616,
) -> CallsiteSource8616 | None:
    """Return an exact source when the write targets a different register."""
    projection = register_value_projection_8616(destination_name, register)
    if mnemonic == "mov" and rhs.type == X86_OP_IMM and projection is not None:
        shift, bits = projection
        return ("imm", (int(rhs.imm) >> shift) & ((1 << bits) - 1))
    requested_view = _BYTE_VIEW_PARENTS_8616.get(register)
    rhs_name = _register_name_8616(instruction, rhs)
    if (
        requested_view is not None
        and destination_name == requested_view[0]
        and mnemonic in {"add", "and", "or", "sub", "xor"}
        and rhs_name is not None
    ):
        return (
            "register_binary_subview",
            mnemonic,
            destination_name,
            rhs_name,
            requested_view[1],
            8,
            instruction.address,
        )
    return None


def _direct_mov_source_8616(
    instruction: DecodedInstructionFactSurface8616,
    mnemonic: str,
    rhs: _Operand8616,
) -> CallsiteSource8616 | None:
    """Return an exact immediate or memory source for a direct MOV write."""
    if mnemonic != "mov":
        return None
    if rhs.type == X86_OP_IMM:
        return ("imm", int(rhs.imm))
    if rhs.type == X86_OP_MEM and rhs.mem.index == 0:
        base_name = (
            instruction.insn.reg_name(rhs.mem.base).lower()
            if rhs.mem.base
            else ""
        )
        segment_name = (
            instruction.insn.reg_name(rhs.mem.segment).lower()
            if rhs.mem.segment
            else ""
        )
        width = int(rhs.size) if int(rhs.size) > 0 else 2
        if base_name == "bp" and segment_name in {"", "ss"}:
            return ("bp", int(rhs.mem.disp), width)
        if not base_name and segment_name in {"", "ds"}:
            return ("global", int(rhs.mem.disp), width)
    return None


def register_replacement_source_8616(
    instruction: DecodedInstructionFactSurface8616,
    register: str,
) -> CallsiteSource8616 | None:
    """Return an exact source for one complete register definition."""
    operands = tuple(instruction.insn.operands)
    if len(operands) != 2:
        return None
    destination_name = _register_name_8616(instruction, operands[0])
    if destination_name is None:
        return None
    mnemonic = instruction.mnemonic.lower()
    rhs = operands[1]
    if destination_name != register:
        return _subview_replacement_source_8616(
            instruction, register, destination_name, mnemonic, rhs,
        )
    source = _direct_mov_source_8616(instruction, mnemonic, rhs)
    if source is not None:
        return source
    if mnemonic in {"sub", "xor"} and _register_name_8616(instruction, rhs) == register:
        return ("imm", 0)
    return None


def register_storage_snapshot_source_8616(
    instruction: DecodedInstructionFactSurface8616,
    register: str,
) -> CallsiteSource8616 | None:
    """Return storage proven equal to ``register`` by an exact MOV store."""
    operands = tuple(instruction.insn.operands)
    if instruction.mnemonic.lower() != "mov" or len(operands) != 2:
        return None
    destination, value = operands
    if destination.type != X86_OP_MEM or _register_name_8616(instruction, value) != register:
        return None
    width = int(destination.size)
    if width <= 0 or int(value.size) != width:
        return None
    base_name = instruction.insn.reg_name(destination.mem.base).lower() if destination.mem.base else ""
    segment_name = (
        instruction.insn.reg_name(destination.mem.segment).lower()
        if destination.mem.segment
        else ""
    )
    if base_name == "bp" and destination.mem.index == 0 and segment_name in {"", "ss"}:
        return ("bp", int(destination.mem.disp), width)
    if not base_name and destination.mem.index == 0 and segment_name in {"", "ds"}:
        return ("global", int(destination.mem.disp), width)
    return None
