"""Recover register-addressed segmented stores from exact constant evidence.

Layer: Types/Lowering.
Responsibility: collect binary-proven segmented store identities when a
same-block register constant supplies the effective offset or stored value.
This module does not use source, COD metadata, assembly text, or rendered C.
Consumes alias, widening, and typed facts; it does not invent them.
Do not recover semantics from COD, source, assembly, or rendered C text.
Unknown register writes erase evidence instead of guessing.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol

from capstone.x86_const import (
    X86_INS_ADD,
    X86_INS_MOV,
    X86_INS_SUB,
    X86_INS_XOR,
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_INVALID,
)

from ..ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin

type RegisterNameResolver8616 = Callable[[object, int | None], str | None]


class MemoryOperandView8616(Protocol):
    """Typed memory fields consumed from a normalized Capstone operand."""

    @property
    def segment(self) -> int | None:
        """Return the explicit segment-register identifier, if present."""
        ...

    @property
    def base(self) -> int | None:
        """Return the base-register identifier, if present."""
        ...

    @property
    def index(self) -> int | None:
        """Return the index-register identifier, if present."""
        ...

    @property
    def displacement(self) -> int | None:
        """Return the decoded displacement, if present."""
        ...


class OperandView8616(Protocol):
    """Typed normalized Capstone operand consumed by this collector."""

    @property
    def kind(self) -> int | None:
        """Return the decoded Capstone operand kind."""
        ...

    @property
    def register(self) -> int | None:
        """Return the register identifier for a register operand."""
        ...

    @property
    def size(self) -> int | None:
        """Return the decoded operand width in bytes."""
        ...

    @property
    def immediate(self) -> int | None:
        """Return the immediate value for an immediate operand."""
        ...

    @property
    def memory(self) -> MemoryOperandView8616 | None:
        """Return normalized memory fields for a memory operand."""
        ...


class InstructionView8616(Protocol):
    """Typed normalized Capstone instruction consumed by this collector."""

    @property
    def raw(self) -> object:
        """Return the third-party instruction used for register names."""
        ...

    @property
    def instruction_id(self) -> int | None:
        """Return the decoded Capstone instruction identifier."""
        ...

    @property
    def address(self) -> int | None:
        """Return the instruction address, if present."""
        ...

    @property
    def operands(self) -> Sequence[OperandView8616]:
        """Return normalized operands in instruction order."""
        ...


@dataclass(frozen=True, slots=True)
class RegisterConstantSegmentedStoreEvidence8616:
    """Exact store identity recovered through same-block register constants."""

    offset: int
    width: int
    space: MemSpace
    ins_addr: int
    immediate_value: int | None
    segment_value: int | None


@dataclass(frozen=True, slots=True)
class SegmentRegisterMemorySourceEvidence8616:
    """Exact memory source held by a segment register at one access."""

    ins_addr: int
    segment_name: str
    source: IRAddress


def _memory_access_sources_8616(
    instruction: InstructionView8616,
    sources: dict[str, IRAddress],
    segment_name: RegisterNameResolver8616,
    recovered: list[SegmentRegisterMemorySourceEvidence8616],
) -> None:
    """Record evidence when a tracked segment register feeds one operand."""
    if not isinstance(instruction.address, int):
        return
    for operand in instruction.operands:
        memory = operand.memory
        if operand.kind != X86_OP_MEM or memory is None:
            continue
        access_segment = segment_name(instruction.raw, memory.segment)
        source = sources.get(access_segment) if access_segment is not None else None
        if access_segment is not None and source is not None:
            recovered.append(
                SegmentRegisterMemorySourceEvidence8616(
                    ins_addr=int(instruction.address),
                    segment_name=access_segment,
                    source=source,
                )
            )


def _direct_word_memory_source_8616(source_operand: OperandView8616 | None) -> bool:
    """Check one mov source operand is a direct word memory reference."""
    if source_operand is None or source_operand.kind != X86_OP_MEM:
        return False
    source_memory = source_operand.memory
    return (
        source_memory is not None
        and source_memory.base in {None, 0, X86_REG_INVALID}
        and source_memory.index in {None, 0, X86_REG_INVALID}
        and isinstance(source_memory.displacement, int)
        and source_operand.size == 2
    )


def _segment_destination_update_8616(
    instruction: InstructionView8616,
    sources: dict[str, IRAddress],
    register_name: RegisterNameResolver8616,
    segment_name: RegisterNameResolver8616,
) -> None:
    """Track or invalidate one segment-register memory source."""
    operands = instruction.operands
    if not operands or operands[0].kind != X86_OP_REG:
        return
    destination_name = register_name(instruction.raw, operands[0].register)
    if destination_name not in {"ds", "es", "ss"}:
        return
    source_address: IRAddress | None = None
    source_operand = (
        operands[1]
        if instruction.instruction_id == X86_INS_MOV and len(operands) == 2
        else None
    )
    if _direct_word_memory_source_8616(source_operand):
        assert source_operand is not None
        source_memory = source_operand.memory
        assert source_memory is not None
        assert isinstance(source_memory.displacement, int)
        source_segment = segment_name(instruction.raw, source_memory.segment)
        source_space = MemSpace.DS if source_segment == "ds" else MemSpace.ES if source_segment == "es" else None
        if source_space is not None and source_segment not in sources:
            source_address = IRAddress(
                space=source_space,
                offset=int(source_memory.displacement) & 0xFFFF,
                size=2,
                status=AddressStatus.STABLE,
                segment_origin=SegmentOrigin.PROVEN,
            )
    sources.pop(destination_name, None)
    if source_address is not None:
        sources[destination_name] = source_address


def recover_segment_register_memory_sources_8616(
    instructions: Sequence[InstructionView8616],
    *,
    register_name: RegisterNameResolver8616,
    segment_name: RegisterNameResolver8616,
) -> tuple[SegmentRegisterMemorySourceEvidence8616, ...]:
    """Track direct memory loads into segment registers within one basic block."""
    sources: dict[str, IRAddress] = {}
    recovered: list[SegmentRegisterMemorySourceEvidence8616] = []
    for instruction in instructions:
        _memory_access_sources_8616(instruction, sources, segment_name, recovered)
        _segment_destination_update_8616(
            instruction,
            sources,
            register_name,
            segment_name,
        )
    return tuple(recovered)


def _forget_register_8616(constants: dict[str, int], register_name: str | None) -> None:
    """Invalidate one register and its overlapping aliases."""
    if register_name is None:
        return
    constants.pop(register_name, None)
    alias_groups = (
        frozenset(("al", "ah", "ax", "eax")),
        frozenset(("bl", "bh", "bx", "ebx")),
        frozenset(("cl", "ch", "cx", "ecx")),
        frozenset(("dl", "dh", "dx", "edx")),
    )
    for aliases in alias_groups:
        if register_name in aliases:
            for alias in aliases:
                constants.pop(alias, None)
            return


def _source_constant_8616(
    instruction: InstructionView8616,
    operand: OperandView8616,
    constants: dict[str, int],
    register_name: RegisterNameResolver8616,
) -> int | None:
    """Resolve an immediate or exactly tracked register source."""
    if operand.kind == X86_OP_IMM and isinstance(operand.immediate, int):
        return int(operand.immediate)
    if operand.kind != X86_OP_REG:
        return None
    source_name = register_name(instruction.raw, operand.register)
    return constants.get(source_name) if source_name is not None else None


def _store_evidence_8616(
    instruction: InstructionView8616,
    constants: dict[str, int],
    register_name: RegisterNameResolver8616,
    segment_name: RegisterNameResolver8616,
) -> RegisterConstantSegmentedStoreEvidence8616 | None:
    """Classify one register-addressed MOV store when every address term is exact."""
    operands = instruction.operands
    if instruction.instruction_id != X86_INS_MOV or len(operands) != 2:
        return None
    destination, source = operands
    memory = destination.memory
    if destination.kind != X86_OP_MEM or memory is None:
        return None
    if memory.base in {None, 0, X86_REG_INVALID} or memory.index not in {None, 0, X86_REG_INVALID}:
        return None
    base_name = register_name(instruction.raw, memory.base)
    base_value = constants.get(base_name) if base_name is not None else None
    if base_value is None or not isinstance(memory.displacement, int):
        return None
    resolved_segment = segment_name(instruction.raw, memory.segment)
    space = MemSpace.DS if resolved_segment == "ds" else MemSpace.ES if resolved_segment == "es" else None
    if space is None or destination.size not in {1, 2, 4} or not isinstance(instruction.address, int):
        return None
    source_value = _source_constant_8616(instruction, source, constants, register_name)
    segment_value = constants.get(resolved_segment) if resolved_segment is not None else None
    mask = (1 << (int(destination.size) * 8)) - 1
    return RegisterConstantSegmentedStoreEvidence8616(
        offset=(base_value + int(memory.displacement)) & 0xFFFF,
        width=int(destination.size),
        space=space,
        ins_addr=int(instruction.address),
        immediate_value=source_value & mask if source_value is not None else None,
        segment_value=segment_value & 0xFFFF if segment_value is not None else None,
    )


def _update_register_constants_8616(
    instruction: InstructionView8616,
    constants: dict[str, int],
    register_name: RegisterNameResolver8616,
) -> None:
    """Apply the supported exact register transfer or invalidate its destination."""
    operands = instruction.operands
    if not operands or operands[0].kind != X86_OP_REG:
        return
    destination_name = register_name(instruction.raw, operands[0].register)
    if destination_name is None:
        return
    source = operands[1] if len(operands) == 2 else None
    value: int | None = None
    if instruction.instruction_id == X86_INS_MOV and source is not None:
        value = _source_constant_8616(instruction, source, constants, register_name)
    elif (
        instruction.instruction_id in {X86_INS_SUB, X86_INS_XOR}
        and source is not None
        and source.kind == X86_OP_REG
        and register_name(instruction.raw, source.register) == destination_name
    ):
        value = 0
    elif (
        instruction.instruction_id in {X86_INS_ADD, X86_INS_SUB}
        and source is not None
        and source.kind == X86_OP_IMM
        and isinstance(source.immediate, int)
        and destination_name in constants
    ):
        delta = int(source.immediate)
        value = constants[destination_name] + (delta if instruction.instruction_id == X86_INS_ADD else -delta)
    _forget_register_8616(constants, destination_name)
    if value is not None:
        constants[destination_name] = value & 0xFFFF


def recover_register_constant_segmented_stores_8616(
    instructions: Sequence[InstructionView8616],
    *,
    register_name: RegisterNameResolver8616,
    segment_name: RegisterNameResolver8616,
) -> tuple[RegisterConstantSegmentedStoreEvidence8616, ...]:
    """Recover exact register-addressed segmented stores within one basic block."""
    constants: dict[str, int] = {}
    recovered: list[RegisterConstantSegmentedStoreEvidence8616] = []
    for instruction in instructions:
        evidence = _store_evidence_8616(
            instruction,
            constants,
            register_name,
            segment_name,
        )
        if evidence is not None:
            recovered.append(evidence)
        _update_register_constants_8616(instruction, constants, register_name)
    return tuple(recovered)
