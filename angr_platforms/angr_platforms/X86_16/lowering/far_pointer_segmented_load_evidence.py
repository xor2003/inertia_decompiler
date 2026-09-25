"""Recover exact segmented loads through stack-resident far pointers.

Layer: Types/Lowering.
Responsibility: connect LES/LDS stack-pair evidence to later segmented load
sites. This module consumes decoded instructions and typed stack identities;
it never reads source, COD metadata, assembly text, or rendered C.
Consumes alias, widening, and typed facts; it does not invent them.
Do not recover semantics from COD, source, assembly, or rendered C text.

Unknown register writes erase carriers. Ambiguous address terms are refused.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from enum import StrEnum

from capstone.x86_const import (
    X86_INS_LDS,
    X86_INS_LES,
    X86_INS_MOV,
    X86_INS_SAL,
    X86_INS_SHL,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_INVALID,
)

from .far_pointer_constant_flow import (
    FarPointerConstantState8616,
    apply_far_pointer_constant_instruction_8616,
)
from .register_constant_segmented_store import (
    InstructionView8616,
    OperandView8616,
    RegisterNameResolver8616,
)


class FarPointerSegmentRegister8616(StrEnum):
    """Architectural segment register loaded from one far-pointer pair."""

    DS = "ds"
    ES = "es"


@dataclass(frozen=True, slots=True)
class FarPointerStackValueSource8616:
    """Exact stack value copied into one component of a far-pointer pair."""

    stack_offset: int
    width: int


@dataclass(frozen=True, slots=True)
class FarPointerStackSource8616:
    """Exact adjacent stack words holding a far offset and segment selector."""

    offset_stack_offset: int
    segment_stack_offset: int
    segment_value_source: FarPointerStackValueSource8616 | None = None
    offset_constant: int | None = None


@dataclass(frozen=True, slots=True)
class FarPointerSegmentedLoadEvidence8616:
    """Exact segmented load site reached through an LES/LDS stack pair."""

    segment_register: FarPointerSegmentRegister8616
    pointer_source: FarPointerStackSource8616
    width: int
    displacement: int
    ins_addr: int
    index_stack_offset: int | None = None
    index_stack_width: int = 2
    index_shift: int = 0


_StackIndex8616 = tuple[int, int, int]
_REGISTER_ALIAS_GROUPS_8616 = (
    frozenset(("al", "ah", "ax", "eax")),
    frozenset(("bl", "bh", "bx", "ebx")),
    frozenset(("cl", "ch", "cx", "ecx")),
    frozenset(("dl", "dh", "dx", "edx")),
)


def _register_aliases_8616(register_name: str) -> frozenset[str]:
    """Return the overlapping architectural names for one register."""
    for aliases in _REGISTER_ALIAS_GROUPS_8616:
        if register_name in aliases:
            return aliases
    return frozenset((register_name,))


def _forget_register_8616(
    register_name: str,
    stack_indices: dict[str, _StackIndex8616],
    far_offsets: dict[str, FarPointerStackSource8616],
) -> None:
    """Invalidate every tracked view overlapping one written register."""
    for alias in _register_aliases_8616(register_name):
        stack_indices.pop(alias, None)
        far_offsets.pop(alias, None)


def _forget_stack_value_sources_8616(
    offset: int,
    width: int,
    stack_value_sources: dict[int, FarPointerStackValueSource8616],
) -> None:
    """Invalidate tracked stack destinations overlapping one memory write."""
    write_end = offset + width
    for destination in tuple(stack_value_sources):
        source_width = stack_value_sources[destination].width
        if destination < write_end and offset < destination + source_width:
            stack_value_sources.pop(destination, None)


def _stack_slot_8616(
    instruction: InstructionView8616,
    operand: OperandView8616,
    *,
    register_name: RegisterNameResolver8616,
    segment_name: RegisterNameResolver8616,
) -> tuple[int, int] | None:
    """Return an exact BP-relative stack slot from one memory operand."""
    memory = operand.memory
    if operand.kind != X86_OP_MEM or memory is None or not isinstance(memory.displacement, int):
        return None
    base = register_name(instruction.raw, memory.base)
    index = register_name(instruction.raw, memory.index)
    explicit_segment = memory.segment not in {None, 0, X86_REG_INVALID}
    segment = segment_name(instruction.raw, memory.segment) if explicit_segment else None
    if base != "bp" or index is not None or segment not in {None, "ss"}:
        return None
    if operand.size not in {1, 2, 4}:
        return None
    return int(memory.displacement), int(operand.size)


def _far_pointer_load_kind_8616(instruction_id: int | None) -> FarPointerSegmentRegister8616 | None:
    """Map LES/LDS to the segment register they load."""
    if instruction_id == X86_INS_LES:
        return FarPointerSegmentRegister8616.ES
    if instruction_id == X86_INS_LDS:
        return FarPointerSegmentRegister8616.DS
    return None


def _segmented_pointer_source_8616(
    instruction: InstructionView8616,
    memory: object,
    source: object,
    segment_sources: dict[FarPointerSegmentRegister8616, FarPointerStackSource8616],
    segment_name: RegisterNameResolver8616,
) -> tuple[FarPointerSegmentRegister8616, FarPointerStackSource8616] | None:
    """Resolve the segment override to a proven far-pointer stack source."""
    segment_text = segment_name(instruction.raw, memory.segment)
    if segment_text is None:
        return None
    try:
        segment_register = FarPointerSegmentRegister8616(segment_text)
    except (TypeError, ValueError):
        return None
    pointer_source = segment_sources.get(segment_register)
    if pointer_source is None or source.size not in {1, 2, 4}:
        return None
    return segment_register, pointer_source


def _pointer_index_parts_8616(
    instruction: InstructionView8616,
    memory: object,
    pointer_source: FarPointerStackSource8616,
    stack_indices: dict[str, _StackIndex8616],
    far_offsets: dict[str, FarPointerStackSource8616],
    register_name: RegisterNameResolver8616,
) -> tuple[int | None, int, int] | None:
    """Resolve base/index registers to one far pointer plus an optional stack index."""
    address_registers = tuple(
        dict.fromkeys(
            name
            for register in (memory.base, memory.index)
            if (name := register_name(instruction.raw, register)) is not None
        )
    )
    pointer_registers = tuple(
        name for name in address_registers if far_offsets.get(name) == pointer_source
    )
    if len(pointer_registers) != 1:
        return None
    remaining = tuple(name for name in address_registers if name != pointer_registers[0])
    if len(remaining) > 1:
        return None
    index = stack_indices.get(remaining[0]) if remaining else None
    if remaining and index is None:
        return None
    index_offset, index_width, index_shift = index if index is not None else (None, 2, 0)
    if index_shift < 0 or index_shift > 4:
        return None
    return index_offset, index_width, index_shift


def _segmented_load_evidence_8616(
    instruction: InstructionView8616,
    stack_indices: dict[str, _StackIndex8616],
    far_offsets: dict[str, FarPointerStackSource8616],
    segment_sources: dict[FarPointerSegmentRegister8616, FarPointerStackSource8616],
    *,
    register_name: RegisterNameResolver8616,
    segment_name: RegisterNameResolver8616,
) -> FarPointerSegmentedLoadEvidence8616 | None:
    """Classify one MOV load whose segment and offset share a proven far pair."""
    operands = instruction.operands
    if instruction.instruction_id != X86_INS_MOV or len(operands) != 2:
        return None
    destination, source = operands
    memory = source.memory
    if destination.kind != X86_OP_REG or source.kind != X86_OP_MEM or memory is None:
        return None
    gated = _segmented_pointer_source_8616(instruction, memory, source, segment_sources, segment_name)
    if gated is None:
        return None
    segment_register, pointer_source = gated
    if not isinstance(memory.displacement, int) or not isinstance(instruction.address, int):
        return None
    resolved = _pointer_index_parts_8616(
        instruction, memory, pointer_source, stack_indices, far_offsets, register_name
    )
    if resolved is None:
        return None
    index_offset, index_width, index_shift = resolved
    return FarPointerSegmentedLoadEvidence8616(
        segment_register=segment_register,
        pointer_source=pointer_source,
        width=int(source.size),
        displacement=int(memory.displacement),
        ins_addr=int(instruction.address),
        index_stack_offset=index_offset,
        index_stack_width=index_width,
        index_shift=index_shift,
    )


@dataclass(slots=True)
class _FarPointerScanState8616:
    """Mutable per-block state while scanning instructions for far loads."""

    stack_indices: dict[str, _StackIndex8616] = field(default_factory=dict)
    far_offsets: dict[str, FarPointerStackSource8616] = field(default_factory=dict)
    segment_sources: dict[FarPointerSegmentRegister8616, FarPointerStackSource8616] = field(default_factory=dict)
    stack_value_sources: dict[int, FarPointerStackValueSource8616] = field(default_factory=dict)


def _scan_stack_slot_8616(
    instruction: InstructionView8616,
    operand: OperandView8616,
    *,
    register_name: RegisterNameResolver8616,
    segment_name: RegisterNameResolver8616,
) -> tuple[int, int] | None:
    """Resolve one operand to a typed stack slot when it names one."""
    return _stack_slot_8616(
        instruction,
        operand,
        register_name=register_name,
        segment_name=segment_name,
    )


def _apply_far_pointer_load_8616(
    state: _FarPointerScanState8616,
    constant_state: FarPointerConstantState8616,
    instruction: InstructionView8616,
    operands: tuple[OperandView8616, ...],
    *,
    register_name: RegisterNameResolver8616,
    segment_name: RegisterNameResolver8616,
) -> bool:
    """Track one LES/LDS-style load; return True when it was handled."""
    far_kind = _far_pointer_load_kind_8616(instruction.instruction_id)
    if far_kind is None or len(operands) != 2 or operands[0].kind != X86_OP_REG:
        return False
    destination = register_name(instruction.raw, operands[0].register)
    source_slot = _scan_stack_slot_8616(
        instruction, operands[1], register_name=register_name, segment_name=segment_name
    )
    if destination is not None:
        _forget_register_8616(destination, state.stack_indices, state.far_offsets)
    state.segment_sources.pop(far_kind, None)
    if destination is not None and source_slot is not None and source_slot[1] in {2, 4}:
        segment_offset = source_slot[0] + 2
        pointer_source = FarPointerStackSource8616(
            source_slot[0],
            segment_offset,
            state.stack_value_sources.get(segment_offset),
            constant_state.stack_constant(source_slot[0], 2),
        )
        state.far_offsets[destination] = pointer_source
        state.segment_sources[far_kind] = pointer_source
    return True


def _update_stack_slot_target_8616(
    state: _FarPointerScanState8616,
    instruction: InstructionView8616,
    operands: tuple[OperandView8616, ...],
    *,
    register_name: RegisterNameResolver8616,
    segment_name: RegisterNameResolver8616,
) -> None:
    """Invalidate a stack destination and record proven stack value copies."""
    destination_slot = (
        _scan_stack_slot_8616(
            instruction, operands[0], register_name=register_name, segment_name=segment_name
        )
        if operands
        else None
    )
    if destination_slot is None:
        return
    destination_offset, destination_width = destination_slot
    _forget_stack_value_sources_8616(
        destination_offset,
        destination_width,
        state.stack_value_sources,
    )
    if instruction.instruction_id == X86_INS_MOV and len(operands) == 2 and operands[1].kind == X86_OP_REG:
        source_name = register_name(instruction.raw, operands[1].register)
        copied_source = state.stack_indices.get(source_name) if source_name is not None else None
        if copied_source is not None:
            source_offset, source_width, source_shift = copied_source
            if source_shift == 0 and source_width == destination_width:
                state.stack_value_sources[destination_offset] = FarPointerStackValueSource8616(
                    source_offset,
                    source_width,
                )


def _apply_mov_register_copy_8616(
    state: _FarPointerScanState8616,
    instruction: InstructionView8616,
    operands: tuple[OperandView8616, ...],
    *,
    register_name: RegisterNameResolver8616,
    segment_name: RegisterNameResolver8616,
) -> bool:
    """Track one MOV into a register; return True when it was handled."""
    if instruction.instruction_id != X86_INS_MOV or len(operands) != 2 or operands[0].kind != X86_OP_REG:
        return False
    destination = register_name(instruction.raw, operands[0].register)
    source_operand = operands[1]
    copied_stack = None
    copied_far = None
    if source_operand.kind == X86_OP_REG:
        source_name = register_name(instruction.raw, source_operand.register)
        copied_stack = state.stack_indices.get(source_name) if source_name is not None else None
        copied_far = state.far_offsets.get(source_name) if source_name is not None else None
    stack_slot = _scan_stack_slot_8616(
        instruction, source_operand, register_name=register_name, segment_name=segment_name
    )
    if destination is not None:
        _forget_register_8616(destination, state.stack_indices, state.far_offsets)
        if copied_stack is not None:
            state.stack_indices[destination] = copied_stack
        elif stack_slot is not None and stack_slot[1] in {1, 2}:
            state.stack_indices[destination] = (stack_slot[0], stack_slot[1], 0)
        if copied_far is not None:
            state.far_offsets[destination] = copied_far
        with contextlib.suppress(ValueError):
            state.segment_sources.pop(FarPointerSegmentRegister8616(destination), None)
    return True


def _apply_shift_index_8616(
    state: _FarPointerScanState8616,
    instruction: InstructionView8616,
    operands: tuple[OperandView8616, ...],
    register_name: RegisterNameResolver8616,
) -> bool:
    """Track one SHL/SAL index update; return True when it was handled."""
    if instruction.instruction_id not in {X86_INS_SHL, X86_INS_SAL} or len(operands) != 2:
        return False
    destination = register_name(instruction.raw, operands[0].register) if operands[0].kind == X86_OP_REG else None
    amount = operands[1].immediate
    previous = state.stack_indices.get(destination) if destination is not None else None
    if destination is not None:
        _forget_register_8616(destination, state.stack_indices, state.far_offsets)
        if previous is not None and isinstance(amount, int):
            offset, width, old_shift = previous
            if 0 <= old_shift + int(amount) <= 4:
                state.stack_indices[destination] = (offset, width, old_shift + int(amount))
    return True


def _invalidate_register_destination_8616(
    state: _FarPointerScanState8616,
    instruction: InstructionView8616,
    operands: tuple[OperandView8616, ...],
    register_name: RegisterNameResolver8616,
) -> None:
    """Forget tracking for any other instruction that clobbers a register."""
    if operands and operands[0].kind == X86_OP_REG:
        destination = register_name(instruction.raw, operands[0].register)
        if destination is not None:
            _forget_register_8616(destination, state.stack_indices, state.far_offsets)
            with contextlib.suppress(ValueError):
                state.segment_sources.pop(FarPointerSegmentRegister8616(destination), None)


def recover_far_pointer_segmented_loads_8616(
    instructions: tuple[InstructionView8616, ...],
    *,
    register_name: RegisterNameResolver8616,
    segment_name: RegisterNameResolver8616,
) -> tuple[FarPointerSegmentedLoadEvidence8616, ...]:
    """Recover exact same-block loads through LES/LDS stack far pointers."""
    state = _FarPointerScanState8616()
    constant_state = FarPointerConstantState8616()
    recovered: list[FarPointerSegmentedLoadEvidence8616] = []
    for instruction in instructions:
        evidence = _segmented_load_evidence_8616(
            instruction,
            state.stack_indices,
            state.far_offsets,
            state.segment_sources,
            register_name=register_name,
            segment_name=segment_name,
        )
        if evidence is not None:
            recovered.append(evidence)
        operands = instruction.operands
        apply_far_pointer_constant_instruction_8616(
            constant_state,
            instruction,
            register_name=register_name,
            stack_slot=lambda current_instruction, operand: _scan_stack_slot_8616(
                current_instruction,
                operand,
                register_name=register_name,
                segment_name=segment_name,
            ),
        )
        if _apply_far_pointer_load_8616(
            state, constant_state, instruction, operands,
            register_name=register_name, segment_name=segment_name,
        ):
            continue
        _update_stack_slot_target_8616(
            state, instruction, operands,
            register_name=register_name, segment_name=segment_name,
        )
        if _apply_mov_register_copy_8616(
            state, instruction, operands,
            register_name=register_name, segment_name=segment_name,
        ):
            continue
        if _apply_shift_index_8616(state, instruction, operands, register_name):
            continue
        _invalidate_register_destination_8616(state, instruction, operands, register_name)
    return tuple(dict.fromkeys(recovered))