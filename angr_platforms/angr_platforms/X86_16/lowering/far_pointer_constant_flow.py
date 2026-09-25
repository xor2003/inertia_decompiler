"""Track exact constants feeding stack-resident far-pointer offsets.

Layer: Types/Lowering.
Responsibility: retain only same-basic-block register constants and their exact
BP-relative stack stores for far-pointer evidence collection. Every overlapping
or unknown write invalidates the affected value. This module consumes decoded
instruction structure and never reads assembly text, source, or sidecars.

Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from capstone.x86_const import (
    X86_INS_ADD,
    X86_INS_MOV,
    X86_INS_SAL,
    X86_INS_SHL,
    X86_INS_SUB,
    X86_OP_IMM,
    X86_OP_REG,
)

from .register_constant_segmented_store import (
    InstructionView8616,
    OperandView8616,
    RegisterNameResolver8616,
)

type StackSlotResolver8616 = Callable[[InstructionView8616, OperandView8616], tuple[int, int] | None]
type _ConstantValue8616 = tuple[int, int]

__all__ = [
    "FarPointerConstantState8616",
    "StackSlotResolver8616",
    "apply_far_pointer_constant_instruction_8616",
]

_REGISTER_ALIAS_GROUPS_8616 = (
    frozenset(("al", "ah", "ax", "eax")),
    frozenset(("bl", "bh", "bx", "ebx")),
    frozenset(("cl", "ch", "cx", "ecx")),
    frozenset(("dl", "dh", "dx", "edx")),
)


def _register_aliases_8616(register_name: str) -> frozenset[str]:
    """Return every architectural register view overlapping one name."""
    for aliases in _REGISTER_ALIAS_GROUPS_8616:
        if register_name in aliases:
            return aliases
    return frozenset((register_name,))


def _normalized_constant_8616(value: int, width: int) -> int:
    """Apply the architectural write width to one exact integer value."""
    return value & ((1 << (width * 8)) - 1)


@dataclass(slots=True)
class FarPointerConstantState8616:
    """Exact same-block register and BP-stack constant state."""

    register_values: dict[str, _ConstantValue8616] = field(default_factory=dict)
    stack_values: dict[int, _ConstantValue8616] = field(default_factory=dict)

    def forget_register(self, register_name: str) -> None:
        """Invalidate all aliases overlapping one written register."""
        for alias in _register_aliases_8616(register_name):
            self.register_values.pop(alias, None)

    def forget_stack_range(self, offset: int, width: int) -> None:
        """Invalidate every tracked stack constant overlapping one write."""
        write_end = offset + width
        for destination, (_value, source_width) in tuple(self.stack_values.items()):
            if destination < write_end and offset < destination + source_width:
                self.stack_values.pop(destination, None)

    def stack_constant(self, offset: int, width: int) -> int | None:
        """Return one exact stack constant only at the requested width."""
        value = self.stack_values.get(offset)
        return value[0] if value is not None and value[1] == width else None

    def set_register(self, register_name: str, value: int, width: int) -> None:
        """Publish one exact register value after invalidating aliases."""
        self.forget_register(register_name)
        self.register_values[register_name] = (
            _normalized_constant_8616(value, width),
            width,
        )


def apply_far_pointer_constant_instruction_8616(
    state: FarPointerConstantState8616,
    instruction: InstructionView8616,
    *,
    register_name: RegisterNameResolver8616,
    stack_slot: StackSlotResolver8616,
) -> None:
    """Advance exact constant state across one decoded instruction."""
    operands = instruction.operands
    destination_slot = stack_slot(instruction, operands[0]) if operands else None
    if destination_slot is not None:
        _apply_stack_store_8616(state, instruction, operands, destination_slot, register_name)
        return

    if operands and operands[0].kind != X86_OP_REG:
        if operands[0].memory is not None:
            state.stack_values.clear()
        return

    if not operands or operands[0].kind != X86_OP_REG:
        return
    destination = register_name(instruction.raw, operands[0].register)
    width = operands[0].size
    if destination is None:
        return
    if width not in {1, 2, 4}:
        state.forget_register(destination)
        return
    width = int(width)

    if _apply_register_mov_8616(
        state, instruction, operands, destination, width, register_name, stack_slot
    ):
        return
    if _apply_register_arithmetic_8616(
        state, instruction, operands, destination, width, register_name
    ):
        return
    state.forget_register(destination)


def _apply_stack_store_8616(
    state: FarPointerConstantState8616,
    instruction: InstructionView8616,
    operands: Sequence[OperandView8616],
    destination_slot: tuple[int, int],
    register_name: RegisterNameResolver8616,
) -> None:
    """Apply one proven BP-stack write, retaining only exact MOV sources."""
    destination_offset, destination_width = destination_slot
    state.forget_stack_range(destination_offset, destination_width)
    if instruction.instruction_id == X86_INS_MOV and len(operands) == 2:
        source = operands[1]
        source_name = (
            register_name(instruction.raw, source.register)
            if source.kind == X86_OP_REG
            else None
        )
        source_value = state.register_values.get(source_name) if source_name is not None else None
        if source_value is not None and source_value[1] == destination_width:
            state.stack_values[destination_offset] = source_value


def _mov_source_value_8616(
    state: FarPointerConstantState8616,
    instruction: InstructionView8616,
    source: OperandView8616,
    width: int,
    register_name: RegisterNameResolver8616,
    stack_slot: StackSlotResolver8616,
) -> _ConstantValue8616 | None:
    """Resolve one MOV source to an exact constant only at matching width."""
    if source.kind == X86_OP_IMM and isinstance(source.immediate, int):
        return (_normalized_constant_8616(source.immediate, width), width)
    if source.kind == X86_OP_REG:
        source_name = register_name(instruction.raw, source.register)
        candidate = state.register_values.get(source_name) if source_name is not None else None
        if candidate is not None and candidate[1] == width:
            return candidate
        return None
    source_slot = stack_slot(instruction, source)
    if source_slot is not None:
        candidate = state.stack_values.get(source_slot[0])
        if candidate is not None and candidate[1] == width == source_slot[1]:
            return candidate
    return None


def _apply_register_mov_8616(
    state: FarPointerConstantState8616,
    instruction: InstructionView8616,
    operands: Sequence[OperandView8616],
    destination: str,
    width: int,
    register_name: RegisterNameResolver8616,
    stack_slot: StackSlotResolver8616,
) -> bool:
    """Track one register-destination MOV; return True only for a MOV shape."""
    if instruction.instruction_id != X86_INS_MOV or len(operands) != 2:
        return False
    value = _mov_source_value_8616(
        state, instruction, operands[1], width, register_name, stack_slot
    )
    state.forget_register(destination)
    if value is not None:
        state.register_values[destination] = value
    return True


def _apply_register_arithmetic_8616(
    state: FarPointerConstantState8616,
    instruction: InstructionView8616,
    operands: Sequence[OperandView8616],
    destination: str,
    width: int,
    register_name: RegisterNameResolver8616,
) -> bool:
    """Track proven SUB-self, ADD/SUB-immediate, and SHL/SAL-immediate updates."""
    if instruction.instruction_id == X86_INS_SUB and len(operands) == 2 and operands[1].kind == X86_OP_REG:
        source_register_name = register_name(instruction.raw, operands[1].register)
        if source_register_name == destination:
            state.set_register(destination, 0, width)
            return True

    if instruction.instruction_id in {X86_INS_ADD, X86_INS_SUB} and len(operands) == 2:
        immediate = operands[1].immediate if operands[1].kind == X86_OP_IMM else None
        previous = state.register_values.get(destination)
        if isinstance(immediate, int) and previous is not None and previous[1] == width:
            delta = immediate if instruction.instruction_id == X86_INS_ADD else -immediate
            state.set_register(destination, previous[0] + delta, width)
            return True

    if instruction.instruction_id in {X86_INS_SHL, X86_INS_SAL} and len(operands) == 2:
        amount = operands[1].immediate if operands[1].kind == X86_OP_IMM else None
        previous = state.register_values.get(destination)
        if isinstance(amount, int) and previous is not None and previous[1] == width:
            state.set_register(destination, previous[0] << amount, width)
            return True

    return False
