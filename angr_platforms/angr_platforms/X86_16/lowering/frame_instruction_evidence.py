"""Prove canonical x86-16 BP-frame instruction sequences.

Layer: Types/Lowering.
Responsibility: classify decoded ``push bp; mov bp, sp`` entry evidence and
contiguous ``mov sp, bp; pop bp; ret`` teardown evidence by exact operands.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Do not inspect rendered assembly or C text and do not mutate structured C.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol, cast

from capstone.x86_const import (
    X86_INS_MOV,
    X86_INS_POP,
    X86_INS_PUSH,
    X86_INS_RET,
    X86_OP_REG,
    X86_REG_BP,
    X86_REG_SP,
)


class _CapstoneOperand8616(Protocol):
    """Capstone register operand fields consumed by frame classification."""

    type: int
    reg: int


class _CapstoneInstruction8616(Protocol):
    """Capstone instruction fields consumed by frame classification."""

    address: int
    id: int
    operands: Sequence[_CapstoneOperand8616]
    size: int


class _CapstoneWrapper8616(Protocol):
    """angr wrapper field exposing the underlying Capstone instruction."""

    insn: _CapstoneInstruction8616


def _instruction_8616(value: object) -> _CapstoneInstruction8616:
    """Unwrap one angr Capstone wrapper at the third-party boundary."""
    wrapper = cast(_CapstoneWrapper8616, value)
    try:
        return wrapper.insn
    except AttributeError:
        return cast(_CapstoneInstruction8616, value)


def _instruction_registers_8616(value: object) -> tuple[int, ...] | None:
    """Return exact register operands for one decoded instruction."""
    instruction = _instruction_8616(value)
    try:
        operands = tuple(instruction.operands)
    except (AttributeError, TypeError):
        return None
    if any(operand.type != X86_OP_REG for operand in operands):
        return None
    return tuple(int(operand.reg) for operand in operands)


def _instruction_end_8616(value: object) -> int | None:
    """Return the exclusive address of one decoded instruction."""
    instruction = _instruction_8616(value)
    try:
        address = instruction.address
        size = instruction.size
    except AttributeError:
        return None
    return address + size if isinstance(address, int) and isinstance(size, int) and size > 0 else None


def _entry_setup_end_8616(
    instructions_by_addr: Mapping[int, object],
    function_addr: int,
) -> int | None:
    """Prove the mandatory ``push bp; mov bp, sp`` entry; return setup end."""
    push = _instruction_8616(instructions_by_addr.get(function_addr))
    try:
        push_id = push.id
    except AttributeError:
        return None
    push_end = _instruction_end_8616(push)
    if (
        push_id != X86_INS_PUSH
        or _instruction_registers_8616(push) != (X86_REG_BP,)
        or push_end is None
    ):
        return None
    frame_setup = _instruction_8616(instructions_by_addr.get(push_end))
    try:
        setup_id = frame_setup.id
    except AttributeError:
        return None
    if setup_id != X86_INS_MOV or _instruction_registers_8616(frame_setup) != (
        X86_REG_BP,
        X86_REG_SP,
    ):
        return None
    return push_end


def _teardown_sequence_8616(
    instructions_by_addr: Mapping[int, object],
    raw_instruction: object,
) -> tuple[int, int] | None:
    """Return ``(pop_addr, ret_addr)`` for a contiguous teardown or None."""
    instruction = _instruction_8616(raw_instruction)
    try:
        instruction_id = instruction.id
    except AttributeError:
        return None
    if instruction_id != X86_INS_MOV or _instruction_registers_8616(instruction) != (
        X86_REG_SP,
        X86_REG_BP,
    ):
        return None
    pop_addr = _instruction_end_8616(instruction)
    if pop_addr is None:
        return None
    pop = _instruction_8616(instructions_by_addr.get(pop_addr))
    try:
        pop_id = pop.id
    except AttributeError:
        return None
    if pop_id != X86_INS_POP or _instruction_registers_8616(pop) != (X86_REG_BP,):
        return None
    ret_addr = _instruction_end_8616(pop)
    if ret_addr is None:
        return None
    ret = _instruction_8616(instructions_by_addr.get(ret_addr))
    try:
        ret_id = ret.id
    except AttributeError:
        return None
    if ret_id != X86_INS_RET:
        return None
    return pop_addr, ret_addr


def canonical_frame_instruction_addresses_8616(
    instructions_by_addr: Mapping[int, object],
    function_addr: int,
) -> frozenset[int]:
    """Return exact decoded entry and teardown addresses for a BP frame.

    The entry pair is mandatory. Teardown addresses are admitted only as a
    contiguous ``mov sp, bp; pop bp; ret`` sequence. Callers must separately
    prove that structured C contains a matching push or setup carrier before
    pruning.
    """
    push_end = _entry_setup_end_8616(instructions_by_addr, function_addr)
    if push_end is None:
        return frozenset()

    addresses = {function_addr, push_end}
    for address, raw_instruction in instructions_by_addr.items():
        teardown = _teardown_sequence_8616(
            instructions_by_addr, _instruction_8616(raw_instruction)
        )
        if teardown is not None:
            pop_addr, ret_addr = teardown
            addresses.update((address, pop_addr, ret_addr))
    return frozenset(addresses)


__all__ = ["canonical_frame_instruction_addresses_8616"]
