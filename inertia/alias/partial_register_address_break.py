"""Prove that a partial register write breaks whole-address provenance.

Layer: Alias.
Responsibility: retain exact decoded-instruction evidence that an immediate
byte write is the latest write to a word register before that word is pushed.
This proves the pushed value is not an unchanged Alias-derived stack address;
it does not claim that the unknown full word equals the byte immediate.
Owns storage identity.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, cast

from capstone.x86_const import (
    X86_INS_CALL,
    X86_INS_IRET,
    X86_INS_LCALL,
    X86_INS_MOV,
    X86_INS_PUSH,
    X86_INS_RET,
    X86_INS_RETF,
    X86_OP_IMM,
    X86_OP_REG,
)

from .domains import FULL16, register_domain_for_name, register_view_for_name

__all__ = [
    "PartialRegisterAddressBreakEvidence8616",
    "collect_partial_register_address_break_8616",
]

_BOUNDARY_IDS_8616 = frozenset(
    {X86_INS_CALL, X86_INS_IRET, X86_INS_LCALL, X86_INS_RET, X86_INS_RETF}
)


class _Operand8616(Protocol):
    """Typed fields read from one dynamic Capstone x86 operand."""

    type: int
    reg: int
    imm: int


class _Instruction8616(Protocol):
    """Typed decoded-instruction boundary needed by this Alias proof."""

    address: int
    id: int
    operands: Sequence[_Operand8616]

    def reg_name(self, reg_id: int) -> str:
        """Return the decoded name for one register id."""
        ...

    def regs_access(self) -> tuple[list[int], list[int]]:
        """Return registers read and written by this instruction."""
        ...


class _InstructionWrapper8616(Protocol):
    """Typed angr wrapper around one decoded Capstone instruction."""

    insn: _Instruction8616


@dataclass(frozen=True, slots=True)
class PartialRegisterAddressBreakEvidence8616:
    """One exact partial write that destroys a full register's provenance."""

    push_instruction_addr: int
    definition_instruction_addr: int
    carrier_register: str
    written_register: str
    immediate: int

    @property
    def complete(self) -> bool:
        """Return whether both registers are exact unequal views of one domain."""
        carrier_domain = register_domain_for_name(self.carrier_register)
        written_domain = register_domain_for_name(self.written_register)
        written_view = register_view_for_name(self.written_register)
        return bool(
            self.definition_instruction_addr >= 0
            and self.definition_instruction_addr < self.push_instruction_addr
            and carrier_domain is not None
            and carrier_domain == written_domain
            and register_view_for_name(self.carrier_register) == FULL16
            and written_view is not None
            and written_view != FULL16
            and type(self.immediate) is int
        )


def _decoded_instruction_8616(candidate: object) -> _Instruction8616:
    """Unwrap angr's Capstone wrapper at the dynamic frontend boundary."""
    try:
        return cast(_InstructionWrapper8616, candidate).insn
    except AttributeError:
        return cast(_Instruction8616, candidate)


def _written_register_names_8616(instruction: _Instruction8616) -> tuple[str, ...]:
    """Return exact decoded register writes, with an operand fallback."""
    try:
        _read_ids, written_ids = instruction.regs_access()
        return tuple(instruction.reg_name(reg_id).lower() for reg_id in written_ids)
    except (AttributeError, TypeError, ValueError):
        operands = tuple(instruction.operands)
        if not operands or operands[0].type != X86_OP_REG:
            return ()
        return (instruction.reg_name(operands[0].reg).lower(),)


def collect_partial_register_address_break_8616(
    instructions: Sequence[object],
    push_instruction_addr: int,
) -> PartialRegisterAddressBreakEvidence8616 | None:
    """Prove the latest carrier write is one exact partial immediate MOV."""
    decoded = tuple(_decoded_instruction_8616(item) for item in instructions)
    try:
        decoded_surface = tuple(
            (instruction.address, instruction.id, tuple(instruction.operands))
            for instruction in decoded
        )
    except (AttributeError, TypeError):
        return None
    if any(
        not isinstance(address, int) or not isinstance(instruction_id, int)
        for address, instruction_id, _operands in decoded_surface
    ):
        return None
    push_indexes = tuple(
        index
        for index, instruction in enumerate(decoded)
        if instruction.address == push_instruction_addr
    )
    if len(push_indexes) != 1:
        return None
    push_index = push_indexes[0]
    push = decoded[push_index]
    push_operands = tuple(push.operands)
    if push.id != X86_INS_PUSH or len(push_operands) != 1 or push_operands[0].type != X86_OP_REG:
        return None
    carrier_register = push.reg_name(push_operands[0].reg).lower()
    carrier_domain = register_domain_for_name(carrier_register)
    if carrier_domain is None or register_view_for_name(carrier_register) != FULL16:
        return None

    for instruction in reversed(decoded[max(0, push_index - 8) : push_index]):
        if instruction.id in _BOUNDARY_IDS_8616:
            return None
        written_names = _written_register_names_8616(instruction)
        domain_writes = tuple(
            name for name in written_names if register_domain_for_name(name) == carrier_domain
        )
        if not domain_writes:
            continue
        operands = tuple(instruction.operands)
        if (
            instruction.id != X86_INS_MOV
            or len(operands) != 2
            or operands[0].type != X86_OP_REG
            or operands[1].type != X86_OP_IMM
        ):
            return None
        written_register = instruction.reg_name(operands[0].reg).lower()
        evidence = PartialRegisterAddressBreakEvidence8616(
            push_instruction_addr=push_instruction_addr,
            definition_instruction_addr=instruction.address,
            carrier_register=carrier_register,
            written_register=written_register,
            immediate=int(operands[1].imm),
        )
        return evidence if evidence.complete else None
    return None
