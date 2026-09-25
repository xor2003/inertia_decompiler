"""Recover binary-proven near-pointer arguments and stack-slot versions.

Layer: Types/Lowering.
Responsibility: retain the value version carried from a BP argument load to an
exact register-indirect dereference, including intervening writes to that stack
slot. Consumes alias, widening, and typed facts at the Types/Lowering boundary;
this collector contributes exact decoded-instruction evidence to that contract.
Do not recover semantics from COD, source, assembly, or rendered C text.
An argument indexing a BP-based stack object is a scalar index, not evidence
of a near pointer. LEA computes an address and never proves a dereference.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace
from typing import Protocol, cast

from capstone import CS_AC_WRITE
from capstone.x86_const import (
    X86_INS_ADC,
    X86_INS_ADD,
    X86_INS_AND,
    X86_INS_CALL,
    X86_INS_DEC,
    X86_INS_INC,
    X86_INS_LCALL,
    X86_INS_LEA,
    X86_INS_MOV,
    X86_INS_OR,
    X86_INS_SBB,
    X86_INS_SUB,
    X86_INS_XOR,
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_BP,
    X86_REG_INVALID,
)

from ..function_evidence_inventory import (
    FunctionEvidenceKind8616,
    collect_function_binary_evidence_8616,
)
from .real_mode_linear import (
    _capstone_insns_for_direct_global_update_8616,
    _direct_global_update_blocks_8616,
)

_FALLBACK_MEMORY_WRITE_INSNS_8616 = frozenset(
    {
        X86_INS_ADC,
        X86_INS_ADD,
        X86_INS_AND,
        X86_INS_DEC,
        X86_INS_INC,
        X86_INS_MOV,
        X86_INS_OR,
        X86_INS_SBB,
        X86_INS_SUB,
        X86_INS_XOR,
    }
)


class _MemoryOperandBoundary8616(Protocol):
    """Typed view of Capstone x86 memory operand fields."""

    base: int
    index: int
    disp: int


class _OperandBoundary8616(Protocol):
    """Typed view of one Capstone x86 operand."""

    type: int
    size: int
    reg: int
    imm: int
    access: int
    mem: _MemoryOperandBoundary8616


class _InstructionBoundary8616(Protocol):
    """Typed view of one decoded Capstone instruction."""

    address: int
    id: int
    operands: Sequence[_OperandBoundary8616]

    def reg_name(self, register: int) -> str | None:
        """Return Capstone's architectural name for an explicit register ID."""
        ...


class _InstructionWrapperBoundary8616(Protocol):
    """Typed view of angr's Capstone instruction wrapper."""

    insn: _InstructionBoundary8616


class _CapstoneBlockBoundary8616(Protocol):
    """Typed view of decoded instructions attached to one angr block."""

    insns: Sequence[_InstructionWrapperBoundary8616]


class _BlockBoundary8616(Protocol):
    """Typed view of an angr function block used by fact collection."""

    addr: int
    capstone: _CapstoneBlockBoundary8616


class _FunctionBoundary8616(Protocol):
    """Typed view of an angr function's decoded blocks."""

    blocks: Sequence[_BlockBoundary8616]


@dataclass(frozen=True, slots=True)
class NearPointerArgumentFact8616:
    """Prove pointer use separately from the exact value in its current carrier.

    Missing carrier metadata never authorizes substituting a register with the
    argument. An adjusted carrier still proves pointer use, not value equality.
    """

    stack_offset: int
    carrier_load_ins_addr: int
    dereference_ins_addr: int
    access_width_bytes: int
    source_version_delta: int = 0
    source_update_ins_addrs: tuple[int, ...] = ()
    carrier_register_name: str | None = None
    carrier_value_is_exact: bool = False


@dataclass(frozen=True, slots=True)
class _NearPointerCarrier8616:
    """Current binary value-version state for one pointer carrier register."""

    stack_offset: int
    carrier_load_ins_addr: int
    source_version_delta: int = 0
    source_update_ins_addrs: tuple[int, ...] = ()
    value_is_exact: bool = True


def _direct_bp_stack_operand_8616(operand: _OperandBoundary8616) -> tuple[int, int] | None:
    """Return a positive BP slot and width for one exact memory operand."""
    if (
        operand.type != X86_OP_MEM
        or int(operand.mem.base) != X86_REG_BP
        or int(operand.mem.index) != X86_REG_INVALID
        or int(operand.mem.disp) < 4
    ):
        return None
    return int(operand.mem.disp), int(operand.size)


def _operand_is_written_8616(insn: _InstructionBoundary8616, operand: _OperandBoundary8616) -> bool:
    """Read Capstone write metadata, with a conservative fixture fallback."""
    try:
        return bool(int(operand.access) & CS_AC_WRITE)
    except AttributeError:
        return insn.id in _FALLBACK_MEMORY_WRITE_INSNS_8616


def _direct_stack_write_delta_8616(
    insn: _InstructionBoundary8616,
    operands: tuple[_OperandBoundary8616, ...],
) -> tuple[int, int | None] | None:
    """Classify one direct BP argument write and its exact additive delta."""
    if not operands:
        return None
    slot = _direct_bp_stack_operand_8616(operands[0])
    if slot is None or slot[1] != 2 or not _operand_is_written_8616(insn, operands[0]):
        return None
    offset, _width = slot
    if insn.id == X86_INS_INC:
        return offset, 1
    if insn.id == X86_INS_DEC:
        return offset, -1
    if insn.id in {X86_INS_ADD, X86_INS_SUB} and len(operands) == 2 and operands[1].type == X86_OP_IMM:
        immediate = int(operands[1].imm)
        if -0x8000 <= immediate <= 0xFFFF:
            immediate &= 0xFFFF
            if immediate & 0x8000:
                immediate -= 0x10000
            return offset, immediate if insn.id == X86_INS_ADD else -immediate
    return offset, None


def _unique_memory_carrier_8616(
    operand: _OperandBoundary8616,
    carriers: dict[int, _NearPointerCarrier8616],
) -> tuple[int, _NearPointerCarrier8616] | None:
    """Find a sole argument address carrier outside a BP-based stack object."""
    address_registers = (int(operand.mem.base), int(operand.mem.index))
    if X86_REG_BP in address_registers:
        return None
    carrier_registers = tuple(register for register in address_registers if register in carriers)
    if len(carrier_registers) != 1:
        return None
    register = carrier_registers[0]
    return register, carriers[register]


def _record_pointer_facts_8616(
    insn: _InstructionBoundary8616,
    insn_addr: int,
    operands: tuple[_OperandBoundary8616, ...],
    carriers: dict[int, _NearPointerCarrier8616],
    facts: list[NearPointerArgumentFact8616],
    seen: set[tuple[int, int, int]],
) -> None:
    """Record pointer dereferences proven through one live carrier."""
    for operand in operands:
        if operand.type != X86_OP_MEM or insn.id == X86_INS_LEA:
            continue
        carrier_match = _unique_memory_carrier_8616(operand, carriers)
        if carrier_match is None or int(operand.size) <= 0:
            continue
        register, carrier = carrier_match
        try:
            register_name = insn.reg_name(register)
        except AttributeError:
            register_name = None
        key = (carrier.stack_offset, insn_addr, int(operand.size))
        if key in seen:
            continue
        seen.add(key)
        facts.append(
            NearPointerArgumentFact8616(
                stack_offset=carrier.stack_offset,
                carrier_load_ins_addr=carrier.carrier_load_ins_addr,
                dereference_ins_addr=insn_addr,
                access_width_bytes=int(operand.size),
                source_version_delta=carrier.source_version_delta,
                source_update_ins_addrs=carrier.source_update_ins_addrs,
                carrier_register_name=register_name,
                carrier_value_is_exact=carrier.value_is_exact and register_name is not None,
            )
        )


def _update_carriers_8616(
    insn: _InstructionBoundary8616,
    insn_addr: int,
    operands: tuple[_OperandBoundary8616, ...],
    carriers: dict[int, _NearPointerCarrier8616],
) -> None:
    """Apply one instruction's carrier version, transfer, or invalidation."""
    stack_write = _direct_stack_write_delta_8616(insn, operands)
    if stack_write is not None:
        stack_offset, delta = stack_write
        for register, carrier in tuple(carriers.items()):
            if carrier.stack_offset != stack_offset:
                continue
            if delta is None:
                carriers.pop(register, None)
                continue
            carriers[register] = replace(
                carrier,
                source_version_delta=carrier.source_version_delta + delta,
                source_update_ins_addrs=(*carrier.source_update_ins_addrs, insn_addr),
            )
    if not operands or operands[0].type != X86_OP_REG:
        return
    destination_register = int(operands[0].reg)
    if insn.id == X86_INS_ADD and destination_register in carriers:
        carriers[destination_register] = replace(carriers[destination_register], value_is_exact=False)
        return
    if insn.id != X86_INS_MOV or len(operands) != 2:
        carriers.pop(destination_register, None)
        return
    source = operands[1]
    source_stack_slot = _direct_bp_stack_operand_8616(source)
    if source_stack_slot is not None and source_stack_slot[0] >= 4 and source_stack_slot[1] == 2:
        carriers[destination_register] = _NearPointerCarrier8616(source_stack_slot[0], insn_addr)
        return
    if source.type == X86_OP_REG and int(source.reg) in carriers:
        carriers[destination_register] = carriers[int(source.reg)]
        return
    carriers.pop(destination_register, None)


def _collect_near_pointer_argument_facts_uncached_8616(
    project: object | None,
    function: object,
) -> tuple[NearPointerArgumentFact8616, ...]:
    """Collect BP-argument facts from one decoded binary function surface."""
    if function is None:
        return ()
    if project is not None:
        blocks = _direct_global_update_blocks_8616(project, function)
    else:
        try:
            blocks = tuple(cast(_FunctionBoundary8616, function).blocks)
        except (AttributeError, TypeError):
            return ()
    facts: list[NearPointerArgumentFact8616] = []
    seen: set[tuple[int, int, int]] = set()
    for block in sorted(blocks, key=lambda candidate: int(candidate.addr)):
        carriers: dict[int, _NearPointerCarrier8616] = {}
        wrapped_insns = (
            _capstone_insns_for_direct_global_update_8616(project, block)
            if project is not None
            else tuple(block.capstone.insns)
        )
        for wrapped in wrapped_insns:
            try:
                insn = cast(_InstructionWrapperBoundary8616, wrapped).insn
            except AttributeError:
                insn = cast(_InstructionBoundary8616, wrapped)
            operands = tuple(insn.operands)
            insn_addr = int(insn.address)
            _record_pointer_facts_8616(insn, insn_addr, operands, carriers, facts, seen)
            if insn.id in {X86_INS_CALL, X86_INS_LCALL}:
                carriers.clear()
                continue
            _update_carriers_8616(insn, insn_addr, operands, carriers)
    return tuple(sorted(facts, key=lambda fact: (fact.dereference_ins_addr, fact.stack_offset)))


def collect_near_pointer_argument_facts_8616(
    function: object,
    *,
    project: object | None = None,
) -> tuple[NearPointerArgumentFact8616, ...]:
    """Collect or reuse BP-argument facts for one decoded binary surface."""
    return cast(
        tuple[NearPointerArgumentFact8616, ...],
        collect_function_binary_evidence_8616(
            project,
            function,
            kind=FunctionEvidenceKind8616.NEAR_POINTER_ARGUMENTS,
            builder=_collect_near_pointer_argument_facts_uncached_8616,
        ),
    )
