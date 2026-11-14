# cython: language_level=3, infer_types=True
"""Recover exact storage facts for direct multi-register call results.

Layer: Semantics.
Responsibility: classify immediate direct calls whose AX:DX result is stored
immediately into adjacent words in one proven DS object. This module emits
typed facts only; Widening owns object extent and Lowering owns C materialization.
Do not infer storage from names, sidecars, assembly text, or rendered C.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

from capstone.x86_const import (
    X86_INS_CALL,
    X86_INS_LCALL,
    X86_INS_MOV,
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_AX,
    X86_REG_DS,
    X86_REG_DX,
)
import dataclasses
import operator


class DirectCallResultMemoryView8616(Protocol):
    """Typed memory fields required from a decoded operand snapshot."""

    @property
    def segment(self) -> int | None:
        """Return the explicit segment register ID, or zero for the default."""
        ...

    @property
    def base(self) -> int | None:
        """Return the base register ID, or zero for direct addressing."""
        ...

    @property
    def index(self) -> int | None:
        """Return the index register ID, or zero for direct addressing."""
        ...

    @property
    def displacement(self) -> int | None:
        """Return the decoded memory displacement."""
        ...


class DirectCallResultOperandView8616(Protocol):
    """Typed operand fields required by direct result-store recovery."""

    @property
    def kind(self) -> int | None:
        """Return the decoded Capstone operand kind."""
        ...

    @property
    def register(self) -> int | None:
        """Return the decoded register ID."""
        ...

    @property
    def size(self) -> int | None:
        """Return the operand width in bytes."""
        ...

    @property
    def immediate(self) -> int | None:
        """Return the decoded immediate value."""
        ...

    @property
    def memory(self) -> DirectCallResultMemoryView8616 | None:
        """Return the decoded memory operand view."""
        ...


class DirectCallResultInstructionView8616(Protocol):
    """Typed instruction fields required by direct result-store recovery."""

    @property
    def instruction_id(self) -> int | None:
        """Return the decoded Capstone instruction ID."""
        ...

    @property
    def address(self) -> int | None:
        """Return the instruction address."""
        ...

    @property
    def operands(self) -> object:
        """Return immutable decoded operand snapshots."""
        ...


@dataclasses.dataclass(frozen=True, )
class DirectCallResultStorageFact8616:
    """Proof that one direct call result occupies a four-byte DS object."""

    offset: cython.longlong
    width: cython.longlong
    source_call_target: cython.longlong
    source_call_ins_addr: cython.longlong
    low_store_ins_addr: cython.longlong
    high_store_ins_addr: cython.longlong


@cython.ccall
def _direct_call_target_8616(instruction: DirectCallResultInstructionView8616) -> int | None:
    """Return an exact immediate target for one direct call instruction."""
    if instruction.instruction_id not in {X86_INS_CALL, X86_INS_LCALL} or not instruction.operands:
        return None
    target = instruction.operands[0]
    return target.immediate if operator.eq(target.kind, X86_OP_IMM) and isinstance(target.immediate, int) else None


@cython.ccall
def _flat_memory_8616(memory: object) -> cython.bint:
    """Return whether the memory operand is a flat DS/absolute address."""
    return (
        memory is not None
        and memory.segment in {None, 0, X86_REG_DS}
        and memory.base in {None, 0}
        and memory.index in {None, 0}
        and isinstance(memory.displacement, int)
    )


@cython.ccall
def _direct_ds_word_store_8616(
    instruction: DirectCallResultInstructionView8616,
    source_register: cython.longlong,
) -> int | None:
    """Return the exact DS offset stored from one required word register."""
    memory: object
    if operator.ne(instruction.instruction_id, X86_INS_MOV) or len(instruction.operands) < 2:
        return None
    destination, source = tuple(instruction.operands[:2])
    memory = destination.memory
    if operator.ne(destination.kind, X86_OP_MEM) or destination.size != 2 or not _flat_memory_8616(memory):
        return None
    if operator.ne(source.kind, X86_OP_REG) or operator.ne(source.register, source_register) or source.size != 2:
        return None
    assert memory is not None and isinstance(memory.displacement, int)
    return memory.displacement & 0xFFFF


@cython.ccall
def _ordered_int_addresses_8616(
    call: DirectCallResultInstructionView8616,
    low_store: DirectCallResultInstructionView8616,
    high_store: DirectCallResultInstructionView8616,
) -> cython.bint:
    """Return whether the three sites carry strictly ordered int addresses."""
    return (
        isinstance(call.address, int)
        and isinstance(low_store.address, int)
        and isinstance(high_store.address, int)
        and call.address < low_store.address < high_store.address
    )


@cython.ccall
def recover_direct_call_result_storage_facts_8616(
    instructions: Iterable[DirectCallResultInstructionView8616],
) -> tuple[DirectCallResultStorageFact8616, ...]:
    """Classify adjacent CALL, DS:[base]=AX, DS:[base+2]=DX sequences."""
    high_offset: object
    low_offset: object
    target: object
    call: object
    high_store: object
    low_store: object
    ordered = tuple(instructions)
    facts: list[DirectCallResultStorageFact8616] = []
    for call, low_store, high_store in zip(ordered, ordered[1:], ordered[2:], strict=False):
        target = _direct_call_target_8616(call)
        low_offset = _direct_ds_word_store_8616(low_store, X86_REG_AX)
        high_offset = _direct_ds_word_store_8616(high_store, X86_REG_DX)
        if (
            target is None
            or low_offset is None
            or high_offset is None
            or operator.ne(((low_offset + 2) & 0xFFFF), high_offset)
            or not _ordered_int_addresses_8616(call, low_store, high_store)
        ):
            continue
        assert isinstance(call.address, int)
        assert isinstance(low_store.address, int)
        assert isinstance(high_store.address, int)
        facts.append(
            DirectCallResultStorageFact8616(
                offset=low_offset,
                width=4,
                source_call_target=target,
                source_call_ins_addr=call.address,
                low_store_ins_addr=low_store.address,
                high_store_ins_addr=high_store.address,
            )
        )
    return tuple(dict.fromkeys(facts))


__all__ = [
    "DirectCallResultInstructionView8616",
    "DirectCallResultMemoryView8616",
    "DirectCallResultOperandView8616",
    "DirectCallResultStorageFact8616",
    "recover_direct_call_result_storage_facts_8616",
]
