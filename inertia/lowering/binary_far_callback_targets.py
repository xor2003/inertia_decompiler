# cython: language_level=3, infer_types=True
"""Prove far callback code identities from a loaded DOS image and callee ABI.

Layer: Types/Lowering.
Responsibility: validate a caller-proven segment:offset Value against one exact
DOS MZ image entry, closed decoded control flow, and a callee-owned far-pointer
parameter fact. This does not prove the caller's Value or four-byte Alias object.
Unknown, open, or near-return bodies remain typed refusals.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, cast

from capstone import CS_ARCH_X86, CS_GRP_INT, CS_GRP_JUMP, CS_MODE_16, Cs, CsError, CsInsn
from capstone.x86_const import (
    X86_INS_HLT,
    X86_INS_IRET,
    X86_INS_JMP,
    X86_INS_MOV,
    X86_INS_PUSH,
    X86_INS_RET,
    X86_INS_RETF,
    X86_OP_IMM,
    X86_OP_REG,
    X86_REG_BP,
    X86_REG_SP,
)

from inertia.frontend.x86_16.load_dos_mz import DOSMZ

from .function_pointer_parameter_evidence import FunctionPointerParameterFact8616
import dataclasses
import operator

_MAX_FUNCTION_BYTES_8616: cython.longlong = 256
_MAX_FUNCTION_INSTRUCTIONS_8616: cython.longlong = 128


class BinaryFarCallbackTargetStatus8616(StrEnum):
    """Typed outcome of one source-free far callback target check."""

    PROVEN = "proven"
    INVALID_POINTER_ABI = "invalid_pointer_abi"
    INVALID_FAR_ADDRESS = "invalid_far_address"
    NO_LOADED_IMAGE = "no_loaded_image"
    NO_CODE_ENTRY = "no_code_entry"
    OPEN_DECODE = "open_decode"
    NON_FAR_RETURN = "non_far_return"


@dataclasses.dataclass(frozen=True, )
class BinaryFarCallbackTargetProof8616:
    """Exact far function identity with decoded exits and callee-owned ABI."""

    addr: cython.longlong
    name: object
    segment: cython.longlong
    offset: cython.longlong
    far_return_addrs: object
    decoded_insn_addrs: object
    parameter_fact: FunctionPointerParameterFact8616


@cython.ccall
def _ordered_unique_addresses_8616(addresses: object) -> cython.bint:
    """Check that durable decoded addresses have one canonical ordering."""
    return bool(addresses) and operator.eq(addresses, tuple(sorted(tuple(set(addresses)))))


@cython.ccall
def _proof_matches_result_8616(
    proof: BinaryFarCallbackTargetProof8616,
    segment: cython.longlong,
    offset: cython.longlong,
    address: object,
) -> cython.bint:
    """Keep a published code identity, ABI, and decoded exits coherent."""
    if address is None or not (0 <= segment <= 0xFFFF and 0 <= offset <= 0xFFFF):
        return False
    if operator.ne(address, segment * 16 + offset) or address > 0xFFFFF:
        return False
    identity_matches = (
        operator.eq(proof.addr, address)
        and operator.eq(proof.segment, segment)
        and operator.eq(proof.offset, offset)
        and proof.name == f"sub_{address:x}"
        and proof.parameter_fact.pointer_width == 4
    )
    if not identity_matches:
        return False
    returns = proof.far_return_addrs
    decoded = proof.decoded_insn_addrs
    if not _ordered_unique_addresses_8616(returns) or not _ordered_unique_addresses_8616(decoded):
        return False
    return (
        operator.eq(decoded[0], address)
        and decoded[-1] < address + _MAX_FUNCTION_BYTES_8616
        and set(returns).issubset(decoded)
    )


@dataclasses.dataclass(frozen=True, )
class BinaryFarCallbackTargetResult8616:
    """Closed single-target census that never publishes an unproved symbol."""

    status: BinaryFarCallbackTargetStatus8616
    segment: cython.longlong
    offset: cython.longlong
    addr: int | None = None
    proof: BinaryFarCallbackTargetProof8616 | None = None
    raw_fact_count: cython.longlong = 1
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 1

    @property
    def complete(self) -> cython.bint:
        """Require verdict-specific counters and matching durable proof fields."""
        if type(self.status) is not BinaryFarCallbackTargetStatus8616:
            return False
        counts = (
            self.raw_fact_count,
            self.normalized_fact_count,
            self.classified_fact_count,
            self.materialized_count,
            self.failure_count,
        )
        if self.status is BinaryFarCallbackTargetStatus8616.PROVEN:
            return (
                counts == (1, 1, 1, 1, 0)
                and self.proof is not None
                and _proof_matches_result_8616(self.proof, self.segment, self.offset, self.addr)
            )
        if self.status in {
            BinaryFarCallbackTargetStatus8616.INVALID_POINTER_ABI,
            BinaryFarCallbackTargetStatus8616.INVALID_FAR_ADDRESS,
            BinaryFarCallbackTargetStatus8616.NO_LOADED_IMAGE,
        }:
            return counts == (1, 0, 0, 0, 1) and self.addr is None and self.proof is None
        return (
            counts == (1, 1, 0, 0, 1)
            and self.proof is None
            and self.addr is not None
            and operator.eq(self.addr, self.segment * 16 + self.offset)
        )


@cython.ccall
def _loaded_dos_address_8616(project: object, segment: cython.longlong, offset: cython.longlong) -> int | None:
    """Resolve a non-wrapping far pair inside the exact relocated MZ image."""
    main = cast(Any, project).loader.main_object
    if not isinstance(main, DOSMZ):
        return None
    if type(segment) is not int or type(offset) is not int:
        return None
    if not (0 <= segment <= 0xFFFF and 0 <= offset <= 0xFFFF):
        return None
    image_base = int(main.min_addr)
    image_end = int(main.max_addr)
    load_segment = int(main.mz_load_segment)
    address = segment * 16 + offset
    if not (
        0 <= load_segment <= segment
        and operator.eq(image_base, load_segment * 16)
        and image_base <= address <= image_end
        and address <= 0xFFFFF
    ):
        return None
    return address


@cython.ccall
def _decode_instruction_8616(project: object, decoder: Cs, address: cython.longlong, image_end: cython.longlong) -> CsInsn | None:
    """Decode one image-backed 16-bit instruction without crossing its end."""
    instruction: object
    if address > image_end:
        return None
    byte_count = min(15, image_end - address + 1)
    try:
        data = cast(Any, project).loader.memory.load(address, byte_count)
        instruction = next(decoder.disasm(bytes(data), address, count=1), None)
    except (AttributeError, KeyError, TypeError, ValueError, CsError):
        return None
    if instruction is None or operator.ne(instruction.address, address) or instruction.size < 1:
        return None
    if address + instruction.size - 1 > image_end:
        return None
    return instruction


@cython.ccall
def _bp_frame_entry_8616(first: CsInsn, second: CsInsn) -> cython.bint:
    """Require a positive decoded compiler-style entry witness."""
    if operator.ne(first.id, X86_INS_PUSH) or operator.ne(second.id, X86_INS_MOV):
        return False
    push_operands = tuple(first.operands)
    mov_operands = tuple(second.operands)
    return (
        len(push_operands) == 1
        and operator.eq(push_operands[0].type, X86_OP_REG)
        and operator.eq(push_operands[0].reg, X86_REG_BP)
        and len(mov_operands) == 2
        and operator.eq(mov_operands[0].type, X86_OP_REG)
        and operator.eq(mov_operands[0].reg, X86_REG_BP)
        and operator.eq(mov_operands[1].type, X86_OP_REG)
        and operator.eq(mov_operands[1].reg, X86_REG_SP)
    )


@cython.ccall
def _direct_jump_target_8616(instruction: CsInsn) -> int | None:
    """Retain only an immediate target from a decoded branch operand."""
    operands = tuple(instruction.operands)
    if len(operands) != 1 or operator.ne(operands[0].type, X86_OP_IMM):
        return None
    return int(operands[0].imm)


def _bounded_decoded_instruction_8616(
    project: object,
    decoder: Cs,
    address: cython.longlong,
    entry: cython.longlong,
    image_end: cython.longlong,
    occupied: object,
) -> CsInsn | None:
    """Decode one in-function instruction without accepting overlapping paths."""
    instruction: object
    if not (entry <= address < entry + _MAX_FUNCTION_BYTES_8616):
        return None
    instruction = _decode_instruction_8616(project, decoder, address, image_end)
    if instruction is None:
        return None
    instruction_end = address + instruction.size
    if instruction_end > entry + _MAX_FUNCTION_BYTES_8616:
        return None
    if any(
        byte_addr in occupied and operator.ne(occupied[byte_addr], address)
        for byte_addr in range(address, instruction_end)
    ):
        return None
    for byte_addr in range(address, instruction_end):
        occupied[byte_addr] = address
    return instruction


@cython.ccall
def _decoded_successors_8616(
    instruction: CsInsn,
) -> tuple[BinaryFarCallbackTargetStatus8616 | None, tuple[cython.longlong, ...]]:
    """Classify non-far exits and enumerate every local decoded successor."""
    target: object
    if instruction.id in {X86_INS_RET, X86_INS_IRET}:
        return BinaryFarCallbackTargetStatus8616.NON_FAR_RETURN, ()
    if operator.eq(instruction.id, X86_INS_HLT) or instruction.group(CS_GRP_INT):
        return BinaryFarCallbackTargetStatus8616.OPEN_DECODE, ()
    next_addr = instruction.address + instruction.size
    if instruction.group(CS_GRP_JUMP):
        target = _direct_jump_target_8616(instruction)
        if target is None:
            return BinaryFarCallbackTargetStatus8616.OPEN_DECODE, ()
        if operator.eq(instruction.id, X86_INS_JMP):
            return None, (target,)
        return None, (target, next_addr)
    return None, (next_addr,)


@cython.ccall
def _closed_far_return_cfg_8616(
    project: object, decoder: Cs, entry: cython.longlong, image_end: cython.longlong
) -> tuple[BinaryFarCallbackTargetStatus8616, tuple[cython.longlong, ...], tuple[cython.longlong, ...]]:
    """Follow every decoded local branch until only far returns terminate it."""
    address: object
    instruction: object
    refusal: object
    pending = [entry]
    decoded: dict[cython.longlong, CsInsn] = {}
    occupied: dict[cython.longlong, cython.longlong] = {}
    far_returns: set[cython.longlong] = set()
    while pending:
        address = pending.pop()
        if address in decoded:
            continue
        if len(decoded) >= _MAX_FUNCTION_INSTRUCTIONS_8616:
            return BinaryFarCallbackTargetStatus8616.OPEN_DECODE, (), tuple(sorted(decoded))
        instruction = _bounded_decoded_instruction_8616(
            project, decoder, address, entry, image_end, occupied
        )
        if instruction is None:
            return BinaryFarCallbackTargetStatus8616.OPEN_DECODE, (), tuple(sorted(decoded))
        decoded[address] = instruction
        if operator.eq(instruction.id, X86_INS_RETF):
            far_returns.add(address)
            continue
        refusal, successors = _decoded_successors_8616(instruction)
        if refusal is not None:
            return refusal, (), tuple(sorted(decoded))
        pending.extend(successors)
    if not far_returns:
        return BinaryFarCallbackTargetStatus8616.OPEN_DECODE, (), tuple(sorted(decoded))
    return BinaryFarCallbackTargetStatus8616.PROVEN, tuple(sorted(far_returns)), tuple(sorted(decoded))


@cython.ccall
def prove_binary_far_callback_target_8616(
    project: object,
    *,
    segment: cython.longlong,
    offset: cython.longlong,
    parameter_fact: FunctionPointerParameterFact8616,
) -> BinaryFarCallbackTargetResult8616:
    """Prove one caller-supplied far Value names decoded DOS code of the callee ABI.

    The caller must independently establish the exact segment and offset Value
    on every reaching path. A closed decode here proves only target identity;
    it neither widens caller storage nor rewrites the C call.
    """
    address: object
    first: object
    second: object
    if parameter_fact.pointer_width != 4:
        return BinaryFarCallbackTargetResult8616(
            BinaryFarCallbackTargetStatus8616.INVALID_POINTER_ABI, segment, offset
        )
    try:
        main = cast(Any, project).loader.main_object
    except AttributeError:
        return BinaryFarCallbackTargetResult8616(
            BinaryFarCallbackTargetStatus8616.NO_LOADED_IMAGE, segment, offset
        )
    if not isinstance(main, DOSMZ):
        return BinaryFarCallbackTargetResult8616(
            BinaryFarCallbackTargetStatus8616.NO_LOADED_IMAGE, segment, offset
        )
    address = _loaded_dos_address_8616(project, segment, offset)
    if address is None:
        return BinaryFarCallbackTargetResult8616(
            BinaryFarCallbackTargetStatus8616.INVALID_FAR_ADDRESS, segment, offset
        )
    decoder = Cs(CS_ARCH_X86, CS_MODE_16)
    decoder.detail = True
    first = _decode_instruction_8616(project, decoder, address, int(main.max_addr))
    second = None if first is None else _decode_instruction_8616(
        project, decoder, address + first.size, int(main.max_addr)
    )
    if first is None or second is None or not _bp_frame_entry_8616(first, second):
        return BinaryFarCallbackTargetResult8616(
            BinaryFarCallbackTargetStatus8616.NO_CODE_ENTRY,
            segment,
            offset,
            addr=address,
            normalized_fact_count=1,
        )
    status, far_returns, decoded = _closed_far_return_cfg_8616(
        project, decoder, address, int(main.max_addr)
    )
    if status is not BinaryFarCallbackTargetStatus8616.PROVEN:
        return BinaryFarCallbackTargetResult8616(
            status, segment, offset, addr=address, normalized_fact_count=1
        )
    proof = BinaryFarCallbackTargetProof8616(
        addr=address,
        name=f"sub_{address:x}",
        segment=segment,
        offset=offset,
        far_return_addrs=far_returns,
        decoded_insn_addrs=decoded,
        parameter_fact=parameter_fact,
    )
    return BinaryFarCallbackTargetResult8616(
        BinaryFarCallbackTargetStatus8616.PROVEN,
        segment,
        offset,
        addr=address,
        proof=proof,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
    )


__all__ = [
    "BinaryFarCallbackTargetProof8616",
    "BinaryFarCallbackTargetResult8616",
    "BinaryFarCallbackTargetStatus8616",
    "prove_binary_far_callback_target_8616",
]
