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

from ..load_dos_mz import DOSMZ
from .function_pointer_parameter_evidence import FunctionPointerParameterFact8616

_MAX_FUNCTION_BYTES_8616: int = 256
_MAX_FUNCTION_INSTRUCTIONS_8616: int = 128


class BinaryFarCallbackTargetStatus8616(StrEnum):
    """Typed outcome of one source-free far callback target check."""

    PROVEN = "proven"
    INVALID_POINTER_ABI = "invalid_pointer_abi"
    INVALID_FAR_ADDRESS = "invalid_far_address"
    NO_LOADED_IMAGE = "no_loaded_image"
    NO_CODE_ENTRY = "no_code_entry"
    OPEN_DECODE = "open_decode"
    NON_FAR_RETURN = "non_far_return"


@dataclass(frozen=True, slots=True)
class BinaryFarCallbackTargetProof8616:
    """Exact far function identity with decoded exits and callee-owned ABI."""

    addr: int
    name: str
    segment: int
    offset: int
    far_return_addrs: tuple[int, ...]
    decoded_insn_addrs: tuple[int, ...]
    parameter_fact: FunctionPointerParameterFact8616


def _ordered_unique_addresses_8616(addresses: tuple[int, ...]) -> bool:
    """Check that durable decoded addresses have one canonical ordering."""
    return bool(addresses) and addresses == tuple(sorted(set(addresses)))


def _proof_matches_result_8616(
    proof: BinaryFarCallbackTargetProof8616,
    segment: int,
    offset: int,
    address: int | None,
) -> bool:
    """Keep a published code identity, ABI, and decoded exits coherent."""
    if address is None or not (0 <= segment <= 0xFFFF and 0 <= offset <= 0xFFFF):
        return False
    if address != segment * 16 + offset or address > 0xFFFFF:
        return False
    identity_matches = (
        proof.addr == address
        and proof.segment == segment
        and proof.offset == offset
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
        decoded[0] == address
        and decoded[-1] < address + _MAX_FUNCTION_BYTES_8616
        and set(returns).issubset(decoded)
    )


@dataclass(frozen=True, slots=True)
class BinaryFarCallbackTargetResult8616:
    """Closed single-target census that never publishes an unproved symbol."""

    status: BinaryFarCallbackTargetStatus8616
    segment: int
    offset: int
    addr: int | None = None
    proof: BinaryFarCallbackTargetProof8616 | None = None
    raw_fact_count: int = 1
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 1

    @property
    def complete(self) -> bool:
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
            and self.addr == self.segment * 16 + self.offset
        )


def _loaded_dos_address_8616(project: object, segment: int, offset: int) -> int | None:
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
        and image_base == load_segment * 16
        and image_base <= address <= image_end
        and address <= 0xFFFFF
    ):
        return None
    return address


def _decode_instruction_8616(project: object, decoder: Cs, address: int, image_end: int) -> CsInsn | None:
    """Decode one image-backed 16-bit instruction without crossing its end."""
    if address > image_end:
        return None
    byte_count = min(15, image_end - address + 1)
    try:
        data = cast(Any, project).loader.memory.load(address, byte_count)
        instruction = next(decoder.disasm(bytes(data), address, count=1), None)
    except (AttributeError, KeyError, TypeError, ValueError, CsError):
        return None
    if instruction is None or instruction.address != address or instruction.size < 1:
        return None
    if address + instruction.size - 1 > image_end:
        return None
    return instruction


def _bp_frame_entry_8616(first: CsInsn, second: CsInsn) -> bool:
    """Require a positive decoded compiler-style entry witness."""
    if first.id != X86_INS_PUSH or second.id != X86_INS_MOV:
        return False
    push_operands = tuple(first.operands)
    mov_operands = tuple(second.operands)
    return (
        len(push_operands) == 1
        and push_operands[0].type == X86_OP_REG
        and push_operands[0].reg == X86_REG_BP
        and len(mov_operands) == 2
        and mov_operands[0].type == X86_OP_REG
        and mov_operands[0].reg == X86_REG_BP
        and mov_operands[1].type == X86_OP_REG
        and mov_operands[1].reg == X86_REG_SP
    )


def _direct_jump_target_8616(instruction: CsInsn) -> int | None:
    """Retain only an immediate target from a decoded branch operand."""
    operands = tuple(instruction.operands)
    if len(operands) != 1 or operands[0].type != X86_OP_IMM:
        return None
    return int(operands[0].imm)


def _bounded_decoded_instruction_8616(
    project: object,
    decoder: Cs,
    address: int,
    entry: int,
    image_end: int,
    occupied: dict[int, int],
) -> CsInsn | None:
    """Decode one in-function instruction without accepting overlapping paths."""
    if not (entry <= address < entry + _MAX_FUNCTION_BYTES_8616):
        return None
    instruction = _decode_instruction_8616(project, decoder, address, image_end)
    if instruction is None:
        return None
    instruction_end = address + instruction.size
    if instruction_end > entry + _MAX_FUNCTION_BYTES_8616:
        return None
    if any(
        byte_addr in occupied and occupied[byte_addr] != address
        for byte_addr in range(address, instruction_end)
    ):
        return None
    for byte_addr in range(address, instruction_end):
        occupied[byte_addr] = address
    return instruction


def _decoded_successors_8616(
    instruction: CsInsn,
) -> tuple[BinaryFarCallbackTargetStatus8616 | None, tuple[int, ...]]:
    """Classify non-far exits and enumerate every local decoded successor."""
    if instruction.id in {X86_INS_RET, X86_INS_IRET}:
        return BinaryFarCallbackTargetStatus8616.NON_FAR_RETURN, ()
    if instruction.id == X86_INS_HLT or instruction.group(CS_GRP_INT):
        return BinaryFarCallbackTargetStatus8616.OPEN_DECODE, ()
    next_addr = instruction.address + instruction.size
    if instruction.group(CS_GRP_JUMP):
        target = _direct_jump_target_8616(instruction)
        if target is None:
            return BinaryFarCallbackTargetStatus8616.OPEN_DECODE, ()
        if instruction.id == X86_INS_JMP:
            return None, (target,)
        return None, (target, next_addr)
    return None, (next_addr,)


def _closed_far_return_cfg_8616(
    project: object, decoder: Cs, entry: int, image_end: int
) -> tuple[BinaryFarCallbackTargetStatus8616, tuple[int, ...], tuple[int, ...]]:
    """Follow every decoded local branch until only far returns terminate it."""
    pending = [entry]
    decoded: dict[int, CsInsn] = {}
    occupied: dict[int, int] = {}
    far_returns: set[int] = set()
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
        if instruction.id == X86_INS_RETF:
            far_returns.add(address)
            continue
        refusal, successors = _decoded_successors_8616(instruction)
        if refusal is not None:
            return refusal, (), tuple(sorted(decoded))
        pending.extend(successors)
    if not far_returns:
        return BinaryFarCallbackTargetStatus8616.OPEN_DECODE, (), tuple(sorted(decoded))
    return BinaryFarCallbackTargetStatus8616.PROVEN, tuple(sorted(far_returns)), tuple(sorted(decoded))


def prove_binary_far_callback_target_8616(
    project: object,
    *,
    segment: int,
    offset: int,
    parameter_fact: FunctionPointerParameterFact8616,
) -> BinaryFarCallbackTargetResult8616:
    """Prove one caller-supplied far Value names decoded DOS code of the callee ABI.

    The caller must independently establish the exact segment and offset Value
    on every reaching path. A closed decode here proves only target identity;
    it neither widens caller storage nor rewrites the C call.
    """
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
