"""Prove that a decoded entry prefix overwrites an incoming register value.

Layer: Semantics.
Responsibility: consume contiguous decoded instruction effects, retaining every
incoming bit until an unconditional write kills it. This is not a deletion
authorization: consumers must also prove real-image provenance, caller uses,
and the identity of the materialized argument before removing setup code.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from capstone import CsError, CsInsn
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from .register_value_preservation import decoded_register_bit_effects_8616, register_value_projection_8616


class RegisterEntryOverwriteVerdict8616(StrEnum):
    """Distinguish complete overwrite evidence from conservative refusal."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


class RegisterEntryOverwriteReason8616(StrEnum):
    """Explain which bounded-prefix obligation succeeded or failed."""

    OVERWRITTEN = "overwritten"
    UNKNOWN_REGISTER = "unknown_register"
    NONCONTIGUOUS = "noncontiguous"
    UNSUPPORTED_INSTRUCTION = "unsupported_instruction"
    MISSING_EFFECTS = "missing_effects"
    INCOMING_READ = "incoming_read"
    INCOMPLETE_PREFIX = "incomplete_prefix"
    INVALID_PRODUCER = "invalid_producer"
    CALLER_USE = "caller_use"
    FRAME_CHANGED = "frame_changed"
    INVALID_PUSH = "invalid_push"
    INVALID_CALL = "invalid_call"


@dataclass(frozen=True)
class RegisterEntryOverwriteProof8616:
    """Bit-precise evidence over an entry prefix, not a function ABI guess."""

    verdict: RegisterEntryOverwriteVerdict8616
    reason: RegisterEntryOverwriteReason8616
    remaining_mask: int
    instruction_addresses: tuple[int, ...]


@dataclass(frozen=True)
class ConsumedStackAddressSetup8616:
    """Exact machine identities required by a recovered BP-address argument."""

    producer_address: int
    push_address: int
    call_address: int
    target_address: int
    bp_offset: int
    register: str


# Only unconditional, ordinary fallthrough effects are admitted. Calls, jumps,
# returns, conditional moves and unrecognized instructions end the proof.
_FALLTHROUGH_MNEMONICS = frozenset({
    "add", "and", "cld", "lea", "lds", "les", "mov", "nop", "or",
    "pop", "push", "std", "sub", "xor",
})


def prove_register_entry_overwrite_8616(
    instructions: Sequence[CsInsn],
    *,
    entry_address: int,
    register: str,
    instruction_budget: int = 32,
) -> RegisterEntryOverwriteProof8616:
    """Require every incoming bit to die before its first observable use.

    An exhausted, empty, noncontiguous or unsupported prefix refuses. A partial
    write kills only its actual bits, so clearing AX cannot prove EAX dead.
    Decoded instructions must come from the real callee image; this routine
    deliberately owns no loader, cache, synthetic-stub or AST policy.
    """
    projection = register_value_projection_8616(register, register)
    reason = RegisterEntryOverwriteReason8616.UNKNOWN_REGISTER
    remaining = (1 << projection[1]) - 1 if projection is not None else 0
    addresses: list[int] = []
    next_address = entry_address
    if projection is not None:
        reason = RegisterEntryOverwriteReason8616.INCOMPLETE_PREFIX
        for instruction in instructions[:max(0, instruction_budget)]:
            if instruction.address != next_address or instruction.size <= 0:
                reason = RegisterEntryOverwriteReason8616.NONCONTIGUOUS
                break
            if instruction.mnemonic.lower() not in _FALLTHROUGH_MNEMONICS:
                reason = RegisterEntryOverwriteReason8616.UNSUPPORTED_INSTRUCTION
                break
            effects = decoded_register_bit_effects_8616(instruction, register)
            if effects is None:
                reason = RegisterEntryOverwriteReason8616.MISSING_EFFECTS
                break
            addresses.append(instruction.address)
            read_mask, write_mask = effects
            if read_mask & remaining:
                reason = RegisterEntryOverwriteReason8616.INCOMING_READ
                break
            remaining &= ~write_mask
            if remaining == 0:
                return RegisterEntryOverwriteProof8616(
                    RegisterEntryOverwriteVerdict8616.PROVEN,
                    RegisterEntryOverwriteReason8616.OVERWRITTEN,
                    remaining,
                    tuple(addresses),
                )
            next_address += instruction.size
    return RegisterEntryOverwriteProof8616(
        RegisterEntryOverwriteVerdict8616.UNKNOWN_REFUSE, reason, remaining, tuple(addresses),
    )


def _producer_lea_shape_8616(
    producer: CsInsn,
    request: ConsumedStackAddressSetup8616,
) -> bool:
    """Return whether the producer is the exact expected LEA BP form."""
    operands = producer.operands
    return bool(
        producer.address == request.producer_address and producer.mnemonic == "lea"
        and len(operands) == 2 and operands[0].type == X86_OP_REG
        and operands[0].size == 2 and producer.reg_name(operands[0].reg) == request.register
        and operands[1].type == X86_OP_MEM and operands[1].mem.index == 0
        and producer.reg_name(operands[1].mem.base) == "bp"
        and operands[1].mem.disp == request.bp_offset
    )


def _terminal_call_shape_8616(
    instruction: CsInsn,
    request: ConsumedStackAddressSetup8616,
    consumed: bool,
    is_last: bool,
) -> bool:
    """Return whether the call site is the exact consumed terminal call."""
    operands = instruction.operands
    return bool(
        consumed and is_last and instruction.mnemonic == "call"
        and len(operands) == 1 and operands[0].type == X86_OP_IMM
        and operands[0].imm == request.target_address
    )


def _consumed_push_shape_8616(
    instruction: CsInsn,
    request: ConsumedStackAddressSetup8616,
    effects: tuple[int, int],
    consumed: bool,
) -> bool:
    """Return whether one PUSH is the exact sole consumed producer use."""
    operands = instruction.operands
    return bool(
        not consumed and instruction.mnemonic == "push" and len(operands) == 1
        and operands[0].type == X86_OP_REG and operands[0].size == 2
        and instruction.reg_name(operands[0].reg) == request.register
        and effects == (0xFFFF, 0)
    )


@dataclass(slots=True)
class _CallerSetupScan8616:
    """Sequential caller scan state for the consumed-PUSH proof."""

    request: ConsumedStackAddressSetup8616
    caller: Sequence[CsInsn]
    next_address: int
    consumed: bool = False

    def step(
        self,
        instruction: CsInsn,
    ) -> tuple[RegisterEntryOverwriteReason8616 | None, bool]:
        """Advance one instruction; returns ``(reason, done)``."""
        if instruction.address != self.next_address or instruction.size <= 0:
            return RegisterEntryOverwriteReason8616.NONCONTIGUOUS, True
        if instruction.address == self.request.call_address:
            if not _terminal_call_shape_8616(
                instruction, self.request, self.consumed,
                instruction is self.caller[-1],
            ):
                return RegisterEntryOverwriteReason8616.INVALID_CALL, True
            return None, True
        if instruction.mnemonic not in _FALLTHROUGH_MNEMONICS:
            return RegisterEntryOverwriteReason8616.UNSUPPORTED_INSTRUCTION, True
        effects = decoded_register_bit_effects_8616(instruction, self.request.register)
        frame_effects = decoded_register_bit_effects_8616(instruction, "bp")
        if effects is None or frame_effects is None:
            return RegisterEntryOverwriteReason8616.MISSING_EFFECTS, True
        if frame_effects[1]:
            return RegisterEntryOverwriteReason8616.FRAME_CHANGED, True
        if instruction.address == self.request.push_address:
            if not _consumed_push_shape_8616(
                instruction, self.request, effects, self.consumed,
            ):
                return RegisterEntryOverwriteReason8616.INVALID_PUSH, True
            self.consumed = True
        elif effects != (0, 0):
            return RegisterEntryOverwriteReason8616.CALLER_USE, True
        self.next_address += instruction.size
        return None, False


def _caller_setup_refusal_8616(
    caller: Sequence[CsInsn], request: ConsumedStackAddressSetup8616,
) -> RegisterEntryOverwriteReason8616 | None:
    """Check the sole consumed PUSH use of a word-sized BP-address producer."""
    if not caller or request.register not in {"ax", "bx", "cx", "dx", "si", "di"}:
        return RegisterEntryOverwriteReason8616.INVALID_PRODUCER
    producer = caller[0]
    if not _producer_lea_shape_8616(producer, request):
        return RegisterEntryOverwriteReason8616.INVALID_PRODUCER
    scan = _CallerSetupScan8616(
        request=request,
        caller=caller,
        next_address=producer.address + producer.size,
    )
    for instruction in caller[1:]:
        reason, done = scan.step(instruction)
        if done:
            return reason
    return RegisterEntryOverwriteReason8616.INCOMPLETE_PREFIX


def prove_consumed_stack_address_setup_8616(
    caller: Sequence[CsInsn],
    callee: Sequence[CsInsn],
    request: ConsumedStackAddressSetup8616,
) -> RegisterEntryOverwriteProof8616:
    """Combine a sole consumed PUSH use with callee overwrite-before-read.

    The caller must supply at most 32 instructions from LEA through the exact
    direct call. This proves machine value liveness only. Real-image provenance
    and the recovered argument's storage identity remain consumer obligations.
    No ABI caller-saved designation is used as overwrite evidence.
    """
    try:
        reason = (
            RegisterEntryOverwriteReason8616.INCOMPLETE_PREFIX if len(caller) > 32
            else _caller_setup_refusal_8616(caller, request)
        )
    except (CsError, AttributeError, TypeError, ValueError):
        reason = RegisterEntryOverwriteReason8616.MISSING_EFFECTS
    if reason is not None:
        return RegisterEntryOverwriteProof8616(
            RegisterEntryOverwriteVerdict8616.UNKNOWN_REFUSE, reason, 0xFFFF, (),
        )
    return prove_register_entry_overwrite_8616(
        callee, entry_address=request.target_address, register=request.register,
    )
