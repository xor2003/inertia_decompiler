"""Callee entry overwrite evidence must preserve partially live register bits."""

from dataclasses import replace

import pytest
from capstone import CS_ARCH_X86, CS_MODE_16, Cs

from inertia.semantics.register_entry_overwrite import (
    ConsumedStackAddressSetup8616,
    prove_consumed_stack_address_setup_8616,
    prove_register_entry_overwrite_8616,
)
from inertia.semantics.register_entry_overwrite import (
    RegisterEntryOverwriteReason8616 as Reason,
)
from inertia.semantics.register_entry_overwrite import (
    RegisterEntryOverwriteVerdict8616 as Verdict,
)


def decoded(code, detail=True, address=0x2000):
    decoder = Cs(CS_ARCH_X86, CS_MODE_16)
    decoder.detail = detail
    return tuple(decoder.disasm(bytes.fromhex(code), address))


@pytest.mark.parametrize("code,register", [
    ("55 89 e5 57 c4 7e 06 fc 31 c0", "ax"),
    ("30 c0 30 e4", "ax"),
    ("b0 01 88 c3 b4 02", "ax"),
    ("66 31 c0", "eax"),
])
def test_complete_overwrite_before_incoming_read(code, register):
    proof = prove_register_entry_overwrite_8616(decoded(code), entry_address=0x2000, register=register)
    assert proof.verdict is Verdict.PROVEN
    assert proof.reason is Reason.OVERWRITTEN
    assert proof.remaining_mask == 0
    assert proof.instruction_addresses[0] == 0x2000


@pytest.mark.parametrize("code,register,reason,remaining", [
    ("89 c3 31 c0", "ax", Reason.INCOMING_READ, 0xFFFF),
    ("50 31 c0", "ax", Reason.INCOMING_READ, 0xFFFF),
    ("89 07 31 c0", "ax", Reason.INCOMING_READ, 0xFFFF),
    ("b0 01 88 e3 30 e4", "ax", Reason.INCOMING_READ, 0xFF00),
    ("31 c0", "eax", Reason.INCOMPLETE_PREFIX, 0xFFFF0000),
    ("30 c0", "ax", Reason.INCOMPLETE_PREFIX, 0xFF00),
    ("74 00 31 c0", "ax", Reason.UNSUPPORTED_INSTRUCTION, 0xFFFF),
    ("e8 00 00 31 c0", "ax", Reason.UNSUPPORTED_INSTRUCTION, 0xFFFF),
    ("c3 31 c0", "ax", Reason.UNSUPPORTED_INSTRUCTION, 0xFFFF),
    ("", "ax", Reason.INCOMPLETE_PREFIX, 0xFFFF),
    ("31 c0", "unknown", Reason.UNKNOWN_REGISTER, 0),
])
def test_unproven_prefix_keeps_incoming_value(code, register, reason, remaining):
    proof = prove_register_entry_overwrite_8616(decoded(code), entry_address=0x2000, register=register)
    assert proof.verdict is Verdict.UNKNOWN_REFUSE
    assert proof.reason is reason
    assert proof.remaining_mask == remaining


def test_entry_and_instruction_contiguity_are_required():
    instructions = decoded("90 90 31 c0")
    for prefix in (instructions[1:], (instructions[0], instructions[2])):
        proof = prove_register_entry_overwrite_8616(prefix, entry_address=0x2000, register="ax")
        assert proof.reason is Reason.NONCONTIGUOUS
        assert proof.verdict is Verdict.UNKNOWN_REFUSE


@pytest.mark.parametrize("budget", [-1, 0, 1])
def test_instruction_budget_cannot_be_bypassed(budget):
    proof = prove_register_entry_overwrite_8616(
        decoded("90 31 c0"), entry_address=0x2000, register="ax", instruction_budget=budget,
    )
    assert proof.reason is Reason.INCOMPLETE_PREFIX
    assert proof.verdict is Verdict.UNKNOWN_REFUSE


def test_missing_capstone_detail_refuses_without_crashing():
    proof = prove_register_entry_overwrite_8616(
        decoded("31 c0", detail=False), entry_address=0x2000, register="ax",
    )
    assert proof.reason is Reason.MISSING_EFFECTS
    assert proof.verdict is Verdict.UNKNOWN_REFUSE


def caller_setup(prefix="8d 46 f0 16 50 0e", push_offset=4):
    code = bytes.fromhex(prefix)
    displacement = 0x3000 - (0x2000 + len(code) + 3)
    caller = decoded((code + b"\xe8" + displacement.to_bytes(2, "little")).hex())
    request = ConsumedStackAddressSetup8616(
        producer_address=0x2000, push_address=0x2000 + push_offset,
        call_address=caller[-1].address, target_address=0x3000, bp_offset=-16, register="ax",
    )
    return caller, request


def test_consumed_stack_address_setup_requires_both_caller_and_callee():
    caller, request = caller_setup()
    proof = prove_consumed_stack_address_setup_8616(
        caller, decoded("55 89 e5 31 c0", address=0x3000), request,
    )
    assert proof.verdict is Verdict.PROVEN
    proof = prove_consumed_stack_address_setup_8616(
        caller, decoded("89 c3 31 c0", address=0x3000), request,
    )
    assert proof.verdict is Verdict.UNKNOWN_REFUSE
    assert proof.reason is Reason.INCOMING_READ


@pytest.mark.parametrize("boundary", [
    "e8 00 00",  # Direct call still requires real target evidence.
    "ff 16 40 00",  # Indirect near call through memory.
    "ff 1e 40 00",  # Indirect far call through memory.
    "cd 10",  # Interrupt effects cannot be inferred from Capstone alone.
])
@pytest.mark.parametrize("prefix,remaining", [("", 0xFFFF), ("b4 02", 0x00FF)])
def test_consumed_setup_retains_bits_across_unproven_callee_boundaries(boundary, prefix, remaining):
    caller, request = caller_setup()
    callee = decoded(f"{prefix} {boundary} 31 c0", address=0x3000)
    proof = prove_consumed_stack_address_setup_8616(caller, callee, request)
    assert proof.verdict is Verdict.UNKNOWN_REFUSE
    assert proof.reason is Reason.UNSUPPORTED_INSTRUCTION
    assert proof.remaining_mask == remaining
    assert callee[-1].address not in proof.instruction_addresses


@pytest.mark.parametrize("field,value,reason", [
    ("producer_address", 0x2001, Reason.INVALID_PRODUCER),
    ("push_address", 0x2003, Reason.INVALID_PUSH),
    ("call_address", 0x2007, Reason.UNSUPPORTED_INSTRUCTION),
    ("target_address", 0x3001, Reason.INVALID_CALL),
    ("bp_offset", -18, Reason.INVALID_PRODUCER),
    ("register", "bx", Reason.INVALID_PRODUCER),
    ("register", "bp", Reason.INVALID_PRODUCER),
])
def test_mismatched_setup_identity_refuses(field, value, reason):
    caller, request = caller_setup()
    proof = prove_consumed_stack_address_setup_8616(
        caller, decoded("31 c0", address=0x3000), replace(request, **{field: value}),
    )
    assert proof.verdict is Verdict.UNKNOWN_REFUSE
    assert proof.reason is reason


@pytest.mark.parametrize("prefix,push_offset,reason", [
    ("8d 46 f0 89 c3 50", 5, Reason.CALLER_USE),
    ("8d 46 f0 b0 01 50", 5, Reason.CALLER_USE),
    ("8d 46 f0 50 50", 3, Reason.CALLER_USE),
    ("8d 46 f0 89 e5 50", 5, Reason.FRAME_CHANGED),
    ("8d 46 f0 66 89 e5 50", 6, Reason.FRAME_CHANGED),
    ("8d 46 f0 66 50", 3, Reason.INVALID_PUSH),
    ("8d 46 f0 74 00 50", 5, Reason.UNSUPPORTED_INSTRUCTION),
    ("8d 40 f0 50", 3, Reason.INVALID_PRODUCER),
])
def test_unconsumed_reads_writes_or_control_flow_keep_setup(prefix, push_offset, reason):
    caller, request = caller_setup(prefix, push_offset)
    proof = prove_consumed_stack_address_setup_8616(caller, decoded("31 c0", address=0x3000), request)
    assert proof.verdict is Verdict.UNKNOWN_REFUSE
    assert proof.reason is reason


def test_caller_budget_and_missing_call_refuse():
    caller, request = caller_setup("8d 46 f0 50 " + "90 " * 32, push_offset=3)
    proof = prove_consumed_stack_address_setup_8616(caller, decoded("31 c0", address=0x3000), request)
    assert proof.verdict is Verdict.UNKNOWN_REFUSE
    assert proof.reason is Reason.INCOMPLETE_PREFIX
    caller, request = caller_setup()
    proof = prove_consumed_stack_address_setup_8616(caller[:-1], decoded("31 c0", address=0x3000), request)
    assert proof.verdict is Verdict.UNKNOWN_REFUSE
    assert proof.reason is Reason.INCOMPLETE_PREFIX
