"""Check binary-proven caller identity across both callsite inventories."""

from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.frontend_caller_return_use_program import build_caller_return_use_program_evidence_8616
from angr_platforms.X86_16.lowering import callee_range_callsite_facts as ranges


def test_invalid_and_conflicting_entry_witnesses_refuse():
    from angr_platforms.X86_16.frontend_caller_entry_identity import (
        CallerEntryIdentity8616,
        caller_target_identity_8616,
    )

    with pytest.raises(ValueError, match="invalid caller entry identity"):
        CallerEntryIdentity8616(0x1100, 0x1110, 0x1102, b"\x90\xcc")
    identities = (
        CallerEntryIdentity8616(0x1100, 0x1110, 0x1102, b"\x90\x90"),
        CallerEntryIdentity8616(0x1101, 0x1110, 0x1103, b"\x90\x90"),
    )
    with pytest.raises(ValueError, match="conflicting caller entry aliases"):
        caller_target_identity_8616(0x1101, identities)


def test_short_binary_read_is_a_closed_refusal_not_an_entry_proof():
    program = _program(_project(b"\x90\xc3"), 0x1107)
    assert program.stats.materialized_count == 0
    assert program.stats.failure_count == 1
    assert program.stats.closed


def test_missing_caller_bytes_cannot_prove_all_callers_discard_return():
    from angr_platforms.X86_16.caller_return_use_contracts import CallerReturnUseVerdict8616
    from angr_platforms.X86_16.callsite_summary import collect_caller_return_use_evidence_8616

    project = _project(bytes.fromhex("e8 1d 00 31 c0 c3"))
    evidence = collect_caller_return_use_evidence_8616(
        project, 0x1120, ((0x1100, 0x1106), (0x1110, 0x1116)),
    )
    assert evidence.verdict is CallerReturnUseVerdict8616.UNKNOWN
    assert evidence.failure_count > 0


def test_nop_only_range_and_segment_crossing_do_not_establish_aliases():
    from angr_platforms.X86_16.frontend_caller_entry_identity import prove_caller_entry_identity_8616

    for start, data in ((0x1100, b"\x90\x90"), (0xffff, b"\x90\xc3")):
        identity = prove_caller_entry_identity_8616(start, start + len(data), data)
        assert identity.entry_addr == start
        assert identity.nop_prefix == b""


@pytest.mark.parametrize("target", [0x1100, 0x1101, 0x1102])
def test_recursive_passthrough_remains_excluded_for_each_proven_alias(target):
    from angr_platforms.X86_16.callsite_summary import collect_caller_return_use_evidence_8616

    project = _project(bytes.fromhex("90 90 e8 fb ff c3"))
    evidence = collect_caller_return_use_evidence_8616(project, target, ((0x1100, 0x1106),))
    assert evidence.raw_fact_count == 1
    assert evidence.excluded_callsite_count == 1
    assert evidence.facts[0].caller_addr == 0x1102


def test_transitive_return_observation_follows_call_to_padded_wrapper():
    from angr_platforms.X86_16.caller_return_use_contracts import CallerReturnUseVerdict8616
    from angr_platforms.X86_16.callsite_summary import collect_caller_return_use_evidence_8616

    code = bytes.fromhex("e8 0d 00 31 c0 c3") + b"\xcc" * 10 + bytes.fromhex("90 90 e8 0b 00 c3")
    project = _project(code)
    evidence = collect_caller_return_use_evidence_8616(
        project, 0x1120, ((0x1100, 0x1106), (0x1110, 0x1116)),
    )
    assert evidence.raw_fact_count == 1
    assert evidence.facts[0].caller_addr == 0x1112
    assert evidence.verdict is CallerReturnUseVerdict8616.UNUSED


def test_canonical_return_evidence_survives_worker_json_codec():
    import json

    from angr_platforms.X86_16.callsite_summary import collect_caller_return_use_evidence_8616

    from inertia_decompiler.discovery_cache_contract import (
        caller_return_use_evidence_from_record_8616,
        caller_return_use_evidence_record_8616,
    )

    project = _project(bytes.fromhex("90 90 e8 fb ff c3"))
    original = collect_caller_return_use_evidence_8616(project, 0x1100, ((0x1100, 0x1106),))
    record = json.loads(json.dumps(caller_return_use_evidence_record_8616(original)))
    restored = caller_return_use_evidence_from_record_8616(record)
    assert restored == original
    assert restored.facts[0].caller_addr == 0x1102
from capstone import CS_ARCH_X86, CS_MODE_16, Cs
from capstone.x86_const import X86_OP_IMM


def _project(code, base=0x1100):
    def load(address, size):
        return code[address - base:address - base + size]

    return SimpleNamespace(
        arch=SimpleNamespace(capstone=Cs(CS_ARCH_X86, CS_MODE_16)),
        loader=SimpleNamespace(memory=SimpleNamespace(load=load)),
    )


def _target(instruction):
    if instruction.mnemonic == "call" and instruction.operands[0].type == X86_OP_IMM:
        return instruction.operands[0].imm
    return None


def _program(project, end):
    return build_caller_return_use_program_evidence_8616(
        project, ((0x1100, end),), direct_target_resolver=_target,
        instruction_address_resolver=lambda instruction: instruction.address,
    )


def test_return_inventory_keeps_decode_bounds_but_uses_nop_equivalent_entry():
    # Two NOPs; push bp; call the padded entry; ret. No prologue pattern needed.
    program = _program(_project(bytes.fromhex("90 90 55 e8 fa ff c3")), 0x1107)
    calls = program.callsites.for_target(0x1100)
    assert len(calls) == 1
    assert calls[0].caller_start == 0x1102
    assert calls[0].callsite_addr == 0x1103
    assert calls[0].instructions[0].address == 0x1100
    assert program.function_ranges == ((0x1100, 0x1107),)
    assert program.callsites.for_target(0x1102) == calls
    assert program.stats.closed and program.callsites.stats.closed


@pytest.mark.parametrize("prefix", [b"\x00\x00", b"\xcc", b"\x40", b"\x66\x90"])
def test_non_nop_entry_is_not_merged(prefix):
    # Byte patterns accepted by old discovery heuristics are not NOP proofs.
    code = prefix + bytes.fromhex("55 e8 00 00 c3")
    program = _program(_project(code), 0x1100 + len(code))
    calls = program.callsites.for_target(0x1100 + len(code) - 1)
    assert len(calls) == 1
    assert calls[0].caller_start == 0x1100


@pytest.mark.parametrize("targeted", [False, True])
def test_argument_inventory_uses_same_binary_entry_and_boundary(monkeypatch, targeted):
    code = bytes.fromhex("90 90 55 e8 fa ff c3")
    project = _project(code)
    observed = []

    def inventory(_project, function_ranges):
        observed.extend(function_ranges)
        return SimpleNamespace(boundaries=tuple(
            SimpleNamespace(addr=start, size=end - start) for start, end in function_ranges
        ))

    monkeypatch.setattr(ranges, "exact_function_range_inventory_8616", inventory)
    monkeypatch.setattr(ranges, "canonicalize_x86_16_padding_call_target_8616", lambda *_: 0x1102)
    monkeypatch.setattr(ranges, "summarize_x86_16_callsite", lambda *_: SimpleNamespace(stack_probe_helper=False))
    function_ranges = ((0x1100, 0x1107),)
    facts = (
        ranges.collect_range_callsite_facts_for_target_8616(project, 0x1102, function_ranges)
        if targeted else ranges.collect_range_callsite_facts_8616(project, function_ranges)
    )
    assert len(facts) == 1
    assert facts[0].caller_addr == facts[0].caller_function.addr == 0x1102
    assert facts[0].callsite_addr == 0x1103
    assert observed == [(0x1102, 0x1107)]
