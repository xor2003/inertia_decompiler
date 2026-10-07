"""Do not reuse narrow register sources across overlapping 80386 writes."""

from types import SimpleNamespace

import pytest
from inertia.semantics.callsite_register_instruction_facts import instruction_writes_register_8616
from inertia.semantics.callsite_register_provenance import recover_register_source_before_instruction_8616
from capstone import CS_ARCH_X86, CS_MODE_16, Cs

from inertia.alias.register_reaching_source import RegisterReachingSourceVerdict8616
from inertia.semantics.register_value_preservation import (
    decoded_instruction_self_clears_register_8616,
    decoded_register_bit_effects_8616,
    register_value_family_8616,
    register_value_projection_8616,
)
from inertia.cli.project_loading import _build_project_from_bytes


def decode(code):
    decoder = Cs(CS_ARCH_X86, CS_MODE_16)
    decoder.detail = True
    instruction = next(decoder.disasm(bytes.fromhex(code), 0x1000))
    return SimpleNamespace(insn=instruction, mnemonic=instruction.mnemonic, address=instruction.address)


@pytest.mark.parametrize("code,register", [
    ("66 b8 10 32 54 76", "ax"),
    ("66 b8 10 32 54 76", "ah"),
    ("b0 12", "eax"),
    ("66 be 10 32 54 76", "si"),
    ("be 10 32", "esi"),
    ("66 bd 10 32 54 76", "bp"),
])
def test_decoded_write_overlaps_both_narrow_and_wide_views(code, register):
    assert instruction_writes_register_8616(decode(code), register)


@pytest.mark.parametrize("code,register,effects", [
    ("30 c0", "ax", (0, 0xFF)),
    ("30 e4", "ax", (0, 0xFF00)),
    ("31 c0", "eax", (0, 0xFFFF)),
    ("66 31 c0", "eax", (0, 0xFFFFFFFF)),
    ("89 c3", "ax", (0xFFFF, 0)),
    ("b0 01", "ah", (0, 0)),
])
def test_register_bit_effects_distinguish_inputs_and_partial_kills(code, register, effects):
    assert decoded_register_bit_effects_8616(decode(code), register) == effects


def test_sibling_byte_write_is_not_a_clobber():
    assert not instruction_writes_register_8616(decode("b0 01"), "ah")
    assert decoded_register_bit_effects_8616(object(), "ax") is None


def test_family_overlap_does_not_prove_full_width_clear():
    assert "eax" in register_value_family_8616("ax")
    assert "ax" in register_value_family_8616("eax")
    assert not decoded_instruction_self_clears_register_8616(decode("31 c0"), "eax")
    assert not decoded_instruction_self_clears_register_8616(decode("30 c0"), "ah")
    assert decoded_instruction_self_clears_register_8616(decode("66 31 c0"), "ax")
    assert decoded_instruction_self_clears_register_8616(decode("66 31 c0"), "ah")


@pytest.mark.parametrize("writer,reader,projection", [
    ("eax", "ax", (0, 16)),
    ("eax", "ah", (8, 8)),
    ("ax", "al", (0, 8)),
    ("esi", "si", (0, 16)),
    ("ax", "eax", None),
    ("al", "ah", None),
    ("esi", "ax", None),
    ("unknown", "ax", None),
])
def test_register_projection_requires_complete_bit_coverage(writer, reader, projection):
    assert register_value_projection_8616(writer, reader) == projection


def test_narrow_write_does_not_keep_an_old_full_register_constant():
    project = _build_project_from_bytes(
        bytes.fromhex("66 b8 78 56 34 12 b0 10 66 50 c3"),
        base_addr=0x1000, entry_point=0x1000,
    )
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    result = recover_register_source_before_instruction_8616(
        cfg.kb.functions[0x1000], instruction_addr=0x1008, register="eax",
    )
    assert result.verdict is RegisterReachingSourceVerdict8616.UNKNOWN_REFUSE
    assert result.source is None
    assert result.failure_count == 1


@pytest.mark.parametrize("code,register", [
    ("b8 34 12 66 b8 10 32 54 76 50 c3", "ax"),
    ("be 34 12 66 be 10 32 54 76 56 c3", "si"),
])
def test_reaching_source_replaces_stale_word_after_dword_replacement(code, register):
    project = _build_project_from_bytes(bytes.fromhex(code), base_addr=0x1000, entry_point=0x1000)
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    result = recover_register_source_before_instruction_8616(
        cfg.kb.functions[0x1000], instruction_addr=0x1009, register=register,
    )
    assert result.verdict is RegisterReachingSourceVerdict8616.PROVEN
    assert result.source == ("imm", 0x3210)
    assert result.classified_fact_count == result.materialized_count == 1
    assert result.failure_count == 0
