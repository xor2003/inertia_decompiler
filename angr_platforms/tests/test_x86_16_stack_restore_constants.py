"""Exact saved values must survive bytewise stack-register restoration."""

from dataclasses import replace

import pytest
from angr_platforms.X86_16.alias.segment_stack_fragments import SegmentStackByteOrigin8616, complete_stack_constant_8616
from angr_platforms.X86_16.alias.segment_stack_restore import (
    SegmentStackRestoreVerdict8616,
    build_x86_16_stack_register_restore_artifact_8616,
)
from angr_platforms.X86_16.ir.constant_flow import IRConstantFlow8616
from angr_platforms.X86_16.ir.core import IRInstr, IRRefusal, IRValue, MemSpace
from test_x86_16_segment_stack_restore import _lift_function


@pytest.mark.parametrize("prefix,expected", [("29 c0", 0), ("31 c0", 0), ("b8 34 12", 0x1234)])
def test_register_save_retains_exact_constant(prefix, expected):
    """Register identity and constant value describe the same saved bytes."""
    artifact = _lift_function(bytes.fromhex(prefix + " 50 b8 ff ff 5b c3"))
    restored = build_x86_16_stack_register_restore_artifact_8616(
        artifact, tracked_registers=frozenset({"ax", "bx"}),
    )
    facts = [fact for fact in restored.facts if fact.verdict is SegmentStackRestoreVerdict8616.PROVEN]
    assert len(facts) == 1
    assert facts[0].saved_register == "ax"
    assert facts[0].restore_register == "bx"
    assert facts[0].constant_value == expected


@pytest.mark.parametrize("prefix", ["b8 34 12 88 d8", "b8 34 12 89 d8"])
def test_unknown_overlapping_write_does_not_keep_old_constant(prefix):
    """An unknown AL or AX write invalidates the earlier complete AX value."""
    artifact = _lift_function(bytes.fromhex(prefix + " 50 5b c3"))
    restored = build_x86_16_stack_register_restore_artifact_8616(
        artifact, tracked_registers=frozenset({"ax", "bx"}),
    )
    facts = [fact for fact in restored.facts if fact.verdict is SegmentStackRestoreVerdict8616.PROVEN]
    assert len(facts) == 1
    assert facts[0].constant_value is None


@pytest.mark.parametrize("writer", ["ax", "al", "eax", "call"])
def test_old_register_snapshots_do_not_equal_new_reads(writer):
    """Temporary identity, not the repeated register label, proves self-subtraction."""
    state = IRConstantFlow8616()
    ax = IRValue(MemSpace.REG, name="ax", size=2)
    first = IRValue(MemSpace.TMP, name="first", size=2, source_tmp=1)
    second = IRValue(MemSpace.TMP, name="second", size=2, source_tmp=2)
    difference = IRValue(MemSpace.TMP, name="difference", size=2, source_tmp=3)
    state.observe(IRInstr("MOV", first, (ax,)))
    if writer == "call":
        state.observe(IRInstr("CALL", None, ()))
    else:
        size = {"al": 1, "ax": 2, "eax": 4}[writer]
        state.observe(IRInstr("MOV", IRValue(MemSpace.REG, name=writer, size=size),
                              (IRValue(MemSpace.REG, name="bx", size=2),)))
    state.observe(IRInstr("MOV", second, (ax,)))
    state.observe(IRInstr("Iop_Sub16", difference, (first, second)))
    assert state.constant(difference) is None


def test_missing_temporary_never_borrows_current_register_value():
    state = IRConstantFlow8616()
    ax = IRValue(MemSpace.REG, name="ax", size=2)
    state.observe(IRInstr("MOV", ax, (IRValue(MemSpace.CONST, const=0x1234, size=2),)))
    assert state.constant(ax) == 0x1234
    assert state.constant(IRValue(MemSpace.REG, name="ax", size=2, source_tmp=999)) is None


def test_incomplete_ir_cannot_publish_a_saved_constant():
    artifact = _lift_function(bytes.fromhex("29 c0 50 5b c3"))
    first, *remaining = artifact.blocks
    refusal = IRRefusal("unsupported_stmt", "unknown register effects", first.addr)
    artifact = replace(artifact, blocks=(replace(first, refusals=(refusal,)), *remaining))
    restored = build_x86_16_stack_register_restore_artifact_8616(
        artifact, tracked_registers=frozenset({"ax", "bx"}),
    )
    assert all(fact.constant_value is None for fact in restored.facts)


def test_reversed_stack_bytes_do_not_prove_a_native_word_constant():
    fragments = frozenset({
        SegmentStackByteOrigin8616("ax", 0x1000, 0, 0, -1, 0x34),
        SegmentStackByteOrigin8616("ax", 0x1000, 1, 1, -2, 0x12),
    })
    assert complete_stack_constant_8616(fragments) is None


def test_register_name_normalization_does_not_retain_a_stale_alias():
    state = IRConstantFlow8616()
    upper = IRValue(MemSpace.REG, name="AX", size=2)
    lower = IRValue(MemSpace.REG, name="ax", size=2)
    state.observe(IRInstr("MOV", upper, (IRValue(MemSpace.CONST, const=0x1234, size=2),)))
    state.observe(IRInstr("MOV", lower, (IRValue(MemSpace.REG, name="bx", size=2),)))
    assert state.constant(upper) is None
