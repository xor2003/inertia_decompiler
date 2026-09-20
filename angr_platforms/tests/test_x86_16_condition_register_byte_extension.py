"""Prove zero-extended condition values from independently reaching bytes."""

import pytest
from angr_platforms.X86_16.alias.condition_register_bindings import (
    ConditionRegisterSourceBindingVerdict8616,
    bind_condition_register_sources_8616,
)
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.core import IRBinaryValue, IRValue, MemSpace

from inertia_decompiler.project_loading import _build_project_from_bytes


def _bind(prefix, register="ax", compare="83 f8 01", width_bits=16):
    """Use native decoded CFG facts, with the comparison in another block."""
    base = 0x1000
    producer = base + len(prefix) + 2
    code = prefix + bytes.fromhex("eb 00 " + compare + " 75 01 c3 c3")
    project = _build_project_from_bytes(code, base_addr=base, entry_point=base)
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    condition = ConditionIR(
        op="ne",
        lhs=IRValue(MemSpace.REG, name=register, size=width_bits // 8),
        rhs=IRValue(MemSpace.CONST, const=1, size=width_bits // 8),
        width_bits=width_bits,
        source=("cmp", "jne"),
        producer_insn=producer,
        src_insn=producer + len(bytes.fromhex(compare)),
        block_addr=producer,
        producer_semantics=("cmp_reg_imm16", register, 1),
    )
    return bind_condition_register_sources_8616(cfg.kb.functions[base], (condition,))


@pytest.mark.parametrize(
    ("register", "load", "clear", "compare"),
    [
        ("ax", "8a 46 08", "2a e4", "83 f8 01"),
        ("bx", "8a 5e 08", "30 ff", "83 fb 01"),
        ("cx", "8a 4e 08", "30 ed", "83 f9 01"),
        ("dx", "8a 56 08", "30 f6", "83 fa 01"),
    ],
)
@pytest.mark.parametrize("clear_first", [False, True])
def test_zero_extended_register_binds_exact_byte(register, load, clear, compare, clear_first):
    """Disjoint byte definitions prove a word irrespective of their order."""
    prefix = bytes.fromhex(f"{clear} {load}" if clear_first else f"{load} {clear}")
    result = _bind(prefix, register, compare)

    assert result.verdict is ConditionRegisterSourceBindingVerdict8616.MATERIALIZED
    binding, = result.conditions[0].register_bindings
    assert binding.register_name == register
    assert binding.value == IRBinaryValue(
        "and",
        IRValue(MemSpace.SS, name="bp", offset=8, size=1),
        IRValue(MemSpace.CONST, const=0xFF, size=2),
        size=2,
    )
    assert result.stats.classified_fact_count == result.stats.materialized_count == 1
    assert result.stats.failure_count == 0


@pytest.mark.parametrize(
    "prefix",
    [
        "8a 46 08",  # AH remains unknown.
        "2a e4",  # AL remains unknown.
        "8a 46 08 b4 01",  # Nonzero AH is not zero extension.
        "8a 46 08 2a e4 fe c4",  # Later high-byte write.
        "8a 46 08 2a e4 fe c0",  # Later low-byte update.
        "8a 46 08 2a e4 c6 46 08 05",  # Memory no longer equals saved AL.
        "26 a0 34 12 2a e4",  # ES is not a proven DS storage source.
        "74 05 8a 46 08 eb 03 8a 46 0a 2a e4",  # Conflicting reaching sources.
    ],
)
def test_byte_extension_refuses_incomplete_or_changed_sources(prefix):
    """A missing lane, conflicting CFG path or stale memory must stay unknown."""
    result = _bind(bytes.fromhex(prefix))

    assert result.verdict is ConditionRegisterSourceBindingVerdict8616.UNKNOWN_REFUSE
    assert not result.conditions[0].register_bindings
    assert result.stats.materialized_count == 0
    assert result.stats.failure_count == 1


def test_matching_byte_sources_join_across_both_cfg_arms():
    """Every incoming path must agree on the same byte storage."""
    result = _bind(bytes.fromhex("74 05 8a 46 08 eb 03 8a 46 08 2a e4"))

    assert result.verdict is ConditionRegisterSourceBindingVerdict8616.MATERIALIZED
    binding, = result.conditions[0].register_bindings
    assert binding.value.lhs == IRValue(MemSpace.SS, name="bp", offset=8, size=1)


def test_cleared_ah_does_not_prove_upper_eax_word():
    """AX byte coverage must never manufacture a 32-bit register value."""
    result = _bind(bytes.fromhex("8a 46 08 2a e4"), "eax", "66 83 f8 01", 32)

    assert result.verdict is ConditionRegisterSourceBindingVerdict8616.UNKNOWN_REFUSE
    assert not result.conditions[0].register_bindings


def test_zero_extended_global_byte_keeps_ds_identity():
    """Word reconstruction must not flatten or relabel the source segment."""
    result = _bind(bytes.fromhex("a0 34 12 2a e4"))

    assert result.verdict is ConditionRegisterSourceBindingVerdict8616.MATERIALIZED
    binding, = result.conditions[0].register_bindings
    assert binding.value.lhs == IRValue(MemSpace.DS, offset=0x1234, size=1)
