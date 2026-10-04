"""Regress typed condition caching at the pyvex ownership boundary."""

from __future__ import annotations

from types import SimpleNamespace

import pyvex
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.core import IRBinaryValue, IRValue, MemSpace
from angr_platforms.X86_16.lift_86_16 import Instruction_ANY


class _OwnedOperand:
    """Model a pyvex value whose equality is invalid across IRSB owners."""

    def __eq__(self, _other: object) -> bool:
        """Refuse direct equality, as pyvex does for cross-IRSB values."""
        raise AssertionError("cross-owner operand equality")

    def __str__(self) -> str:
        """Return the stable rendering used by the typed condition key."""
        return "owned-operand"


def test_lifter_condition_cache_deduplicates_without_operand_equality() -> None:
    """Use the IR key instead of comparing pyvex-owned operand objects."""
    original_cache = Instruction_ANY._inertia_module_condition_cache
    instruction = Instruction_ANY.__new__(Instruction_ANY)
    instruction.addr = 0x4014
    instruction.cs = SimpleNamespace(bytes=b"\x90")
    instruction.emu = SimpleNamespace(
        _inertia_current_block_addr=0x4010,
        _inertia_typed_conditions=[],
    )
    conditions = (
        ConditionIR("ne", _OwnedOperand(), 0, src_insn=0x4014, block_addr=0x4010),
        ConditionIR("ne", _OwnedOperand(), 0, src_insn=0x4014, block_addr=0x4010),
    )
    Instruction_ANY._inertia_module_condition_cache = {}

    try:
        for condition in conditions:
            instruction._record_typed_condition_8616(condition)
        cached = Instruction_ANY._inertia_module_condition_cache[0x4010]
    finally:
        Instruction_ANY._inertia_module_condition_cache = original_cache

    assert len(cached) == 1
    assert cached[0] is conditions[0]
    assert instruction.emu._inertia_typed_conditions == list(conditions)


def test_direct_word_pair_or_zero_test_uses_block_local_value_provenance(monkeypatch) -> None:
    """Keep both direct DS operands in MOV/OR/JZ condition evidence."""
    monkeypatch.setattr(Instruction_ANY, "_inertia_module_condition_cache", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_condition_index_reg_state_8616", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_condition_reg_value_state_8616", {})

    pyvex.lift(
        bytes.fromhex("a134010b063201740290c3"),
        0x4000,
        Arch86_16(),
        opt_level=0,
    )

    [condition] = Instruction_ANY._inertia_module_condition_cache[0x4000]
    assert isinstance(condition, ConditionIR)
    assert condition.op == "zero"
    assert condition.src_insn == 0x4007
    assert condition.producer_insn == 0x4003
    assert condition.lhs == IRBinaryValue(
        op="or",
        lhs=IRValue(
            MemSpace.DS,
            offset=0x0134,
            size=2,
            expr=("cmp-ds",),
            memory_access_size=2,
            memory_access_insn=0x4000,
        ),
        rhs=IRValue(
            MemSpace.DS,
            offset=0x0132,
            size=2,
            expr=("cmp-ds",),
            memory_access_size=2,
            memory_access_insn=0x4003,
        ),
        size=2,
    )
