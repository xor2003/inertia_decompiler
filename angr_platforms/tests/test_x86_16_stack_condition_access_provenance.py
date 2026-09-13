"""A memory comparison retains its load address separately from its branch."""

import pytest
import pyvex
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.core import IRValue, MemSpace
from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

CODE_BASE = 0x4000
WORD_BYTES = 2

@pytest.mark.parametrize("machine_code,side", [
    ("837efe63740290c3", "lhs"),
    ("3946fe740290c3", "lhs"),
    ("3b46fe740290c3", "rhs"),
])
def test_stack_compare_retains_exact_memory_access(monkeypatch, machine_code, side):
    monkeypatch.setattr(Instruction_ANY, "_inertia_module_condition_cache", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_pending_condition_sources_by_addr", {})
    monkeypatch.setattr(Instruction_ANY, "_inertia_condition_reg_value_state_8616", {})
    pyvex.lift(bytes.fromhex(machine_code), CODE_BASE, Arch86_16(), opt_level=0)
    [condition] = Instruction_ANY._inertia_module_condition_cache[CODE_BASE]
    operand = condition.lhs if side == "lhs" else condition.rhs
    assert isinstance(operand, IRValue)
    assert (operand.space, operand.offset, operand.size) == (MemSpace.SS, -2, 2)
    assert operand.memory_access_insn == CODE_BASE
    assert operand.memory_access_size == WORD_BYTES
    assert condition.src_insn != operand.memory_access_insn


def test_stack_operand_without_access_evidence_does_not_invent_a_producer():
    operand = Instruction_ANY._condition_stack_value_8616(("bp", 0xFFFE, -2))
    assert operand is not None
    assert operand.memory_access_insn is None
    assert operand.memory_access_size is None
