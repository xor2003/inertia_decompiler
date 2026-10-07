"""Tests for binary-proven direct global-to-stack copies."""

from __future__ import annotations

from types import SimpleNamespace

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.real_mode_linear import (
    DirectStackMoveExpressionOp8616,
    DirectStackMoveSourceKind8616,
    _direct_stack_move_instruction_facts_8616,
)
from capstone.x86_const import (
    X86_INS_MOV,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_AX,
    X86_REG_BP,
    X86_REG_INVALID,
)


def _register_operand(register: int) -> SimpleNamespace:
    """Build one word register operand at the Capstone boundary."""
    return SimpleNamespace(type=X86_OP_REG, size=2, reg=register)


def _memory_operand(*, base: int, displacement: int) -> SimpleNamespace:
    """Build one word memory operand at the Capstone boundary."""
    return SimpleNamespace(
        type=X86_OP_MEM,
        size=2,
        mem=SimpleNamespace(
            base=base,
            index=X86_REG_INVALID,
            scale=1,
            disp=displacement,
        ),
    )


def test_collects_unmodified_global_word_copy_into_stack_slot() -> None:
    """An adjacent global load/store must retain its exact source identity."""
    load = SimpleNamespace(
        address=0x4010,
        id=X86_INS_MOV,
        operands=(
            _register_operand(X86_REG_AX),
            _memory_operand(base=X86_REG_INVALID, displacement=0x0BA2),
        ),
    )
    store = SimpleNamespace(
        address=0x4013,
        id=X86_INS_MOV,
        operands=(
            _memory_operand(base=X86_REG_BP, displacement=-4),
            _register_operand(X86_REG_AX),
        ),
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(load, store))),),
    )

    facts = _direct_stack_move_instruction_facts_8616(
        SimpleNamespace(arch=Arch86_16()),
        function,
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.source_kind is DirectStackMoveSourceKind8616.GLOBAL_EXPR
    assert fact.source_global_displacement == 0x0BA2
    assert fact.source_op is DirectStackMoveExpressionOp8616.ADD
    assert fact.source_immediate == 0
    assert fact.dst_offset == -4
