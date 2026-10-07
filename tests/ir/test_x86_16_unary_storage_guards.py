"""Active computation cannot masquerade as exact storage or a literal target."""
from dataclasses import replace

import pytest
from inertia.ir.core import (
    IRActiveUnary8616,
    IRCondition,
    IRInstr,
    IRValue,
    MemSpace,
)
from inertia.ir.scalar_instruction_effects import (
    ScalarInstructionEffectKind8616,
    scalar_instruction_effect_8616,
)


def _operation():
    return IRActiveUnary8616(
        "Iop_Not16", IRValue(MemSpace.CONST, const=1, size=2), 16,
    )


def test_active_unary_cannot_be_a_destination():
    destination = IRValue(MemSpace.TMP, source_tmp=1, size=2)
    source = IRValue(MemSpace.CONST, const=1, size=2)
    plain = IRInstr("MOV", destination, (source,), size=2)
    assert scalar_instruction_effect_8616(plain).kind is ScalarInstructionEffectKind8616.CLOSED_DESTINATION
    decorated = replace(plain, dst=replace(destination, active_unary=_operation()))
    assert scalar_instruction_effect_8616(decorated).kind is ScalarInstructionEffectKind8616.UNKNOWN


@pytest.mark.parametrize("op", ["JMP", "CJMP"])
def test_active_unary_cannot_be_a_literal_control_target(op):
    target = IRValue(MemSpace.CONST, const=0x1000, size=2)
    condition = IRCondition("nonzero", (IRValue(MemSpace.CONST, const=1, size=1),), width_bits=8)
    args = (target,) if op == "JMP" else (condition, target)
    plain = IRInstr(op, None, args, size=0)
    assert scalar_instruction_effect_8616(plain).kind is ScalarInstructionEffectKind8616.INSTRUCTION_POINTER_WRITE
    target = replace(target, active_unary=_operation())
    args = (target,) if op == "JMP" else (condition, target)
    assert scalar_instruction_effect_8616(replace(plain, args=args)).kind is ScalarInstructionEffectKind8616.UNKNOWN
