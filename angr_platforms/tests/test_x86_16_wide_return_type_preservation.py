"""Argument-width evidence must not overwrite an established wide return type."""

from types import SimpleNamespace

import pytest
from angr.sim_type import SimTypeFunction, SimTypeLong, SimTypeShort
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.calling_convention_compat import _wide_stack_arithmetic_prototype_from_evidence_8616
from angr_platforms.X86_16.widening.stack_argument_widths import WideStackArgumentWidthEvidence8616


@pytest.mark.parametrize("signed", [False, True])
def test_wide_width_promotion_retains_existing_return_signedness(signed):
    arch = Arch86_16()
    return_type = SimTypeLong(signed).with_arch(arch)
    word = SimTypeShort(False).with_arch(arch)
    function = SimpleNamespace(prototype=SimTypeFunction([word, word], return_type).with_arch(arch))
    result = _wide_stack_arithmetic_prototype_from_evidence_8616(
        SimpleNamespace(arch=arch), function,
        evidence=WideStackArgumentWidthEvidence8616(1, 1, (4,)),
        loaded_offsets=(4, 6), signed=not signed, terminal_wide_return=True,
    )
    assert result is not None
    _, prototype, evidence = result
    assert prototype.returnty is return_type
    assert prototype.returnty.signed is signed
    assert isinstance(prototype.args[0], SimTypeLong)
    assert evidence.materialized_count == 1
