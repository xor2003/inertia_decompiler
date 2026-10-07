"""Entry-word value liveness consumes the shared typed IR effect owner.

Layer: Widening regression tests.
Responsibility: preserve unchanged data words through closed pure/control
effects, while retaining IP clobbers, unknown effects and CALL refusals.
No control-frontier, flags, callee or generated-C acceptance is implied.
"""

from __future__ import annotations

import pytest
from inertia.ir.core import IRCondition, IRInstr
from tests.fixtures.entry_stack_byte_test_support import _const, _mov, _reg, _tmp
from tests.widening.test_x86_16_entry_stack_word_values import _prove, _word_instrs

from inertia.widening.entry_stack_word_value_contracts import (
    EntryStackWordVerdict8616 as Verdict,
)


def _conditional() -> IRInstr:
    """A typed IP-only branch leaves unrelated data registers unchanged."""
    return IRInstr(
        "CJMP", None,
        (IRCondition("eq", (_const(1, 1),)), _const(0x10600)),
    )


@pytest.mark.parametrize("effect", [
    IRInstr("Iop_CmpLT16U", _tmp(90, 1), (_const(1), _const(2)), size=1),
    _conditional(),
])
def test_closed_non_data_effect_preserves_entry_word(effect: IRInstr) -> None:
    """The exact existing CX word survives without a new memory read."""
    instructions = [*_word_instrs(), effect, _mov(_reg("dx"), _reg("cx"))]
    proof = _prove(instructions, len(instructions) - 1)
    assert proof.verdict is Verdict.PROVEN
    assert proof.fact is not None and proof.fact.target_name == "dx"
    assert (proof.raw_fact_count, proof.normalized_fact_count,
            proof.classified_fact_count, proof.materialized_count,
            proof.failure_count) == (1, 1, 1, 1, 0)


def test_conditional_does_not_preserve_entry_word_in_ip() -> None:
    """An IP-only effect still invalidates an earlier word held in IP."""
    instructions = [*_word_instrs("ip"), _conditional(), _mov(_reg("dx"), _reg("ip"))]
    assert _prove(instructions, len(instructions) - 1).verdict is Verdict.REFUSED


@pytest.mark.parametrize("effect", [
    IRInstr("Iop_CmpLTU16", _tmp(90, 1), (_const(1), _const(2)), size=1),
    IRInstr("Iop_CmpLT16U", _tmp(90, 2), (_const(1), _const(2)), size=2),
    IRInstr("OPAQUE", None, ()),
    IRInstr("CALL", _const(0x10600), ()),
])
def test_unknown_or_call_effect_does_not_preserve_current_word(effect: IRInstr) -> None:
    """Unproved clobbers cannot become a guessed register-preservation fact."""
    instructions = [*_word_instrs(), effect, _mov(_reg("dx"), _reg("cx"))]
    assert _prove(instructions, len(instructions) - 1).verdict is Verdict.REFUSED
