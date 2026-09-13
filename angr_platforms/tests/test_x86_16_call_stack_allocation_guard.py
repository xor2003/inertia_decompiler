"""Reject stack-allocation requests masquerading as balanced CALL proofs."""

from dataclasses import replace

import pytest
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.ir import IRBlock, IRFunctionArtifact, IRInstr
from angr_platforms.X86_16.semantics.call_stack_effect_contracts import CallStackEffectFailure8616
from angr_platforms.X86_16.semantics.call_stack_effects import materialize_call_stack_effects_8616


def _summary() -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=0x1000,
        target_addr=0x2000,
        return_addr=0x1003,
        kind="direct_near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=0,
        return_register=None,
        return_used=False,
    )


def _effects(summary: CallsiteSummary8616):
    artifact = IRFunctionArtifact(
        0x1000, (IRBlock(0x1000, (IRInstr("CALL", None, (), addr=0x1000),)),)
    )
    return materialize_call_stack_effects_8616(artifact, {0x1000: summary})


@pytest.mark.parametrize("allocation", [None, 0, 18])
def test_probe_request_is_not_proof_of_a_balanced_call(allocation):
    summary = replace(
        _summary(), stack_probe_helper=True, stack_probe_allocation_size=allocation
    )
    result = _effects(summary)

    assert not result.complete
    assert result.stats.closed
    assert result.stats.failure_count == 1
    assert result.facts[0].effect.net_stack_delta is None
    assert not result.facts[0].effect.complete
    assert result.facts[0].failure is CallStackEffectFailure8616.STACK_ALLOCATION_UNPROVEN


def test_allocation_without_helper_classification_cannot_be_ignored():
    result = _effects(replace(_summary(), stack_probe_allocation_size=18))

    assert not result.complete
    assert result.facts[0].failure is CallStackEffectFailure8616.STACK_ALLOCATION_UNPROVEN


def test_ordinary_zero_argument_call_still_has_balanced_stack_effect():
    result = _effects(_summary())

    assert result.complete
    assert result.facts[0].effect.net_stack_delta == 0
