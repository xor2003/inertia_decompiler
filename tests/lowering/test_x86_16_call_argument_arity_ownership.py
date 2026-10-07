"""Tests for binary-owned callsite arity preservation."""

from __future__ import annotations

from dataclasses import replace

from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.lowering.call_argument_arity_ownership import (
    CallsiteZeroArgumentDecision8616,
    classify_callsite_zero_argument_ownership_8616,
)


def _summary() -> CallsiteSummary8616:
    """Return one complete direct zero-argument binary callsite summary."""
    return CallsiteSummary8616(
        callsite_addr=0x10F52,
        target_addr=0x1137E,
        return_addr=0x10F55,
        kind="direct_near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=0,
        return_register="ax",
        return_used=True,
    )


def test_complete_zero_argument_summary_refuses_nonzero_candidate() -> None:
    """A fallback candidate cannot override exact empty PUSH/cleanup evidence."""
    result = classify_callsite_zero_argument_ownership_8616(_summary(), 1)

    assert result.decision is CallsiteZeroArgumentDecision8616.REFUSE_NONZERO_CANDIDATE
    assert result.enforces_zero_arguments
    assert result.blocks_candidate
    assert result.classified_fact_count == result.materialized_count == 1
    assert result.failure_count == 0


def test_complete_zero_argument_summary_preserves_empty_candidate() -> None:
    """The already-empty generated call satisfies the authoritative fact."""
    result = classify_callsite_zero_argument_ownership_8616(_summary(), 0)

    assert result.decision is CallsiteZeroArgumentDecision8616.PRESERVE_ZERO_ARGUMENT
    assert result.enforces_zero_arguments
    assert not result.blocks_candidate


def test_incomplete_zero_argument_summary_fails_closed() -> None:
    """Conflicting physical widths cannot authorize candidate materialization."""
    result = classify_callsite_zero_argument_ownership_8616(
        replace(_summary(), arg_widths=(2,)),
        1,
    )

    assert result.decision is CallsiteZeroArgumentDecision8616.INVALID_ZERO_ARGUMENT_FACT
    assert not result.enforces_zero_arguments
    assert result.blocks_candidate
    assert result.failure_count == 1


def test_positive_argument_summary_does_not_claim_zero_arity() -> None:
    """Nonzero binary arity remains owned by normal argument materialization."""
    result = classify_callsite_zero_argument_ownership_8616(
        replace(
            _summary(),
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            push_arg_sources=(("imm", 15),),
            push_arg_instruction_addrs=(0x10F50,),
            stack_cleanup_instruction_addr=0x10F55,
        ),
        1,
    )

    assert result.decision is CallsiteZeroArgumentDecision8616.NOT_ZERO_ARGUMENT
    assert not result.enforces_zero_arguments
    assert not result.blocks_candidate
