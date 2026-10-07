"""Exact physical-to-logical far callback argument evidence."""

from __future__ import annotations

from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.lowering.call_argument_shape import (
    CallerStackObject8616,
    LogicalArgumentShapeEvidenceSource8616,
    exact_far_callback_call_shape_evidence_8616,
)
from inertia.lowering.far_callback_call_shape import (
    FarCallbackCallShapeRefusalKind8616,
    publish_binary_far_callback_shapes_8616,
)
from inertia.lowering.function_pointer_parameter_evidence import (
    FunctionPointerParameterFact8616,
)

from inertia.lowering.analysis_helpers import CallTargetKind8616
from inertia.cli.project_loading import _build_project_from_bytes


def _caller(*, high_offset: int = -2) -> CallsiteSummary8616:
    """Model the exact far caller's three physical word pushes."""
    return CallsiteSummary8616(
        callsite_addr=0x1009B,
        target_addr=0x10034,
        return_addr=0x100A0,
        kind=CallTargetKind8616.DIRECT_FAR_CALL,
        arg_count=3,
        arg_widths=(2, 2, 2),
        stack_cleanup=6,
        return_register="ax",
        return_used=True,
        push_arg_sources=(("bp", 8, 2), ("bp", high_offset, 2), ("bp", -4, 2)),
    )


def _callee_indirect(callsite_addr: int) -> CallsiteSummary8616:
    """Model one callee indirect CALL FAR through its first parameter."""
    return CallsiteSummary8616(
        callsite_addr=callsite_addr,
        target_addr=None,
        return_addr=callsite_addr + 3,
        kind=None,
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register="ax",
        return_used=True,
        target_source=("bp", 6, 4),
        push_arg_sources=(("bp", 10, 2),),
    )


def _fact(*, pointer_width: int = 4) -> FunctionPointerParameterFact8616:
    """Retain the callee's binary-classified first parameter contract."""
    return FunctionPointerParameterFact8616(
        stack_offset=6,
        argument_widths=(2,),
        return_width=2,
        callsite_addresses=(0x10044, 0x10050),
        pointer_width=pointer_width,
    )


def test_far_callback_word_pair_has_exact_logical_shape() -> None:
    """The callee ABI and caller pushes prove a four-byte first argument."""
    evidence = exact_far_callback_call_shape_evidence_8616(
        _caller(),
        callee_addr=0x10034,
        callee_fact=_fact(),
        callee_indirect_calls=(_callee_indirect(0x10044), _callee_indirect(0x10050)),
    )

    assert evidence is not None
    assert evidence.widths == (4, 2)
    assert evidence.source is LogicalArgumentShapeEvidenceSource8616.EXACT_CALLEE_ABI


def test_far_callback_shape_refuses_nonadjacent_caller_words() -> None:
    """Numeric proximity to code is not a substitute for exact pushed slices."""
    assert exact_far_callback_call_shape_evidence_8616(
        _caller(high_offset=-8),
        callee_addr=0x10034,
        callee_fact=_fact(),
        callee_indirect_calls=(_callee_indirect(0x10044), _callee_indirect(0x10050)),
    ) is None


def test_far_callback_shape_refuses_near_or_incomplete_callee_proof() -> None:
    """Both far width and every callee indirect call are required."""
    calls = (_callee_indirect(0x10044), _callee_indirect(0x10050))
    assert exact_far_callback_call_shape_evidence_8616(
        _caller(), callee_addr=0x10034, callee_fact=_fact(pointer_width=2), callee_indirect_calls=calls
    ) is None
    assert exact_far_callback_call_shape_evidence_8616(
        _caller(), callee_addr=0x10034, callee_fact=_fact(), callee_indirect_calls=calls[:1]
    ) is None


def test_binary_far_callback_shape_is_published_without_changing_physical_pushes() -> None:
    """Decoded callee calls can publish a logical shape for the caller."""
    image = bytearray(0x100)
    image[0x34:0x43] = bytes.fromhex("55 8b ec ff 76 0a ff 5e 06 83 c4 02 5d cb 90")
    project = _build_project_from_bytes(bytes(image), base_addr=0x10000, entry_point=0x10034)
    caller = _caller()

    result = publish_binary_far_callback_shapes_8616(
        project,
        {caller.callsite_addr: caller},
        caller_stack_objects=(CallerStackObject8616(-4, 4),),
    )

    published = result.inventory[caller.callsite_addr]
    assert published.arg_widths == (2, 2, 2)
    assert published.push_arg_sources == caller.push_arg_sources
    assert published.logical_arg_widths == (4, 2)
    assert (result.raw_fact_count, result.normalized_fact_count, result.classified_fact_count) == (1, 1, 1)
    assert result.materialized_count == 1
    assert result.failure_count == 0
    assert result.refusals == ()
    assert result.complete


def test_binary_far_callback_shape_refuses_without_widened_caller_storage() -> None:
    """A callee ABI alone cannot make two local words one C pointer object."""
    image = bytearray(0x100)
    image[0x34:0x43] = bytes.fromhex("55 8b ec ff 76 0a ff 5e 06 83 c4 02 5d cb 90")
    project = _build_project_from_bytes(bytes(image), base_addr=0x10000, entry_point=0x10034)
    caller = _caller()

    result = publish_binary_far_callback_shapes_8616(
        project,
        {caller.callsite_addr: caller},
        caller_stack_objects=(),
    )

    assert result.inventory[caller.callsite_addr] is caller
    assert result.raw_fact_count == 1
    assert result.normalized_fact_count == 1
    assert result.classified_fact_count == 0
    assert result.materialized_count == 0
    assert result.failure_count == 1
    assert result.refusals[0].kind is FarCallbackCallShapeRefusalKind8616.NO_WIDENED_CALLER_OBJECT
    assert result.refusals[0].callsite_addr == caller.callsite_addr
    assert result.complete

    separate_words = publish_binary_far_callback_shapes_8616(
        project,
        {caller.callsite_addr: caller},
        caller_stack_objects=(CallerStackObject8616(-4, 2), CallerStackObject8616(-2, 2)),
    )
    assert separate_words.inventory[caller.callsite_addr] is caller
    assert separate_words.materialized_count == 0
    assert separate_words.failure_count == 1
    assert separate_words.complete


def test_binary_far_callback_shape_records_incomplete_callee_and_abi_refusals() -> None:
    """Every attempted far callback must close as one publication or typed refusal."""
    image = bytearray(0x100)
    project = _build_project_from_bytes(bytes(image), base_addr=0x10000, entry_point=0x10034)
    caller = _caller()
    missing = publish_binary_far_callback_shapes_8616(
        project,
        {caller.callsite_addr: caller},
        caller_stack_objects=(CallerStackObject8616(-4, 4),),
    )
    assert missing.refusals[0].kind is FarCallbackCallShapeRefusalKind8616.NO_CALLEE_EVIDENCE
    assert missing.failure_count == 1
    assert missing.complete

    image[0x34:0x43] = bytes.fromhex("55 8b ec ff 76 0a ff 5e 06 83 c4 02 5d cb 90")
    project = _build_project_from_bytes(bytes(image), base_addr=0x10000, entry_point=0x10034)
    incompatible = publish_binary_far_callback_shapes_8616(
        project,
        {caller.callsite_addr: _caller(high_offset=-8)},
        caller_stack_objects=(CallerStackObject8616(-4, 4),),
    )
    assert incompatible.refusals[0].kind is FarCallbackCallShapeRefusalKind8616.ABI_NOT_PROVEN
    assert incompatible.failure_count == 1
    assert incompatible.complete
