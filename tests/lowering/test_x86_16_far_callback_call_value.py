"""Path-correlated caller Value proofs for a split far callback argument."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.ir.core import IRFunctionArtifact
from inertia.ir.logical_memory_write_value import trace_logical_word_write_values_8616
from inertia.ir.ssa_function import SSAFunctionArtifact, build_x86_16_function_ssa
from inertia.ir.vex_import import build_x86_16_ir_function_artifact
from inertia.ir.vex_terminal_jump import TerminalJumpRefusalReason8616
from inertia.lowering.far_callback_call_value import (
    FarCallbackCallValueFailureKind8616,
    prove_far_callback_call_path_values_8616,
)
from inertia.lowering.function_pointer_parameter_evidence import (
    FunctionPointerParameterFact8616,
)

from inertia.lowering.analysis_helpers import CallTargetKind8616
from inertia.cli.project_loading import _build_project_from_bytes


def _caller_source(base_addr: int) -> IRFunctionArtifact:
    """Retain identical callback bytes in either admitted or ambiguous layout."""
    code = bytes.fromhex(
        "55 8b ec 83 ec 04 83 f8 00 74 0c "
        "c7 46 fc 00 00 c7 46 fe 00 10 eb 0c "
        "c7 46 fc 1a 00 c7 46 fe 00 10 eb 00 "
        "ff 76 08 ff 76 fe ff 76 fc "
        "9a 34 00 00 10 83 c4 06 8b e5 5d cb"
    )
    project = _build_project_from_bytes(code, base_addr=base_addr, entry_point=base_addr)
    function = SimpleNamespace(
        addr=base_addr,
        block_addrs_set={base_addr + offset for offset in (0, 0x0B, 0x17, 0x23)},
        graph=SimpleNamespace(edges=tuple(
            (base_addr + source, base_addr + target)
            for source, target in ((0, 0x0B), (0, 0x17), (0x0B, 0x23), (0x17, 0x23))
        )),
        info={},
    )
    return build_x86_16_ir_function_artifact(project, function)


def _caller_ssa() -> SSAFunctionArtifact:
    """Prove callback words only in the selector-invariant positive layout."""
    source = _caller_source(0x1000)
    assert not source.refusals
    return build_x86_16_function_ssa(source)


@pytest.mark.parametrize("base_addr", (0x10000, 0x10065))
def test_original_high_callback_layout_keeps_unproved_control(base_addr: int) -> None:
    """Original high layouts need a CS premise, not a substituted low fixture."""
    source = _caller_source(base_addr)
    assert len(source.refusals) == 1
    assert source.refusals[0].kind == TerminalJumpRefusalReason8616.SELECTOR_WINDOW_UNPROVED
    assert source.refusals[0].block_addr == base_addr + 0x0B


def _caller() -> CallsiteSummary8616:
    """Retain physical argument and instruction identities from the CALL."""
    return CallsiteSummary8616(
        callsite_addr=0x102C, target_addr=0x10034, return_addr=0x1031,
        kind=CallTargetKind8616.DIRECT_FAR_CALL, arg_count=3,
        arg_widths=(2, 2, 2), stack_cleanup=6, return_register="ax", return_used=True,
        push_arg_sources=(("bp", 8, 2), ("bp", -2, 2), ("bp", -4, 2)),
        push_arg_instruction_addrs=(0x1023, 0x1026, 0x1029),
    )


def _callee_indirect(addr: int) -> CallsiteSummary8616:
    """Supply two exact indirect far uses of the callee's first parameter."""
    return CallsiteSummary8616(
        callsite_addr=addr, target_addr=None, return_addr=addr + 3,
        kind=None, arg_count=1, arg_widths=(2,), stack_cleanup=2,
        return_register="ax", return_used=True, target_source=("bp", 6, 4),
        push_arg_sources=(("bp", 10, 2),),
    )


def _callee_fact() -> FunctionPointerParameterFact8616:
    """Supply the decoded first-parameter callback ABI contract."""
    return FunctionPointerParameterFact8616(
        stack_offset=6, argument_widths=(2,), return_width=2,
        callsite_addresses=(0x10044, 0x10050), pointer_width=4,
    )


def _prove(ssa: SSAFunctionArtifact, caller: CallsiteSummary8616):
    """Run the public join against the caller's exact logical writes."""
    return prove_far_callback_call_path_values_8616(
        ssa, trace_logical_word_write_values_8616(ssa), caller,
        callee_fact=_callee_fact(),
        callee_indirect_calls=(_callee_indirect(0x10044), _callee_indirect(0x10050)),
    )


def test_far_callback_words_join_by_same_cfg_predecessor() -> None:
    """Every path retains its own offset and the exact paired code segment."""
    result = _prove(_caller_ssa(), _caller())
    assert result.closed and result.proof is not None
    assert result.refusal is None
    assert result.proof.complete
    assert tuple((path.source_block_addr, path.offset, path.segment)
                 for path in result.proof.paths) == (
        (0x100B, 0, 0x1000), (0x1017, 0x1A, 0x1000),
    )
    assert result.proof.logical_widths == (4, 2)
    assert result.proof.caller.push_arg_sources == _caller().push_arg_sources
    assert not replace(result, callsite_addr=result.callsite_addr + 1).closed
    assert not replace(result, materialized_count=0).closed
    assert not replace(result.proof, paths=result.proof.paths[:1]).complete
    assert (result.raw_fact_count, result.normalized_fact_count,
            result.classified_fact_count, result.materialized_count,
            result.failure_count) == (1, 1, 1, 1, 0)


def test_far_callback_values_refuse_missing_exact_push_identity() -> None:
    """A BP source without its decoded PUSH address cannot select a read."""
    result = _prove(_caller_ssa(), replace(_caller(), push_arg_instruction_addrs=()))
    assert result.closed and result.proof is None
    assert result.refusal is not None
    assert result.refusal.kind is FarCallbackCallValueFailureKind8616.MISSING_PUSH_IDENTITY
    assert not replace(result, refusal=replace(
        result.refusal, callsite_addr=result.refusal.callsite_addr + 1,
    )).closed


def test_far_callback_values_refuse_swapped_push_identity() -> None:
    """Do not pair values from a different memory read or guessed order."""
    result = _prove(_caller_ssa(), replace(
        _caller(), push_arg_instruction_addrs=(0x1023, 0x1029, 0x1026),
    ))
    assert result.closed and result.proof is None
    assert result.refusal is not None
    assert result.refusal.kind is FarCallbackCallValueFailureKind8616.MISSING_PUSH_IDENTITY


def test_far_callback_values_refuse_unrelated_word_read() -> None:
    """A monotonic PUSH address still needs a matching BP word LOAD."""
    result = _prove(_caller_ssa(), replace(
        _caller(), push_arg_instruction_addrs=(0x1023, 0x1024, 0x1029),
    ))
    assert result.closed and result.proof is None
    assert result.refusal is not None
    assert result.refusal.kind is FarCallbackCallValueFailureKind8616.MISSING_WORD_READ


def test_far_callback_values_refuse_incompatible_callee_abi() -> None:
    """Typed word values alone are not enough to classify a far callback."""
    ssa = _caller_ssa()
    result = prove_far_callback_call_path_values_8616(
        ssa, trace_logical_word_write_values_8616(ssa), _caller(),
        callee_fact=replace(_callee_fact(), pointer_width=2),
        callee_indirect_calls=(_callee_indirect(0x10044), _callee_indirect(0x10050)),
    )
    assert result.closed and result.proof is None
    assert result.refusal is not None
    assert result.refusal.kind is FarCallbackCallValueFailureKind8616.ABI_NOT_PROVEN
