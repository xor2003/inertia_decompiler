"""Binary controls for stack-address transport into a near call's data segment."""

import io
from dataclasses import replace

import angr
import pytest
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.callsite_summary import summarize_x86_16_callsite
from inertia.ir.function_ir_registry import (
    publish_function_ir_artifact_8616,
    registered_function_ir_artifact_8616,
)
from inertia.ir.ir_boundary_cfg import prove_ir_boundary_coverage_8616
from inertia.ir.segment_call_preservation import prove_segment_call_preservation_8616
from inertia.ir.segment_effect_closure import prove_segment_effect_closure_8616
from inertia.ir.segment_state import build_x86_16_segment_state_artifact
from inertia.ir.vex_import import build_x86_16_ir_function_artifact
from inertia.lowering.interprocedural_storage_return_pointer import classify_pointer_return_storage_8616
from inertia.lowering.near_pointer_stack_input_segment import bind_near_pointer_stack_input_segment_8616
from inertia.lowering.near_return_segment_use import bind_near_return_data_segment_use_8616

from inertia.frontend.x86_16.frontend_direct_callsite_index import build_boundary_direct_callsite_index_8616
from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from inertia.semantics.call_stack_effect_pipeline import semantic_function_ssa_artifact_at_address_8616
from inertia.semantics.call_target_evidence_8616 import resolve_call_target_evidence_8616
from tests.lowering.test_x86_16_interprocedural_storage_return_pointer import _definition, _fact


def _inputs(equal_segments=True):
    copy = "8cd2 8eda" if equal_segments else "89d9 89d9"
    code = bytes.fromhex("55 8bec " + copy + "8d46fe 50 e80500 89c3 8b0f c3 55 8bec 8b4604 5d c3")
    project = angr.Project(io.BytesIO(code), main_opts={"backend": "blob", "arch": Arch86_16(),
        "base_addr": 0x1000, "entry_point": 0x1000}, auto_load_libs=False)
    boundaries = (exact_function_range_boundary_8616(project, 0x1000, 0x1013),
                  exact_function_range_boundary_8616(project, 0x1013, 0x101b))
    assert all(boundary is not None for boundary in boundaries)
    ssa = semantic_function_ssa_artifact_at_address_8616(
        project, 0x1000, function=boundaries[0]
    ).artifact
    assert ssa is not None
    caller_ir = registered_function_ir_artifact_8616(project, 0x1000).artifact
    assert caller_ir is not None
    callee_ir = build_x86_16_ir_function_artifact(project, boundaries[1])
    publish_function_ir_artifact_8616(project, callee_ir)
    coverage = (prove_ir_boundary_coverage_8616(project, boundaries[0], caller_ir),
                prove_ir_boundary_coverage_8616(project, boundaries[1], callee_ir))
    index = build_boundary_direct_callsite_index_8616(boundaries[0],
        direct_target_resolver=lambda instruction: resolve_direct_call_target_from_instruction_8616(project, instruction))
    closure = prove_segment_effect_closure_8616(coverage[1], build_x86_16_segment_state_artifact(callee_ir))
    preservation = prove_segment_call_preservation_8616(coverage[0], closure, index, 0x100b)
    assert preservation.complete
    fact = replace(_fact(witness=0x100e), callsite_addr=0x100b)
    pointer = classify_pointer_return_storage_8616(
        ssa, fact, _definition(ssa, fact, project=project)
    )
    assert pointer.complete and pointer.pointer_use is not None
    use = bind_near_return_data_segment_use_8616(pointer.pointer_use, preservation, (preservation,))
    assert use.complete
    summary = summarize_x86_16_callsite(boundaries[0], 0x100b)
    assert summary is not None
    return project, ssa, summary, use


@pytest.mark.parametrize("equal_segments", (True, False))
def test_stack_address_requires_actual_selector_equality(equal_segments):
    values = _inputs(equal_segments)
    result = bind_near_pointer_stack_input_segment_8616(*values[:3], 0, values[3])
    assert result.complete is equal_segments
    assert result.classified_fact_count == result.materialized_count == int(equal_segments)
    assert result.failure_count == int(not equal_segments)
    if equal_segments:
        assert result.address.offset == -2
        assert not replace(result, raw_fact_count=True).complete
        assert not replace(result, address=replace(result.address, offset=-4)).complete
        assert not replace(result, caller_ssa=replace(values[1])).complete


@pytest.mark.parametrize("mutation", ("source", "offset", "target", "callsite", "boolean_index"))
def test_unbound_address_or_call_receipts_refuse(mutation):
    project, ssa, summary, use = _inputs()
    logical_index = 0
    if mutation == "source":
        summary = replace(summary, push_arg_sources=(("imm", 2),))
    elif mutation == "offset":
        summary = replace(summary, push_arg_sources=(("bp_addr", -4),))
    elif mutation == "target":
        summary = replace(summary, target_addr=0x2000)
    elif mutation == "callsite":
        summary = replace(summary, callsite_addr=0x100a)
    else:
        logical_index = False
    result = bind_near_pointer_stack_input_segment_8616(project, ssa, summary, logical_index, use)
    assert not result.complete
    assert result.classified_fact_count == result.materialized_count == 0
    assert result.failure_count == 1


def test_pushed_word_source_slices_must_be_contiguous_and_complete():
    """Neither an omitted byte nor duplicate source slices prove a word offset."""
    from inertia.lowering.interprocedural_storage_reaching_defs import (
        resolve_call_argument_reaching_definition_8616,
    )
    from inertia.lowering.near_pointer_stack_input_segment import _logical_stack_address_8616

    project, ssa, summary, _ = _inputs()
    evidence = resolve_call_target_evidence_8616(project, 0x1000)
    assert evidence.complete
    resolution = resolve_call_argument_reaching_definition_8616(ssa, summary, 0,
        project=project, expected_target_addr=0x1013,
        callsite_index=evidence.callsite_index, projection=evidence.projection)
    assert resolution.stats.complete and len(resolution.definitions) == 2
    assert _logical_stack_address_8616(resolution.definitions, -2) is not None
    first, second = resolution.definitions
    assert _logical_stack_address_8616((first,), -2) is None
    assert _logical_stack_address_8616((first, first), -2) is None
    assert _logical_stack_address_8616((first, second), -4) is None
    assert _logical_stack_address_8616((replace(first, source_storage=None), second), -2) is None


@pytest.mark.parametrize("missing", ("projection", "callsite_index"))
def test_stack_address_refuses_incomplete_retained_target_evidence(monkeypatch, missing):
    """A native project cannot substitute for either retained target obligation."""
    import inertia.lowering.near_pointer_stack_input_segment as owner

    project, ssa, summary, use = _inputs()
    evidence = owner.resolve_call_target_evidence_8616(project, 0x1000)
    assert evidence.complete
    incomplete = replace(evidence, **{missing: None})
    assert not incomplete.complete
    monkeypatch.setattr(owner, "resolve_call_target_evidence_8616", lambda *_: incomplete)
    result = bind_near_pointer_stack_input_segment_8616(project, ssa, summary, 0, use)
    assert not result.complete
    assert result.failure is owner.NearPointerStackInputFailure8616.SOURCE_DEFINITION_UNPROVEN
    assert result.classified_fact_count == result.materialized_count == 0
    assert result.failure_count == 1
