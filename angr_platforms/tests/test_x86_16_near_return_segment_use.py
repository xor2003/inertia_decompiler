"""Bind returned offsets to actual DS lifetime, never to a guessed segment."""

import io
from dataclasses import replace

import angr
import pytest
from angr_platforms.X86_16.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.frontend_direct_callsite_index import build_boundary_direct_callsite_index_8616
from angr_platforms.X86_16.frontend_function_boundary import exact_function_range_boundary_8616
from angr_platforms.X86_16.ir.function_ir_registry import publish_function_ir_artifact_8616
from angr_platforms.X86_16.ir.ir_boundary_cfg import prove_ir_boundary_coverage_8616
from angr_platforms.X86_16.ir.segment_call_preservation import prove_segment_call_preservation_8616
from angr_platforms.X86_16.ir.segment_effect_closure import prove_segment_effect_closure_8616
from angr_platforms.X86_16.ir.segment_state import build_x86_16_segment_state_artifact
from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact
from angr_platforms.X86_16.lowering.interprocedural_storage_return_pointer import classify_pointer_return_storage_8616
from test_x86_16_interprocedural_storage_return_pointer import _definition, _fact


def _receipt(caller_write: bool = False, callee_write: bool = False, selector: str = "ds", *, boot=None):
    selector_copy = {"ds": "", "ss": "8cda 8ed2 36", "es": "8cda 8ec2 26", "stack_entry": "36"}[selector]
    caller_code = bytes.fromhex("e81000 89c3 " + ("b80000 8ed8 " if caller_write else "") + selector_copy + "8b0f c3")
    callee_code = bytes.fromhex("b80000 8ed8 c3" if callee_write else "c3")
    image = caller_code + bytes(0x13 - len(caller_code)) + callee_code
    image += bytes(0x30 - len(image)) + bytes.fromhex("161f e8cbff c3")
    if boot is not None:
        # Consume the relocated bytes authenticated by initialized MZ startup.
        image = boot.image.chunks[0][1]
    project = angr.Project(io.BytesIO(image), main_opts={"backend": "blob", "arch": Arch86_16(),
        "base_addr": 0x1000, "entry_point": 0x1000}, auto_load_libs=False)
    boundaries = (exact_function_range_boundary_8616(project, 0x1000, 0x1000 + len(caller_code)),
                  exact_function_range_boundary_8616(project, 0x1013, 0x1013 + len(callee_code)))
    assert all(boundary is not None for boundary in boundaries)
    raw = tuple(build_x86_16_ir_function_artifact(project, boundary) for boundary in boundaries)
    for artifact in raw:
        publish_function_ir_artifact_8616(project, artifact)
    coverage = tuple(prove_ir_boundary_coverage_8616(project, boundary, artifact)
                     for boundary, artifact in zip(boundaries, raw, strict=True))
    assert all(item.complete for item in coverage)
    index = build_boundary_direct_callsite_index_8616(boundaries[0],
        direct_target_resolver=lambda instruction: resolve_direct_call_target_from_instruction_8616(project, instruction))
    closure = prove_segment_effect_closure_8616(coverage[1], build_x86_16_segment_state_artifact(raw[1]))
    preservation = prove_segment_call_preservation_8616(coverage[0], closure, index, 0x1000)
    assert preservation.complete
    ssa = build_x86_16_function_ssa(raw[0])
    fact = _fact()
    classified = classify_pointer_return_storage_8616(ssa, fact, _definition(ssa, fact, project=project))
    assert classified.complete and classified.pointer_use is not None
    return classified.pointer_use, preservation, project


@pytest.mark.parametrize("selector", ("ss", "es"))
def test_other_selectors_require_actual_data_segment_copy(selector: str) -> None:
    """Raw MOV segment effects can establish equality without an ABI assumption."""
    from angr_platforms.X86_16.ir import MemSpace
    from angr_platforms.X86_16.lowering.near_return_segment_use import bind_near_return_data_segment_use_8616

    use, preservation, _ = _receipt(selector=selector)
    assert use.address.space is MemSpace(selector)
    result = bind_near_return_data_segment_use_8616(use, preservation, (preservation,))
    assert result.complete
    assert (result.raw_fact_count, result.normalized_fact_count, result.classified_fact_count,
            result.materialized_count, result.failure_count) == (1, 1, 1, 1, 0)


def test_stack_selector_consumes_only_retained_caller_entry_context() -> None:
    """A real upstream near call establishes DS==SS for this invocation only."""
    from angr_platforms.X86_16.alias.segment_stack_restore import build_x86_16_segment_stack_restore_artifact
    from angr_platforms.X86_16.ir.direct_call_segment_context import bind_direct_call_segment_context_8616
    from angr_platforms.X86_16.ir.real16_invocation_domain import prove_real16_invocation_domain_8616
    from angr_platforms.X86_16.lowering.near_return_segment_use import bind_near_return_data_segment_use_8616
    from test_x86_16_invocation_domain import _boot, _recompute

    boot = _boot()
    use, preservation, project = _receipt(selector="stack_entry", boot=boot)
    boundary = exact_function_range_boundary_8616(project, 0x1030, 0x1036)
    assert boundary is not None
    raw = build_x86_16_ir_function_artifact(project, boundary)
    publish_function_ir_artifact_8616(project, raw)
    coverage = prove_ir_boundary_coverage_8616(project, boundary, raw)
    index = build_boundary_direct_callsite_index_8616(boundary,
        direct_target_resolver=lambda instruction: resolve_direct_call_target_from_instruction_8616(project, instruction))
    sources = build_x86_16_segment_stack_restore_artifact(raw).restore_sources
    # The backward near call has different physical targets for unrestricted
    # CS values. Segment equality alone must not admit that target.
    unbound = bind_direct_call_segment_context_8616(
        coverage, preservation.caller, index, sources, 0x1032,
    )
    assert not unbound.complete
    invocation = prove_real16_invocation_domain_8616(
        project, coverage, 0x1032, boot=boot, boot_recompute=_recompute,
        call_preservations=(preservation,),
    )
    assert invocation.complete
    context = bind_direct_call_segment_context_8616(
        coverage, preservation.caller, index, sources, 0x1032,
        invocation=invocation,
    )
    assert context.complete
    assert context.invocation is invocation
    assert not bind_near_return_data_segment_use_8616(use, preservation, (preservation,)).complete
    result = bind_near_return_data_segment_use_8616(use, preservation, (preservation,), caller_entry_context=context)
    assert result.complete
    assert not replace(result, caller_entry_context=None).complete
    foreign = replace(context, callee=replace(context.callee, artifact=replace(context.callee.artifact)))
    assert not replace(result, caller_entry_context=foreign).complete


@pytest.mark.parametrize("caller_write,callee_write,accepted", ((False, False, True),
                                                              (True, False, False), (False, True, False)))
def test_actual_caller_and_callee_segment_effects_bind_the_return(caller_write: bool, callee_write: bool, accepted: bool) -> None:
    from angr_platforms.X86_16.lowering.near_return_segment_use import bind_near_return_data_segment_use_8616

    use, preservation, _ = _receipt(caller_write, callee_write)
    result = bind_near_return_data_segment_use_8616(use, preservation, (preservation,))
    assert result.complete is accepted
    assert result.materialized_count == int(accepted)
    assert result.failure_count == int(not accepted)
    if accepted:
        assert not replace(result, materialized_count=0).complete
        assert not replace(result, raw_fact_count=True).complete
        assert not replace(result, caller_preservations=()).complete
        assert not replace(result, pointer_use=replace(use, callsite_addr=0x1001)).complete
        assert not replace(result, call_preservation=replace(preservation,
            caller=replace(preservation.caller, artifact=replace(preservation.caller.artifact)))).complete


@pytest.mark.parametrize("mode", ("absent", "duplicate", "foreign_use", "stack_selector"))
def test_segment_use_refuses_unbound_or_ambiguous_receipts(mode: str) -> None:
    from angr_platforms.X86_16.ir import MemSpace
    from angr_platforms.X86_16.lowering.near_return_segment_use import bind_near_return_data_segment_use_8616

    use, preservation, _ = _receipt()
    proofs = (preservation,)
    if mode == "absent":
        proofs = ()
    elif mode == "duplicate":
        proofs = (preservation, preservation)
    elif mode == "foreign_use":
        use = replace(use, caller_addr=0x2000)
    else:
        use = replace(use, address=replace(use.address, space=MemSpace.SS))
    result = bind_near_return_data_segment_use_8616(use, preservation, proofs)
    assert not result.complete and result.failure_count == 1
    assert result.classified_fact_count == result.materialized_count == 0
