"""Keep callee segment entry equality exact-callsite-bound and fail closed."""

import io
from dataclasses import replace

import angr
import pytest
from angr_platforms.X86_16.alias.segment_stack_restore import build_x86_16_segment_stack_restore_artifact
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.frontend_function_boundary import exact_function_range_boundary_8616
from angr_platforms.X86_16.ir.core import SegmentOrigin
from angr_platforms.X86_16.ir.direct_call_segment_context import bind_direct_call_segment_context_8616
from angr_platforms.X86_16.ir.function_ir_registry import publish_function_ir_artifact_8616
from angr_platforms.X86_16.ir.ir_boundary_cfg import prove_ir_boundary_coverage_8616
from angr_platforms.X86_16.ir.segment_effect_closure import (
    SegmentEffectClosureFailure8616,
    prove_segment_effect_closure_8616,
)
from angr_platforms.X86_16.ir.segment_state import build_x86_16_segment_state_artifact
from angr_platforms.X86_16.ir.segment_state_transfer import SegmentValueKind8616
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact
from test_x86_16_direct_call_segment_entry import _binary_callsite_index


def _context(callee_code: str = "c3", caller_prefix: str = "16 1f"):
    prefix = bytes.fromhex(caller_prefix)
    code = prefix + bytes.fromhex("e8 02 00 c3 90 " + callee_code)
    callsite = 0x1000 + len(prefix)
    callee_addr = callsite + 5
    project = angr.Project(io.BytesIO(code), main_opts={
        "backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000, "entry_point": 0x1000,
    }, auto_load_libs=False)
    caller = exact_function_range_boundary_8616(project, 0x1000, callsite + 4)
    callee = exact_function_range_boundary_8616(project, callee_addr, 0x1000 + len(code))
    assert caller is not None and callee is not None
    raw_caller = build_x86_16_ir_function_artifact(project, caller)
    raw_callee = build_x86_16_ir_function_artifact(project, callee)
    publish_function_ir_artifact_8616(project, raw_caller)
    publish_function_ir_artifact_8616(project, raw_callee)
    sources = build_x86_16_segment_stack_restore_artifact(raw_caller).restore_sources
    caller_coverage = prove_ir_boundary_coverage_8616(project, caller, raw_caller)
    callee_coverage = prove_ir_boundary_coverage_8616(project, callee, raw_callee)
    assert caller_coverage.complete, caller_coverage
    assert callee_coverage.complete, callee_coverage
    return bind_direct_call_segment_context_8616(
        caller_coverage, callee_coverage,
        _binary_callsite_index(project, caller), sources, callsite,
    )


def test_contextual_entry_preserves_equality_without_global_publication() -> None:
    context = _context()
    assert context.complete
    artifact = context.callee.artifact
    ordinary = build_x86_16_segment_state_artifact(artifact)
    contextual = build_x86_16_segment_state_artifact(artifact, entry_context=context)
    assert ordinary.entry_states[artifact.function_addr]["ds"].source == "ds"
    assert contextual.entry_states[artifact.function_addr]["ds"].source == "ss"
    assert contextual.entry_states[artifact.function_addr]["ds"].value_kind is SegmentValueKind8616.CALL_ENTRY_RELATION
    assert contextual.entry_states[artifact.function_addr]["ss"].source == "ss"
    assert contextual.summary["raw_fact_count"] == contextual.summary["materialized_count"] == 1
    assert contextual.summary["failure_count"] == 0
    assert build_x86_16_segment_state_artifact(artifact).entry_states == ordinary.entry_states


def test_context_rechecks_raw_identity_and_closed_counts() -> None:
    context = _context()
    assert context.complete
    assert not replace(context, materialized_count=0).complete
    stale = replace(context, callee=replace(context.callee, artifact=replace(context.callee.artifact)))
    assert not stale.complete
    with pytest.raises(ValueError, match="entry context"):
        build_x86_16_segment_state_artifact(context.callee.artifact, entry_context=stale)
    with pytest.raises(ValueError, match="entry context"):
        build_x86_16_segment_state_artifact(context.caller.artifact, entry_context=context)


def test_context_is_not_a_universal_callee_preservation_summary() -> None:
    context = _context()
    contextual = build_x86_16_segment_state_artifact(context.callee.artifact, entry_context=context)
    closure = prove_segment_effect_closure_8616(context.callee, contextual)
    assert not closure.complete
    assert closure.failure is SegmentEffectClosureFailure8616.CONTEXTUAL_ENTRY
    assert closure.failure_count == 1


def test_unproved_nested_call_discards_contextual_entry_relation() -> None:
    context = _context("e8 01 00 c3 c3")
    assert context.complete
    contextual = build_x86_16_segment_state_artifact(context.callee.artifact, entry_context=context)
    before = contextual.state_before_instruction(0x1007, "ds")
    after = contextual.state_after_instruction(0x1007, "ds")
    assert before is not None and before.source == "ss"
    assert after is not None and after.origin is SegmentOrigin.UNKNOWN


def test_explicit_segment_write_replaces_contextual_entry_equality() -> None:
    context = _context("b8 00 00 8e d8 c3")
    assert context.complete
    contextual = build_x86_16_segment_state_artifact(context.callee.artifact, entry_context=context)
    after = contextual.state_after_instruction(0x100a, "ds")
    assert after is not None and after.constant_value() == 0


def test_cross_selector_overwrite_cannot_supply_entry_equality() -> None:
    """DS:[SP-derived BX] may overwrite the SS save before POP DS."""
    context = _context(caller_prefix="16 89 e3 89 07 1f")
    assert not context.complete
    assert context.failure_count == 1


@pytest.mark.parametrize("prefix,accepted", (("", True), ("b8 00 00 8e d8", False)))
def test_context_can_transfer_to_an_exact_nested_near_call(prefix: str, accepted: bool) -> None:
    """An inherited relation survives only the actual caller's segment effects."""
    from angr_platforms.X86_16.ir.direct_call_segment_context import bind_propagated_segment_context_8616

    context = _context(prefix + " e8 01 00 c3 c3")
    project = context.callee.boundary.project
    site = 0x1007 + len(bytes.fromhex(prefix))
    boundary = exact_function_range_boundary_8616(project, site + 4, site + 5)
    assert boundary is not None
    raw = build_x86_16_ir_function_artifact(project, boundary)
    publish_function_ir_artifact_8616(project, raw)
    coverage = prove_ir_boundary_coverage_8616(project, boundary, raw)
    transferred = bind_propagated_segment_context_8616(
        context, coverage, _binary_callsite_index(project, context.callee.boundary), site,
    )
    assert transferred.complete is accepted
    assert transferred.materialized_count == int(accepted)
    assert transferred.failure_count == int(not accepted)
    if accepted:
        contextual = build_x86_16_segment_state_artifact(raw, entry_context=transferred)
        assert contextual.entry_states[raw.function_addr]["ds"].source == "ss"
        assert contextual.to_dict()["entry_context_callsite"] == site
        assert not replace(transferred, materialized_count=0).complete
        assert not replace(transferred, parent=replace(context, materialized_count=0)).complete
        assert not replace(transferred, candidate=replace(transferred.candidate, callsite_addr=site + 1)).complete
        assert not replace(transferred, callee=replace(coverage, artifact=replace(raw))).complete
        far_entries = {
            key: tuple(replace(entry, is_far=True) for entry in entries)
            for key, entries in transferred.index._entries_by_normalized_target.items()
        }
        assert not replace(transferred, index=replace(
            transferred.index, _entries_by_normalized_target=far_entries,
        )).complete
        closure = prove_segment_effect_closure_8616(coverage, contextual)
        assert closure.failure is SegmentEffectClosureFailure8616.CONTEXTUAL_ENTRY


@pytest.mark.parametrize("preserve", (False, True))
def test_transfer_replays_prior_call_preservation(preserve: bool) -> None:
    """An earlier CALL requires its own complete bound preservation evidence."""
    from angr_platforms.X86_16.ir.direct_call_segment_context import bind_propagated_segment_context_8616
    from angr_platforms.X86_16.ir.segment_call_preservation import prove_segment_call_preservation_8616

    context = _context("e8 04 00 e8 01 00 c3 c3")
    project = context.callee.boundary.project
    boundary = exact_function_range_boundary_8616(project, 0x100e, 0x100f)
    assert boundary is not None
    raw = build_x86_16_ir_function_artifact(project, boundary)
    publish_function_ir_artifact_8616(project, raw)
    coverage = prove_ir_boundary_coverage_8616(project, boundary, raw)
    index = _binary_callsite_index(project, context.callee.boundary)
    closure = prove_segment_effect_closure_8616(coverage, build_x86_16_segment_state_artifact(raw))
    proof = prove_segment_call_preservation_8616(context.callee, closure, index, 0x1007)
    assert proof.complete
    transferred = bind_propagated_segment_context_8616(
        context, coverage, index, 0x100a, call_preservations=(proof,) if preserve else (),
    )
    assert transferred.complete is preserve
    if preserve:
        assert not replace(transferred, call_preservations=()).complete
        assert not replace(transferred, call_preservations=(proof, proof)).complete


def test_transferred_context_remains_replayable_at_a_third_call_depth() -> None:
    """A longer invocation chain does not need a global DS==SS assumption."""
    from angr_platforms.X86_16.ir.direct_call_segment_context import bind_propagated_segment_context_8616

    context = _context("e8 01 00 c3 e8 01 00 c3 c3")
    project = context.callee.boundary.project
    for site, start, end in ((0x1007, 0x100b, 0x100f), (0x100b, 0x100f, 0x1010)):
        boundary = exact_function_range_boundary_8616(project, start, end)
        assert boundary is not None
        raw = build_x86_16_ir_function_artifact(project, boundary)
        publish_function_ir_artifact_8616(project, raw)
        coverage = prove_ir_boundary_coverage_8616(project, boundary, raw)
        context = bind_propagated_segment_context_8616(
            context, coverage, _binary_callsite_index(project, context.callee.boundary), site,
        )
        assert context.complete
    assert build_x86_16_segment_state_artifact(raw, entry_context=context).entry_states[start]["ds"].source == "ss"


@pytest.mark.parametrize("register,site,refuse", (("ds", 0x1007, True), ("ss", 0x1007, True),
                                                ("ax", 0x1007, False), ("ds", 0x1006, False)))
def test_transfer_rejects_hidden_same_instruction_segment_effects(register: str, site: int, refuse: bool) -> None:
    """Machine-address entry state must not hide a later IR segment assignment."""
    from angr_platforms.X86_16.ir.core import IRInstr, IRValue, MemSpace
    from angr_platforms.X86_16.ir.direct_call_segment_context import _call_has_same_instruction_segment_write_8616

    context = _context("e8 01 00 c3 c3")
    artifact = context.callee.artifact
    block = artifact.blocks[0]
    effect = IRInstr("MOV", IRValue(MemSpace.REG, name=register, size=2),
                     (IRValue(MemSpace.CONST, const=0, size=2),), addr=site)
    corrupted = replace(artifact, blocks=(replace(block, instrs=(effect, *block.instrs)), *artifact.blocks[1:]))
    assert _call_has_same_instruction_segment_write_8616(corrupted, 0x1007) is refuse
