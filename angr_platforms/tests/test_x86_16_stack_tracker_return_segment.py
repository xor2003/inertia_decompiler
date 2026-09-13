"""Keep native SP transfer consistent with proven far-return prefixes."""

import io
from dataclasses import replace

import angr
import pytest
from angr.calling_conventions import SimCCStdcall
from angr.sim_type import SimTypeFunction, SimTypeInt
from angr_platforms.X86_16.ir import IRFunctionArtifact
from angr_platforms.X86_16.ir.vex_import import _block_to_ir
from angr_platforms.X86_16.semantics.call_return_segment import collect_return_segment_frames_8616
from angr_platforms.X86_16.semantics.call_stack_effects import materialize_call_stack_effects_8616
from test_x86_16_call_return_segment import _project
from test_x86_16_call_stack_effects import _summary
from test_x86_16_packed_mz import _mz


@pytest.mark.parametrize("base", [0x1000, 0x11000])
@pytest.mark.parametrize(("callee", "expected"), [("c2 08 00", 0), ("c3", -8)])
def test_native_cleanup_resolves_near_targets_in_loaded_code_segment(base, callee, expected):
    code = bytes.fromhex("50 50 50 50 e8 01 00 c3 " + callee)
    project = angr.Project(
        io.BytesIO(_mz(code, header_paragraphs=4)), auto_load_libs=False,
        main_opts={"backend": "dos_mz", "base_addr": base},
    )
    cfg = project.analyses.CFGFast(normalize=True, function_starts=[base, base + 8])
    tracker = project.analyses.StackPointerTracker(cfg.kb.functions[base], {project.arch.sp_offset})
    assert tracker.offset_before(base + 7, project.arch.sp_offset) == (expected & 0xffffffff)


def test_native_cleanup_rebases_out_of_slice_target_exactly_once():
    code = bytes.fromhex("50 50 50 50 e8 01 00 c3 c2 08 00")
    original = angr.Project(
        io.BytesIO(_mz(code, header_paragraphs=4)), auto_load_libs=False,
        main_opts={"backend": "dos_mz", "base_addr": 0x10000},
    )
    sliced = angr.Project(
        io.BytesIO(code[:8]), auto_load_libs=False,
        main_opts={"backend": "blob", "arch": original.arch, "base_addr": 0x1000, "entry_point": 0x1000},
    )
    sliced._inertia_original_project = original
    sliced._inertia_original_linear_delta = 0xf000
    cfg = sliced.analyses.CFGFast(normalize=True)
    tracker = sliced.analyses.StackPointerTracker(cfg.kb.functions[0x1000], {sliced.arch.sp_offset})
    assert tracker.offset_before(0x1007, sliced.arch.sp_offset) == 0


@pytest.mark.parametrize("callee", ["cb", "85 c0 74 01 cb cb"])
def test_native_tracker_consumes_proven_return_segment(callee):
    project, function = _project(callee)
    tracker = project.analyses.StackPointerTracker(function, {project.arch.sp_offset})
    assert tracker.offset_before(0x1004, project.arch.sp_offset) == 0


def test_native_tracker_keeps_cs_argument_for_near_return():
    project, function = _project("c3")
    tracker = project.analyses.StackPointerTracker(function, {project.arch.sp_offset})
    assert tracker.offset_before(0x1004, project.arch.sp_offset) == (-2 & 0xffffffff)


@pytest.mark.parametrize(("callee", "expected"), [("c2 02 00", 0), ("c3", -2)])
def test_native_tracker_consumes_binary_near_argument_cleanup(callee, expected):
    project, function = _project(callee)
    tracker = project.analyses.StackPointerTracker(function, {project.arch.sp_offset})
    assert tracker.offset_before(0x1004, project.arch.sp_offset) == (expected & 0xffffffff)


@pytest.mark.parametrize("callee", ["c2 02 00", "c3"])
def test_binary_cleanup_replaces_native_prototype_estimate(callee):
    project, function = _project(callee)
    target = project.kb.functions[0x1005]
    target.calling_convention = SimCCStdcall(project.arch)
    target.prototype = SimTypeFunction([SimTypeInt()], SimTypeInt()).with_arch(project.arch)
    tracker = project.analyses.StackPointerTracker(function, {project.arch.sp_offset})
    expected = 0 if callee.startswith("c2") else -2
    assert tracker.offset_before(0x1004, project.arch.sp_offset) == (expected & 0xffffffff)


@pytest.mark.parametrize("callee", ["85 c0 74 03 c2 02 00 c3", "ff e0"])
def test_native_cleanup_does_not_guess_from_incomplete_or_mixed_returns(callee):
    project, function = _project(callee)
    tracker = project.analyses.StackPointerTracker(function, {project.arch.sp_offset})
    assert tracker.offset_before(0x1004, project.arch.sp_offset) == (-2 & 0xffffffff)


@pytest.mark.parametrize(("callee", "adjustment"), [("cb", 2), ("c3", 0)])
@pytest.mark.parametrize("arg_widths", [(), (2, 2)])
def test_ir_call_effect_consumes_the_same_return_segment_proof(callee, adjustment, arg_widths):
    project, function = _project(callee)
    block, _transport = _block_to_ir(project.factory.block(0x1000))
    artifact = IRFunctionArtifact(0x1000, (block,))
    summary = replace(
        _summary(arg_widths=arg_widths, cleanup=sum(arg_widths)),
        callsite_addr=0x1001, target_addr=0x1005, return_addr=0x1004,
    )
    frames = collect_return_segment_frames_8616(project, function, {0x1001: 0x1004})
    result = materialize_call_stack_effects_8616(
        artifact, {0x1001: summary}, return_segment_frames={frame.callsite_addr: frame for frame in frames},
    )
    assert result.complete
    assert result.facts[0].effect.net_stack_delta == adjustment


def test_block_scoped_return_proof_matches_full_function_collection():
    project, function = _project("cb")
    full = collect_return_segment_frames_8616(project, function, {0x1001: 0x1004})
    scoped = collect_return_segment_frames_8616(project, function, {0x1001: 0x1004}, block_addr=0x1000)
    assert scoped == full
    refused = collect_return_segment_frames_8616(project, function, {0x1001: 0x1004}, block_addr=0x1005)
    assert refused[0].additional_return_bytes is None
