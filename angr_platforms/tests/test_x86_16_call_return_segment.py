"""Separate PUSH CS effects need a matching, fully known far-return boundary."""

import io
from dataclasses import replace
from typing import Any, cast

import angr
import pytest
from angr.analyses.calling_convention.fact_collector import FactCollector
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.call_frame_compat import _FactCollectorBoundary8616
from angr_platforms.X86_16.semantics.call_return_frame_effects import CallReturnFrameEffectRole8616
from angr_platforms.X86_16.semantics.call_return_segment import (
    ReturnSegmentRefusal8616,
    callee_return_evidence_8616,
    collect_function_return_frames_8616,
    collect_return_segment_frames_8616,
)
from angr_platforms.X86_16.semantics.terminal_stack_cleanup import (
    _terminal_cleanup_cache_8616,
    terminal_stack_cleanup_at_address_8616,
)


def _project(callee):
    code = bytes.fromhex("0e e8 01 00 c3 " + callee)
    project = angr.Project(
        io.BytesIO(code), auto_load_libs=False,
        main_opts={"backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000, "entry_point": 0x1000},
    )
    cfg = project.analyses.CFGFast(normalize=True)
    return project, cfg.kb.functions[0x1000]


@pytest.mark.parametrize("callee", ["cb", "85 c0 74 01 cb cb"])
def test_return_segment_has_exact_push_owned_effects(callee):
    project, function = _project(callee)
    (frame,) = collect_return_segment_frames_8616(project, function, {0x1001: 0x1004})
    assert frame.refusal is None
    assert frame.callsite_addr == 0x1001
    assert {effect.source_addr for effect in frame.effects} == {0x1000}
    assert {effect.vex_block_addr for effect in frame.effects} == {0x1000}
    assert tuple(effect.role for effect in frame.effects) == (
        CallReturnFrameEffectRole8616.STACK_POINTER_UPDATE,
        CallReturnFrameEffectRole8616.STACK_STORE,
        CallReturnFrameEffectRole8616.STACK_STORE,
    )


@pytest.mark.parametrize(
    ("callee", "reason"),
    [
        ("c3", ReturnSegmentRefusal8616.RETURN_MISMATCH),
        ("85 c0 74 01 c3 cb", ReturnSegmentRefusal8616.RETURN_MISMATCH),
        ("ca 02 00", ReturnSegmentRefusal8616.UNSUPPORTED_WIDTH_OR_CLEANUP),
        ("66 cb", ReturnSegmentRefusal8616.UNSUPPORTED_WIDTH_OR_CLEANUP),
        ("ff e0", ReturnSegmentRefusal8616.UNKNOWN_CALLEE),
    ],
)
def test_return_segment_refuses_incompatible_or_unknown_returns(callee, reason):
    project, function = _project(callee)
    (frame,) = collect_return_segment_frames_8616(project, function, {0x1001: 0x1004})
    assert frame.refusal is reason
    assert not frame.effects


def test_return_segment_refuses_wrong_fallthrough():
    project, function = _project("cb")
    (frame,) = collect_return_segment_frames_8616(project, function, {0x1001: 0x1003})
    assert frame.refusal is ReturnSegmentRefusal8616.UNKNOWN_CALLEE
    assert not frame.effects


def test_return_segment_requires_known_callee():
    project, function = _project("cb")
    del project.kb.functions[0x1005]
    (frame,) = collect_return_segment_frames_8616(project, function, {0x1001: 0x1004})
    assert frame.refusal is ReturnSegmentRefusal8616.UNKNOWN_CALLEE
    assert not frame.effects


@pytest.mark.parametrize(
    ("callee", "reason"),
    [("cb", None), ("85 c0 74 01 cb cb", None),
     ("c3", ReturnSegmentRefusal8616.RETURN_MISMATCH),
     ("85 c0 74 01 c3 cb", ReturnSegmentRefusal8616.RETURN_MISMATCH),
     ("66 cb", ReturnSegmentRefusal8616.UNSUPPORTED_WIDTH_OR_CLEANUP),
     ("85 c0 74 01 cb 66 cb", ReturnSegmentRefusal8616.UNSUPPORTED_WIDTH_OR_CLEANUP),
     ("ca 02 00", ReturnSegmentRefusal8616.UNSUPPORTED_WIDTH_OR_CLEANUP),
     ("ff e0", ReturnSegmentRefusal8616.UNKNOWN_CALLEE)],
)
def test_bodyless_callee_uses_complete_binary_return_evidence(callee, reason):
    project, caller = _project(callee)
    del project.kb.functions[0x1005]
    stub = project.kb.functions.function(addr=0x1005, create=True)
    assert stub is not None
    assert not stub.block_addrs_set and not stub.ret_sites
    (frame,) = collect_return_segment_frames_8616(project, caller, {0x1001: 0x1004})
    assert frame.refusal is reason
    assert bool(frame.effects) is (reason is None)
    assert not stub.block_addrs_set and not stub.ret_sites


@pytest.mark.parametrize(
    ("encoded", "frame_bytes", "cleanup"),
    [("c3", 2, 0), ("66 c3", 4, 0), ("cb", 4, 0), ("66 cb", 8, 0),
     ("c2 06 00", 2, 6), ("66 c2 06 00", 4, 6), ("ca 06 00", 4, 6), ("66 ca 06 00", 8, 6)],
)
def test_native_cleanup_inference_excludes_machine_return_frame(encoded, frame_bytes, cleanup):
    project, _caller = _project(encoded)
    function = project.kb.functions[0x1005]
    frames = collect_function_return_frames_8616(project, function)
    assert frames is not None and len(frames) == 1
    assert frames[0].frame_bytes == frame_bytes
    assert frames[0].cleanup_bytes == cleanup
    facts = project.analyses[FactCollector](function)
    assert facts.extra_pop == cleanup
    proof = cast(_FactCollectorBoundary8616, facts)._inertia_return_cleanup_evidence_8616
    assert proof.raw_fact_count == proof.normalized_fact_count == 1
    assert proof.classified_fact_count == proof.materialized_count == 1
    assert proof.failure_count == 0
    assert proof.frames == frames


@pytest.mark.parametrize("widths", [frozenset(), frozenset({None}), frozenset({16, None}), frozenset({16, 32})])
def test_bodyless_return_refuses_missing_or_mixed_width_evidence(widths):
    project, caller = _project("cb")
    evidence = terminal_stack_cleanup_at_address_8616(project, 0x1005)
    assert evidence.consistent_return_operand_bits == 16
    del project.kb.functions[0x1005]
    project.kb.functions.function(addr=0x1005, create=True)
    _terminal_cleanup_cache_8616(project)[0x1005] = replace(evidence, return_operand_bits=widths)
    (frame,) = collect_return_segment_frames_8616(project, caller, {0x1001: 0x1004})
    assert frame.refusal is ReturnSegmentRefusal8616.UNSUPPORTED_WIDTH_OR_CLEANUP
    assert not frame.effects


@pytest.mark.parametrize("callee,accepted", [("cb", True), ("66 cb", False), ("c3", False), ("ff e0", False)])
def test_rebased_callee_return_uses_exact_original_project(callee, accepted):
    original, _ = _project(callee)
    sliced = angr.Project(
        io.BytesIO(bytes.fromhex("0e e8 01 00 c3")), auto_load_libs=False,
        main_opts={"backend": "blob", "arch": Arch86_16(), "base_addr": 0x2000, "entry_point": 0x2000},
    )
    cfg = sliced.analyses.CFGFast(normalize=True)
    caller = cfg.kb.functions[0x2000]
    sliced.kb.functions.function(addr=0x2005, create=True)
    assert sliced.loader.find_object_containing(0x2005) is None
    cast(Any, sliced)._inertia_original_project = original
    cast(Any, sliced)._inertia_original_linear_delta = -0x1000
    (frame,) = collect_return_segment_frames_8616(sliced, caller, {0x2001: 0x2004})
    assert bool(frame.effects) is accepted
    assert (frame.refusal is None) is accepted


def test_mapped_callee_bytes_override_conflicting_original_return():
    original, _ = _project("cb")
    current, caller = _project("c3")
    del current.kb.functions[0x1005]
    current.kb.functions.function(addr=0x1005, create=True)
    cast(Any, current)._inertia_original_project = original
    cast(Any, current)._inertia_original_linear_delta = 0
    (frame,) = collect_return_segment_frames_8616(current, caller, {0x1001: 0x1004})
    assert frame.refusal is ReturnSegmentRefusal8616.RETURN_MISMATCH
    assert not frame.effects


@pytest.mark.parametrize(
    "encoded,cleanup,width",
    [("c2 08 00", 8, 16), ("66 c2 08 00", 8, 32),
     ("85 c0 74 03 c2 08 00 c2 04 00", None, 16)],
)
def test_rebased_argument_cleanup_retains_independent_width_and_agreement(encoded, cleanup, width):
    """An out-of-slice RET immediate is argument cleanup, not return-frame size."""
    original, _ = _project(encoded)
    sliced = angr.Project(
        io.BytesIO(bytes.fromhex("e8 02 00 c3")), auto_load_libs=False,
        main_opts={"backend": "blob", "arch": Arch86_16(), "base_addr": 0x2000, "entry_point": 0x2000},
    )
    cast(Any, sliced)._inertia_original_project = original
    cast(Any, sliced)._inertia_original_linear_delta = -0x1000
    assert sliced.loader.find_object_containing(0x2005) is None
    evidence = callee_return_evidence_8616(sliced, 0x2005)
    assert evidence.complete
    assert evidence.consistent_cleanup == cleanup
    assert evidence.consistent_return_operand_bits == width
    assert evidence.raw_fact_count == evidence.normalized_fact_count
    assert evidence.classified_fact_count == evidence.materialized_count == evidence.raw_fact_count
    assert evidence.failure_count == 0
