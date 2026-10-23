"""Tests for independently evidenced per-call SP coordinates."""

from __future__ import annotations

from dataclasses import replace

import pytest

from inertia.cli.project_loading import _build_project_from_bytes
from inertia.ir.call_stack_coordinates import (
    CALL_STACK_COORDINATE_SLOTS_8616,
    CallArgumentAnchorKind8616,
    CallStackCoordinateRefusal8616,
)
from inertia.ir.core import MemSpace
from inertia.ir.vex_import import build_x86_16_ir_function_artifact
from inertia.semantics.call_return_segment import collect_return_segment_frames_8616
from inertia.semantics.call_stack_coordinates import prove_call_stack_coordinates_8616
from inertia.semantics.call_stack_effects import materialize_call_stack_effects_8616
from inertia.semantics.callsite_summary_program import (
    build_callsite_summary_inventory_with_program_evidence_8616,
)

pytestmark = pytest.mark.decompiler

_BASE = 0x1000
_CALLEE = 0x1010


def _image(caller_hex: str, callee_hex: str) -> bytes:
    """Lay a caller at the base and a callee at the fixed target address."""
    caller = bytes.fromhex(caller_hex)
    pad = bytes(_CALLEE - (_BASE + len(caller)))
    return caller + pad + bytes.fromhex(callee_hex)


def _world(code: bytes, callsite_addr: int):
    """Build a real project, function, IR artifact, and callsite summary."""
    project = _build_project_from_bytes(code, base_addr=_BASE, entry_point=_BASE)
    cfg = project.analyses.CFGFast(normalize=True)
    function = cfg.functions[_BASE]
    artifact = build_x86_16_ir_function_artifact(project, function)
    summaries = build_callsite_summary_inventory_with_program_evidence_8616(
        project, function, (callsite_addr,),
    )
    return project, function, artifact, summaries[callsite_addr]


def _call_site(artifact, callsite_addr):
    """Return the admitted (CALL instruction, owning block) pair."""
    for block in artifact.blocks:
        for instruction in block.instrs:
            if instruction.op == "CALL" and instruction.addr == callsite_addr:
                return instruction, block
    raise AssertionError(f"no CALL at {callsite_addr:#x}")


def _prove(project, artifact, summary):
    """Prove coordinates bound to the real admitted CALL instruction."""
    instruction, block = _call_site(artifact, summary.callsite_addr)
    return prove_call_stack_coordinates_8616(
        project, summary, instruction=instruction, block=block,
    )


def test_coordinate_observation_checks_body_once_and_rechecks_after_mutation(monkeypatch) -> None:
    """One observation shares its fresh proof; the next cannot reuse stale evidence."""
    from inertia.alias import callee_stack_pointer

    code = _image("6a01 e8 0b00 c3", "55 89 e5 8b 46 04 5d c2 0200")
    project, _function, artifact, summary = _world(code, 0x1002)
    coordinates = _prove(project, artifact, summary)
    original = callee_stack_pointer._return_transfers_8616
    calls = 0

    def counted(coverage):
        nonlocal calls
        calls += 1
        return original(coverage)

    monkeypatch.setattr(callee_stack_pointer, "_return_transfers_8616", counted)
    observed = coordinates.observe()
    assert observed.sp_delta_proven
    assert observed.proven_net_sp_delta == 2
    assert calls == 1
    # Keep the same objects and machine instruction widths, change RET's purge.
    project.loader.memory.store(0x1018, b"\x04")
    changed = coordinates.observe()
    assert not changed.sp_delta_proven
    assert changed.proven_net_sp_delta is None


def test_balanced_near_call_proves_independent_coordinates() -> None:
    """push imm; CALL; RET against a RET2 callee decomposes each fact."""
    code = _image("6a01 e8 0b00 c3", "55 89 e5 8b 46 04 5d c2 0200")
    project, _function, artifact, summary = _world(code, 0x1002)

    coordinates = _prove(project, artifact, summary)

    assert coordinates.callsite_addr == 0x1002
    assert coordinates.return_frame_bytes == 2
    assert coordinates.callee_purged_bytes == 2
    assert coordinates.net_sp_delta == 2
    assert coordinates.additional_return_bytes == 0
    assert coordinates.caller_cleanup_bytes is None
    assert CallStackCoordinateRefusal8616.CALLER_CLEANUP_UNPROVEN in coordinates.refusals
    top = coordinates.argument_top
    assert top is not None
    assert top.space is MemSpace.SS
    assert top.anchor is CallArgumentAnchorKind8616.CALLER_SP_BEFORE_CALL
    assert top.top_offset_bytes == 0 and top.extent_bytes == 2
    assert top.push_instruction_addrs == (0x1000,)

    result = materialize_call_stack_effects_8616(artifact, {0x1002: summary}, project=project)
    effect = result.facts[0].effect
    assert effect.net_stack_delta == 2
    assert effect.stack_coordinates == coordinates


def test_plain_ret_callee_proves_known_zero_purge() -> None:
    """A plain RET census proves zero, distinct from absent evidence."""
    code = _image("6a01 e8 0b00 c3", "55 89 e5 8b 46 04 5d c3")
    project, _function, artifact, summary = _world(code, 0x1002)

    coordinates = _prove(project, artifact, summary)

    assert coordinates.callee_purged_bytes == 0
    assert coordinates.net_sp_delta == 0
    result = materialize_call_stack_effects_8616(artifact, {0x1002: summary}, project=project)
    assert result.facts[0].effect.net_stack_delta == 0


def test_high_imm16_callee_purge_projects_signed_word_delta() -> None:
    """RET 0x8000 is a real census fact; the SP delta is 16-bit modular."""
    code = _image("6a01 e8 0b00 c3", "c2 00 80")
    project, _function, artifact, summary = _world(code, 0x1002)

    coordinates = _prove(project, artifact, summary)

    assert coordinates.callee_purged_bytes == 0x8000
    assert coordinates.net_sp_delta == -0x8000


def test_mixed_return_cleanups_keep_arg_top_but_refuse_purge() -> None:
    """A divergent callee census refuses purge while keeping proven fields."""
    code = _image("6a01 6a02 e8 0900 c3", "85 c0 74 03 c2 0200 c3")
    project, _function, artifact, summary = _world(code, 0x1004)

    coordinates = _prove(project, artifact, summary)

    assert coordinates.callee_purged_bytes is None
    assert coordinates.net_sp_delta is None
    assert (
        CallStackCoordinateRefusal8616.CALLEE_TERMINAL_EVIDENCE_INCOMPLETE
        in coordinates.refusals
    )
    assert coordinates.argument_top is not None
    assert coordinates.argument_top.extent_bytes == 4
    assert not coordinates.complete
    assert coordinates.materialized_count < coordinates.raw_fact_count == CALL_STACK_COORDINATE_SLOTS_8616

    result = materialize_call_stack_effects_8616(artifact, {0x1004: summary}, project=project)
    effect = result.facts[0].effect
    assert effect.complete is False
    assert effect.stack_coordinates == coordinates


def test_unknown_target_never_guesses_callee_purge() -> None:
    code = _image("6a01 ff 16 0020 c3", "c3")
    project, _function, artifact, summary = _world(code, 0x1002)
    summary = replace(summary, target_addr=None)

    coordinates = _prove(project, artifact, summary)

    assert coordinates.callee_purged_bytes is None
    assert coordinates.net_sp_delta is None
    assert CallStackCoordinateRefusal8616.CALL_TARGET_UNRESOLVED in coordinates.refusals


def test_wide_return_operand_refuses_purge() -> None:
    """A 0x66-prefixed return is not 16-bit purge evidence."""
    code = _image("6a01 e8 0b00 c3", "66 c2 0200")
    project, _function, artifact, summary = _world(code, 0x1002)

    coordinates = _prove(project, artifact, summary)

    assert coordinates.callee_purged_bytes is None
    assert coordinates.net_sp_delta is None
    assert (
        CallStackCoordinateRefusal8616.CALLEE_RETURN_OPERAND_WIDTH_UNPROVEN
        in coordinates.refusals
    )


def test_far_terminal_without_linked_frame_refuses_composition() -> None:
    """A RETF callee behind a plain near call has no proven caller frame."""
    code = _image("6a01 e8 0b00 c3", "cb")
    project, _function, artifact, summary = _world(code, 0x1002)

    coordinates = _prove(project, artifact, summary)

    assert coordinates.callee_purged_bytes == 0
    assert coordinates.net_sp_delta is None
    assert (
        CallStackCoordinateRefusal8616.RETURN_FRAME_KIND_CONFLICT
        in coordinates.refusals
    )


def test_linked_far_return_adds_proven_segment_extra() -> None:
    """PUSH CS + near CALL + RETF composes purge plus the CS slot."""
    caller = bytes.fromhex("0e e8 0c00 c3")
    code = caller + bytes(_CALLEE - (_BASE + len(caller))) + bytes.fromhex("cb")
    project = _build_project_from_bytes(code, base_addr=_BASE, entry_point=_BASE)
    cfg = project.analyses.CFGFast(normalize=True)
    function = cfg.functions[_BASE]
    summary = build_callsite_summary_inventory_with_program_evidence_8616(
        project, function, (0x1001,),
    )[0x1001]
    frame = collect_return_segment_frames_8616(project, function, {0x1001: 0x1004})[0]
    assert frame.additional_return_bytes == 2
    artifact = build_x86_16_ir_function_artifact(project, function)
    instruction, block = _call_site(artifact, summary.callsite_addr)

    coordinates = prove_call_stack_coordinates_8616(
        project, summary, instruction=instruction, block=block, return_frame=frame,
    )

    assert coordinates.return_frame_bytes == 2
    assert coordinates.callee_purged_bytes == 0
    assert coordinates.additional_return_bytes == 2
    assert coordinates.net_sp_delta == 2


def test_stale_push_evidence_refuses_argument_top() -> None:
    """Recorded push addresses that do not decode as pushes stay unknown."""
    code = _image("6a01 e8 0b00 c3", "c3")
    project, _function, _artifact, summary = _world(code, 0x1002)
    stale = replace(
        summary,
        arg_count=1,
        arg_widths=(2,),
        push_arg_instruction_addrs=(0x1002,),
    )

    coordinates = _prove(project, _artifact, stale)

    assert coordinates.argument_top is None
    assert (
        CallStackCoordinateRefusal8616.ARGUMENT_REGION_AMBIGUOUS
        in coordinates.refusals
    )


def test_caller_cleanup_never_replaces_callee_purge_evidence() -> None:
    """A caller ADD SP cleanup must not substitute for the callee census."""
    # Two words pushed, callee RET2 and caller ADD SP,2 split the reclaim.
    code = _image("6a01 6a02 e8 0900 83 c4 02 c3", "55 89 e5 8b 46 04 5d c2 0200")
    project, _function, artifact, summary = _world(code, 0x1004)

    coordinates = _prove(project, artifact, summary)

    assert coordinates.callee_purged_bytes == 2
    assert coordinates.caller_cleanup_bytes == 2
    assert coordinates.caller_cleanup_instruction_addr == 0x1007
    assert coordinates.net_sp_delta == 2
    result = materialize_call_stack_effects_8616(artifact, {0x1004: summary}, project=project)
    assert result.facts[0].effect.net_stack_delta == 2


def test_saved_segment_prefix_keeps_independent_facts() -> None:
    """PUSH DS before the call is not an argument and POP ES is not a proof."""
    code = _image("1e 6a01 e8 0a00 07 c3", "55 89 e5 8b 46 04 5d c2 0200")
    project, _function, artifact, summary = _world(code, 0x1003)

    coordinates = _prove(project, artifact, summary)

    assert coordinates.callee_purged_bytes == 2
    assert coordinates.caller_cleanup_bytes is None
    assert coordinates.net_sp_delta == 2
    assert coordinates.argument_top is not None
    assert coordinates.argument_top.push_instruction_addrs == (0x1001,)
    result = materialize_call_stack_effects_8616(artifact, {0x1003: summary}, project=project)
    assert result.facts[0].effect.net_stack_delta == 2


def test_undecodable_callee_purge_stays_unknown_despite_caller_cleanup() -> None:
    """Without callee bytes, caller cleanup cannot stand in for purge zero."""
    caller = bytes.fromhex("6a01 e8 0900 83 c4 02 c3")
    code = caller + bytes(0x40 - len(caller))
    project = _build_project_from_bytes(code, base_addr=_BASE, entry_point=_BASE)
    cfg = project.analyses.CFGFast(normalize=True)
    function = cfg.functions[_BASE]
    summary = build_callsite_summary_inventory_with_program_evidence_8616(
        project, function, (0x1002,),
    )[0x1002]
    assert summary.stack_cleanup_instruction_addr is not None
    artifact = build_x86_16_ir_function_artifact(project, function)

    coordinates = _prove(project, artifact, summary)

    assert coordinates.caller_cleanup_bytes == 2
    assert coordinates.callee_purged_bytes is None
    assert coordinates.net_sp_delta is None


def test_registered_stub_callee_cannot_publish_placeholder_purge() -> None:
    """A marked analysis-only callee must not prove RET4 through coordinates."""
    from inertia.frontend.x86_16.synthetic_call_stub_evidence import (
        record_synthetic_call_stubs_8616,
    )

    code = _image("e8 0d00 c3", "c2 0400")
    project, _function, artifact, summary = _world(code, 0x1000)
    real = materialize_call_stack_effects_8616(
        artifact, {0x1000: summary}, project=project,
    ).facts[0].effect
    assert real.stack_coordinates.net_sp_delta == 4
    assert real.net_stack_delta == 4

    record_synthetic_call_stubs_8616(project, frozenset({0x1010}))
    refused = materialize_call_stack_effects_8616(
        artifact, {0x1000: summary}, project=project,
    ).facts[0].effect
    coordinates = refused.stack_coordinates
    assert coordinates.callee_purged_bytes is None
    assert coordinates.net_sp_delta is None
    assert refused.net_stack_delta is None
