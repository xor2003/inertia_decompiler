"""Tests for the nonpublishing DS==SS direct-call entry proof.

Layer: Tests.
Responsibility: cover the IR proof that a local Alias-proved PUSH SS / POP DS
copy keeps DS and SS equal at one exact direct near CALL, plus the refused
boundaries of that proof.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, replace
from types import SimpleNamespace
from typing import cast

import angr
import pytest
from angr_platforms.X86_16.alias.segment_stack_restore import (
    build_x86_16_segment_stack_restore_artifact,
)
from angr_platforms.X86_16.analysis_helpers import (
    resolve_direct_call_target_from_instruction_8616,
)
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.frontend_capstone_block import DirectCapstoneInstruction8616
from angr_platforms.X86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsiteIndex8616,
    DecodedFarCallTarget8616,
    build_boundary_direct_callsite_index_8616,
    build_decoded_direct_callsite_index_8616,
)
from angr_platforms.X86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
    exact_function_range_boundary_8616,
)
from angr_platforms.X86_16.ir import (
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRRefusal,
    IRValue,
    MemSpace,
    SegmentOrigin,
    build_x86_16_segment_state_artifact,
)
from angr_platforms.X86_16.ir.direct_call_segment_entry import (
    DirectCallSegmentEntryCandidate8616,
    DirectCallSegmentEntryProof8616,
    DirectCallSegmentEntryRefusal8616,
    DirectCallSegmentEntryStats8616,
    DirectCallSegmentEntryVerdict8616,
    prove_x86_16_direct_call_segment_entry_8616,
)
from angr_platforms.X86_16.ir.function_ir_registry import (
    publish_function_ir_artifact_8616,
)
from angr_platforms.X86_16.ir.segment_state_transfer import SegmentRestoreSource
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact
from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401

_BASE = 0x1000


def test_entry_proof_requires_closed_ordered_evidence() -> None:
    """A verdict alone cannot authorize interprocedural segment propagation."""
    candidate = DirectCallSegmentEntryCandidate8616(_BASE, 0x1002, 0x1007)
    proof = DirectCallSegmentEntryProof8616(
        candidate,
        DirectCallSegmentEntryVerdict8616.PROVEN,
        None,
        DirectCallSegmentEntryStats8616(1, 1, 1, 1, 0),
        block_addr=_BASE,
        saved_instruction_addr=_BASE,
        saved_register="ss",
        restore_instruction_addr=0x1001,
        restore_register="ds",
    )
    assert proof.complete
    assert proof.to_dict()["complete"] is True
    assert not replace(proof, saved_register="ds").complete
    assert replace(proof, saved_register="ds").to_dict()["complete"] is False
    assert not replace(proof, restore_instruction_addr=0x1002).complete
    assert not replace(proof, block_addr=0x1001).complete
    assert not replace(proof, stats=DirectCallSegmentEntryStats8616(1, 1, 0, 0, 1)).complete
    assert not replace(proof, refusal=DirectCallSegmentEntryRefusal8616.CFG_NOT_CLOSED).complete


@dataclass(frozen=True, slots=True)
class _DecodedInstruction:
    """Minimal decoded-instruction stand-in for the direct-callsite index."""

    target: int | DecodedFarCallTarget8616 | None
    address: int | None


def _lift_caller(code: bytes) -> tuple[object, IRFunctionArtifact]:
    """Lift exact bytes into a typed IR artifact for the entry function."""
    project = angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": _BASE,
            "entry_point": _BASE,
        },
        auto_load_libs=False,
        simos="DOS",
    )
    cfg = project.analyses.CFGFast(normalize=True)
    return project, build_x86_16_ir_function_artifact(project, cfg.functions[_BASE])


def _callsite_index(
    caller_start: int,
    caller_end: int,
    calls: tuple[tuple[int, int | DecodedFarCallTarget8616 | None], ...],
    extra_callers: tuple[tuple[int, int, tuple[tuple[int, int], ...]], ...] = (),
) -> DecodedDirectCallsiteIndex8616:
    """Build a decoded direct-call index over exact caller ranges."""
    decoded_ranges: dict[tuple[int, int], tuple[_DecodedInstruction, ...]] = {
        (caller_start, caller_end): tuple(
            _DecodedInstruction(target, address) for address, target in calls
        ),
    }
    decoded_ranges.update(
        {
            (start, end): tuple(
                _DecodedInstruction(target, address) for address, target in call_list
            )
            for start, end, call_list in extra_callers
        }
    )
    def resolve_target(instruction: object) -> int | DecodedFarCallTarget8616 | None:
        assert isinstance(instruction, _DecodedInstruction)
        return instruction.target

    def resolve_address(instruction: object) -> int | None:
        assert isinstance(instruction, _DecodedInstruction)
        return instruction.address

    return build_decoded_direct_callsite_index_8616(
        decoded_ranges,
        direct_target_resolver=resolve_target,
        instruction_address_resolver=resolve_address,
    )


def _callee_boundary(project: object, callee_addr: int, callee_end: int) -> ExactFunctionRangeBoundary8616:
    """Build the exact callee boundary from real binary reachability."""
    boundary = exact_function_range_boundary_8616(project, callee_addr, callee_end)
    assert boundary is not None
    return boundary


def _binary_callsite_index(
    project: object,
    boundary: ExactFunctionRangeBoundary8616,
) -> DecodedDirectCallsiteIndex8616:
    """Index real decoded instructions from the exact byte-backed boundary."""
    return build_boundary_direct_callsite_index_8616(
        boundary,
        direct_target_resolver=lambda instruction: resolve_direct_call_target_from_instruction_8616(
            project, instruction,
        ),
    )


def test_push_ss_pop_ds_direct_call_proves_ds_equals_ss() -> None:
    """Real lifted PUSH SS; POP DS; near CALL proves register equality."""
    # push ss; pop ds; call 0x1007; ret; nop; callee: ret
    project, artifact = _lift_caller(bytes.fromhex("16 1f e8 02 00 c3 90 c3"))
    caller_boundary = exact_function_range_boundary_8616(project, _BASE, 0x1006)
    assert caller_boundary is not None
    callee_boundary = _callee_boundary(project, 0x1007, 0x1008)
    restoration = build_x86_16_segment_stack_restore_artifact(artifact)
    assert len(restoration.restore_sources) == 1
    index = _binary_callsite_index(project, caller_boundary)
    assert publish_function_ir_artifact_8616(project, artifact).artifact is artifact

    proof = prove_x86_16_direct_call_segment_entry_8616(
        DirectCallSegmentEntryCandidate8616(
            caller_start=_BASE,
            callsite_addr=0x1002,
            callee_addr=0x1007,
        ),
        caller_boundary=caller_boundary,
        callee_boundary=callee_boundary,
        artifact=artifact,
        callsite_index=index,
        restore_sources=restoration.restore_sources,
    )

    assert proof.verdict is DirectCallSegmentEntryVerdict8616.PROVEN
    assert proof.refusal is None
    assert proof.block_addr == _BASE
    assert proof.saved_instruction_addr == 0x1000
    assert proof.saved_register == "ss"
    assert proof.restore_instruction_addr == 0x1001
    assert proof.restore_register == "ds"
    assert proof.stats.raw_fact_count == 1
    assert proof.stats.classified_fact_count == 1
    assert proof.stats.materialized_count == 1
    assert proof.stats.failure_count == 0
    assert proof.stats.closed
    assert proof.complete


def test_unknown_numeric_ss_still_proves_ds_equals_ss() -> None:
    """Equality is a live-register fact even when no numeric segment is known."""
    # mov ss,ax; push ss; pop ds; call 0x1009; ret; nop; callee: ret
    project, artifact = _lift_caller(bytes.fromhex("8e d0 16 1f e8 02 00 c3 90 c3"))
    caller_boundary = exact_function_range_boundary_8616(project, _BASE, 0x1008)
    assert caller_boundary is not None
    callee_boundary = _callee_boundary(project, 0x1009, 0x100A)
    restoration = build_x86_16_segment_stack_restore_artifact(artifact)
    assert len(restoration.restore_sources) == 1
    segment_state = build_x86_16_segment_state_artifact(
        artifact,
        restore_sources=restoration.restore_sources,
    )
    # The lattice cannot name a value: both registers stay UNKNOWN at the call.
    ss_state = segment_state.state_before_instruction(0x1004, "ss")
    ds_state = segment_state.state_before_instruction(0x1004, "ds")
    assert ss_state is not None and ss_state.origin is SegmentOrigin.UNKNOWN
    assert ds_state is not None and ds_state.origin is SegmentOrigin.UNKNOWN
    index = _binary_callsite_index(project, caller_boundary)
    assert publish_function_ir_artifact_8616(project, artifact).artifact is artifact

    proof = prove_x86_16_direct_call_segment_entry_8616(
        DirectCallSegmentEntryCandidate8616(
            caller_start=_BASE,
            callsite_addr=0x1004,
            callee_addr=0x1009,
        ),
        caller_boundary=caller_boundary,
        callee_boundary=callee_boundary,
        artifact=artifact,
        callsite_index=index,
        restore_sources=restoration.restore_sources,
    )

    assert proof.verdict is DirectCallSegmentEntryVerdict8616.PROVEN
    assert proof.saved_instruction_addr == 0x1002
    assert proof.restore_instruction_addr == 0x1003
    assert proof.stats.closed


@pytest.mark.parametrize(
    "code,callee_addr,restore_count,refusal",
    [
        pytest.param(
            # PUSH SS; MOV SS,SI; POP DS reads the new SS storage.
            bytes.fromhex("16 8e d6 1f e8 02 00 c3 90 c3"),
            0x1009, 0, DirectCallSegmentEntryRefusal8616.ALIAS_SOURCE_MISSING,
            id="uncaptured-stack-read",
        ),
        pytest.param(
            # The intermediate DX transport is not an Alias-proven DS copy.
            bytes.fromhex("16 5a 8e d6 8e da e8 02 00 c3 90 c3"),
            0x100B, 0, DirectCallSegmentEntryRefusal8616.ALIAS_SOURCE_MISSING,
            id="gpr-bridge-unproven",
        ),
        pytest.param(
            # POP DS captures the old selector before MOV SS changes storage.
            bytes.fromhex("16 1f 8e d6 e8 02 00 c3 90 c3"),
            0x1009, 1, DirectCallSegmentEntryRefusal8616.SS_WRITE_AFTER_SAVE,
            id="captured-segment-window",
        ),
    ],
)
def test_ss_write_between_save_and_call_refuses(
    code: bytes,
    callee_addr: int,
    restore_count: int,
    refusal: DirectCallSegmentEntryRefusal8616,
) -> None:
    """Keep both missing-copy and surviving-copy CALL refusals explicit."""
    # Both fixtures end with CALL rel16 +2; RET; NOP; callee: RET.
    caller_end = callee_addr - 1
    callsite_addr = callee_addr - 5
    project, artifact = _lift_caller(code)
    caller_boundary = exact_function_range_boundary_8616(project, _BASE, caller_end)
    assert caller_boundary is not None
    callee_boundary = _callee_boundary(project, callee_addr, callee_addr + 1)
    restoration = build_x86_16_segment_stack_restore_artifact(artifact)
    copies = tuple(
        source for source in restoration.restore_sources
        if source.restore_register == "ds" and source.saved_register == "ss"
    )
    assert len(copies) == restore_count
    index = _binary_callsite_index(project, caller_boundary)

    proof = prove_x86_16_direct_call_segment_entry_8616(
        DirectCallSegmentEntryCandidate8616(_BASE, callsite_addr, callee_addr),
        caller_boundary=caller_boundary,
        callee_boundary=callee_boundary,
        artifact=artifact,
        callsite_index=index,
        restore_sources=restoration.restore_sources,
    )

    assert proof.verdict is DirectCallSegmentEntryVerdict8616.UNKNOWN_REFUSE
    assert proof.refusal is refusal
    assert proof.stats.closed


def test_ds_write_between_restore_and_call_refuses() -> None:
    """MOV DS,AX after POP DS discards the restored equality before the CALL."""
    # push ss; pop ds; mov ds,ax; call 0x1009; ret; nop; callee: ret
    project, artifact = _lift_caller(bytes.fromhex("16 1f 8e d8 e8 02 00 c3 90 c3"))
    caller_boundary = exact_function_range_boundary_8616(project, _BASE, 0x1008)
    assert caller_boundary is not None
    callee_boundary = _callee_boundary(project, 0x1009, 0x100A)
    restoration = build_x86_16_segment_stack_restore_artifact(artifact)
    assert len(restoration.restore_sources) == 1
    index = _binary_callsite_index(project, caller_boundary)

    proof = prove_x86_16_direct_call_segment_entry_8616(
        DirectCallSegmentEntryCandidate8616(_BASE, 0x1004, 0x1009),
        caller_boundary=caller_boundary,
        callee_boundary=callee_boundary,
        artifact=artifact,
        callsite_index=index,
        restore_sources=restoration.restore_sources,
    )

    assert proof.verdict is DirectCallSegmentEntryVerdict8616.UNKNOWN_REFUSE
    assert proof.refusal is DirectCallSegmentEntryRefusal8616.DS_WRITE_AFTER_RESTORE
    assert proof.stats.closed


def _synthetic_project() -> object:
    return SimpleNamespace()


def _synthetic_boundary(
    project: object,
    addr: int,
    block_addrs: frozenset[int],
    instruction_addrs: frozenset[int],
    edges: tuple[tuple[int, int], ...],
) -> ExactFunctionRangeBoundary8616:
    return ExactFunctionRangeBoundary8616(
        project=project,
        addr=addr,
        size=0x100,
        block_addrs_set=block_addrs,
        reachable_instruction_addrs=instruction_addrs,
        successor_edges=edges,
    )


def _const(value: int) -> IRValue:
    return IRValue(MemSpace.CONST, const=value, size=4)


def test_intervening_call_between_save_and_call_refuses() -> None:
    """A CALL inside the save->call window cannot keep DS==SS proven."""
    project = _synthetic_project()
    artifact = IRFunctionArtifact(
        function_addr=_BASE,
        blocks=(
            IRBlock(
                addr=_BASE,
                instrs=(
                    IRInstr("MOV", IRValue(MemSpace.REG, name="sp", size=2), (_const(0),), addr=_BASE),
                    IRInstr("CALL", None, (_const(0x2000),), addr=0x1001),
                    IRInstr(
                        "MOV",
                        IRValue(MemSpace.REG, name="ds", size=2),
                        (IRValue(MemSpace.TMP, name="t0", size=2),),
                        addr=0x1002,
                    ),
                    IRInstr("CALL", None, (_const(0x1007),), addr=0x1003),
                ),
            ),
        ),
    )
    caller_boundary = _synthetic_boundary(
        project,
        _BASE,
        frozenset({_BASE}),
        frozenset({_BASE, 0x1001, 0x1002, 0x1003}),
        (),
    )
    callee_boundary = _synthetic_boundary(
        project, 0x1007, frozenset({0x1007}), frozenset({0x1007}), ()
    )
    index = _callsite_index(
        _BASE, 0x1010, ((0x1001, 0x2000), (0x1003, 0x1007))
    )
    source = SegmentRestoreSource(_BASE, 0x1002, "ds", _BASE, "ss")

    proof = prove_x86_16_direct_call_segment_entry_8616(
        DirectCallSegmentEntryCandidate8616(_BASE, 0x1003, 0x1007),
        caller_boundary=caller_boundary,
        callee_boundary=callee_boundary,
        artifact=artifact,
        callsite_index=index,
        restore_sources=(source,),
    )

    assert proof.verdict is DirectCallSegmentEntryVerdict8616.UNKNOWN_REFUSE
    assert proof.refusal is DirectCallSegmentEntryRefusal8616.INTERVENING_CALL
    assert proof.stats.closed


def test_missing_alias_source_refuses() -> None:
    """Without the Alias PUSH SS / POP DS relation there is no equality proof."""
    project, artifact = _lift_caller(bytes.fromhex("16 1f e8 02 00 c3 90 c3"))
    caller_boundary = exact_function_range_boundary_8616(project, _BASE, 0x1006)
    assert caller_boundary is not None
    callee_boundary = _callee_boundary(project, 0x1007, 0x1008)
    index = _binary_callsite_index(project, caller_boundary)

    proof = prove_x86_16_direct_call_segment_entry_8616(
        DirectCallSegmentEntryCandidate8616(_BASE, 0x1002, 0x1007),
        caller_boundary=caller_boundary,
        callee_boundary=callee_boundary,
        artifact=artifact,
        callsite_index=index,
        restore_sources=(),
    )

    assert proof.verdict is DirectCallSegmentEntryVerdict8616.UNKNOWN_REFUSE
    assert proof.refusal is DirectCallSegmentEntryRefusal8616.ALIAS_SOURCE_MISSING
    assert proof.stats.closed


def test_wrong_callee_identity_refuses() -> None:
    """A callee that no decoded callsite reaches has no matching index entry."""
    project, artifact = _lift_caller(bytes.fromhex("16 1f e8 02 00 c3 90 c3"))
    caller_boundary = exact_function_range_boundary_8616(project, _BASE, 0x1006)
    assert caller_boundary is not None
    callee_boundary = _synthetic_boundary(
        project, 0x1200, frozenset({0x1200}), frozenset({0x1200}), ()
    )
    index = _callsite_index(_BASE, 0x1006, ((0x1002, 0x1007),))

    proof = prove_x86_16_direct_call_segment_entry_8616(
        DirectCallSegmentEntryCandidate8616(_BASE, 0x1002, 0x1200),
        caller_boundary=caller_boundary,
        callee_boundary=callee_boundary,
        artifact=artifact,
        callsite_index=index,
        restore_sources=(),
    )

    assert proof.verdict is DirectCallSegmentEntryVerdict8616.UNKNOWN_REFUSE
    assert proof.refusal is DirectCallSegmentEntryRefusal8616.TARGET_INDEX_MISSING
    assert proof.stats.closed


def test_decoded_index_and_ir_target_disagreement_refuses() -> None:
    """The decoded target and the typed IR target must name the same callee."""
    project, artifact = _lift_caller(bytes.fromhex("16 1f e8 02 00 c3 90 c3 90 c3"))
    caller_boundary = exact_function_range_boundary_8616(project, _BASE, 0x1006)
    assert caller_boundary is not None
    # The index claims the callsite targets 0x1009 while the IR CALL is 0x1007.
    native_index = _binary_callsite_index(project, caller_boundary)
    native_entry, = native_index.for_target(0x1007)
    index = DecodedDirectCallsiteIndex8616(
        {0x1009: (replace(native_entry, target_addr=0x1009),)}, native_index.stats,
    )

    proof = prove_x86_16_direct_call_segment_entry_8616(
        DirectCallSegmentEntryCandidate8616(_BASE, 0x1002, 0x1009),
        caller_boundary=caller_boundary,
        callee_boundary=_callee_boundary(project, 0x1009, 0x100A),
        artifact=artifact,
        callsite_index=index,
        restore_sources=(),
    )

    assert proof.verdict is DirectCallSegmentEntryVerdict8616.UNKNOWN_REFUSE
    assert proof.refusal is DirectCallSegmentEntryRefusal8616.TARGET_MISMATCH
    assert proof.stats.closed


def test_ambiguous_index_entries_refuse() -> None:
    """Two decoded entries for this exact callsite cannot name one boundary."""
    project, artifact = _lift_caller(bytes.fromhex("16 1f e8 02 00 c3 90 c3"))
    caller_boundary = exact_function_range_boundary_8616(project, _BASE, 0x1006)
    assert caller_boundary is not None
    callee_boundary = _callee_boundary(project, 0x1007, 0x1008)
    index = _callsite_index(
        _BASE,
        0x1006,
        ((0x1002, 0x1007), (0x1002, 0x1007)),
    )

    proof = prove_x86_16_direct_call_segment_entry_8616(
        DirectCallSegmentEntryCandidate8616(_BASE, 0x1002, 0x1007),
        caller_boundary=caller_boundary,
        callee_boundary=callee_boundary,
        artifact=artifact,
        callsite_index=index,
        restore_sources=(),
    )

    assert proof.verdict is DirectCallSegmentEntryVerdict8616.UNKNOWN_REFUSE
    assert proof.refusal is DirectCallSegmentEntryRefusal8616.TARGET_INDEX_AMBIGUOUS
    assert proof.stats.closed


def test_far_call_candidate_refuses() -> None:
    """A far CALL boundary is outside this candidate's direct near-call scope."""
    project, artifact = _lift_caller(bytes.fromhex("16 1f e8 02 00 c3 90 c3"))
    caller_boundary = exact_function_range_boundary_8616(project, _BASE, 0x1006)
    assert caller_boundary is not None
    callee_boundary = _synthetic_boundary(
        project, 0x11007, frozenset({0x11007}), frozenset({0x11007}), ()
    )
    index = _callsite_index(
        _BASE, 0x1006, ((0x1002, DecodedFarCallTarget8616(0x11007)),)
    )

    proof = prove_x86_16_direct_call_segment_entry_8616(
        DirectCallSegmentEntryCandidate8616(_BASE, 0x1002, 0x11007),
        caller_boundary=caller_boundary,
        callee_boundary=callee_boundary,
        artifact=artifact,
        callsite_index=index,
        restore_sources=(),
    )

    assert proof.verdict is DirectCallSegmentEntryVerdict8616.UNKNOWN_REFUSE
    assert proof.refusal is DirectCallSegmentEntryRefusal8616.CALL_NOT_DIRECT_NEAR
    assert proof.stats.closed


def test_branching_caller_without_local_alias_refuses() -> None:
    """A closed branched caller still needs its own local Alias copy proof."""
    project = _synthetic_project()
    artifact = IRFunctionArtifact(
        function_addr=_BASE,
        blocks=(
            IRBlock(
                addr=_BASE,
                instrs=(IRInstr("CALL", None, (_const(0x1007),), addr=0x1003),),
                successor_addrs=(0x1010, 0x1020),
            ),
            IRBlock(addr=0x1010),
            IRBlock(addr=0x1020),
        ),
    )
    caller_boundary = _synthetic_boundary(
        project,
        _BASE,
        frozenset({_BASE, 0x1010, 0x1020}),
        frozenset({_BASE, 0x1003, 0x1010, 0x1020}),
        ((_BASE, 0x1010), (_BASE, 0x1020)),
    )
    callee_boundary = _synthetic_boundary(
        project, 0x1007, frozenset({0x1007}), frozenset({0x1007}), ()
    )
    index = _callsite_index(_BASE, 0x1010, ((0x1003, 0x1007),))

    proof = prove_x86_16_direct_call_segment_entry_8616(
        DirectCallSegmentEntryCandidate8616(_BASE, 0x1003, 0x1007),
        caller_boundary=caller_boundary,
        callee_boundary=callee_boundary,
        artifact=artifact,
        callsite_index=index,
        restore_sources=(),
    )

    assert proof.verdict is DirectCallSegmentEntryVerdict8616.UNKNOWN_REFUSE
    assert proof.refusal is DirectCallSegmentEntryRefusal8616.ALIAS_SOURCE_MISSING
    assert proof.stats.closed


def test_open_edge_outside_boundary_refuses() -> None:
    """An artifact edge leaving the closed boundary is an open path."""
    project = _synthetic_project()
    artifact = IRFunctionArtifact(
        function_addr=_BASE,
        blocks=(
            IRBlock(
                addr=_BASE,
                instrs=(IRInstr("CALL", None, (_const(0x1007),), addr=0x1003),),
                successor_addrs=(0x1999,),
            ),
        ),
    )
    caller_boundary = _synthetic_boundary(
        project,
        _BASE,
        frozenset({_BASE}),
        frozenset({_BASE, 0x1003}),
        (),
    )
    callee_boundary = _synthetic_boundary(
        project, 0x1007, frozenset({0x1007}), frozenset({0x1007}), ()
    )
    index = _callsite_index(_BASE, 0x1010, ((0x1003, 0x1007),))

    proof = prove_x86_16_direct_call_segment_entry_8616(
        DirectCallSegmentEntryCandidate8616(_BASE, 0x1003, 0x1007),
        caller_boundary=caller_boundary,
        callee_boundary=callee_boundary,
        artifact=artifact,
        callsite_index=index,
        restore_sources=(),
    )

    assert proof.verdict is DirectCallSegmentEntryVerdict8616.UNKNOWN_REFUSE
    assert proof.refusal is DirectCallSegmentEntryRefusal8616.CFG_NOT_CLOSED


def test_second_block_starting_inside_proof_window_refuses() -> None:
    """A mid-window block boundary could bypass the PUSH SS capture."""
    project = _synthetic_project()
    artifact = IRFunctionArtifact(
        function_addr=_BASE,
        blocks=(
            IRBlock(
                addr=_BASE,
                instrs=(
                    IRInstr("MOV", IRValue(MemSpace.REG, name="sp", size=2), (_const(0),), addr=_BASE),
                    IRInstr(
                        "MOV",
                        IRValue(MemSpace.REG, name="ds", size=2),
                        (IRValue(MemSpace.TMP, name="t0", size=2),),
                        addr=0x1001,
                    ),
                    IRInstr("CALL", None, (_const(0x1007),), addr=0x1002),
                ),
                successor_addrs=(0x1001,),
            ),
            IRBlock(addr=0x1001),
        ),
    )
    caller_boundary = _synthetic_boundary(
        project,
        _BASE,
        frozenset({_BASE, 0x1001}),
        frozenset({_BASE, 0x1001, 0x1002}),
        ((_BASE, 0x1001),),
    )
    callee_boundary = _synthetic_boundary(
        project, 0x1007, frozenset({0x1007}), frozenset({0x1007}), ()
    )
    index = _callsite_index(_BASE, 0x1010, ((0x1002, 0x1007),))
    source = SegmentRestoreSource(_BASE, 0x1001, "ds", _BASE, "ss")

    proof = prove_x86_16_direct_call_segment_entry_8616(
        DirectCallSegmentEntryCandidate8616(_BASE, 0x1002, 0x1007),
        caller_boundary=caller_boundary,
        callee_boundary=callee_boundary,
        artifact=artifact,
        callsite_index=index,
        restore_sources=(source,),
    )

    assert proof.verdict is DirectCallSegmentEntryVerdict8616.UNKNOWN_REFUSE
    assert proof.refusal is DirectCallSegmentEntryRefusal8616.AMBIGUOUS_BLOCK_PATH
    assert proof.stats.closed


def test_missing_instruction_address_refuses() -> None:
    """An instruction without an exact address cannot bound the proof window."""
    project = _synthetic_project()
    artifact = IRFunctionArtifact(
        function_addr=_BASE,
        blocks=(
            IRBlock(
                addr=_BASE,
                instrs=(
                    IRInstr("MOV", IRValue(MemSpace.REG, name="sp", size=2), (_const(0),), addr=_BASE),
                    IRInstr("MOV", IRValue(MemSpace.REG, name="cx", size=2), (_const(1),)),
                    IRInstr(
                        "MOV",
                        IRValue(MemSpace.REG, name="ds", size=2),
                        (IRValue(MemSpace.TMP, name="t0", size=2),),
                        addr=0x1001,
                    ),
                    IRInstr("CALL", None, (_const(0x1007),), addr=0x1002),
                ),
            ),
        ),
    )
    caller_boundary = _synthetic_boundary(
        project,
        _BASE,
        frozenset({_BASE}),
        frozenset({_BASE, 0x1001, 0x1002}),
        (),
    )
    callee_boundary = _synthetic_boundary(
        project, 0x1007, frozenset({0x1007}), frozenset({0x1007}), ()
    )
    index = _callsite_index(_BASE, 0x1010, ((0x1002, 0x1007),))
    source = SegmentRestoreSource(_BASE, 0x1001, "ds", _BASE, "ss")

    proof = prove_x86_16_direct_call_segment_entry_8616(
        DirectCallSegmentEntryCandidate8616(_BASE, 0x1002, 0x1007),
        caller_boundary=caller_boundary,
        callee_boundary=callee_boundary,
        artifact=artifact,
        callsite_index=index,
        restore_sources=(source,),
    )

    assert proof.verdict is DirectCallSegmentEntryVerdict8616.UNKNOWN_REFUSE
    assert proof.refusal is DirectCallSegmentEntryRefusal8616.INSTRUCTION_ADDR_UNKNOWN
    assert proof.stats.closed


def test_ir_refusal_present_refuses() -> None:
    """A caller artifact that already carries a refusal cannot be exact."""
    project = _synthetic_project()
    artifact = IRFunctionArtifact(
        function_addr=_BASE,
        blocks=(IRBlock(addr=_BASE),),
        refusals=(IRRefusal("block_decode_failed", "test", _BASE),),
    )
    caller_boundary = _synthetic_boundary(
        project, _BASE, frozenset({_BASE}), frozenset({_BASE}), ()
    )
    callee_boundary = _synthetic_boundary(
        project, 0x1007, frozenset({0x1007}), frozenset({0x1007}), ()
    )
    index = _callsite_index(_BASE, 0x1010, ())

    proof = prove_x86_16_direct_call_segment_entry_8616(
        DirectCallSegmentEntryCandidate8616(_BASE, 0x1003, 0x1007),
        caller_boundary=caller_boundary,
        callee_boundary=callee_boundary,
        artifact=artifact,
        callsite_index=index,
        restore_sources=(),
    )

    assert proof.verdict is DirectCallSegmentEntryVerdict8616.UNKNOWN_REFUSE
    assert proof.refusal is DirectCallSegmentEntryRefusal8616.IR_REFUSAL_PRESENT


def test_mismatched_caller_callee_project_refuses() -> None:
    """Caller and callee boundaries must belong to one binary image."""
    project = _synthetic_project()
    artifact = IRFunctionArtifact(
        function_addr=_BASE,
        blocks=(IRBlock(addr=_BASE),),
    )
    caller_boundary = _synthetic_boundary(
        project, _BASE, frozenset({_BASE}), frozenset({_BASE}), ()
    )
    callee_boundary = _synthetic_boundary(
        _synthetic_project(), 0x1007, frozenset({0x1007}), frozenset({0x1007}), ()
    )
    index = _callsite_index(_BASE, 0x1010, ())

    proof = prove_x86_16_direct_call_segment_entry_8616(
        DirectCallSegmentEntryCandidate8616(_BASE, 0x1003, 0x1007),
        caller_boundary=caller_boundary,
        callee_boundary=callee_boundary,
        artifact=artifact,
        callsite_index=index,
        restore_sources=(),
    )

    assert proof.verdict is DirectCallSegmentEntryVerdict8616.UNKNOWN_REFUSE
    assert proof.refusal is DirectCallSegmentEntryRefusal8616.PROJECT_MISMATCH


def test_candidate_rejects_non_integer_identity() -> None:
    """Malformed candidate identities fail loudly at construction."""
    with pytest.raises(ValueError):
        DirectCallSegmentEntryCandidate8616(_BASE, cast(int, None), 0x1007)


def test_branches_before_local_window_do_not_refuse() -> None:
    """Earlier branch paths enter before the exact in-block SS->DS copy."""
    project, artifact = _lift_caller(
        bytes.fromhex("85 c0 74 05 bb 01 00 eb 05 bb 02 00 eb 00 16 1f e8 02 00 c3 90 c3"),
    )
    caller = exact_function_range_boundary_8616(project, _BASE, 0x1014)
    assert caller is not None
    # Import the same exact Frontend census, rather than CFGFast's normalized
    # NOP/branch block partition, so the owned boundary surfaces agree.
    artifact = build_x86_16_ir_function_artifact(project, caller)
    callee = _callee_boundary(project, 0x1015, 0x1016)
    restoration = build_x86_16_segment_stack_restore_artifact(artifact)
    assert publish_function_ir_artifact_8616(project, artifact).artifact is artifact

    proof = prove_x86_16_direct_call_segment_entry_8616(
        DirectCallSegmentEntryCandidate8616(_BASE, 0x1010, 0x1015),
        caller_boundary=caller,
        callee_boundary=callee,
        artifact=artifact,
        callsite_index=_binary_callsite_index(project, caller),
        restore_sources=restoration.restore_sources,
    )

    assert proof.verdict is DirectCallSegmentEntryVerdict8616.PROVEN
    assert proof.saved_instruction_addr == 0x100E
    assert proof.stats.closed


def test_unrelated_callers_do_not_create_ambiguity() -> None:
    """A call elsewhere to the same callee does not duplicate this callsite."""
    project, artifact = _lift_caller(bytes.fromhex("16 1f e8 02 00 c3 90 c3 e8 fc ff c3"))
    caller = exact_function_range_boundary_8616(project, _BASE, 0x1006)
    assert caller is not None
    restoration = build_x86_16_segment_stack_restore_artifact(artifact)
    other_caller = _callee_boundary(project, 0x1008, 0x100C)
    original = _binary_callsite_index(project, caller).for_target(0x1007)
    unrelated = _binary_callsite_index(project, other_caller).for_target(0x1007)
    assert len(original) == len(unrelated) == 1
    index = build_decoded_direct_callsite_index_8616(
        {(_BASE, 0x1006): original[0].instructions,
         (0x1008, 0x100C): unrelated[0].instructions},
        direct_target_resolver=lambda instruction: resolve_direct_call_target_from_instruction_8616(
            project, instruction,
        ),
        instruction_address_resolver=lambda instruction: cast(DirectCapstoneInstruction8616, instruction).address,
    )
    assert publish_function_ir_artifact_8616(project, artifact).artifact is artifact

    proof = prove_x86_16_direct_call_segment_entry_8616(
        DirectCallSegmentEntryCandidate8616(_BASE, 0x1002, 0x1007),
        caller_boundary=caller,
        callee_boundary=_callee_boundary(project, 0x1007, 0x1008),
        artifact=artifact,
        callsite_index=index,
        restore_sources=restoration.restore_sources,
    )

    assert proof.verdict is DirectCallSegmentEntryVerdict8616.PROVEN
    assert proof.stats.closed


def test_near_low_word_collision_refuses_foreign_segment() -> None:
    """A different exact code segment cannot borrow this near call's target."""
    project, artifact = _lift_caller(bytes.fromhex("16 1f e8 02 00 c3 90 c3"))
    caller = exact_function_range_boundary_8616(project, _BASE, 0x1006)
    assert caller is not None
    restoration = build_x86_16_segment_stack_restore_artifact(artifact)
    foreign_callee = _synthetic_boundary(
        project, 0x11007, frozenset({0x11007}), frozenset({0x11007}), (),
    )

    proof = prove_x86_16_direct_call_segment_entry_8616(
        DirectCallSegmentEntryCandidate8616(_BASE, 0x1002, 0x11007),
        caller_boundary=caller,
        callee_boundary=foreign_callee,
        artifact=artifact,
        callsite_index=_binary_callsite_index(project, caller),
        restore_sources=restoration.restore_sources,
    )

    assert proof.verdict is DirectCallSegmentEntryVerdict8616.UNKNOWN_REFUSE
    assert proof.refusal is DirectCallSegmentEntryRefusal8616.TARGET_MISMATCH
    assert proof.stats.closed


def test_incomplete_direct_call_index_refuses() -> None:
    """A missing instruction coordinate in the supplied census stays refused."""
    project, artifact = _lift_caller(bytes.fromhex("16 1f e8 02 00 c3 90 c3"))
    caller = exact_function_range_boundary_8616(project, _BASE, 0x1006)
    assert caller is not None
    restoration = build_x86_16_segment_stack_restore_artifact(artifact)
    index = build_decoded_direct_callsite_index_8616(
        {(_BASE, 0x1006): (
            _DecodedInstruction(0x1007, 0x1002),
            _DecodedInstruction(0x1007, None),
        )},
        direct_target_resolver=lambda item: cast(_DecodedInstruction, item).target,
        instruction_address_resolver=lambda item: cast(_DecodedInstruction, item).address,
    )

    proof = prove_x86_16_direct_call_segment_entry_8616(
        DirectCallSegmentEntryCandidate8616(_BASE, 0x1002, 0x1007),
        caller_boundary=caller,
        callee_boundary=_callee_boundary(project, 0x1007, 0x1008),
        artifact=artifact,
        callsite_index=index,
        restore_sources=restoration.restore_sources,
    )

    assert proof.verdict is DirectCallSegmentEntryVerdict8616.UNKNOWN_REFUSE
    assert proof.stats.failure_count == 1
