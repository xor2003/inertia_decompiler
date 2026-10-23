"""Machine-frame positions must distinguish caller SP from callee entry SP."""

from dataclasses import replace

import pytest

from inertia.alias.call_stack_positions import (
    CallStackPositionRefusal8616,
    call_stack_position_is_current_8616,
    prove_call_stack_position_8616,
)
from inertia.ir.core import IRValue, MemSpace
from inertia.semantics.call_return_segment import collect_return_segment_frames_8616
from inertia.semantics.call_stack_effects import materialize_call_stack_effects_8616
from inertia.semantics.callsite_summary_program import build_callsite_summary_inventory_with_program_evidence_8616
from tests.semantics.test_call_stack_coordinates import _world


def _fixture(encoded: str, callsite: int):
    """Keep real lifted preparation and current callee transfer evidence."""
    project, function, source, summary = _world(bytes.fromhex(encoded), callsite)
    frames = collect_return_segment_frames_8616(project, function, {callsite: summary.return_addr})
    artifact = materialize_call_stack_effects_8616(
        source, {callsite: summary}, project=project,
        return_segment_frames={frame.callsite_addr: frame for frame in frames},
    ).function
    block, index = next(
        (block, index) for block in artifact.blocks for index, instruction in enumerate(block.instrs)
        if instruction.op == "CALL" and instruction.addr == callsite
    )
    return project, artifact, block, index


@pytest.mark.parametrize(
    ("encoded", "callsite", "expected"),
    [
        ("e80500 83c001 c3 90 89e0 c3", 0x1000, (0, -2, 0, 2)),
        ("55 89e5 50 e80900 83c402 89e0 89ec 5d c3 c3", 0x1004, (-4, -6, -4, 2)),
        ("55 89e5 50 9a12100000 83c402 89e0 89ec 5d c3 cb", 0x1004, (-4, -8, -4, 4)),
        ("55 89e5 50 0e e80900 83c402 89e0 89ec 5d c3 cb", 0x1005, (-6, -8, -4, 2)),
        ("55 89e5 50 0e e80900 83c404 89e0 89ec 5d c3 c3", 0x1005, (-6, -8, -6, 2)),
        ("55 89e5 6650 e80900 83c404 89e0 89ec 5d c3 c3", 0x1005, (-6, -8, -6, 2)),
        ("5050 e80b00 c3 90909090909090909090 c20400", 0x1002, (-4, -6, 0, 2)),
    ],
    ids=["entry", "near", "far", "linked-far-return", "cs-argument", "dword-argument", "ret-n"],
)
def test_call_positions_use_physical_preparation_once(encoded, callsite, expected):
    """Machine CALL pushes and RET-N are distinct from later caller cleanup."""
    _, artifact, block, index = _fixture(encoded, callsite)
    result = prove_call_stack_position_8616(artifact, block.addr, index)
    proof = result.proof
    assert proof is not None, result.to_dict()
    assert (proof.caller_before_offset, proof.callee_entry_offset,
            proof.caller_after_offset, proof.return_frame_bytes) == expected
    assert proof.callsite_addr == callsite
    assert call_stack_position_is_current_8616(artifact, proof)
    assert (result.raw_fact_count, result.normalized_fact_count, result.classified_fact_count,
            result.materialized_count, result.failure_count) == (1, 1, 1, 1, 0)


def test_call_position_rejects_changed_physical_frame_preparation():
    """A retained frame proof cannot overwrite conflicting current IR."""
    _, artifact, block, index = _fixture("e80500 83c001 c3 90 89e0 c3", 0x1000)
    original = prove_call_stack_position_8616(artifact, block.addr, index).proof
    assert original is not None
    changed = tuple(
        replace(instruction, args=(IRValue(MemSpace.CONST, const=0x7000, size=2),))
        if instruction.dst is not None and instruction.dst.space is MemSpace.REG
        and instruction.dst.name == "sp" else instruction for instruction in block.instrs
    )
    altered_block = replace(block, instrs=changed)
    altered = replace(artifact, blocks=tuple(altered_block if item is block else item for item in artifact.blocks))
    result = prove_call_stack_position_8616(altered, block.addr, index)
    assert result.proof is None
    assert result.refusal is CallStackPositionRefusal8616.UNKNOWN_POSITION
    assert not call_stack_position_is_current_8616(altered, original)
    assert (result.classified_fact_count, result.materialized_count, result.failure_count) == (0, 0, 1)


def test_call_position_revalidates_live_callee_bytes():
    """Changing a near RET to RETF must invalidate the saved boundary proof."""
    project, artifact, block, index = _fixture("e80500 83c001 c3 90 89e0 c3", 0x1000)
    original = prove_call_stack_position_8616(artifact, block.addr, index).proof
    assert original is not None
    project.loader.memory.store(0x100a, b"\xcb")
    result = prove_call_stack_position_8616(artifact, block.addr, index)
    assert result.proof is None
    assert result.refusal is CallStackPositionRefusal8616.UNPROVEN_EFFECT
    assert not call_stack_position_is_current_8616(artifact, original)


def test_call_position_refuses_conflicting_incoming_sp():
    """Conditional PUSH creates two real entry positions at the same CALL."""
    _, artifact, block, index = _fixture("85c0 7401 50 e80800 c3 90909090909090 c3", 0x1005)
    result = prove_call_stack_position_8616(artifact, block.addr, index)
    assert result.proof is None
    assert result.refusal is CallStackPositionRefusal8616.UNKNOWN_POSITION


def test_call_position_refuses_conflicting_frame_width_in_current_ir():
    """A source CALL proof cannot invent its missing physical frame push."""
    _, artifact, block, index = _fixture("e80500 83c001 c3 90 89e0 c3", 0x1000)
    changed = tuple(
        replace(instruction, args=(IRValue(MemSpace.REG, name="sp", size=2),))
        if instruction.dst is not None and instruction.dst.space is MemSpace.REG
        and instruction.dst.name == "sp" else instruction for instruction in block.instrs
    )
    altered_block = replace(block, instrs=changed)
    altered = replace(artifact, blocks=tuple(altered_block if item is block else item for item in artifact.blocks))
    result = prove_call_stack_position_8616(altered, block.addr, index)
    assert result.proof is None
    assert result.refusal is CallStackPositionRefusal8616.FRAME_MISMATCH


def test_call_position_rejects_changed_call_target():
    """The saved decomposition must authenticate the same typed source CALL."""
    _, artifact, block, index = _fixture("e80500 83c001 c3 90 89e0 c3", 0x1000)
    changed_call = replace(block.instrs[index], args=(IRValue(MemSpace.CONST, const=0x2000, size=4),))
    altered_block = replace(block, instrs=(*block.instrs[:index], changed_call, *block.instrs[index + 1:]))
    altered = replace(artifact, blocks=tuple(altered_block if item is block else item for item in artifact.blocks))
    result = prove_call_stack_position_8616(altered, block.addr, index)
    assert result.proof is None
    assert result.refusal is CallStackPositionRefusal8616.UNPROVEN_EFFECT


def test_call_position_requires_the_same_function_scope():
    """Even equivalent positions cannot authorize a different source function."""
    _, artifact, block, index = _fixture("e80500 83c001 c3 90 89e0 c3", 0x1000)
    proof = prove_call_stack_position_8616(artifact, block.addr, index).proof
    assert proof is not None
    assert not call_stack_position_is_current_8616(artifact, replace(proof, function_addr=0x2000))


def test_call_position_rejects_missing_cfg_successor():
    """Incomplete source coverage cannot become an entry-coordinate proof."""
    _, artifact, block, index = _fixture("e80500 83c001 c3 90 89e0 c3", 0x1000)
    altered_block = replace(block, successor_addrs=(0x3000,))
    altered = replace(artifact, blocks=tuple(altered_block if item is block else item for item in artifact.blocks))
    result = prove_call_stack_position_8616(altered, block.addr, index)
    assert result.proof is None
    assert result.refusal is CallStackPositionRefusal8616.INVALID_SOURCE


def test_later_call_consumes_the_preceding_callee_purge():
    """The second position includes a real earlier RET-N transfer exactly once."""
    project, function, source, _ = _world(
        bytes.fromhex("50e80c00 50e80800 c3 90909090909090 89e0c20200"), 0x1001,
    )
    summaries = build_callsite_summary_inventory_with_program_evidence_8616(project, function, (0x1001, 0x1005))
    artifact = materialize_call_stack_effects_8616(source, summaries, project=project).function
    results = [
        prove_call_stack_position_8616(artifact, block.addr, index)
        for block in artifact.blocks for index, instruction in enumerate(block.instrs)
        if instruction.op == "CALL"
    ]
    assert len(results) == 2
    for result in results:
        proof = result.proof
        assert proof is not None, result.to_dict()
        assert (proof.caller_before_offset, proof.callee_entry_offset, proof.caller_after_offset) == (-2, -4, 0)


def test_call_position_survives_equal_sp_with_different_stack_bytes():
    """Must-state joins need equal SP coordinates, independent of saved values."""
    _, artifact, block, index = _fixture("85c0 7403 50 eb01 53 e80500 5ac3 909090 89e0c3", 0x1008)
    result = prove_call_stack_position_8616(artifact, block.addr, index)
    proof = result.proof
    assert proof is not None, result.to_dict()
    assert (proof.caller_before_offset, proof.callee_entry_offset, proof.caller_after_offset) == (-2, -4, -2)


def test_call_position_does_not_require_memory_preservation():
    """Unknown saved-byte identity cannot erase an independently proved SP."""
    _, artifact, block, index = _fixture("e80500 83c001 c3 90 89e0 c3", 0x1000)
    call = block.instrs[index]
    assert call.call_stack_effect is not None
    changed_call = replace(call, call_stack_effect=replace(call.call_stack_effect, complete=False, bp_preserved=False))
    altered_block = replace(block, instrs=(*block.instrs[:index], changed_call, *block.instrs[index + 1:]))
    altered = replace(artifact, blocks=tuple(altered_block if item is block else item for item in artifact.blocks))
    result = prove_call_stack_position_8616(altered, block.addr, index)
    proof = result.proof
    assert proof is not None, result.to_dict()
    assert (proof.caller_before_offset, proof.callee_entry_offset, proof.caller_after_offset) == (0, -2, 0)


def test_call_position_rejects_competing_net_transfer():
    """Retained net effects and their source decomposition must agree."""
    _, artifact, block, index = _fixture("e80500 83c001 c3 90 89e0 c3", 0x1000)
    call = block.instrs[index]
    assert call.call_stack_effect is not None
    changed_call = replace(call, call_stack_effect=replace(call.call_stack_effect, net_stack_delta=2))
    altered_block = replace(block, instrs=(*block.instrs[:index], changed_call, *block.instrs[index + 1:]))
    altered = replace(artifact, blocks=tuple(altered_block if item is block else item for item in artifact.blocks))
    result = prove_call_stack_position_8616(altered, block.addr, index)
    assert result.proof is None
    assert result.refusal is CallStackPositionRefusal8616.UNPROVEN_EFFECT
