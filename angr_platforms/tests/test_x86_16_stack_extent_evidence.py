"""Frame extents are allocation facts, never dead-store permission."""

from dataclasses import replace

import pytest
from angr_platforms.X86_16.alias.stack_memory_ssa import build_x86_16_stack_memory_ssa_alias_artifact
from angr_platforms.X86_16.ir import AddressStatus, IRAddress, IRInstr, IRValue, MemSpace, SegmentOrigin
from angr_platforms.X86_16.ir.ssa import SSABlock
from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa
from angr_platforms.X86_16.ir.stack_extent_evidence import (
    StackExtentRefusal8616,
    build_stack_extent_evidence_8616,
    collect_released_stack_extents_8616,
)
from x86_16_logical_memory_fixtures import lift_ir_artifact


def _move(name, version, source_name, source_version, offset=0):
    return IRInstr(
        "MOV", IRValue(MemSpace.REG, name=name, size=2, version=version),
        (IRValue(MemSpace.REG, name=source_name, size=2, version=source_version, offset=offset),),
        size=2,
    )


def _block():
    return SSABlock(0x1000, (
        _move("sp", 1, "sp", 0, -2),
        _move("bp", 1, "sp", 1),
        _move("sp", 2, "sp", 1, -4),
        _move("sp", 3, "bp", 1),
        _move("sp", 4, "sp", 3, 2),
    ), ())


def test_matches_local_and_saved_register_extents_without_conflating_them():
    extents = collect_released_stack_extents_8616(_block())
    assert [(e.allocation_index, e.release_index, e.lower_offset, e.upper_offset) for e in extents] == [
        (0, 4, -2, 0), (2, 3, -6, -2),
    ]


@pytest.mark.parametrize("barrier", ("CALL", "CBRANCH", "CJMP", "JMP"))
def test_control_effect_refuses_block_extent_proof(barrier):
    block = _block()
    assert collect_released_stack_extents_8616(replace(block, instrs=(*block.instrs, IRInstr(barrier, None, ())))) == ()


def test_binary_frame_release_survives_later_unknown_restored_bp_value():
    artifact = lift_ir_artifact(bytes.fromhex("558bec83ec048be55dc3"))
    ssa = build_x86_16_function_ssa(artifact)
    extents = collect_released_stack_extents_8616(ssa.blocks[0])
    assert (-6, -2) in {(e.lower_offset, e.upper_offset) for e in extents}
    alias = build_x86_16_stack_memory_ssa_alias_artifact(ssa)
    assert alias.released_stack_extents == extents
    assert alias.to_dict()["released_stack_extents"] == [extent.to_dict() for extent in extents]


@pytest.mark.parametrize("replacement", (
    _move("sp", 2, "bp", 0),
    _move("sp", 1, "sp", 1, -4),
    _move("sp", 2, "sp", 1, -(1 << 16)),
    _move("esp", 2, "sp", 1, -4),
    replace(_move("sp", 2, "sp", 1, -4), dst=IRValue(MemSpace.REG, name="sp", size=4, version=2)),
))
def test_unknown_duplicate_wrap_and_mixed_width_updates_refuse(replacement):
    block = _block()
    changed = replace(block, instrs=(*block.instrs[:2], replacement, *block.instrs[3:]))
    assert collect_released_stack_extents_8616(changed) == ()


def test_partial_release_does_not_claim_whole_span_lifetime():
    block = _block()
    partial = _move("sp", 3, "sp", 2, 2)
    changed = replace(block, instrs=(*block.instrs[:3], partial, block.instrs[4]))
    assert collect_released_stack_extents_8616(changed) == ()


def test_upstream_ssa_refusal_prevents_extent_publication():
    assert collect_released_stack_extents_8616(replace(_block(), refusals=("unknown definition",))) == ()


@pytest.mark.parametrize("block, refusal", (
    (SSABlock(0x1000, (), ()), StackExtentRefusal8616.NONE),
    (replace(_block(), refusals=("unknown definition",)), StackExtentRefusal8616.UNKNOWN_COORDINATE),
    (replace(_block(), instrs=_block().instrs[:-1]), StackExtentRefusal8616.UNRELEASED_ALLOCATION),
    (SSABlock(0x1000, (_move("sp", 1, "sp", 0, -(1 << 16)),), ()), StackExtentRefusal8616.WRAP_SIZED_MOVEMENT),
))
def test_empty_extent_result_retains_explicit_verdict_and_closed_census(block, refusal):
    evidence = build_stack_extent_evidence_8616(block)
    assert evidence.extents == ()
    assert evidence.refusal is refusal
    assert evidence.complete == (refusal is StackExtentRefusal8616.NONE)
    stats = evidence.to_dict()["stats"]
    assert stats["raw_fact_count"] == stats["materialized_count"] + stats["failure_count"]
    assert stats["classified_fact_count"] == stats["materialized_count"]


def test_alias_serialization_preserves_extent_completion_state():
    ssa = build_x86_16_function_ssa(lift_ir_artifact(bytes.fromhex("558bec83ec048be55dc3")))
    alias = build_x86_16_stack_memory_ssa_alias_artifact(ssa)
    assert len(alias.stack_extent_evidence) == len(ssa.blocks)
    assert all(evidence.complete for evidence in alias.stack_extent_evidence)
    assert alias.to_dict()["stack_extent_evidence"] == [evidence.to_dict() for evidence in alias.stack_extent_evidence]


@pytest.mark.parametrize("index_shift", (0, 1, 2))
def test_indexed_sp_expression_is_not_a_constant_frame_displacement(index_shift):
    block = _block()
    allocation = block.instrs[2]
    source = replace(
        allocation.args[0], index=IRValue(MemSpace.REG, name="ax", size=2, version=0), index_shift=index_shift,
    )
    indexed = replace(allocation, args=(source,))
    changed = replace(block, instrs=(*block.instrs[:2], indexed, *block.instrs[3:]))
    evidence = build_stack_extent_evidence_8616(changed)
    assert evidence.refusal is StackExtentRefusal8616.UNKNOWN_COORDINATE
    assert evidence.extents == ()


def _local_address():
    return IRAddress(
        MemSpace.SS, ("bp",), -4, 2, AddressStatus.STABLE, SegmentOrigin.PROVEN,
        base_values=(IRValue(MemSpace.REG, name="bp", size=2, version=1),),
    )


def test_exact_ssa_address_is_resolved_only_after_its_definition():
    evidence = build_stack_extent_evidence_8616(_block())
    address = _local_address()
    expected_entry_offset = -6
    assert evidence.address_entry_offset(_block().addr, 2, address) == expected_entry_offset
    assert evidence.address_entry_offset(_block().addr, 1, address) is None
    assert evidence.address_entry_offset(_block().addr + 1, 2, address) is None


@pytest.mark.parametrize("address", (
    replace(_local_address(), space=MemSpace.DS),
    replace(_local_address(), base_values=()),
    replace(_local_address(), size=0),
    replace(_local_address(), segment_origin=SegmentOrigin.UNKNOWN),
    replace(_local_address(), base_values=(IRValue(MemSpace.REG, name="bp", size=2),)),
    replace(_local_address(), base_values=(IRValue(MemSpace.REG, name="bp", size=2, version=0),)),
    replace(_local_address(), base_values=(IRValue(MemSpace.REG, name="bp", size=4, version=1),)),
))
def test_unknown_or_mismatched_memory_base_cannot_be_normalized(address):
    evidence = build_stack_extent_evidence_8616(_block())
    assert evidence.address_entry_offset(_block().addr, 2, address) is None


def test_binary_control_stack_reads_do_not_overlap_local_write_coordinates():
    body = bytes.fromhex("558bec83ec04c746fc1704c746fe00002bdb8ec3bb1704268c078be55dc3")
    ssa = build_x86_16_function_ssa(lift_ir_artifact(body))
    block = ssa.blocks[0]
    evidence = build_stack_extent_evidence_8616(block)
    reads = set()
    writes = set()
    for index, instruction in enumerate(block.instrs):
        if instruction.op not in {"LOAD", "STORE"}:
            continue
        address = instruction.args[0]
        if not isinstance(address, IRAddress) or address.space is not MemSpace.SS:
            continue
        offset = evidence.address_entry_offset(block.addr, index, address)
        assert offset is not None
        cells = set(range(offset, offset + address.size))
        (reads if instruction.op == "LOAD" else writes).update(cells)
    assert reads == {-2, -1, 0, 1}
    assert writes == {-6, -5, -4, -3, -2, -1}
    assert reads.isdisjoint({-6, -5, -4, -3})
