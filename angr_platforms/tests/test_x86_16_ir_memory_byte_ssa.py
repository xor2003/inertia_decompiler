from dataclasses import replace

import pytest
from angr_platforms.X86_16.ir.core import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRCallStackEffect8616,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa
from angr_platforms.X86_16.ir.ssa_memory_contracts import SSAMemoryOverlapRelation8616


def _bp_slot(offset: int, size: int) -> IRAddress:
    return IRAddress(
        MemSpace.SS,
        base=("bp",),
        offset=offset,
        size=size,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.DEFAULTED,
    )


def _store(address: IRAddress, value: int = 1) -> IRInstr:
    return IRInstr(
        "STORE",
        None,
        (address, IRValue(MemSpace.CONST, const=value, size=address.size)),
        size=address.size,
    )


def _load(address: IRAddress) -> IRInstr:
    return IRInstr(
        "LOAD",
        IRValue(MemSpace.REG, name="ax", size=address.size),
        (address,),
        size=address.size,
    )


@pytest.mark.parametrize("offset,size", [(-4, 1), (-3, 1), (-5, 2), (-5, 4)])
def test_call_escape_invalidates_containing_word_without_separate_byte_access(offset: int, size: int) -> None:
    """An escaped subrange need not occur as a separate caller load/store."""
    word = _bp_slot(-4, 2)
    effect = IRCallStackEffect8616(
        net_stack_delta=0, preserved_ranges=(word,),
        escaped_ranges=(_bp_slot(offset, size),), complete=True,
    )
    assert not effect.preserves(word)
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(IRBlock(addr=0x1000, instrs=(
            _store(word), IRInstr("CALL", None, (), call_stack_effect=effect), _load(word),
        )),),
    )
    result = build_x86_16_function_ssa(artifact)
    assert result.memory_refusals


@pytest.mark.parametrize("offset", [-6, -2])
def test_disjoint_call_escape_keeps_word_preservation(offset: int) -> None:
    word = _bp_slot(-4, 2)
    effect = IRCallStackEffect8616(
        net_stack_delta=0, preserved_ranges=(word,),
        escaped_ranges=(_bp_slot(offset, 2),), complete=True,
    )
    assert effect.preserves(word)


@pytest.mark.parametrize("escaped", [
    replace(_bp_slot(100, 1), base=("sp",)),
    replace(_bp_slot(100, 1), status=AddressStatus.UNKNOWN),
    replace(_bp_slot(100, 1), space=MemSpace.UNKNOWN),
    _bp_slot(100, 0),
    replace(_bp_slot(100, 1), base_values=(IRValue(MemSpace.REG, name="bp", version=2),)),
])
def test_call_escape_with_unresolved_coordinate_refuses_preservation(escaped: IRAddress) -> None:
    word = _bp_slot(-4, 2)
    effect = IRCallStackEffect8616(0, (word,), (escaped,), True)
    assert not effect.preserves(word)


@pytest.mark.parametrize("offset", [0, 0xffff])
def test_call_escape_overlap_honors_word_offset_wrap(offset: int) -> None:
    word = _bp_slot(0xffff, 2)
    effect = IRCallStackEffect8616(0, (word,), (_bp_slot(offset, 1),), True)
    assert not effect.preserves(word)


def test_call_escape_in_distinct_segment_keeps_stack_word() -> None:
    word = _bp_slot(-4, 2)
    escaped = replace(word, space=MemSpace.DS)
    assert IRCallStackEffect8616(0, (word,), (escaped,), True).preserves(word)


def test_memory_ssa_versions_partial_overlap_as_disjoint_cells() -> None:
    word = _bp_slot(-4, 2)
    shifted_word = _bp_slot(-3, 2)
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(IRBlock(addr=0x1000, instrs=(_store(word), _load(shifted_word))),),
    )

    function_ssa = build_x86_16_function_ssa(artifact)

    assert function_ssa.memory_stats.complete is True
    expected_facts = 3
    assert function_ssa.memory_stats.raw_fact_count == expected_facts
    assert function_ssa.memory_stats.materialized_count == expected_facts
    assert function_ssa.memory_stats.failure_count == 0
    assert function_ssa.memory_refusals == ()
    assert [binding.address.version for binding in function_ssa.memory_bindings] == [1, 2]
    store_access, load_access = function_ssa.memory_accesses
    assert [
        (item.source_byte_offset, item.address.offset, item.address.size, item.address.version)
        for item in store_access.slices
    ] == [(0, -4, 1, 1), (1, -3, 1, 2)]
    assert [
        (item.source_byte_offset, item.address.offset, item.address.size, item.address.version)
        for item in load_access.slices
    ] == [(0, -3, 1, 2), (1, -2, 1, 0)]
    overlap = function_ssa.memory_overlaps[0]
    assert overlap.relation is SSAMemoryOverlapRelation8616.PARTIAL
    assert (overlap.intersection.offset, overlap.intersection.size) == (-3, 1)
    assert function_ssa.to_dict()["memory_accesses"][1]["complete"] is True
    assert all(
        isinstance(instr.args[0], IRAddress) and instr.args[0].version is None
        for instr in function_ssa.blocks[0].instrs
    )


def test_memory_ssa_contained_byte_load_reaches_word_store_slice() -> None:
    word = _bp_slot(-4, 2)
    high_byte = _bp_slot(-3, 1)
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(IRBlock(addr=0x1000, instrs=(_store(word), _load(high_byte))),),
    )

    function_ssa = build_x86_16_function_ssa(artifact)

    assert function_ssa.memory_refusals == ()
    assert len(function_ssa.memory_accesses[0].slices) == word.size
    byte_access = function_ssa.memory_accesses[1]
    assert len(byte_access.slices) == 1
    high_byte_version = 2
    assert byte_access.slices[0].address.version == high_byte_version
    load_address = function_ssa.blocks[0].instrs[1].args[0]
    assert isinstance(load_address, IRAddress)
    assert load_address.version == high_byte_version
    assert function_ssa.memory_overlaps[0].relation is SSAMemoryOverlapRelation8616.LEFT_CONTAINS_RIGHT


def test_memory_ssa_joins_each_cell_before_contained_byte_load() -> None:
    word = _bp_slot(-4, 2)
    high_byte = _bp_slot(-3, 1)
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(addr=0x1000, successor_addrs=(0x1010, 0x1020)),
            IRBlock(addr=0x1010, successor_addrs=(0x1030,), instrs=(_store(word, 1),)),
            IRBlock(addr=0x1020, successor_addrs=(0x1030,), instrs=(_store(word, 2),)),
            IRBlock(addr=0x1030, instrs=(_load(high_byte),)),
        ),
    )

    function_ssa = build_x86_16_function_ssa(artifact)

    assert function_ssa.memory_stats.complete is True
    assert len(function_ssa.memory_phi_nodes) == word.size
    phi_by_offset = {phi.target.offset: phi for phi in function_ssa.memory_phi_nodes}
    assert [item.address.version for item in phi_by_offset[-4].incoming] == [1, 3]
    assert [item.address.version for item in phi_by_offset[-3].incoming] == [2, 4]
    byte_access = function_ssa.memory_accesses[-1]
    assert byte_access.slices[0].address.version == phi_by_offset[-3].target.version


def test_memory_ssa_preserves_split_cells_from_complete_call_effect() -> None:
    word = _bp_slot(-4, 2)
    high_byte = _bp_slot(-3, 1)
    call_effect = IRCallStackEffect8616(
        net_stack_delta=0,
        preserved_ranges=(word, high_byte),
        complete=True,
    )
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(
                addr=0x1000,
                instrs=(
                    _store(word),
                    IRInstr(
                        "CALL",
                        None,
                        (IRValue(MemSpace.CONST, const=0x2000, size=2),),
                        call_stack_effect=call_effect,
                    ),
                    _load(high_byte),
                ),
            ),
        ),
    )

    function_ssa = build_x86_16_function_ssa(artifact)

    assert function_ssa.memory_refusals == ()
    assert [item.address.version for item in function_ssa.memory_accesses[-1].slices] == [2]


def test_memory_ssa_refuses_connected_overlap_component_on_byte_escape() -> None:
    word = _bp_slot(-4, 2)
    high_byte = _bp_slot(-3, 1)
    call_effect = IRCallStackEffect8616(
        net_stack_delta=0,
        preserved_ranges=(word, high_byte),
        escaped_ranges=(high_byte,),
        complete=True,
    )
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(
                addr=0x1000,
                instrs=(
                    _store(word),
                    IRInstr(
                        "CALL",
                        None,
                        (IRValue(MemSpace.CONST, const=0x2000, size=2),),
                        call_stack_effect=call_effect,
                    ),
                    _load(high_byte),
                ),
            ),
        ),
    )

    function_ssa = build_x86_16_function_ssa(artifact)

    assert function_ssa.memory_stats.complete is True
    assert function_ssa.memory_stats.materialized_count == 1
    refused_access_count = 2
    assert function_ssa.memory_stats.failure_count == refused_access_count
    assert function_ssa.memory_accesses == ()
    assert function_ssa.memory_bindings == ()
    assert {refusal.kind for refusal in function_ssa.memory_refusals} == {
        "unknown_call_stack_effect"
    }
