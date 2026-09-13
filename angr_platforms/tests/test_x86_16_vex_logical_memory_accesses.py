from __future__ import annotations

import pyvex
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir import MemSpace
from angr_platforms.X86_16.ir.logical_memory_capture import collect_accesses_for_function
from angr_platforms.X86_16.ir.logical_memory_contracts import (
    IRLogicalMemoryFailureKind8616,
    IRMemoryAccessKind8616,
)
from x86_16_logical_memory_fixtures import (
    assert_closed_single_refusal,
    lift_ir_artifact,
    lift_ir_artifact_with_blocks,
    logical_address,
    logical_capture,
    memory_instruction,
    resolve_logical_memory,
)


def test_direct_byte_test_records_only_its_executed_byte() -> None:
    """A TEST byte must not claim the adjacent byte as part of its operand."""
    with collect_accesses_for_function(0x1000) as captured:
        pyvex.lift(bytes.fromhex("f6 06 34 12 01 74 02 90 c3"), 0x1000, Arch86_16(), opt_level=0)
    access = captured.accesses[0]
    assert access.kind is IRMemoryAccessKind8616.READ
    assert access.address is not None
    assert (access.address.space, access.address.offset, access.address.size) == (
        MemSpace.DS, 0x1234, 1,
    )


def test_real_vex_import_retains_direct_ds_words_as_two_logical_byte_slices() -> None:
    artifact = lift_ir_artifact(bytes.fromhex("8b 1e 34 12 89 1e 78 56 c3"))

    logical = artifact.logical_memory
    assert logical is not None
    assert logical.closed
    assert logical.refusals == ()
    assert logical.stats.to_dict() == {
        "raw_fact_count": 3,
        "normalized_fact_count": 3,
        "classified_fact_count": 3,
        "materialized_count": 3,
        "failure_count": 0,
    }
    assert tuple(item.kind for item in logical.accesses) == (
        IRMemoryAccessKind8616.READ,
        IRMemoryAccessKind8616.WRITE,
        IRMemoryAccessKind8616.READ,
    )
    assert tuple(
        (item.key.insn_addr, item.address.space, item.address.offset, item.address.size)
        for item in logical.accesses
    ) == (
        (0x1000, MemSpace.DS, 0x1234, 2),
        (0x1004, MemSpace.DS, 0x5678, 2),
        (0x1008, MemSpace.SS, 0, 2),
    )
    assert tuple(
        tuple(
            (
                execution_slice.insn_addr,
                execution_slice.source_byte_offset,
                execution_slice.address.offset,
                execution_slice.address.size,
            )
            for execution_slice in access.execution_slices
        )
        for access in logical.accesses
    ) == (
        ((0x1000, 0, 0x1234, 1), (0x1000, 1, 0x1235, 1)),
        ((0x1004, 0, 0x5678, 1), (0x1004, 1, 0x5679, 1)),
        ((0x1008, 0, 0, 1), (0x1008, 1, 1, 1)),
    )
    for access in logical.accesses:
        expected_op = "LOAD" if access.kind is IRMemoryAccessKind8616.READ else "STORE"
        for execution_slice in access.execution_slices:
            raw_instruction = artifact.blocks[0].instrs[execution_slice.instr_index]
            assert raw_instruction.addr == access.key.insn_addr
            assert raw_instruction.op == expected_op
    assert logical.accesses[-1].address.base == ("sp",)


def test_real_vex_import_recaptures_logical_access_after_cached_prelift() -> None:
    artifact = lift_ir_artifact_with_blocks(
        bytes.fromhex("8b 1e 34 12 c3"),
        (0x1000,),
        (),
        prelift=True,
    )

    logical = artifact.logical_memory
    assert logical is not None
    assert logical.closed
    assert logical.refusals == ()
    assert logical.stats.raw_fact_count == logical.stats.materialized_count == 2
    assert logical.accesses[0].address.offset == 0x1234


def test_real_vex_import_wraps_direct_ds_ffff_word_without_consuming_ret_bytes() -> None:
    artifact = lift_ir_artifact(bytes.fromhex("8b 1e ff ff c3"))

    logical = artifact.logical_memory
    assert logical is not None
    assert logical.closed
    assert logical.refusals == ()
    assert logical.stats.to_dict() == {
        "raw_fact_count": 2,
        "normalized_fact_count": 2,
        "classified_fact_count": 2,
        "materialized_count": 2,
        "failure_count": 0,
    }
    access, ret_access = logical.accesses
    assert access.kind is IRMemoryAccessKind8616.READ
    assert access.key.insn_addr == 0x1000
    assert (
        access.address.space,
        access.address.offset,
        access.address.size,
    ) == (MemSpace.DS, 0xFFFF, 2)
    assert tuple(
        (item.insn_addr, item.source_byte_offset, item.address.space, item.address.offset)
        for item in access.execution_slices
    ) == (
        (0x1000, 0, MemSpace.DS, 0xFFFF),
        (0x1000, 1, MemSpace.DS, 0x0000),
    )
    ret_memory_indexes = {
        index
        for index, instruction in enumerate(artifact.blocks[0].instrs)
        if instruction.addr == 0x1004 and instruction.op in {"LOAD", "STORE"}
    }
    assert ret_memory_indexes
    assert ret_access.address.space is MemSpace.SS
    assert ret_memory_indexes == {item.instr_index for item in ret_access.execution_slices}
    assert ret_memory_indexes.isdisjoint(
        item.instr_index for item in access.execution_slices
    )


def test_overlapping_blocks_keep_only_canonical_logical_memory_capture() -> None:
    artifact = lift_ir_artifact_with_blocks(
        bytes.fromhex("b8 01 00 8b 1e 34 12 c3"),
        (0x1000, 0x1003, 0x1007),
        ((0x1000, 0x1003), (0x1003, 0x1007)),
    )

    logical = artifact.logical_memory
    assert logical is not None
    assert logical.closed
    assert logical.refusals == ()
    assert tuple(
        (item.key.block_addr, item.key.insn_addr) for item in logical.accesses
    ) == ((0x1003, 0x1003), (0x1007, 0x1007))
    assert artifact.summary["logical_memory_capture_raw_fact_count"] == 5
    assert artifact.summary["logical_memory_capture_owned_fact_count"] == 2
    assert artifact.summary["logical_memory_capture_ownership_discarded_count"] == 3


def test_direct_ds_word_read_and_write_each_resolve_to_two_exact_byte_slices() -> None:
    cases = (
        (IRMemoryAccessKind8616.READ, "LOAD"),
        (IRMemoryAccessKind8616.WRITE, "STORE"),
    )
    for kind, raw_op in cases:
        instruction = memory_instruction(kind, offset=0x2345)
        assert instruction.op == raw_op

        _, result = resolve_logical_memory(
            (instruction,),
            (logical_capture(kind, offset=0x2345),),
        )

        assert result.closed
        assert result.refusals == ()
        assert result.stats.materialized_count == 1
        (access,) = result.accesses
        assert access.kind is kind
        assert access.address == logical_address(MemSpace.DS, 0x2345, 2)
        assert tuple(
            (
                item.instr_index,
                item.source_byte_offset,
                item.address.space,
                item.address.offset,
                item.address.size,
            )
            for item in access.execution_slices
        ) == (
            (0, 0, MemSpace.DS, 0x2345, 1),
            (0, 1, MemSpace.DS, 0x2346, 1),
        )


def test_ds_ffff_word_wraps_execution_slices_but_remains_one_typed_operand() -> None:
    _, result = resolve_logical_memory(
        (
            memory_instruction(
                IRMemoryAccessKind8616.READ,
                offset=0xFFFF,
            ),
        ),
        (logical_capture(IRMemoryAccessKind8616.READ, offset=0xFFFF),),
    )

    assert result.closed
    (access,) = result.accesses
    assert access.address == logical_address(MemSpace.DS, 0xFFFF, 2)
    assert tuple(item.source_byte_offset for item in access.execution_slices) == (0, 1)
    assert tuple(item.address.offset for item in access.execution_slices) == (0xFFFF, 0x0000)


def test_ds_and_ss_accesses_keep_distinct_instruction_identity() -> None:
    instructions = (
        memory_instruction(
            IRMemoryAccessKind8616.READ,
            insn_addr=0x1000,
            offset=0x80,
        ),
        memory_instruction(
            IRMemoryAccessKind8616.READ,
            insn_addr=0x1002,
            space=MemSpace.SS,
            offset=0x80,
        ),
    )
    captures = (
        logical_capture(IRMemoryAccessKind8616.READ, insn_addr=0x1000, offset=0x80),
        logical_capture(
            IRMemoryAccessKind8616.READ,
            insn_addr=0x1002,
            space=MemSpace.SS,
            offset=0x80,
        ),
    )

    _, result = resolve_logical_memory(instructions, captures)

    assert result.closed
    assert result.refusals == ()
    assert tuple(
        (item.key.insn_addr, item.key.access_ordinal, item.address.space)
        for item in result.accesses
    ) == (
        (0x1000, 0, MemSpace.DS),
        (0x1002, 0, MemSpace.SS),
    )


def test_adjacent_bytes_from_different_instructions_are_never_fused() -> None:
    _, result = resolve_logical_memory(
        (
            memory_instruction(
                IRMemoryAccessKind8616.READ,
                insn_addr=0x1000,
                offset=0x200,
                size=1,
            ),
            memory_instruction(
                IRMemoryAccessKind8616.READ,
                insn_addr=0x1001,
                offset=0x201,
                size=1,
            ),
        ),
        (logical_capture(IRMemoryAccessKind8616.READ, insn_addr=0x1000, offset=0x200),),
    )

    assert_closed_single_refusal(
        result,
        IRLogicalMemoryFailureKind8616.BYTE_COVERAGE_CONFLICT,
    )


def test_absent_typed_capture_keeps_raw_bytes_without_inventing_a_word() -> None:
    instructions = (
        memory_instruction(
            IRMemoryAccessKind8616.READ,
            offset=0x400,
            size=1,
            ordinal=0,
        ),
        memory_instruction(
            IRMemoryAccessKind8616.READ,
            offset=0x401,
            size=1,
            ordinal=1,
        ),
    )

    block, result = resolve_logical_memory(instructions, ())

    assert block.instrs == instructions
    assert tuple(item.size for item in block.instrs) == (1, 1)
    assert result.closed
    assert result.accesses == ()
    assert result.refusals == ()
    assert result.stats.to_dict() == {
        "raw_fact_count": 0,
        "normalized_fact_count": 0,
        "classified_fact_count": 0,
        "materialized_count": 0,
        "failure_count": 0,
    }


def test_missing_ambiguous_and_conflicting_evidence_has_typed_closed_refusals() -> None:
    ambiguous = (
        memory_instruction(IRMemoryAccessKind8616.READ),
        memory_instruction(IRMemoryAccessKind8616.READ, size=1, ordinal=1),
        memory_instruction(
            IRMemoryAccessKind8616.READ,
            offset=0x2001,
            size=1,
            ordinal=2,
        ),
    )
    cases = (
        ((), IRLogicalMemoryFailureKind8616.MISSING_EXECUTION_SLICES),
        (ambiguous, IRLogicalMemoryFailureKind8616.AMBIGUOUS_EXECUTION_SLICES),
        (
            (memory_instruction(IRMemoryAccessKind8616.WRITE),),
            IRLogicalMemoryFailureKind8616.ACCESS_KIND_CONFLICT,
        ),
        (
            (memory_instruction(IRMemoryAccessKind8616.READ, space=MemSpace.SS),),
            IRLogicalMemoryFailureKind8616.SEGMENT_CONFLICT,
        ),
        (
            (memory_instruction(IRMemoryAccessKind8616.READ, size=1),),
            IRLogicalMemoryFailureKind8616.BYTE_COVERAGE_CONFLICT,
        ),
    )
    for instructions, expected in cases:
        _, result = resolve_logical_memory(
            instructions,
            (logical_capture(IRMemoryAccessKind8616.READ),),
        )

        assert_closed_single_refusal(result, expected)
