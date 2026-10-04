from __future__ import annotations

from dataclasses import replace

import pytest
from angr_platforms.X86_16.ir import IRInstr, IRValue, MemSpace, SSAFunctionArtifact
from angr_platforms.X86_16.ir.logical_memory_contracts import (
    IRLogicalMemoryAccess8616,
    IRMemoryAccessKind8616,
)
from angr_platforms.X86_16.ir.logical_memory_write_value import (
    LogicalWordWriteValueFailureKind8616,
    LogicalWordWriteValueKind8616,
    trace_logical_word_write_values_8616,
)
from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa
from x86_16_logical_memory_fixtures import lift_ir_artifact


def _lift(code: str) -> SSAFunctionArtifact:
    return build_x86_16_function_ssa(lift_ir_artifact(bytes.fromhex(code)))


def _word_write(artifact: SSAFunctionArtifact) -> IRLogicalMemoryAccess8616:
    logical_memory = artifact.logical_memory
    assert logical_memory is not None
    return next(
        access
        for access in logical_memory.accesses
        if access.kind is IRMemoryAccessKind8616.WRITE and access.address.size == 2
    )


def _replace_write(
    artifact: SSAFunctionArtifact,
    write: IRLogicalMemoryAccess8616,
) -> SSAFunctionArtifact:
    logical_memory = artifact.logical_memory
    assert logical_memory is not None
    accesses = tuple(
        write
        if access.kind is IRMemoryAccessKind8616.WRITE and access.address.size == 2
        else access
        for access in logical_memory.accesses
    )
    return replace(artifact, logical_memory=replace(logical_memory, accesses=accesses))


def _assert_single_refusal(
    artifact: SSAFunctionArtifact,
    expected: LogicalWordWriteValueFailureKind8616,
) -> None:
    result = trace_logical_word_write_values_8616(artifact)

    assert result.closed
    assert result.facts == ()
    assert len(result.refusals) == 1
    assert result.refusals[0].failure is expected
    assert result.stats.to_dict() == {
        "raw_fact_count": 1,
        "normalized_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 0,
        "failure_count": 1,
    }


def test_constant_zero_retains_exact_write_slices_and_proof_sites() -> None:
    artifact = _lift("c7 07 00 00 c3")

    result = trace_logical_word_write_values_8616(artifact)

    assert result.closed
    assert result.refusals == ()
    assert result.stats.raw_fact_count == result.stats.materialized_count == 1
    fact = result.facts[0]
    assert fact.complete
    assert fact.kind is LogicalWordWriteValueKind8616.CONSTANT_ZERO
    assert fact.constant == 0
    assert tuple(lane.execution_slice for lane in fact.lanes) == fact.access.execution_slices
    assert tuple(lane.execution_slice.source_byte_offset for lane in fact.lanes) == (0, 1)
    assert fact.lanes[0].proof_sites == ()
    assert tuple(site.op for site in fact.lanes[1].proof_sites) == ("MOV", "Iop_Shr16")
    assert all(
        site.instr_addr == fact.access.key.insn_addr
        for lane in fact.lanes
        for site in lane.proof_sites
    )


@pytest.mark.parametrize("encoding,expected", (
    ("b8 03 00 50 c3", 3),
    ("b8 00 00 50 c3", 0),
    ("b8 03 00 b0 07 50 c3", 7),
    ("b8 03 00 b4 01 50 c3", 0x103),
))
def test_interinstruction_constant_write_retains_replay_receipt(
    encoding: str, expected: int,
) -> None:
    """A prior MOV and partial writes need a current-value proof, not stale SSA."""
    result = trace_logical_word_write_values_8616(_lift(encoding))
    assert result.closed and not result.refusals
    fact = result.facts[0]
    assert fact.complete and fact.constant == expected
    assert fact.constant_receipt is not None and fact.constant_receipt.complete
    assert not replace(fact, constant_receipt=None).complete
    assert not replace(fact, constant=(expected + 1) & 0xFFFF).complete


@pytest.mark.parametrize(
    ("encoding", "expected"),
    (("c7 07 1a 00 c3", 0x001A), ("c7 07 00 10 c3", 0x1000), ("c7 07 ff ff c3", 0xFFFF)),
)
def test_nonzero_immediate_word_retains_one_exact_value(encoding: str, expected: int) -> None:
    """A paired byte-executed immediate STORE proves its full logical word."""
    result = trace_logical_word_write_values_8616(_lift(encoding))

    assert result.closed
    assert result.refusals == ()
    assert len(result.facts) == 1
    fact = result.facts[0]
    assert fact.complete
    assert fact.kind is LogicalWordWriteValueKind8616.CONSTANT_WORD
    assert fact.constant == expected
    assert tuple(lane.execution_slice.source_byte_offset for lane in fact.lanes) == (0, 1)


def test_nonzero_immediate_word_refuses_different_high_lane_root() -> None:
    """Adjacent byte stores are not one immediate when their proven roots differ."""
    artifact = _lift("c7 07 00 10 c3")
    write = _word_write(artifact)
    block = artifact.blocks[0]
    shift_index = next(
        index
        for index, instruction in enumerate(block.instrs)
        if instruction.op == "Iop_Shr16" and instruction.addr == write.key.insn_addr
    )
    shift = block.instrs[shift_index]
    corrupted = replace(
        shift,
        args=(IRValue(MemSpace.CONST, const=0x2000, size=2), shift.args[1]),
    )
    instructions = (*block.instrs[:shift_index], corrupted, *block.instrs[shift_index + 1 :])

    _assert_single_refusal(
        replace(artifact, blocks=(replace(block, instrs=instructions),)),
        LogicalWordWriteValueFailureKind8616.LANE_CONFLICT,
    )


def test_constant_word_fact_rejects_corrupted_value_and_lane_root() -> None:
    """The durable fact must not certify a value detached from its lane proof."""
    fact = trace_logical_word_write_values_8616(_lift("c7 07 00 10 c3")).facts[0]

    assert not replace(fact, constant=0x2000).complete
    altered_high = replace(fact.lanes[1], source_constant_root=0x2000)
    assert not replace(fact, lanes=(fact.lanes[0], altered_high)).complete


def test_old_logical_word_plus_one_retains_load_and_both_write_paths() -> None:
    artifact = _lift("ff 07 c3")

    result = trace_logical_word_write_values_8616(artifact)

    assert result.closed
    assert result.refusals == ()
    fact = result.facts[0]
    assert fact.complete
    assert fact.kind is LogicalWordWriteValueKind8616.OLD_LOGICAL_WORD_PLUS_ONE
    assert fact.constant == 1
    assert fact.source_expression_site is not None
    assert fact.source_expression_site.op == "Iop_Or16"
    assert fact.source_trace is not None
    assert fact.source_trace.complete
    assert fact.source_trace.source == fact.access.address
    assert tuple(lane.execution_slice for lane in fact.lanes) == fact.access.execution_slices
    assert all(path[-1].op == "Iop_Add16" for path in (lane.proof_sites for lane in fact.lanes))
    assert tuple(
        site.op for site in fact.source_trace.definition_path if site.op == "LOAD"
    ) == ("LOAD", "LOAD")
    assert all(
        site.instr_addr == fact.access.key.insn_addr
        for site in (*fact.source_trace.definition_path, fact.source_expression_site)
    )


def test_missing_and_conflicting_little_endian_lanes_refuse() -> None:
    artifact = _lift("c7 07 00 00 c3")
    write = _word_write(artifact)

    missing = _replace_write(artifact, replace(write, execution_slices=write.execution_slices[:1]))
    conflicting = _replace_write(
        artifact,
        replace(write, execution_slices=tuple(reversed(write.execution_slices))),
    )

    _assert_single_refusal(missing, LogicalWordWriteValueFailureKind8616.MISSING_LANE)
    _assert_single_refusal(conflicting, LogicalWordWriteValueFailureKind8616.LANE_CONFLICT)


def test_mixed_logical_access_instruction_refuses() -> None:
    artifact = _lift("c7 07 00 00 c3")
    write = _word_write(artifact)
    low, high = write.execution_slices
    mixed = _replace_write(
        artifact,
        replace(write, execution_slices=(low, replace(high, insn_addr=high.insn_addr + 1))),
    )

    _assert_single_refusal(mixed, LogicalWordWriteValueFailureKind8616.MIXED_INSTRUCTION)


@pytest.mark.parametrize("lane", (0, 1))
def test_non_address_store_operand_refuses_without_address_matching(lane: int) -> None:
    """Malformed execution operands must remain counted refusals, not crashes."""
    artifact = _lift("c7 07 00 00 c3")
    execution_slice = _word_write(artifact).execution_slices[lane]
    block = artifact.blocks[0]
    index = execution_slice.instr_index
    store = block.instrs[index]
    invalid_address = IRValue(execution_slice.address.space, size=1)
    damaged_store = replace(store, args=(invalid_address, store.args[1]))
    instructions = (*block.instrs[:index], damaged_store, *block.instrs[index + 1:])
    damaged = replace(artifact, blocks=(replace(block, instrs=instructions),))

    _assert_single_refusal(damaged, LogicalWordWriteValueFailureKind8616.LOGICAL_ACCESS_CONFLICT)


def test_unknown_store_value_expression_refuses_with_partial_proof() -> None:
    artifact = _lift("c7 07 00 00 c3")
    write = _word_write(artifact)
    high_slice = write.execution_slices[1]
    block = artifact.blocks[0]
    store = block.instrs[high_slice.instr_index]
    stored = store.args[1]
    assert isinstance(stored, IRValue)
    definition_index = next(
        index
        for index, instruction in enumerate(block.instrs[: high_slice.instr_index])
        if instruction.dst is not None and instruction.dst.source_tmp == stored.source_tmp
    )
    definition = block.instrs[definition_index]
    unknown = IRInstr(
        "Iop_Xor8",
        definition.dst,
        (IRValue(MemSpace.CONST, const=0, size=1), IRValue(MemSpace.CONST, const=0, size=1)),
        size=1,
        addr=definition.addr,
    )
    instructions = (*block.instrs[:definition_index], unknown, *block.instrs[definition_index + 1 :])
    changed = replace(artifact, blocks=(replace(block, instrs=instructions),))

    result = trace_logical_word_write_values_8616(changed)

    assert result.closed
    assert result.refusals[0].failure is LogicalWordWriteValueFailureKind8616.UNKNOWN_EXPRESSION
    assert tuple(site.op for site in result.refusals[0].proof_sites) == ("Iop_Xor8",)
