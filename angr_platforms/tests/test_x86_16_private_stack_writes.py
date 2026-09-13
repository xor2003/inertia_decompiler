"""Exact per-write decisions retain control/global effects and unknown reads."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.alias.private_stack_writes import (
    PrivateStackWriteVerdict8616,
    classify_private_stack_writes_8616,
)
from angr_platforms.X86_16.alias.stack_address_escape import StackAddressEscape8616
from angr_platforms.X86_16.alias.stack_memory_ssa import build_x86_16_stack_memory_ssa_alias_artifact
from angr_platforms.X86_16.ir import AddressStatus, IRInstr, IRValue, MemSpace
from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa
from angr_platforms.X86_16.lowering.stack_storage_evidence import alias_proves_private_stack_write_8616
from x86_16_logical_memory_fixtures import FUNCTION_ADDR, lift_ir_artifact


def _artifact(allocation=4):
    body = bytes.fromhex("558bec83ec") + bytes((allocation,))
    body += bytes.fromhex("c746fc1704c746fe00002bdb8ec3bb1704268c078be55dc3")
    return build_x86_16_stack_memory_ssa_alias_artifact(build_x86_16_function_ssa(lift_ir_artifact(body)))


def _approved(artifact):
    return {decision.source_addr for decision in classify_private_stack_writes_8616(artifact)
            if decision.verdict is PrivateStackWriteVerdict8616.UNREAD_RELEASED}


def test_real_binary_only_local_word_writes_are_unread_and_released():
    artifact = _artifact()
    assert _approved(artifact) == {FUNCTION_ADDR + 6, FUNCTION_ADDR + 11}
    decisions = classify_private_stack_writes_8616(artifact)
    assert {decision.source_addr for decision in decisions} == {
        FUNCTION_ADDR, FUNCTION_ADDR + 6, FUNCTION_ADDR + 11, FUNCTION_ADDR + 23,
    }


def test_alias_builder_publishes_complete_source_group_decisions():
    artifact = _artifact()
    assert artifact.private_write_decisions == classify_private_stack_writes_8616(artifact)
    assert {decision.source_addr for decision in artifact.private_write_decisions if decision.proven} == {
        FUNCTION_ADDR + 6, FUNCTION_ADDR + 11,
    }
    serialized = artifact.to_dict()
    assert serialized["private_write_decisions"] == [decision.to_dict() for decision in artifact.private_write_decisions]
    assert serialized["private_write_census"] == {
        "raw_fact_count": 4, "normalized_fact_count": 4,
        "classified_fact_count": 2, "materialized_count": 2, "failure_count": 2,
    }


def test_one_missing_alias_byte_refuses_the_whole_source_instruction():
    artifact = _artifact()
    block = artifact.source_ssa.blocks[0]
    target = FUNCTION_ADDR + 6
    index = next(index for index, instruction in enumerate(block.instrs)
                 if instruction.op == "STORE" and instruction.addr == target)
    changed = replace(artifact,
                      facts=tuple(fact for fact in artifact.facts if fact.instr_index != index),
                      accesses=tuple(access for access in artifact.accesses if access.source.instr_index != index))
    assert target not in _approved(changed)


def test_unknown_read_refuses_all_private_write_decisions():
    artifact = _artifact()
    block = artifact.source_ssa.blocks[0]
    instructions = list(block.instrs)
    index = next(index for index, instruction in enumerate(instructions) if instruction.op == "LOAD")
    instruction = instructions[index]
    instructions[index] = replace(instruction, args=(replace(instruction.args[0], status=AddressStatus.UNKNOWN),))
    function = replace(artifact.source_ssa, blocks=(replace(block, instrs=tuple(instructions)),))
    assert _approved(replace(artifact, source_ssa=function)) == set()


def test_escaped_frame_refuses_all_private_write_decisions():
    artifact = replace(_artifact(), frame_address_escape=StackAddressEscape8616.DERIVED_ADDRESS_ESCAPE)
    assert _approved(artifact) == set()


@pytest.mark.parametrize("allocation", (0, 2, 8))
def test_allocation_size_must_cover_the_entire_local_write(allocation):
    expected = {FUNCTION_ADDR + offset for offset, required in ((6, 4), (11, 2)) if allocation >= required}
    assert _approved(_artifact(allocation)) == expected


def test_even_one_overlapping_read_byte_keeps_the_whole_word_write():
    artifact = _artifact()
    block = artifact.source_ssa.blocks[0]
    target = FUNCTION_ADDR + 6
    store = next(instruction for instruction in block.instrs if instruction.op == "STORE" and instruction.addr == target)
    read = IRInstr("LOAD", IRValue(MemSpace.TMP, name="observed", size=1, version=0), (store.args[0],), size=1)
    function = replace(artifact.source_ssa, blocks=(replace(block, instrs=(*block.instrs[:-1], read, block.instrs[-1])),))
    decisions = classify_private_stack_writes_8616(replace(artifact, source_ssa=function))
    decision = next(decision for decision in decisions if decision.source_addr == target)
    assert decision.verdict is PrivateStackWriteVerdict8616.READ_OVERLAP


def test_alias_memory_version_must_match_the_source_store():
    artifact = _artifact()
    fact = artifact.facts[0]
    changed = replace(artifact, facts=(replace(fact, address=replace(fact.address, version=99)), *artifact.facts[1:]))
    assert FUNCTION_ADDR + 6 not in _approved(changed)


def test_private_write_consumer_requires_current_ssa_and_root_source():
    artifact = _artifact()
    codegen = SimpleNamespace(_inertia_stack_memory_ssa_alias_artifact=artifact,
                              _inertia_vex_ir_function_ssa=artifact.source_ssa,
                              cfunc=SimpleNamespace(addr=artifact.function_addr))
    statement = SimpleNamespace(tags={"ins_addr": FUNCTION_ADDR + 6})
    assert alias_proves_private_stack_write_8616(codegen, statement)
    assert not alias_proves_private_stack_write_8616(codegen, SimpleNamespace(tags={"ins_addr": FUNCTION_ADDR}))
    assert not alias_proves_private_stack_write_8616(codegen, SimpleNamespace(rhs=statement))
    codegen._inertia_vex_ir_function_ssa = replace(artifact.source_ssa)
    assert not alias_proves_private_stack_write_8616(codegen, statement)
    codegen._inertia_vex_ir_function_ssa = artifact.source_ssa
    codegen.cfunc.addr += 1
    assert not alias_proves_private_stack_write_8616(codegen, statement)
