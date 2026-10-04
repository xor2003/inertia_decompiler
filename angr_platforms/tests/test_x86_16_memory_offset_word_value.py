"""Require every memory-offset base and displacement to retain exact value proof."""

from dataclasses import replace

import pytest
from angr_platforms.X86_16.ir.core import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from angr_platforms.X86_16.ir.memory_offset_word_value import trace_memory_offset_word_value_8616
from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa
from x86_16_logical_memory_fixtures import lift_ir_artifact


def _fixture(operation="Iop_Shl16", displacement=1, index_offset=-2):
    def source(offset):
        return IRAddress(MemSpace.SS, base=("bp",), offset=offset, size=2,
                         status=AddressStatus.STABLE, segment_origin=SegmentOrigin.PROVEN)

    bx, si = IRValue(MemSpace.REG, name="bx", size=2), IRValue(MemSpace.REG, name="si", size=2)
    address = IRAddress(MemSpace.DS, base=("bx", "si"), offset=displacement, size=1,
                        status=AddressStatus.STABLE, segment_origin=SegmentOrigin.PROVEN,
                        expr=("segmented_linear", "ds", "bx", "si"), base_values=(bx, si))
    artifact = build_x86_16_function_ssa(IRFunctionArtifact(0x1000, (IRBlock(0x1000, instrs=(
        IRInstr("LOAD", bx, (source(index_offset),), size=2, addr=0x1000),
        IRInstr(operation, bx, (bx, IRValue(MemSpace.CONST, const=1, size=2)), size=2, addr=0x1003),
        IRInstr("LOAD", si, (source(4),), size=2, addr=0x1005),
        IRInstr("STORE", None, (address, IRValue(MemSpace.CONST, const=0, size=1)), size=1, addr=0x1008),
    )),)))
    block = artifact.blocks[0]
    return artifact, block, block.instrs[3].args[0]


@pytest.mark.parametrize("displacement", (0, 1, -1))
def test_two_word_bases_retain_input_index_scale_and_displacement(displacement):
    artifact, block, address = _fixture(displacement=displacement)
    proof = trace_memory_offset_word_value_8616(artifact, address, block_addr=block.addr, instr_index=3)
    assert proof.complete
    assert proof.constant == displacement & 0xffff
    assert tuple((term.source.offset, term.coefficient) for term in proof.terms) == ((-2, 2), (4, 1))
    assert len(proof.traces) == 2 and all(trace.complete for trace in proof.traces)
    assert proof.materialized_count == 1 and proof.failure_count == 0
    for index in (0, 1, 0x7fff, 0xffff):
        for base in (0, 1, 0xfffe, 0xffff):
            actual = (proof.constant + sum(value * term.coefficient for value, term in zip((index, base), proof.terms, strict=True))) & 0xffff
            assert actual == (base + 2 * index + displacement) & 0xffff


def test_foreign_address_or_use_does_not_borrow_a_value_proof():
    artifact, block, address = _fixture()
    assert not trace_memory_offset_word_value_8616(
        artifact, replace(address), block_addr=block.addr, instr_index=3,
    ).complete
    assert not trace_memory_offset_word_value_8616(
        artifact, address, block_addr=block.addr, instr_index=2,
    ).complete


def test_one_unproved_root_refuses_the_entire_memory_offset():
    artifact, block, address = _fixture(operation="Iop_Xor16")
    proof = trace_memory_offset_word_value_8616(artifact, address, block_addr=block.addr, instr_index=3)
    assert not proof.complete
    assert proof.constant is None and proof.terms == ()
    assert proof.materialized_count == 0 and proof.failure_count == 1


def test_component_and_sum_corruption_are_rejected():
    artifact, block, address = _fixture()
    proof = trace_memory_offset_word_value_8616(artifact, address, block_addr=block.addr, instr_index=3)
    assert proof.complete
    assert not replace(proof, constant=2).complete
    assert not replace(proof, terms=proof.terms[:1]).complete
    assert not replace(proof, raw_fact_count=True).complete
    trace = proof.traces[0]
    corrupted = replace(trace, expression=replace(trace.expression, constant=1))
    assert not replace(proof, traces=(corrupted, proof.traces[1])).complete


@pytest.mark.parametrize("constant", (True, 1.0))
def test_numeric_equality_does_not_prove_retained_constant_type(constant):
    artifact, block, address = _fixture()
    proof = trace_memory_offset_word_value_8616(artifact, address, block_addr=block.addr, instr_index=3)
    assert proof.complete and proof.constant == 1
    assert not replace(proof, constant=constant).complete


@pytest.mark.parametrize("coefficient", (True, 1.0))
def test_numeric_equality_does_not_prove_retained_coefficient_type(coefficient):
    artifact, block, address = _fixture()
    proof = trace_memory_offset_word_value_8616(artifact, address, block_addr=block.addr, instr_index=3)
    assert proof.complete
    forged = replace(proof.terms[1], coefficient=coefficient)
    assert not replace(proof, terms=(proof.terms[0], forged)).complete


def test_separate_loads_of_one_storage_do_not_merge_values():
    artifact, block, address = _fixture(index_offset=4)
    proof = trace_memory_offset_word_value_8616(artifact, address, block_addr=block.addr, instr_index=3)
    assert proof.complete
    assert tuple(term.source.offset for term in proof.terms) == (4, 4)
    assert proof.terms[0].value != proof.terms[1].value


@pytest.mark.parametrize("changes", (
    {"status": AddressStatus.UNKNOWN}, {"segment_origin": SegmentOrigin.UNKNOWN},
    {"expr": ("opaque",)}, {"size": 2}, {"offset": True},
))
def test_unproved_address_projection_keeps_a_typed_refusal(changes):
    artifact, block, address = _fixture()
    changed = replace(address, **changes)
    instruction = replace(block.instrs[3], args=(changed, *block.instrs[3].args[1:]))
    artifact = replace(artifact, blocks=(replace(block, instrs=(*block.instrs[:3], instruction)),))
    proof = trace_memory_offset_word_value_8616(artifact, changed, block_addr=block.addr, instr_index=3)
    assert not proof.complete
    assert proof.materialized_count == 0 and proof.failure_count == 1


def test_real_word_store_preserves_both_byte_offset_projections():
    """Binary BX=2*word(BP-2), SI=word(BP+4) has offsets p+2*i and p+2*i+1."""
    artifact = build_x86_16_function_ssa(lift_ir_artifact(bytes.fromhex(
        "55 89 e5 8b 5e fe d1 e3 8b 76 04 89 00 5d c3",
    )))
    proofs = []
    for block in artifact.blocks:
        for index, instruction in enumerate(block.instrs):
            if instruction.op != "STORE" or instruction.args[0].space is not MemSpace.DS:
                continue
            proofs.append(trace_memory_offset_word_value_8616(
                artifact, instruction.args[0], block_addr=block.addr, instr_index=index,
            ))
    assert len(proofs) == 2
    assert all(proof.complete for proof in proofs)
    assert tuple(proof.constant for proof in proofs) == (0, 1)
    for proof in proofs:
        assert tuple((term.source.offset, term.coefficient) for term in proof.terms) == ((-2, 2), (4, 1))
