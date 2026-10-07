"""Adversarial review controls; expected to fail unsafe carry proposal."""
from dataclasses import replace

from inertia.ir.core import IRActiveUnary8616, IRValue, MemSpace
from tests.semantics.test_x86_16_carry_borrow_widening import _lift_ssa, _replace_instruction

from inertia.alias.carry_borrow_projection import project_carry_borrow_aliases_8616
from inertia.semantics.carry_borrow_links import analyze_carry_borrow_links_8616
from inertia.semantics.carry_borrow_ssa import definition_for_8616
from inertia.widening.carry_borrow_values import widen_carry_borrow_values_8616


def test_narrow_then_widen_high_output_is_not_original_arithmetic():
    artifact = _lift_ssa(bytes.fromhex("01 d8 11 ca c3"))
    evidence = analyze_carry_borrow_links_8616(artifact)
    assert len(evidence.links) == 1
    link = evidence.links[0]
    write = link.high_result_write
    source = write.instruction.args[0]
    narrow = IRValue(MemSpace.TMP, size=1, expr=("Iop_16to8",), active_unary=IRActiveUnary8616("Iop_16to8", source, 8))
    widened = IRValue(MemSpace.TMP, size=2, expr=("Iop_8Uto16",), active_unary=IRActiveUnary8616("Iop_8Uto16", narrow, 16))
    corrupted = _replace_instruction(artifact, write.instr_index, replace(write.instruction, args=(widened,)))
    result = analyze_carry_borrow_links_8616(corrupted)
    widened_result = widen_carry_borrow_values_8616(project_carry_borrow_aliases_8616(result))
    assert not result.links
    assert not widened_result.values


def test_active_wrapper_pinned_to_existing_tmp_must_refuse():
    artifact = _lift_ssa(bytes.fromhex("01 d8 11 ca c3"))
    link = analyze_carry_borrow_links_8616(artifact).links[0]
    site = link.high_final_arithmetic
    tmp = site.instruction.dst.source_tmp
    operand = site.instruction.dst
    invalid = IRValue(MemSpace.TMP, size=2, source_tmp=tmp, active_unary=IRActiveUnary8616("Iop_Not16", operand, 16))
    assert definition_for_8616(invalid, {tmp: site}) is None
