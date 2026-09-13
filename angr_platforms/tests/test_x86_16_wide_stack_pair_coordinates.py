"""Wide pair proofs compare IR and C storage in machine BP coordinates."""

import pytest
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CVariable
from angr.sim_type import SimTypeLong
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.lowering.stack_variable_coordinates import record_stack_variable_coordinate_projection_8616
from angr_platforms.X86_16.lowering.wide_stack_pair_evidence import proven_wide_stack_ir_pair_8616
from test_x86_16_wide_stack_condition_chains import _Codegen, _word


def _projected_words(machine_offset=12):
    codegen = _Codegen()
    type_ = SimTypeLong(False).with_arch(codegen.project.arch)
    variable = SimStackVariable(10, 4, base="bp", name="value")
    owner = CVariable(variable, variable_type=type_, codegen=codegen)
    record_stack_variable_coordinate_projection_8616(
        codegen, variable=variable, cvar=owner, bp_offset=machine_offset, entry_sp_offset=10, size=4,
    )
    shift = CBinaryOp("Shr", owner, CConstant(16, type_, codegen=codegen), codegen=codegen)
    high = CBinaryOp("And", shift, CConstant(0xFFFF, type_, codegen=codegen), codegen=codegen)
    low = CBinaryOp("And", owner, CConstant(0xFFFF, type_, codegen=codegen), codegen=codegen)
    return high, low


@pytest.mark.parametrize(("ir_offset", "expected"), [(12, True), (10, False), (16, False)])
def test_pair_proof_uses_machine_offset_not_rendered_offset(ir_offset, expected):
    high, low = _projected_words()
    assert proven_wide_stack_ir_pair_8616(_word(ir_offset + 2), _word(ir_offset), high, low) is expected


def test_equal_variable_shapes_in_different_coordinate_contexts_do_not_prove_a_pair():
    high, _ = _projected_words(machine_offset=16)
    _, low = _projected_words(machine_offset=12)
    assert not proven_wide_stack_ir_pair_8616(_word(14), _word(12), high, low)
