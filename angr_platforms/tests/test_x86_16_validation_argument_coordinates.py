"""Argument labels cannot change the machine coordinate or width of a view."""

import pytest
from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_type import SimTypeLong, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.lowering.stack_variable_coordinates import record_stack_variable_coordinate_projection_8616
from angr_platforms.X86_16.tail_validation_fingerprint import (
    _canonical_or_unresolved_stack_fingerprint_8616,
    _cfunc_source_arg_names_by_offset_8616,
    _cfunc_source_arg_sizes_by_offset_8616,
    _expr_fingerprint,
)
from angr_platforms.X86_16.validation_stack_projection import proven_stack_projection_fingerprint_8616
from test_x86_16_condition_stack_operands import _FakeCodegen
from test_x86_16_validation_stack_projection_views import _Codegen, _high_word_projection


def test_argument_name_and_width_maps_use_machine_bp_coordinates():
    codegen = _FakeCodegen()
    arguments = []
    for machine_offset, name in ((20, "upper_x"), (24, "upper_z")):
        variable = SimStackVariable(machine_offset - 2, 4, base="bp", name=name)
        argument = CVariable(variable, variable_type=SimTypeLong(False).with_arch(codegen.project.arch), codegen=codegen)
        arguments.append(argument)
        record_stack_variable_coordinate_projection_8616(
            codegen, variable=variable, cvar=argument, bp_offset=machine_offset,
            entry_sp_offset=machine_offset - 2, size=4,
        )
    codegen.cfunc.arg_list = arguments
    assert _cfunc_source_arg_names_by_offset_8616(codegen.cfunc) == {20: "upper_x", 24: "upper_z"}
    assert _cfunc_source_arg_sizes_by_offset_8616(codegen.cfunc) == {20: 4, 24: 4}

    word = SimStackVariable(20, 2, base="bp", name="word_view")
    view = CVariable(word, variable_type=SimTypeShort(False), codegen=codegen)
    record_stack_variable_coordinate_projection_8616(
        codegen, variable=word, cvar=view, bp_offset=22, entry_sp_offset=20, size=2,
    )
    fingerprint = _canonical_or_unresolved_stack_fingerprint_8616(20, codegen, source="stack_var", node=view)
    assert fingerprint == "stack_slot:SS:BP+0x16:size2"


def test_proven_high_word_expression_has_the_exact_word_storage_identity():
    codegen = _Codegen()
    expression = _high_word_projection(codegen)
    assert _expr_fingerprint(expression, codegen.project) == "stack_slot:SS:BP+0xc:size2"


@pytest.mark.parametrize("corruption", ["mask", "shift", "owner_offset", "owner_size", "base", "type", "fact"])
def test_projection_identity_refuses_stale_or_corrupt_evidence(corruption):
    codegen = _Codegen()
    expression = _high_word_projection(codegen)
    owner = expression.lhs.lhs
    if corruption == "mask":
        expression.rhs.value = 0xFF
    elif corruption == "shift":
        expression.lhs.rhs.value = 8
    elif corruption == "owner_offset":
        owner.variable.offset += 2
    elif corruption == "owner_size":
        owner.variable.size = 2
    elif corruption == "base":
        owner.variable.base = "sp"
    elif corruption == "type":
        owner.variable_type = SimTypeShort(False).with_arch(codegen.project.arch)
    elif corruption == "fact":
        expression.tags = {}
    assert proven_stack_projection_fingerprint_8616(expression) is None
