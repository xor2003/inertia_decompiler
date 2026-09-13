"""Comparison signedness cannot resize a proven stack storage owner."""

import pytest
from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_type import SimTypeFunction, SimTypeLong, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.decompiler_postprocess_typed_conditions import (
    _apply_signed_stack_arg_types_to_prototype_8616,
)
from angr_platforms.X86_16.lowering.condition_stack_operands import _wide_stack_word_projection
from angr_platforms.X86_16.lowering.condition_stack_value import complete_storage_signedness_requests_8616
from angr_platforms.X86_16.lowering.semantic_cast import CSemanticCast8616
from test_x86_16_decompiler_postprocess_typed_conditions import _codegen, _project

DWORD_BYTES = 4


@pytest.mark.parametrize(("storage_size", "evidence_size"), [(4, 2), (2, 4), (4, 4), (2, 2)])
def test_signedness_requires_complete_storage_width(storage_size, evidence_size):
    project, codegen = _project(), _codegen([])
    storage_type = (SimTypeLong(False) if storage_size == DWORD_BYTES else SimTypeShort(False)).with_arch(project.arch)
    variable = SimStackVariable(4, storage_size, base="bp", name="argument")
    argument = CVariable(variable, variable_type=storage_type, codegen=codegen)
    prototype = SimTypeFunction([storage_type], SimTypeShort(False), arg_names=("argument",))
    codegen.cfunc.arg_list = [argument]
    codegen.cfunc.functy = prototype

    changed = _apply_signed_stack_arg_types_to_prototype_8616(project, codegen, {4: evidence_size})

    assert argument.variable is variable
    assert argument.variable.size == storage_size
    assert argument.variable_type.size == storage_size * 8
    assert codegen.cfunc.functy.args[0].size == storage_size * 8
    assert changed == (storage_size == evidence_size)
    assert argument.variable_type.signed == (storage_size == evidence_size)
    if storage_size != evidence_size:
        assert argument.variable_type is storage_type
        assert codegen.cfunc.functy is prototype


@pytest.mark.parametrize(("owners", "requests", "expected"), [
    ([(4, 4), (6, 2)], {6: 2}, {}),
    ([(4, 4), (4, 2)], {4: 4}, {}),
    ([(4, 2), (6, 2)], {4: 2}, {4: 2}),
    ([(4, 4), (4, 4)], {4: 4}, {4: 4}),
    ([], {4: 2}, {}),
    ([(4, 4)], {4: 0}, {}),
])
def test_signedness_refuses_partial_overlapping_and_missing_owners(owners, requests, expected):
    variables = tuple(SimStackVariable(offset, size, base="bp") for offset, size in owners)
    assert complete_storage_signedness_requests_8616(requests, variables) == expected


def test_high_word_projection_keeps_wide_type_until_after_shift():
    project, codegen = _project(), _codegen([])
    wide_type = SimTypeLong(False).with_arch(project.arch)
    variable = SimStackVariable(4, DWORD_BYTES, base="bp", name="argument")
    declaration = CVariable(variable, variable_type=wide_type, codegen=codegen)
    expression = _wide_stack_word_projection(codegen, declaration, offset=6, signed=True, prefer_word_view=True)
    assert isinstance(expression, CSemanticCast8616)
    source_view = expression.expr.lhs.lhs
    assert source_view.variable is variable
    assert source_view.variable_type is wide_type
