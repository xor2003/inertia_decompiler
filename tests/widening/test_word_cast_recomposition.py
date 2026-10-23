"""Preserve machine word values reconstructed through required byte casts."""
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CExpression,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeChar, SimTypeNum, SimTypeShort
from angr.sim_variable import SimMemoryVariable

from inertia.lowering.semantic_cast import CSemanticCast8616
from inertia.widening.word_projection_recomposition import materialize_word_projection_recompositions_8616
from tests.widening.test_x86_16_widening_rules import _constant, _DummyCodegen, _stack_var


def _fixture(corruption: str | None = None, value: int | None = None) -> tuple[_DummyCodegen, CAssignment, CExpression]:
    codegen = _DummyCodegen()
    word = SimTypeNum(16, False)
    byte = SimTypeChar(False)
    source = _stack_var(4, 2, 'word', codegen)
    source.variable_type = SimTypeShort(False).with_arch(codegen.project.arch)
    if value is not None:
        source = CConstant(value, word, codegen=codegen)
    high_source = source if corruption != 'other_source' else _stack_var(6, 2, 'other', codegen)
    low = CSemanticCast8616(word, byte, source, codegen=codegen)
    shifted = CBinaryOp('Shr', high_source, _constant(8, codegen), codegen=codegen)
    if corruption == 'signed_right':
        shifted._type = SimTypeNum(16, True)
    if corruption == 'narrow_source':
        shifted.lhs = CSemanticCast8616(word, byte, source, codegen=codegen)
    high_byte = CSemanticCast8616(word, SimTypeChar(corruption == 'signed_byte'), shifted, codegen=codegen)
    high = CBinaryOp('Shl', high_byte, _constant(7 if corruption == 'shift' else 8, codegen), codegen=codegen)
    if corruption == 'cast_shift':
        high.rhs = CSemanticCast8616(word, SimTypeNum(1, False), high.rhs, codegen=codegen)
    high._type = SimTypeNum(32 if corruption == 'width' else 16, corruption == 'signed_shift')
    wrapped = CSemanticCast8616(word, word, high, codegen=codegen)
    combined = CBinaryOp('Or', low, wrapped, codegen=codegen)
    combined._type = word
    destination = CVariable(SimMemoryVariable(0x44, 2), variable_type=word, codegen=codegen)
    assignment = CAssignment(destination, combined, codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=CStatements([assignment], codegen=codegen))
    return codegen, assignment, source


def test_required_byte_casts_recompose_exact_word() -> None:
    codegen, assignment, source = _fixture()
    assert materialize_word_projection_recompositions_8616(codegen)
    assert isinstance(assignment.rhs, CVariable)
    assert assignment.rhs.variable is source.variable


@pytest.mark.parametrize('corruption', ['other_source', 'signed_byte', 'shift', 'width', 'signed_shift', 'signed_right', 'narrow_source', 'cast_shift'])
def test_incomplete_or_wrong_typed_lanes_remain(corruption: str) -> None:
    codegen, assignment, _ = _fixture(corruption)
    before = assignment.rhs
    assert not materialize_word_projection_recompositions_8616(codegen)
    assert assignment.rhs is before


@pytest.mark.parametrize("value", [0, 0x7FFF, 0x8000, 0xFF00, 0xFFFF])
def test_machine_unsigned_high_byte_values_recompose(value: int) -> None:
    codegen, assignment, _ = _fixture(value=value)
    assert materialize_word_projection_recompositions_8616(codegen)
    assert isinstance(assignment.rhs, CConstant)
    assert assignment.rhs.value == value
