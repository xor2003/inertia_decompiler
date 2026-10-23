"""Current typed byte reconstruction needs value proof, not shape matching."""

from itertools import count
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CVariable
from angr.sim_type import SimTypeNum
from angr.sim_variable import SimStackVariable

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.native_word_expression import (
    NativeWordExpressionFailure8616 as Failure,
)
from inertia.lowering.native_word_expression import (
    NativeWordExpressionStatus8616 as Status,
)
from inertia.lowering.native_word_expression import (
    validate_native_word_expression_8616,
)
from inertia.lowering.semantic_cast import CSemanticCast8616


def _fixture():
    context = SimpleNamespace(project=SimpleNamespace(arch=Arch86_16()), cfunc=None,
                              next_ident=lambda name: name, next_node_idx=count().__next__,
                              show_casts=False, cstyle_null_cmp=False, const_formats={})
    word = SimTypeNum(16, False).with_arch(context.project.arch)
    leaf = CVariable(SimStackVariable(2, 2), variable_type=word, codegen=context)
    return context, leaf


def _cast(expression, width=16, signed=False):
    return CSemanticCast8616(None, SimTypeNum(width, signed), expression, codegen=expression.codegen)


def _binary(op, lhs, rhs):
    return CBinaryOp(op, lhs, rhs, codegen=lhs.codegen)


def _constant(context, value):
    return CConstant(value, SimTypeNum(16, False), codegen=context)


def _composition(leaf, shift=8, protected=True, other=None):
    constant = _constant(leaf.codegen, 8)
    low = _cast(leaf, 8)
    high = _cast(_binary("Shr", leaf if other is None else other, constant), 8)
    left = _cast(high) if protected else high
    shifted = _binary("Shl", left, _constant(leaf.codegen, shift))
    return _binary("Or", low, _cast(shifted))


def test_actual_retained_word_reconstruction_proves_exact_leaf():
    _context, leaf = _fixture()
    assert validate_native_word_expression_8616(_composition(leaf), leaf).status is Status.PROVEN


def test_wrap_boundary_does_not_require_a_new_physical_word_read():
    context, leaf = _fixture()
    wrapped = CVariable(SimStackVariable(0xFFFF, 2), variable_type=leaf.variable_type, codegen=context)
    # This is value-only proof over a caller-authenticated captured word;
    # no physical contiguity or source coordinate supplies authority here.
    assert validate_native_word_expression_8616(_composition(wrapped), wrapped).status is Status.PROVEN


@pytest.mark.parametrize("shift", [0, 7, 9, 15])
def test_mutated_shift_is_not_the_word(shift):
    _context, leaf = _fixture()
    assert validate_native_word_expression_8616(_composition(leaf, shift=shift), leaf).status is Status.MISMATCH


def test_missing_unsigned_word_before_shift_refuses_despite_bitvector_identity():
    _context, leaf = _fixture()
    proof = validate_native_word_expression_8616(_composition(leaf, protected=False), leaf)
    assert proof.status is Status.REFUSED and proof.failure is Failure.SHIFT


def test_different_leaf_same_coordinates_cannot_grant_identity():
    context, leaf = _fixture()
    other = CVariable(SimStackVariable(2, 2), variable_type=leaf.variable_type, codegen=context)
    assert validate_native_word_expression_8616(_composition(leaf, other=other), leaf).failure is Failure.LEAF


def test_same_variable_with_different_ssa_version_refuses():
    context, leaf = _fixture()
    other = CVariable(leaf.variable, variable_type=leaf.variable_type, codegen=context, vvar_id=1)
    assert validate_native_word_expression_8616(_composition(leaf, other=other), leaf).failure is Failure.LEAF


@pytest.mark.parametrize(("width", "signed"), [(8, False), (16, True), (32, False)])
def test_cast_sign_or_width_mutation_does_not_prove_word(width, signed):
    _context, leaf = _fixture()
    expression = _composition(leaf)
    expression.rhs.expr.lhs = _cast(expression.rhs.expr.lhs.expr, width, signed)
    assert validate_native_word_expression_8616(expression, leaf).status is Status.REFUSED


def test_corrupted_or_constant_has_a_value_mismatch():
    context, leaf = _fixture()
    corrupted = _binary("Or", _composition(leaf), _constant(context, 1))
    assert validate_native_word_expression_8616(corrupted, leaf).status is Status.MISMATCH


def test_unknown_operation_and_hidden_cosmetic_cast_refuse():
    from angr.analyses.decompiler.structured_codegen.c import CTypeCast
    context, leaf = _fixture()
    assert validate_native_word_expression_8616(_binary("Add", leaf, _constant(context, 0)), leaf).failure is Failure.OPERATION
    hidden = CTypeCast(leaf.variable_type, leaf.variable_type, leaf, codegen=context)
    assert validate_native_word_expression_8616(hidden, leaf).failure is Failure.TYPE


def test_depth_budget_refuses_without_recursion_or_solver_growth():
    _context, leaf = _fixture()
    expression = leaf
    for _ in range(17):
        expression = _cast(expression)
    assert validate_native_word_expression_8616(expression, leaf).failure is Failure.LIMIT


def test_ffff_word_is_not_accidentally_truncated_to_byte():
    _context, leaf = _fixture()
    assert validate_native_word_expression_8616(_cast(leaf, 8), leaf).status is Status.MISMATCH


def test_actual_opaque_high_byte_dereference_is_not_a_word_leaf():
    from angr.analyses.decompiler.structured_codegen.c import CUnaryOp
    context, leaf = _fixture()
    expression = _composition(leaf)
    # The actual retained native result still contains an unprojected read
    # here. Its word-looking cast metadata is not captured-byte authority.
    read = CUnaryOp("Dereference", _constant(context, 0), codegen=context)
    expression.rhs.expr.lhs = CSemanticCast8616(
        leaf.variable_type, SimTypeNum(16, False), read, codegen=context,
    )
    assert validate_native_word_expression_8616(expression, leaf).failure is Failure.OPERATION


def test_stale_cast_source_width_refuses():
    _context, leaf = _fixture()
    expression = _composition(leaf)
    expression.rhs.expr.lhs.src_type = SimTypeNum(16, False).with_arch(leaf.codegen.project.arch)
    assert validate_native_word_expression_8616(expression, leaf).failure is Failure.TYPE


def test_wide_tree_node_budget_refuses():
    _context, leaf = _fixture()
    expression = leaf
    for _ in range(5):
        expression = _binary("Or", expression, expression)
    assert validate_native_word_expression_8616(expression, leaf).failure is Failure.LIMIT


def test_unknown_node_subclasses_cannot_override_proven_rendering():
    class CorruptedBinary(CBinaryOp):
        def c_repr_chunks(self, indent=0, asexpr=False):
            yield "0", self

    class CorruptedConstant(CConstant):
        def c_repr_chunks(self, indent=0, asexpr=False):
            yield "1", self

    class CorruptedVariable(CVariable):
        def c_repr_chunks(self, indent=0, asexpr=False):
            yield "0", self

    context, leaf = _fixture()
    unknown_binary = CorruptedBinary("Or", leaf, leaf, codegen=context)
    unknown_constant = CorruptedConstant(0, leaf.variable_type, codegen=context)
    unknown_variable = CorruptedVariable(leaf.variable, variable_type=leaf.variable_type, codegen=context)
    for expression in (unknown_binary, _binary("Or", leaf, unknown_constant), unknown_variable):
        assert validate_native_word_expression_8616(expression, leaf).status is Status.REFUSED


def test_unknown_semantic_cast_subclass_refuses():
    class CorruptedCast(CSemanticCast8616):
        def c_repr_chunks(self, indent=0, asexpr=False):
            yield "0", self

    _context, leaf = _fixture()
    cast = CorruptedCast(None, leaf.variable_type, leaf, codegen=leaf.codegen)
    assert validate_native_word_expression_8616(cast, leaf).failure is Failure.TYPE
