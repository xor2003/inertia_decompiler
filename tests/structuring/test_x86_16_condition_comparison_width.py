"""Require complete value widths before proving comparison orientation."""
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CTypeCast, CVariable
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.c_ast_utils import _same_c_expression_8616
from inertia.lowering.semantic_cast import CSemanticCast8616
from inertia.structuring.condition_comparison_polarity import (
    ConditionComparisonPolarity8616,
    condition_comparison_polarity_8616,
)

pytestmark = pytest.mark.decompiler


def _fixture():
    """Build fixed-width native word storage and its C projections."""
    arch = Arch86_16()
    codegen = SimpleNamespace(project=SimpleNamespace(arch=arch),
                              next_ident=lambda x:x, next_node_idx=lambda:1,
                              next_idx=lambda x:1, cstyle_null_cmp=False)
    word = SimTypeShort(False).with_arch(arch)
    byte = SimTypeChar(False).with_arch(arch)
    variable = SimStackVariable(4,2,base='bp')
    value = CVariable(variable,variable_type=word,codegen=codegen)
    one = CConstant(1,word,codegen=codegen)
    return codegen,word,byte,value,one


@pytest.mark.parametrize('cast_class',[CTypeCast,CSemanticCast8616])
def test_truncated_operand_cannot_prove_word_comparison_polarity(cast_class):
    """Sharing storage does not make a truncated byte the same word value."""
    codegen,word,byte,value,one = _fixture()
    truncated = cast_class(word,byte,value,codegen=codegen)
    original = CBinaryOp('CmpLT',truncated,one,codegen=codegen)
    replacement = CBinaryOp('CmpGE',value,one,codegen=codegen)

    assert condition_comparison_polarity_8616(
        original,replacement,same_expression=_same_c_expression_8616,
    ) is ConditionComparisonPolarity8616.UNKNOWN


def test_different_value_widths_in_same_slot_cannot_prove_polarity():
    """A byte-typed owner of two-byte storage cannot authorize a word guard."""
    codegen,_word,byte,value,one = _fixture()
    byte_value = CVariable(value.variable,variable_type=byte,codegen=codegen)
    original = CBinaryOp('CmpLT',byte_value,one,codegen=codegen)
    replacement = CBinaryOp('CmpGE',value,one,codegen=codegen)

    assert condition_comparison_polarity_8616(
        original,replacement,same_expression=_same_c_expression_8616,
    ) is ConditionComparisonPolarity8616.UNKNOWN


def test_reextended_truncation_cannot_hide_changed_value():
    """Equal outer widths cannot conceal a lossy cast inside one operand."""
    codegen,word,byte,value,one = _fixture()
    truncated = CSemanticCast8616(word,byte,value,codegen=codegen)
    reextended = CSemanticCast8616(byte,word,truncated,codegen=codegen)
    original = CBinaryOp('CmpLT',reextended,one,codegen=codegen)
    replacement = CBinaryOp('CmpGE',value,one,codegen=codegen)

    assert condition_comparison_polarity_8616(
        original,replacement,same_expression=_same_c_expression_8616,
    ) is ConditionComparisonPolarity8616.UNKNOWN


def test_same_width_native_view_keeps_comparison_orientation():
    """A complete native word view can preserve the operator's inverse arm."""
    codegen,word,_byte,value,one = _fixture()
    signed = SimTypeShort(True).with_arch(codegen.project.arch)
    view = CSemanticCast8616(word,signed,value,codegen=codegen)
    original = CBinaryOp('CmpLT',view,one,codegen=codegen)
    replacement = CBinaryOp('CmpGE',view,one,codegen=codegen)

    assert condition_comparison_polarity_8616(
        original,replacement,same_expression=_same_c_expression_8616,
    ) is ConditionComparisonPolarity8616.INVERTED


@pytest.mark.parametrize('other_variable', [
    SimMemoryVariable(4, 2),
    SimStackVariable(4, 2, base='sp'),
])
def test_matching_numeric_offsets_do_not_merge_storage_spaces(other_variable):
    """Stack frames and DS addresses remain distinct despite equal offsets."""
    codegen,word,_byte,value,one = _fixture()
    other = CVariable(other_variable,variable_type=word,codegen=codegen)
    original = CBinaryOp('CmpLT',value,one,codegen=codegen)
    replacement = CBinaryOp('CmpGE',other,one,codegen=codegen)

    assert condition_comparison_polarity_8616(
        original,replacement,same_expression=_same_c_expression_8616,
    ) is ConditionComparisonPolarity8616.UNKNOWN


def test_asymmetric_signed_view_cannot_prove_comparison_truth():
    """Equal bits do not make signed and unsigned relational values equal."""
    codegen,word,_byte,value,one = _fixture()
    signed = SimTypeShort(True).with_arch(codegen.project.arch)
    view = CSemanticCast8616(word,signed,value,codegen=codegen)
    original = CBinaryOp('CmpLT',value,one,codegen=codegen)
    replacement = CBinaryOp('CmpGE',view,one,codegen=codegen)
    assert condition_comparison_polarity_8616(
        original,replacement,same_expression=_same_c_expression_8616,
    ) is ConditionComparisonPolarity8616.UNKNOWN


def test_same_bits_with_different_constant_interpretations_refuse():
    """Signed minus one and unsigned maximum are different C values."""
    codegen,word,_byte,value,_one = _fixture()
    signed = SimTypeShort(True).with_arch(codegen.project.arch)
    negative = CConstant(0xffff,signed,codegen=codegen)
    maximum = CConstant(0xffff,word,codegen=codegen)
    original = CBinaryOp('CmpLT',value,negative,codegen=codegen)
    replacement = CBinaryOp('CmpGE',value,maximum,codegen=codegen)
    assert condition_comparison_polarity_8616(
        original,replacement,same_expression=_same_c_expression_8616,
    ) is ConditionComparisonPolarity8616.UNKNOWN


def test_register_offset_does_not_hide_insufficient_storage():
    """A byte register cannot authorize a word expression at the same offset."""
    codegen,word,_byte,_value,one = _fixture()
    ax = CVariable(SimRegisterVariable(0,2),variable_type=word,codegen=codegen)
    al = CVariable(SimRegisterVariable(0,1),variable_type=word,codegen=codegen)
    original = CBinaryOp('CmpLT',ax,one,codegen=codegen)
    replacement = CBinaryOp('CmpGE',al,one,codegen=codegen)
    assert condition_comparison_polarity_8616(
        original,replacement,same_expression=_same_c_expression_8616,
    ) is ConditionComparisonPolarity8616.UNKNOWN


def test_compound_operand_cannot_hide_nested_truncation():
    """An outer word expression does not authenticate casts inside its inputs."""
    codegen,word,byte,value,one = _fixture()
    truncated = CSemanticCast8616(word,byte,value,codegen=codegen)
    left = CBinaryOp('Add',one,truncated,codegen=codegen)
    right = CBinaryOp('Add',one,value,codegen=codegen)
    original = CBinaryOp('CmpLT',left,one,codegen=codegen)
    replacement = CBinaryOp('CmpGE',right,one,codegen=codegen)
    assert condition_comparison_polarity_8616(
        original,replacement,same_expression=_same_c_expression_8616,
    ) is ConditionComparisonPolarity8616.UNKNOWN


def test_boolean_compound_cannot_hide_different_leaf_value_widths():
    """Boolean result width does not establish equality of its typed inputs."""
    codegen,_word,byte,value,one = _fixture()
    byte_value = CVariable(value.variable,variable_type=byte,codegen=codegen)
    left = CBinaryOp('LogicalAnd',byte_value,one,codegen=codegen)
    right = CBinaryOp('LogicalAnd',value,one,codegen=codegen)
    original = CBinaryOp('CmpNE',left,one,codegen=codegen)
    replacement = CBinaryOp('CmpEQ',right,one,codegen=codegen)
    assert condition_comparison_polarity_8616(
        original,replacement,same_expression=_same_c_expression_8616,
    ) is ConditionComparisonPolarity8616.UNKNOWN
