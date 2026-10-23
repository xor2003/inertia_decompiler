"""Explicit AIL arithmetic types must survive hidden cosmetic C casts."""

from itertools import count
from types import SimpleNamespace

import pytest
from angr.ailment.expression import BinaryOp, Const
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant
from angr.sim_type import SimTypeShort

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.native_integer_operations import lower_native_integer_operation_8616
from inertia.lowering.semantic_cast import CSemanticCast8616

_DWORD_BITS = 32


def _operation(op="Shl", bits=32, signed=False, count_value=16, right_bits=8):
    context = SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()), next_ident=lambda name: name,
        next_node_idx=count().__next__, show_casts=False, cstyle_null_cmp=False, const_formats={},
    )
    type_ = SimTypeShort(True).with_arch(context.project.arch)
    native = CBinaryOp(op, CConstant(-1, type_, codegen=context),
                       CConstant(count_value, type_, codegen=context), codegen=context)
    expression = BinaryOp(0, op, [Const(1, -1, bits), Const(2, count_value, right_bits)], signed, bits=bits)
    return expression, native


def test_word_byte_composition_keeps_required_casts_through_native_cleanup():
    from angr.ailment.expression import Register
    from angr.analyses.decompiler.structured_codegen.c import CVariable, MakeTypecastsImplicit
    from angr.sim_type import SimTypeChar
    from angr.sim_variable import SimStackVariable

    from inertia.lowering.native_integer_constants import apply_native_integer_constant_values_8616

    apply_native_integer_constant_values_8616()
    expression, native = _operation(bits=16, count_value=8)
    byte_type = SimTypeChar(False).with_arch(native.codegen.project.arch)
    word_type = SimTypeShort(False).with_arch(native.codegen.project.arch)
    argument = CVariable(SimStackVariable(2, 2), variable_type=word_type, codegen=native.codegen)
    lane = CBinaryOp("Shr", argument, native.rhs, codegen=native.codegen)
    high_byte = CSemanticCast8616(None, byte_type, lane, codegen=native.codegen)
    native.lhs = high_byte
    expression = BinaryOp(0, "Shl", [Register(1, 8, 16), expression.operands[1]], False, bits=16)
    protected = lower_native_integer_operation_8616(expression, native)
    assert isinstance(protected, CSemanticCast8616)
    shifted = protected.expr
    widened = shifted.lhs
    low_byte = CSemanticCast8616(None, byte_type, argument, codegen=native.codegen)
    composed = CBinaryOp("Or", low_byte, protected, codegen=native.codegen)
    # Codegen cleanup and subsequent cleanup must not reinterpret owned casts
    # as optional promotions, even when the contextual result is already u16.
    for _ in range(2):
        assert MakeTypecastsImplicit().handle(composed) is composed
    assert composed.rhs is protected
    assert protected.expr is shifted
    assert shifted.lhs is widened
    assert widened.expr is high_byte
    assert widened.dst_type.size == 16
    assert widened.dst_type.signed is False


def test_required_conversion_survives_contextual_cast_collapse():
    from angr.analyses.decompiler.structured_codegen.c import MakeTypecastsImplicit

    from inertia.lowering.native_integer_constants import apply_native_integer_constant_values_8616

    apply_native_integer_constant_values_8616()
    expression, native = _operation(bits=16, count_value=8)
    protected = lower_native_integer_operation_8616(expression, native)
    assert MakeTypecastsImplicit.collapse(protected.dst_type, protected) is protected


def test_ordinary_cosmetic_cast_still_collapses():
    from angr.analyses.decompiler.structured_codegen.c import CTypeCast, MakeTypecastsImplicit
    from angr.sim_type import SimTypeNum

    from inertia.lowering.native_integer_constants import apply_native_integer_constant_values_8616

    apply_native_integer_constant_values_8616()
    _expression, native = _operation(bits=16, count_value=8)
    word = SimTypeNum(16, False).with_arch(native.codegen.project.arch)
    cosmetic = CTypeCast(word, word, native.rhs, codegen=native.codegen)
    assert MakeTypecastsImplicit.collapse(word, cosmetic) is native.rhs


@pytest.mark.parametrize("count_value", [0, 1, 16, 31])
def test_dword_shift_keeps_unsigned_semantic_conversion(count_value):
    expression, native = _operation(count_value=count_value)
    result = lower_native_integer_operation_8616(expression, native)
    assert isinstance(result, CBinaryOp)
    assert isinstance(result.lhs, CSemanticCast8616)
    assert result.lhs.dst_type.size == _DWORD_BITS
    assert result.lhs.dst_type.signed is False
    assert "uint32_t" in "".join(text for text, _node in result.c_repr_chunks())
    assert result.rhs is native.rhs


@pytest.mark.parametrize("op", ["Div", "Mod"])
@pytest.mark.parametrize("signed", [False, True])
def test_dword_division_keeps_both_operand_signedness(op, signed):
    expression, native = _operation(op, signed=signed, right_bits=32)
    result = lower_native_integer_operation_8616(expression, native)
    for operand in (result.lhs, result.rhs):
        assert isinstance(operand, CSemanticCast8616)
        assert operand.dst_type.size == _DWORD_BITS
        assert operand.dst_type.signed is signed


@pytest.mark.parametrize(("op", "bits", "count_value", "right_bits"), [
    ("Shl", 8, 1, 8), ("Shl", 32, 32, 8), ("Shl", 32, -1, 8),
    ("Div", 32, 2, 16), ("Add", 32, 2, 32),
])
def test_unknown_or_out_of_scope_arithmetic_is_not_reinterpreted(op, bits, count_value, right_bits):
    expression, native = _operation(op, bits=bits, count_value=count_value, right_bits=right_bits)
    assert lower_native_integer_operation_8616(expression, native) is None


@pytest.mark.parametrize("count_value", [0, 1, 8, 15])
def test_word_shift_widens_before_promotion_and_truncates_result(count_value):
    expression, native = _operation(bits=16, count_value=count_value)
    native.tags = {"ins_addr": 0x1000}
    result = lower_native_integer_operation_8616(expression, native)
    assert isinstance(result, CSemanticCast8616)
    assert result.dst_type.size == 16 and result.dst_type.signed is False
    shifted = result.expr
    assert isinstance(shifted, CBinaryOp)
    assert isinstance(shifted.lhs, CSemanticCast8616)
    assert shifted.lhs.dst_type.size == 16 and shifted.lhs.dst_type.signed is False
    assert shifted.lhs.expr is native.lhs
    assert shifted.rhs is native.rhs
    assert result.codegen is native.codegen
    assert result.tags == native.tags


@pytest.mark.parametrize("count_value", [-1, 16, 32])
def test_word_invalid_shift_count_refuses(count_value):
    expression, native = _operation(bits=16, count_value=count_value)
    assert lower_native_integer_operation_8616(expression, native) is None


def test_word_shift_requires_exact_scalar_left_width_and_literal_count():
    from angr.ailment.expression import Register
    expression, native = _operation(bits=16, count_value=8)
    expression = BinaryOp(0, "Shl", [Const(1, 255, 8), expression.operands[1]], False, bits=16)
    assert lower_native_integer_operation_8616(expression, native) is None
    expression, native = _operation(bits=16, count_value=8)
    expression = BinaryOp(0, "Shl", [expression.operands[0], Register(2, 8, 16)], False, bits=16)
    assert lower_native_integer_operation_8616(expression, native) is None
    expression, native = _operation(bits=16, count_value=8)
    expression = BinaryOp(0, "Shl", expression.operands, False, bits=16, floating_point=True)
    assert lower_native_integer_operation_8616(expression, native) is None


@pytest.mark.parametrize("value,count_value,expected", [(128, 8, 32768), (255, 8, 65280), (65535, 8, 65280), (65535, 15, 32768)])
def test_word_rendered_shift_keeps_native_low_word(tmp_path, value, count_value, expected):
    import shutil
    import subprocess
    compiler = shutil.which("gcc")
    assert compiler is not None, "host gcc is required to execute generated integer expression"
    expression, native = _operation(bits=16, count_value=count_value)
    native.lhs.value = value
    result = lower_native_integer_operation_8616(expression, native)
    assert isinstance(result, CSemanticCast8616)
    rendered = "".join(text for text, _node in result.c_repr_chunks())
    source = tmp_path / "word.c"
    source.write_text("#include <stdint.h>\n#include <stdio.h>\nint main(void){printf(\"%u\",(unsigned)(" + rendered + "));}\n")
    executable = tmp_path / "word"
    subprocess.run([compiler, "-fsanitize=undefined", "-fno-sanitize-recover=all", str(source), "-o", str(executable)], check=True, capture_output=True, timeout=15)
    execution = subprocess.run([str(executable)], check=True, capture_output=True, text=True, timeout=5)
    assert int(execution.stdout) == expected


def test_live_codegen_hook_protects_word_shift_after_byte_cast(monkeypatch):
    from angr.ailment.expression import Register
    from angr.analyses.decompiler.structured_codegen.c import CStructuredCodeGenerator
    from angr.sim_type import SimTypeNum

    from inertia.lowering.native_integer_constants import apply_native_integer_constant_values_8616
    expression, native = _operation(bits=16, count_value=8)
    expression = BinaryOp(0, "Shl", [Register(1, 32, 16), expression.operands[1]], False, bits=16)
    native.lhs = CSemanticCast8616(None, SimTypeNum(8, False), native.lhs, codegen=native.codegen)
    context = native.codegen
    context._variable_map = SimpleNamespace(variable=lambda expression: None)
    def original_codegen(self, expression, **kwargs):
        return native
    monkeypatch.setattr(CStructuredCodeGenerator, "_handle_Expr_BinaryOp", original_codegen)
    apply_native_integer_constant_values_8616()
    result = CStructuredCodeGenerator._handle_Expr_BinaryOp(context, expression)
    assert isinstance(result, CSemanticCast8616)
    assert result.dst_type.size == 16 and result.dst_type.signed is False
    assert isinstance(result.expr.lhs, CSemanticCast8616)
    assert result.expr.lhs.dst_type.size == 16 and result.expr.lhs.dst_type.signed is False
    assert result.expr.lhs.expr is native.lhs
    report = context._inertia_integer_constant_report_8616
    assert (report.raw_fact_count, report.normalized_fact_count, report.classified_fact_count, report.materialized_count, report.failure_count) == (1, 1, 1, 1, 0)


def test_word_shift_refuses_mismatched_native_operation():
    expression, native = _operation(bits=16, count_value=8)
    mismatched = CBinaryOp("Add", native.lhs, native.rhs, codegen=native.codegen)
    assert lower_native_integer_operation_8616(expression, mismatched) is None


def test_address_label_normalization_retains_required_unsigned_shift_casts():
    """Address analysis must not strip conversions from retained value terms."""
    from inertia.lowering.real_mode_linear import _normalize_address_label_terms_8616

    expression, native = _operation(bits=16, count_value=8)
    protected = lower_native_integer_operation_8616(expression, native)
    normalized, folded = _normalize_address_label_terms_8616(protected, native.codegen)
    assert folded == 0
    assert normalized is protected
    assert isinstance(normalized.expr.lhs, CSemanticCast8616)


def test_address_label_fold_keeps_conversion_around_resolved_offset():
    """Resolving a label must preserve its explicit truncation and metadata."""
    from angr.analyses.decompiler.structured_codegen.c import CUnaryOp, CVariable
    from angr.sim_type import SimTypeChar
    from angr.sim_variable import SimMemoryVariable

    from inertia.lowering.real_mode_linear import _normalize_address_label_terms_8616

    _expression, native = _operation(bits=16, count_value=8)
    context = native.codegen
    word = SimTypeShort(False).with_arch(context.project.arch)
    label = CVariable(SimMemoryVariable(0x180, 2), variable_type=word, codegen=context)
    reference = CUnaryOp("Reference", label, codegen=context)
    protected = CSemanticCast8616(None, SimTypeChar(False), reference, codegen=context, tags={"ins_addr": 0x1000})
    normalized, folded = _normalize_address_label_terms_8616(protected, context)
    assert folded == 1
    assert isinstance(normalized, CSemanticCast8616)
    assert normalized.dst_type == protected.dst_type
    assert normalized.expr.value == 0x180
    assert normalized.tags == protected.tags
    assert protected.expr is reference
