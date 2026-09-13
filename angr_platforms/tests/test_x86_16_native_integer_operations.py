"""Explicit AIL arithmetic types must survive hidden cosmetic C casts."""

from itertools import count
from types import SimpleNamespace

import pytest
from angr.ailment.expression import BinaryOp, Const
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.native_integer_operations import lower_native_integer_operation_8616
from angr_platforms.X86_16.lowering.semantic_cast import CSemanticCast8616

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
    ("Shl", 16, 1, 8), ("Shl", 32, 32, 8), ("Shl", 32, -1, 8),
    ("Div", 32, 2, 16), ("Add", 32, 2, 32),
])
def test_unknown_or_out_of_scope_arithmetic_is_not_reinterpreted(op, bits, count_value, right_bits):
    expression, native = _operation(op, bits=bits, count_value=count_value, right_bits=right_bits)
    assert lower_native_integer_operation_8616(expression, native) is None
