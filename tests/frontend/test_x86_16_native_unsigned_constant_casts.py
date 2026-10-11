"""Unsigned literal narrowing must survive native removal of redundant casts."""

from itertools import count
from types import SimpleNamespace

import pytest
from angr.ailment.expression import BinaryOp, Const, Register, VirtualVariable, VirtualVariableCategory
from angr.analyses.decompiler.structured_codegen.c import (
    CConstant,
    CStructuredCodeGenerator,
    CTypeCast,
    MakeTypecastsImplicit,
)
from angr.sim_type import SimTypeBottom, SimTypeChar, SimTypeLong, SimTypeNum, SimTypeShort

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.native_integer_constants import (
    apply_native_integer_constant_values_8616,
    apply_native_unsigned_constant_casts_8616,
    fold_unsigned_narrowing_constant_8616,
    native_integer_constant_value_8616,
)

_BYTE_BITS = 8


def _cast(value, source=None, destination=None):
    arch = Arch86_16()
    context = SimpleNamespace(project=SimpleNamespace(arch=arch), next_ident=lambda name: name,
                              next_node_idx=count().__next__)
    source = (source or SimTypeShort(signed=False)).with_arch(arch)
    destination = (destination or SimTypeChar(signed=False)).with_arch(arch)
    return CTypeCast(source, destination, CConstant(value, source, codegen=context), codegen=context)


@pytest.mark.parametrize("value", [0, 1, 127, 128, 255, 256, 4660, 65535, -1])
def test_native_unsigned_byte_constant_narrowing(value) -> None:
    """Install the adapter explicitly instead of depending on test collection order."""
    apply_native_unsigned_constant_casts_8616()
    expression = _cast(value)
    result = MakeTypecastsImplicit.collapse(expression.dst_type, expression)
    assert isinstance(result, CConstant)
    assert result.value == value % 256
    assert result.type.size == _BYTE_BITS
    assert result.type.signed is False
    report = expression.codegen._inertia_integer_constant_report_8616
    assert report.raw_fact_count == report.normalized_fact_count == report.classified_fact_count == 1
    assert report.materialized_count == 1
    assert report.failure_count == 0


@pytest.mark.parametrize("value", [0, 65535, 65536, 0x12345678, -1])
def test_unsigned_word_constant_narrowing(value) -> None:
    expression = _cast(value, SimTypeLong(signed=False), SimTypeShort(signed=False))
    result = fold_unsigned_narrowing_constant_8616(expression.dst_type, expression)
    assert result.value == value % 65536


@pytest.mark.parametrize("source,destination,context", [
    (SimTypeShort(signed=False), SimTypeChar(signed=True), SimTypeChar(signed=True)),
    (SimTypeChar(signed=False), SimTypeShort(signed=False), SimTypeShort(signed=False)),
    (SimTypeShort(signed=False), SimTypeShort(signed=False), SimTypeShort(signed=False)),
    (SimTypeShort(signed=False), SimTypeChar(signed=False), SimTypeShort(signed=False)),
    (SimTypeBottom(), SimTypeChar(signed=False), SimTypeChar(signed=False)),
])
def test_unproven_or_non_narrowing_cast_is_not_folded(source, destination, context) -> None:
    expression = _cast(1, source, destination)
    assert fold_unsigned_narrowing_constant_8616(context.with_arch(Arch86_16()), expression) is None


@pytest.mark.parametrize("operation,left,right,bits,signed,expected", [
    ("Add", 65535, 1, 16, False, 0), ("Sub", 0, 1, 16, False, 65535),
    ("Add", 32767, 1, 16, True, -32768), ("Mul", 256, 256, 16, False, 0),
    ("Add", 255, 1, 8, False, 0), ("Add", 0xffffffff, 1, 32, False, 0),
    ("Xor", 0xff, 0xf, 8, False, 0xf0),
])
def test_native_literal_arithmetic_retains_machine_width(operation, left, right, bits, signed, expected) -> None:
    expression = BinaryOp(0, operation, [Const(1, left, bits), Const(2, right, bits)], signed, bits=bits)
    assert native_integer_constant_value_8616(expression) == expected


@pytest.mark.parametrize("operation,left_bits,right_bits,floating", [
    ("Div", 16, 16, False), ("Add", 8, 16, False), ("Add", 16, 8, False), ("Add", 16, 16, True),
])
def test_native_constant_arithmetic_refuses_unproved_operations(operation, left_bits, right_bits, floating) -> None:
    expression = BinaryOp(0, operation, [Const(1, 1, left_bits), Const(2, 1, right_bits)],
                          False, bits=16, floating_point=floating)
    assert native_integer_constant_value_8616(expression) is None


def test_packed_arithmetic_is_not_folded_as_a_scalar() -> None:
    expression = BinaryOp(0, "Add", [Const(1, 0x00ff, 16), Const(2, 1, 16)], False,
                          bits=16, vector_count=2, vector_size=8)
    assert native_integer_constant_value_8616(expression) is None


@pytest.mark.parametrize('bits', [8, 16, 32])
@pytest.mark.parametrize('ssa', [False, True])
def test_native_zeroing_xor_uses_pure_register_value_identity(bits, ssa):
    """Pure equal native values cancel before C register projections are built."""
    if ssa:
        left = VirtualVariable(0, 3, bits, VirtualVariableCategory.REGISTER, oident=0)
        right = VirtualVariable(1, 3, bits, VirtualVariableCategory.REGISTER, oident=0)
    else:
        left, right = Register(0, 0, bits), Register(1, 0, bits)
    expression = BinaryOp(2, 'Xor', [left, right], False, bits=bits)
    assert native_integer_constant_value_8616(expression) == 0


@pytest.mark.parametrize('fault', ['different-register', 'different-width', 'different-ssa', 'different-owner', 'floating', 'vector'])
def test_native_zeroing_xor_refuses_conflicting_value_evidence(fault):
    """Matching printed names or widths alone must not establish cancellation."""
    left, right = Register(0, 0, 16), Register(1, 0, 16)
    if fault == 'different-register':
        right = Register(1, 2, 16)
    elif fault == 'different-width':
        right = Register(1, 0, 8)
    elif fault in ('different-ssa', 'different-owner'):
        left = VirtualVariable(0, 3, 16, VirtualVariableCategory.REGISTER, oident=0)
        right = VirtualVariable(1, 4 if fault == 'different-ssa' else 3, 16,
                                VirtualVariableCategory.REGISTER, oident=2 if fault == 'different-owner' else 0)
    options = {'floating_point': True} if fault == 'floating' else {}
    if fault == 'vector':
        options = {'vector_count': 2, 'vector_size': 8}
    expression = BinaryOp(2, 'Xor', [left, right], False, bits=16, **options)
    assert native_integer_constant_value_8616(expression) is None


@pytest.mark.parametrize('variable_backed', [False, True])
def test_native_zeroing_xor_adapter_preserves_bound_variable_nodes(monkeypatch, variable_backed):
    """Wire cancellation into native C construction without losing storage bindings."""
    arch = Arch86_16()
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=arch), next_ident=lambda name: name,
        next_node_idx=count().__next__,
        _variable_map=SimpleNamespace(variable=lambda _expr: object() if variable_backed else None),
        default_simtype_from_bits=lambda bits, signed: SimTypeNum(bits,signed).with_arch(arch),
    )
    retained = CConstant(7,SimTypeShort(False),codegen=codegen)
    calls = []

    def original(_self, expression, **_kwargs):
        calls.append(expression)
        return retained

    monkeypatch.setattr(CStructuredCodeGenerator,'_handle_Expr_BinaryOp',original)
    apply_native_integer_constant_values_8616()
    expression = BinaryOp(2,'Xor',[Register(0,0,16),Register(1,0,16)],False,bits=16)
    result = CStructuredCodeGenerator._handle_Expr_BinaryOp(codegen,expression)
    if variable_backed:
        assert result is retained
        assert calls == [expression]
    else:
        assert isinstance(result,CConstant) and result.value == 0 and result.type.size == 16
        assert not calls
        report = codegen._inertia_integer_constant_report_8616
        assert report.raw_fact_count == report.normalized_fact_count == report.classified_fact_count == 1
        assert report.materialized_count == 1 and report.failure_count == 0
