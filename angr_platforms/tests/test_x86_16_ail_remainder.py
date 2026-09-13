"""Remainder folding must retain the original division's arithmetic contract."""

import subprocess
from types import SimpleNamespace

import pytest
from angr.ailment.expression import BinaryOp, Const, Convert
from angr.analyses.decompiler.peephole_optimizations.modulo_simplifier import ModuloSimplifier
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant
from angr.sim_type import SimTypeNum
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.native_integer_operations import lower_native_integer_operation_8616


def _remainder(signed, divisor=80, bits=32):
    value = Const(0, (1 << bits) - 1, bits)
    denominator = Const(1, divisor, bits)
    quotient = BinaryOp(2, "Div", [value, denominator], signed, bits=bits)
    product = BinaryOp(3, "Mul", [quotient, denominator], False, bits=bits)
    return BinaryOp(4, "Sub", [value, product], False, bits=bits)


def _optimize(expression):
    project = SimpleNamespace(arch=Arch86_16())
    return ModuloSimplifier(project, None, None).optimize(expression)


@pytest.mark.parametrize("signed", [False, True])
@pytest.mark.parametrize("bits", [16, 32])
def test_remainder_keeps_division_signedness(signed, bits):
    expression = _remainder(signed, bits=bits)
    result = _optimize(expression)
    assert isinstance(result, BinaryOp)
    assert result.op == "Mod"
    assert result.signed is signed
    assert result.bits == bits
    assert result.operands[0].likes(expression.operands[0])


def test_remainder_refuses_zero_divisor():
    assert _optimize(_remainder(True, divisor=0)) is None


@pytest.mark.parametrize("divisor", [-1, 0xFFFFFFFF])
def test_remainder_preserves_possible_signed_division_overflow(divisor):
    assert _optimize(_remainder(True, divisor=divisor)) is None


def test_remainder_refuses_mismatched_conversion_semantics():
    expression = _remainder(True)
    value, product = expression.operands
    quotient, divisor = product.operands
    left = Convert(5, 32, 64, True, value)
    right = Convert(6, 32, 64, False, quotient)
    product = BinaryOp(7, "Mul", [right, Const(8, divisor.value, 64)], False, bits=64)
    widened = BinaryOp(9, "Sub", [left, product], False, bits=64)
    assert _optimize(widened) is None


def test_remainder_generated_c_preserves_negative_and_unsigned_results(tmp_path):
    context = SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()), next_ident=lambda name: name,
        next_node_idx=lambda: 0,
        show_casts=False, cstyle_null_cmp=False, const_formats={},
    )
    integer_type = SimTypeNum(32, False).with_arch(context.project.arch)
    checks = []
    for signed in (False, True):
        for value in (-32768, -81, -80, -1, 0, 1, 32767):
            expression = _remainder(signed)
            expression.operands[0].value = value & 0xFFFFFFFF
            result = _optimize(expression)
            native = CBinaryOp(
                "Mod", CConstant(value & 0xFFFFFFFF, integer_type, codegen=context),
                CConstant(80, integer_type, codegen=context), codegen=context,
            )
            lowered = lower_native_integer_operation_8616(result, native)
            rendered = "".join(text for text, _node in lowered.c_repr_chunks())
            magnitude_remainder = abs(value) % 80
            signed_remainder = -magnitude_remainder if value < 0 else magnitude_remainder
            expected = signed_remainder if signed else (value & 0xFFFFFFFF) % 80
            checks.append(f"if ((int32_t)({rendered}) != {expected}) return 1;")
    source = "#include <stdint.h>\nint main(void) {\n" + "\n".join(checks) + "\nreturn 0; }\n"
    executable = tmp_path / "remainder"
    compile_result = subprocess.run(
        ["gcc", "-x", "c", "-std=c11", "-Wall", "-Wextra", "-Werror", "-o", str(executable), "-"],
        input=source, capture_output=True, text=True, check=False,
    )
    assert compile_result.returncode == 0, compile_result.stderr
    assert subprocess.run([str(executable)], check=False).returncode == 0
