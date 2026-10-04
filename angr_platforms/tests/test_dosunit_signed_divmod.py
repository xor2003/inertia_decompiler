"""Shared VEX DivMod lowering must preserve signed narrow divisors."""
import pytest
import pyvex
import z3
from unicorn import UC_ARCH_X86, UC_MODE_32, Uc
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_EDX

from tools.dosunit import straightline_ssa as S


def _value(term: S.SsaExpr):
    if term.op == "const":
        return z3.BitVecVal(term.value, term.width)
    return S._z3_apply(term.op, term.width, [_value(arg) for arg in term.args], z3)


@pytest.mark.parametrize("signed,dividend,divisor,quotient,remainder", [
    (True, -6, -1, 6, 0), (True, 7, -3, -2, 1),
    (True, -7, 3, -2, -1), (True, -7, -3, 2, -1),
    (False, 0xFFFFFFFF, 0xFFFFFFFF, 1, 0), (False, 7, 3, 2, 1),
])
def test_divmod_lowering_matches_native(signed, dividend, divisor, quotient, remainder):
    """Actual IDIV/DIV and the shared lowerer agree on both packed result lanes."""
    expr = pyvex.IRExpr.Binop("Iop_DivModS64to32" if signed else "Iop_DivModU64to32", [
        pyvex.IRExpr.Const(pyvex.IRConst.U64(dividend & ((1 << 64) - 1))),
        pyvex.IRExpr.Const(pyvex.IRConst.U32(divisor & 0xFFFFFFFF)),
    ])
    lowered = S._lower_binop(expr, temp_defs={}, temp_failures={}, reg_versions={},
                            tyenv=None, memory=S.SsaExpr("input", 0, name="memory"))
    assert isinstance(lowered, S.SsaExpr)
    concrete = z3.simplify(_value(lowered))
    assert isinstance(concrete, z3.BitVecNumRef)
    packed = concrete.as_long()
    assert packed & 0xFFFFFFFF == quotient & 0xFFFFFFFF
    assert packed >> 32 == remainder & 0xFFFFFFFF
    guest = Uc(UC_ARCH_X86, UC_MODE_32)
    guest.mem_map(0x1000, 0x1000)
    guest.mem_write(0x1000, bytes.fromhex("f7fb" if signed else "f7f3"))
    guest.reg_write(UC_X86_REG_EAX, dividend & 0xFFFFFFFF)
    guest.reg_write(UC_X86_REG_EDX, (dividend >> 32) & 0xFFFFFFFF)
    guest.reg_write(UC_X86_REG_EBX, divisor & 0xFFFFFFFF)
    guest.emu_start(0x1000, 0x1002)
    assert guest.reg_read(UC_X86_REG_EAX) == quotient & 0xFFFFFFFF
    assert guest.reg_read(UC_X86_REG_EDX) == remainder & 0xFFFFFFFF
