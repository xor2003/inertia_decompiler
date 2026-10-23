"""Focused tests for the x87 numeric instruction owner (flat32_x87_arith).

Expected values come from the pinned SoftFloat3e/86Box semantics and the
parent's host-derived vectors (same oracle family as the stack tests):
ext80 results are literal encodings, condition codes occupy SW bits
8,9,10,14 (C0,C1,C2,C3) with TOP at 11-13.
"""
from __future__ import annotations

from typing import ClassVar

import pytest
import z3

from tools.dosunit.architectures.flat32 import flat32_register_architecture
from tools.dosunit.architectures.flat32_control_word import decode_native_x87, native_x87_body
from tools.dosunit.architectures.flat32_x87_arith import (
    ArithMem,
    ArithReg,
    BcdMem,
    Comi,
    CompareMem,
    CompareReg,
    ConvLoad,
    ConvStore,
    EnvLoad,
    EnvStore,
    FCmov,
    IntLoad,
    IntStore,
    Remainder,
    SqrtOrRnd,
    TstOrXam,
)
from tools.dosunit.ssa.translation import TranslationContext

pytestmark = pytest.mark.ssa_z3

REGS = dict(flat32_register_architecture().registers)
CW = 0x37F  # all exceptions masked, RNE, PC64

ONE = 0x3FFF8000000000000000
TWO = 0x40008000000000000000
THREE = 0x4000C000000000000000
FOUR = 0x40018000000000000000
HALF = 0x3FFE8000000000000000
NEG3 = 0xC000C000000000000000
INDEF = 0xFFFFC000000000000000

# SW bits: IE 0, DE 1, ZE 2, OE 3, UE 4, PE 5, SF 6, ES 7, C0 8, C1 9,
# C2 10, TOP 11-13, B 15, C3 14.
TOP = 0x3800
C0, C1, C2, C3 = 0x0100, 0x0200, 0x0400, 0x4000


def _tags(*classes: int) -> int:
    """Pack per-physical-register tag classes (3=empty) low register first."""
    out = 0
    for i in range(8):
        out |= (classes[i] if i < len(classes) else 3) << (2 * i)
    return out


def _run(raw: bytes, concrete: dict[str, object]) -> dict[str, object]:
    instruction = decode_native_x87(raw)
    assert instruction is not None, raw.hex()
    body = native_x87_body(instruction, continuation=0x1000,
                           registers=REGS, address=0x800)
    inputs = {}
    for item in body["inputs"]:
        name = item["name"] if isinstance(item, dict) else item
        width = item.get("width", 32) if isinstance(item, dict) else 32
        if name == "mem":
            memory = z3.K(z3.BitVecSort(32), z3.BitVecVal(0, 8))
            for addr, value in concrete.get("mem", {}).items():
                memory = z3.Store(memory, z3.BitVecVal(addr, 32),
                                  z3.BitVecVal(value, 8))
            inputs[name] = (memory, 8)
        else:
            inputs[name] = (z3.BitVecVal(concrete.get(name, 0), width), width)
    context = TranslationContext(body, inputs,
                                 {i["id"]: i for i in body["assignments"]},
                                 {}, z3, lambda value, **_kwargs: value)
    outputs = {}
    for name, term in body["outputs"].items():
        value = z3.simplify(context.term(term))
        outputs[name] = value.as_long() if z3.is_bv_value(value) else value
    return outputs


def _mem_bytes(addr: int, data: bytes) -> dict[int, int]:
    return {addr + i: b for i, b in enumerate(data)}


# Two-value stack: ST0 at phys 6, ST1 at phys 7 (TOP=6 -> sw top bits 6<<11).
TWO_STACK = {"x87_status_word": 6 << 11, "x87_tag_word": _tags(3, 3, 3, 3, 3, 3, 0, 0),
             "x87_st6": ONE, "x87_st7": TWO}


def test_decode_admits_arith_forms():
    assert isinstance(decode_native_x87(bytes.fromhex("d8c1")), ArithReg)
    assert isinstance(decode_native_x87(bytes.fromhex("dec1")), ArithReg)
    assert isinstance(decode_native_x87(bytes.fromhex("d8d1")), CompareReg)
    assert isinstance(decode_native_x87(bytes.fromhex("ded9")), CompareReg)
    assert isinstance(decode_native_x87(bytes.fromhex("dde5")), CompareReg)
    assert isinstance(decode_native_x87(bytes.fromhex("dae9")), CompareReg)
    assert isinstance(decode_native_x87(bytes.fromhex("d9f8")), Remainder)
    assert isinstance(decode_native_x87(bytes.fromhex("d9f5")), Remainder)
    assert isinstance(decode_native_x87(bytes.fromhex("d9fa")), SqrtOrRnd)
    assert isinstance(decode_native_x87(bytes.fromhex("d9fc")), SqrtOrRnd)
    assert isinstance(decode_native_x87(bytes.fromhex("d9e4")), TstOrXam)
    assert isinstance(decode_native_x87(bytes.fromhex("d9e5")), TstOrXam)


def test_decode_admits_memory_forms():
    assert isinstance(decode_native_x87(bytes.fromhex("d900")), ConvLoad)     # fld m32
    assert isinstance(decode_native_x87(bytes.fromhex("dd00")), ConvLoad)     # fld m64
    assert isinstance(decode_native_x87(bytes.fromhex("d910")), ConvStore)    # fst m32
    assert isinstance(decode_native_x87(bytes.fromhex("dd18")), ConvStore)    # fstp m64
    assert isinstance(decode_native_x87(bytes.fromhex("db00")), IntLoad)      # fild m32
    assert isinstance(decode_native_x87(bytes.fromhex("df00")), IntLoad)      # fild m16
    assert isinstance(decode_native_x87(bytes.fromhex("df28")), IntLoad)      # fild m64
    assert isinstance(decode_native_x87(bytes.fromhex("db10")), IntStore)     # fist m32
    assert isinstance(decode_native_x87(bytes.fromhex("df38")), IntStore)     # fistp m64
    assert isinstance(decode_native_x87(bytes.fromhex("d801")), ArithMem)     # fadd m32
    assert isinstance(decode_native_x87(bytes.fromhex("dc31")), ArithMem)     # fdiv m64
    from tools.dosunit.architectures.flat32_x87_arith import ArithInt
    assert isinstance(decode_native_x87(bytes.fromhex("da01")), ArithInt)     # fiadd m32
    assert isinstance(decode_native_x87(bytes.fromhex("de11")), CompareMem)   # ficom m16 /2


def test_fadd_sti_adds_and_keeps_top():
    out = _run(bytes.fromhex("d8c1"), dict(TWO_STACK))
    assert out["x87_st6"] == THREE
    assert out["x87_st7"] == TWO
    assert out["x87_status_word"] & TOP == 6 << 11
    assert out["x87_tag_word"] == _tags(3, 3, 3, 3, 3, 3, 0, 0)


def test_faddp_writes_sti_and_pops():
    out = _run(bytes.fromhex("dec1"), dict(TWO_STACK))
    # FADDP ST1: ST1 = ST1 + ST0 = 3.0, pop -> TOP 7, phys6 empty.
    assert out["x87_st7"] == THREE
    assert out["x87_status_word"] & TOP == 7 << 11
    assert out["x87_tag_word"] & 0x3000 == 0x3000


def test_fsubr_order():
    # FSUBR ST(i): D8 E8+i => ST0 = ST(i) - ST0 = 2 - 1 = 1
    out = _run(bytes.fromhex("d8e9"), dict(TWO_STACK))
    assert out["x87_st6"] == ONE
    # DC E8+i FSUB ST(i): ST1 = ST1 - ST0 = 1.0
    out = _run(bytes.fromhex("dce9"), dict(TWO_STACK))
    assert out["x87_st7"] == ONE
    assert out["x87_st6"] == ONE  # ST0 unchanged


def test_fmul_mem_widens_operand():
    # fmul m32 [eax]: mem 2.0f = 0x40000000 LE
    state = {"x87_status_word": 7 << 11, "x87_tag_word": _tags(*(3,) * 7 + (0,)),
             "x87_st7": THREE, "eax": 0x200,
             "mem": _mem_bytes(0x200, bytes.fromhex("00000040"))}
    out = _run(bytes.fromhex("d808"), state)  # d8 08: mod0 /1 r/m0 -> fmul m32 [eax]
    assert out["x87_st7"] == 0x4001C000000000000000  # 3.0 * 2.0 = 6.0 (exp 0x4001, sig 1.5)


def test_fld_m32_pushes_widened():
    state = {"x87_status_word": 0, "x87_tag_word": _tags(),
             "eax": 0x200, "mem": _mem_bytes(0x200, bytes.fromhex("0000803F"))}
    out = _run(bytes.fromhex("d900"), state)
    # FLD m32 pushes 1.0 at phys7, TOP=7.
    assert out["x87_st7"] == ONE
    assert out["x87_status_word"] & TOP == 7 << 11
    assert (out["x87_tag_word"] >> 14) & 3 == 0


def test_fstp_m64_narrows_and_pops():
    state = {"x87_status_word": 7 << 11, "x87_tag_word": _tags(*(3,) * 7 + (0,)),
             "x87_st7": 0x4000D000000000000000,  # 3.25
             "eax": 0x200}
    out = _run(bytes.fromhex("dd18"), state)
    # 3.25 -> double 0x400A000000000000 little-endian at [eax]
    memory = out["memory"]
    stored = z3.simplify(z3.Concat(*[
        z3.Select(memory, z3.BitVecVal(0x200 + i, 32)) for i in range(7, -1, -1)]))
    assert z3.is_bv_value(stored)
    assert int(stored.as_long()) == 0x400A000000000000
    assert out["x87_status_word"] & TOP == 0
    assert out["x87_tag_word"] & 0xC000 == 0xC000


def test_fcom_sets_condition_codes():
    # ST0=1 < ST1=2 -> C0=1
    out = _run(bytes.fromhex("d8d1"), dict(TWO_STACK))
    assert out["x87_status_word"] & (C0 | C2 | C3) == C0
    # ST0 > ST1: all clear
    swapped = dict(TWO_STACK)
    swapped["x87_st6"], swapped["x87_st7"] = TWO, ONE
    out = _run(bytes.fromhex("d8d1"), swapped)
    assert out["x87_status_word"] & (C0 | C2 | C3) == 0


def test_fcompp_pops_twice():
    out = _run(bytes.fromhex("ded9"), dict(TWO_STACK))
    assert out["x87_status_word"] & TOP == 0
    # both registers emptied
    assert (out["x87_tag_word"] & 0xF000) == 0xF000


def test_ftst_flags_vs_zero():
    out = _run(bytes.fromhex("d9e4"), dict(TWO_STACK))
    # ST0=1.0 > +0.0 -> CC clear
    assert out["x87_status_word"] & (C0 | C2 | C3) == 0


def test_fxam_reports_class():
    out = _run(bytes.fromhex("d9e5"), dict(TWO_STACK))
    # normal positive -> class 010 -> C3=0? code 010 = C2 -> bit... class bits
    # map: 010 -> C3C2C0 = 010 -> C2 set? FXAM C3C2C0=010 means C2? Per SDM
    # table the three-bit code goes to C3,C2,C0 -> 0b010 -> C2=0? bit1 of the
    # code lands on C2? code bit0->C0,bit1->C2? No: code bits map (C3,C2,C0)
    # as a group, C1=sign. code 010 -> C2=1? We emit code bit0->C0 (0x100),
    # bit1->C2 (0x400), bit2->C3 (0x4000). normal=0b010 -> C2 set.
    assert out["x87_status_word"] & (C0 | C2 | C3) == C2
    assert out["x87_status_word"] & C1 == 0


def test_fsqrt_negative_gives_indefinite():
    state = {"x87_status_word": 7 << 11, "x87_control_word": CW,
             "x87_tag_word": _tags(*(3,) * 7 + (0,)),
             "x87_st7": NEG3}
    out = _run(bytes.fromhex("d9fa"), state)
    assert out["x87_st7"] == INDEF
    assert out["x87_status_word"] & 0x3F == 0x01  # IE only


def test_frndint_rounds():
    state = {"x87_status_word": 7 << 11, "x87_control_word": CW,
             "x87_tag_word": _tags(*(3,) * 7 + (0,)),
             "x87_st7": 0x4000D000000000000000}  # 3.25 -> 3
    out = _run(bytes.fromhex("d9fc"), state)
    assert out["x87_st7"] == THREE
    assert out["x87_status_word"] & 0x3F == 0x20  # PE


def test_fprem_quotient_bits():
    # FPREM(10,3): remainder 1, quotient 3 -> C1=1,C3=1,C0=0 -> 0xA<<8 C-bits
    state = {"x87_status_word": 6 << 11, "x87_tag_word": _tags(3, 3, 3, 3, 3, 3, 0, 0),
             "x87_st6": 0x4002A000000000000000, "x87_st7": 0x4000C000000000000000}
    out = _run(bytes.fromhex("d9f8"), state)
    assert out["x87_st6"] == ONE
    assert out["x87_status_word"] & (C0 | C1 | C2 | C3) == (C1 | C3)


def test_fprem1_nearest_quotient():
    # FPREM1(7,2): remainder -1 (7 = 4*2 - 1), quotient 4 -> C2=0, q=100 ->
    # C0=1,C1=0,C3=0
    state = {"x87_status_word": 6 << 11, "x87_tag_word": _tags(3, 3, 3, 3, 3, 3, 0, 0),
             "x87_st6": 0x4001E000000000000000, "x87_st7": TWO}
    out = _run(bytes.fromhex("d9f5"), state)
    assert out["x87_st6"] == 0xBFFF8000000000000000  # -1.0
    assert out["x87_status_word"] & (C0 | C1 | C2 | C3) == C0


def test_fild_pushes_exact_integer():
    state = {"x87_status_word": 0, "x87_tag_word": _tags(),
             "eax": 0x200, "mem": _mem_bytes(0x200, (42).to_bytes(4, "little"))}
    out = _run(bytes.fromhex("db00"), state)
    # 42 = 1.3125 * 2^5 -> 0x4004A800000000000000
    assert out["x87_st7"] == 0x4004A800000000000000


def test_underflow_fault_masked_writes_indefinite():
    # FADD ST1 with ST1 empty (tag 3): masked -> IE|SF, dest = indefinite.
    state = {"x87_status_word": 6 << 11, "x87_control_word": CW,
             "x87_tag_word": _tags(3, 3, 3, 3, 3, 3, 0, 3),
             "x87_st6": ONE, "x87_st7": TWO}
    out = _run(bytes.fromhex("d8c1"), state)
    assert out["x87_status_word"] & 0x7F == 0x41
    assert out["x87_st6"] == INDEF


def test_underflow_fault_unmasked_refuses_write():
    cw = CW & ~1  # IM unmasked
    state = {"x87_status_word": 6 << 11,
             "x87_tag_word": _tags(3, 3, 3, 3, 3, 3, 0, 3),
             "x87_control_word": cw,
             "x87_st6": ONE, "x87_st7": TWO}
    out = _run(bytes.fromhex("d8c1"), state)
    assert out["x87_status_word"] & 0x7F == 0x41
    assert out["x87_status_word"] & 0x8080 == 0x8080  # ES|B
    assert out["x87_st6"] == ONE  # dest unchanged


def test_fscale_scales_st0_by_truncated_st1():
    # d9 fd: FSCALE.  ST0=3.0 (phys6, TOP=6), ST1=2.5 (phys7) -> 12.0.
    state = {"x87_status_word": 6 << 11, "x87_control_word": CW,
             "x87_tag_word": _tags(3, 3, 3, 3, 3, 3, 0, 0),
             "x87_st6": THREE, "x87_st7": 0x4000A000000000000000}
    out = _run(bytes.fromhex("d9fd"), state)
    assert out["x87_st6"] == 0x4002C000000000000000  # 12.0
    assert out["x87_status_word"] & 0x3F == 0


def test_fscale_underflow_fault_flags_only():
    # ST1 empty -> IE|SF, dest gets negative indefinite under mask.
    state = {"x87_status_word": 6 << 11, "x87_control_word": CW,
             "x87_tag_word": _tags(3, 3, 3, 3, 3, 3, 0, 3),
             "x87_st6": THREE}
    out = _run(bytes.fromhex("d9fd"), state)
    assert out["x87_status_word"] & 0x7F == 0x41
    assert out["x87_st6"] == INDEF


def test_unmasked_numeric_exception_suppresses_write():
    """host_unmasked_divide (host-unmasked-divide.json): FDIV ST0,ST1 with
    CW=0x037B (ZE unmasked), ST0=1, ST1=0.  Hardware leaves ST0=1 and reports
    SW=b084 at TOP6: B|ES|ZE, destination preserved."""
    state = {"x87_status_word": 6 << 11, "x87_control_word": 0x037B,
             "x87_tag_word": _tags(3, 3, 3, 3, 3, 3, 0, 0),
             "x87_st6": ONE, "x87_st7": 0}
    out = _run(bytes.fromhex("d8f1"), state)
    assert out["x87_st6"] == ONE  # unchanged — not the +inf masked response
    sw = out["x87_status_word"]
    assert sw & TOP == 6 << 11
    assert sw & 0x8084 == 0x8084  # B|ES|ZE


def test_masked_numeric_exception_writes_response():
    """Same divide with ZE masked (CW=0x037F): +inf written, ZE, no ES|B."""
    state = {"x87_status_word": 6 << 11, "x87_control_word": CW,
             "x87_tag_word": _tags(3, 3, 3, 3, 3, 3, 0, 0),
             "x87_st6": ONE, "x87_st7": 0}
    out = _run(bytes.fromhex("d8f1"), state)
    assert out["x87_st6"] == 0x7FFF8000000000000000
    sw = out["x87_status_word"]
    assert sw & 0x8084 == 0x0004  # ZE only


def test_unmasked_precision_suppresses_write():
    """Unmasked PE (CW bit5 clear) aborts an inexact result write."""
    state = {"x87_status_word": 6 << 11, "x87_control_word": CW & ~0x20,
             "x87_tag_word": _tags(3, 3, 3, 3, 3, 3, 0, 0),
             "x87_st6": THREE, "x87_st7": 0x4001C000000000000000}  # 3/6 = 0.5 exact
    out = _run(bytes.fromhex("d8f1"), state)  # FDIV ST0,ST1: 3/6 = 0.5 exact
    assert out["x87_st6"] == HALF  # exact -> no exception -> write proceeds
    # Now inexact: 1/3 at PC24
    state["x87_control_word"] = (CW & ~0x20 & ~0x0300)  # PC24, PE unmasked
    state["x87_st6"], state["x87_st7"] = ONE, THREE
    out = _run(bytes.fromhex("d8f1"), state)
    assert out["x87_st6"] == ONE  # inexact at PC24 -> unmasked PE -> preserved
    assert out["x87_status_word"] & 0x80A0 == 0x80A0  # ES|B|PE


def test_unmasked_exception_suppresses_pop():
    """FDIVP ST1,ST0 with ZE unmasked: no write and no pop."""
    state = {"x87_status_word": 6 << 11, "x87_control_word": 0x037B,
             "x87_tag_word": _tags(3, 3, 3, 3, 3, 3, 0, 0),
             "x87_st6": 0, "x87_st7": ONE}  # DE f9: ST1 <- ST1/ST0 = 1/0
    out = _run(bytes.fromhex("def9"), state)
    assert out["x87_st7"] == ONE
    assert out["x87_status_word"] & TOP == 6 << 11  # TOP unchanged
    assert out["x87_tag_word"] >> 12 & 3 == 0       # phys6 still tagged
    assert out["x87_status_word"] & 0x8084 == 0x8084


def test_unmasked_store_exception_suppresses_memory():
    """FSTP m32 with OE unmasked (CW=0x0377): no memory write, ES|B|OE."""
    huge = 0x7F7E8000000000000000  # ~2^16256, overflows float32
    state = {"x87_status_word": 7 << 11, "x87_control_word": 0x0377,
             "x87_tag_word": _tags(3, 3, 3, 3, 3, 3, 3, 0),
             "x87_st7": huge, "eax": 0x200,
             "mem": _mem_bytes(0x200, bytes.fromhex("efbeadde"))}
    out = _run(bytes.fromhex("d918"), state)
    memory = out["memory"]
    stored = z3.simplify(z3.Concat(*[
        z3.Select(memory, z3.BitVecVal(0x200 + i, 32)) for i in range(3, -1, -1)]))
    assert stored.as_long() == 0xDEADBEEF  # untouched
    assert out["x87_status_word"] & 0x8088 == 0x8088  # ES|B|OE
    assert out["x87_status_word"] & TOP == 7 << 11    # no pop


def test_fxtract_splits_exponent_and_significand():
    # d9 f4: FXTRACT. ST0=12.0 (phys7, TOP=7) -> ST0=1.5 pushed at phys6,
    # ST1=3.0 (exponent real).
    state = {"x87_status_word": 7 << 11, "x87_control_word": CW,
             "x87_tag_word": _tags(3, 3, 3, 3, 3, 3, 3, 0),
             "x87_st7": 0x4002C000000000000000}
    out = _run(bytes.fromhex("d9f4"), state)
    assert out["x87_st6"] == 0x3FFFC000000000000000  # significand 1.5 (new ST0)
    assert out["x87_st7"] == THREE                    # exponent 3.0
    assert out["x87_status_word"] & TOP == 6 << 11    # pushed


def test_fxtract_zero_gives_minus_inf_exponent():
    state = {"x87_status_word": 7 << 11, "x87_control_word": CW,
             "x87_tag_word": _tags(3, 3, 3, 3, 3, 3, 3, 0),
             "x87_st7": 0}
    out = _run(bytes.fromhex("d9f4"), state)
    assert out["x87_st6"] == 0                        # +0 significand
    assert out["x87_st7"] == 0xFFFF8000000000000000   # -inf exponent
    assert out["x87_status_word"] & 0x04              # ZE


def test_fld_m32_unmasked_de_still_pushes():
    """Bochs FLD_SINGLE_REAL: only unmasked *Invalid* suppresses the push;
    unmasked DE still completes it (flags+ES|B recorded)."""
    state = {"x87_status_word": 0, "x87_control_word": CW & ~0x02,
             "x87_tag_word": _tags(),
             "eax": 0x200, "mem": _mem_bytes(0x200, bytes.fromhex("01000000"))}
    out = _run(bytes.fromhex("d900"), state)  # fld m32 [eax], denormal f32
    assert out["x87_status_word"] & TOP == 7 << 11          # push happened
    assert out["x87_st7"] == 0x3F6A8000000000000000         # 2^-149 widened
    assert out["x87_status_word"] & 0x8082 == 0x8082        # ES|B|DE


def test_fld_m32_unmasked_snan_suppresses_push():
    """Same load but SNaN input with IM unmasked: no push."""
    state = {"x87_status_word": 0, "x87_control_word": CW & ~0x01,
             "x87_tag_word": _tags(),
             "eax": 0x200, "mem": _mem_bytes(0x200, bytes.fromhex("0000a07f"))}
    out = _run(bytes.fromhex("d900"), state)  # 0x7FA00000 = f32 SNaN
    assert out["x87_status_word"] & TOP == 0                # no push
    assert out["x87_status_word"] & 0x8081 == 0x8081        # ES|B|IE


_ENV_DWORDS = [0x0000027F, 0x00000200, 0x00005555, 0x0000ABCD,
               0x001B00DE, 0x00007777, 0x00000044]


def _env_mem(base: int = 0x200) -> dict[int, int]:
    """Little-endian bytes for the seven 32-bit env dwords plus ST regs."""
    mem: dict[int, int] = {}
    for index, dword in enumerate(_ENV_DWORDS):
        mem.update(_mem_bytes(base + 4 * index,
                              dword.to_bytes(4, "little")))
    # ST0 = 2.0 ext80 at base+28.
    mem.update(_mem_bytes(base + 28, TWO.to_bytes(10, "little")))
    return mem


def test_decode_admits_env_forms():
    # Independent Capstone audit (parent-env-opcode-audit.json):
    # /4 loads the environment, /6 stores it.
    assert isinstance(decode_native_x87(bytes.fromhex("d920")), EnvLoad)   # fldenv
    assert isinstance(decode_native_x87(bytes.fromhex("d930")), EnvStore)  # fnstenv
    assert isinstance(decode_native_x87(bytes.fromhex("dd20")), EnvLoad)   # frstor
    assert isinstance(decode_native_x87(bytes.fromhex("dd30")), EnvStore)  # fnsave


def _mem_dword(out: dict[str, object], addr: int) -> int:
    memory = out["memory"]
    if z3.is_array(memory):
        got = z3.simplify(z3.Concat(*[z3.Select(
            memory, z3.BitVecVal(addr + i, 32)) for i in (3, 2, 1, 0)]))
        return got.as_long()
    return memory


def test_fnstenv_stores_protected_layout():
    """FNSTENV d9 /6: seven dwords [CW,SW,TW,FIP,FCS|op,FDP,FDS]; the
    reserved upper 16 bits of the word slots store 0xFFFF (host probe
    host_x87_env.c), and CW gains all exception masks afterwards."""
    state = {"x87_status_word": 0x3800, "x87_control_word": 0x0370,
             "x87_tag_word": 0xFF00, "x87_fip": 0x1234,
             "x87_fcs_op": 0x00D8001B, "x87_fdp": 0x5000, "x87_fds": 0x22,
             "eax": 0x200, "ds": 0x23}
    out = _run(bytes.fromhex("d930"), state)
    for index, expected in enumerate(
            (0xFFFF0370, 0xFFFF3800, 0xFFFFFF00, 0x1234, 0x00D8001B,
             0x5000, 0xFFFF0022)):
        assert _mem_dword(out, 0x200 + 4 * index) == expected
    # Host: fnstenv masks all six FP exceptions, no other CW change.
    assert out["x87_control_word"] == 0x037F
    # ...and nothing else in the unit is reset.
    assert out["x87_status_word"] == 0x3800
    assert out["x87_tag_word"] == 0xFF00


def test_fldenv_loads_words_and_pointers():
    """FLDENV d9 /4 loads CW/SW/TW truncated to 16 bits and dword pointers;
    ES|B recomputed from loaded flags & loaded CW (CW masks everything)."""
    state = {"x87_status_word": 0, "x87_control_word": CW,
             "x87_tag_word": _tags(), "eax": 0x200, "mem": _env_mem()}
    out = _run(bytes.fromhex("d920"), state)
    assert out["x87_control_word"] == 0x027F
    assert out["x87_status_word"] == 0x0200    # flags all masked -> ES=B=0
    assert out["x87_tag_word"] == 0x5555
    assert out["x87_fip"] == 0xABCD
    assert out["x87_fcs_op"] == 0x1B00DE
    assert out["x87_fdp"] == 0x7777
    assert out["x87_fds"] == 0x44


def test_fnsave_stores_then_resets():
    """FNSAVE dd /6: env + eight phys regs stored, then FINIT state."""
    state = {"x87_status_word": 0x3800, "x87_control_word": 0x037F,
             "x87_tag_word": 0xFF00, "x87_fip": 0x1234,
             "x87_fcs_op": 0x00D8001B, "x87_fdp": 0x5000, "x87_fds": 0x22,
             "x87_st0": TWO, "eax": 0x200}
    out = _run(bytes.fromhex("dd30"), state)
    assert _mem_dword(out, 0x200) == 0xFFFF037F
    assert out["x87_control_word"] == 0x037F
    assert out["x87_status_word"] == 0
    assert out["x87_tag_word"] == 0xFFFF
    for name in ("x87_fip", "x87_fcs_op", "x87_fdp", "x87_fds"):
        assert out[name] == 0


def test_frstor_loads_env_and_registers():
    """FRSTOR dd /4 loads the env dwords and the eight physical ST regs."""
    state = {"x87_status_word": 0, "x87_control_word": CW,
             "x87_tag_word": _tags(), "eax": 0x200, "mem": _env_mem()}
    out = _run(bytes.fromhex("dd20"), state)
    assert out["x87_control_word"] == 0x027F
    # FRSTOR recomputes tags: stored pair 01 (nonempty) -> tagof(loaded
    # value): phys0 = 2.0 -> 0 (valid); phys1-7 load +0.0 -> 1 (zero).
    assert out["x87_tag_word"] == 0x5554
    assert out["x87_st0"] == TWO


# Lazy EFLAGS inputs: cc_op=0 is the VEX COPY interpretation (dep1 carries
# literal CF/PF/ZF bits); cc_op=1 would be the 8-bit ADD group.
COPY_FLAGS = {"cc_op": 0, "cc_dep1": 0, "cc_dep2": 0, "cc_ndep": 0}


def test_decode_admits_comi_and_fcmov():
    assert isinstance(decode_native_x87(bytes.fromhex("dbf0")), Comi)   # fcomi
    assert isinstance(decode_native_x87(bytes.fromhex("dbe8")), Comi)   # fucomi
    assert isinstance(decode_native_x87(bytes.fromhex("dff0")), Comi)   # fcomip
    assert isinstance(decode_native_x87(bytes.fromhex("dfe8")), Comi)   # fucomip
    assert isinstance(decode_native_x87(bytes.fromhex("dac0")), FCmov)  # fcmovb
    assert isinstance(decode_native_x87(bytes.fromhex("dbd8")), FCmov)  # fcmovnu


def _lazy_flags(out):
    return (out["cc_op"], out["cc_dep1"] & 0x45)


def test_fcomi_less_sets_cf_through_copy():
    state = {**TWO_STACK, "x87_control_word": CW, **COPY_FLAGS,
             "cc_dep1": 0xDEAD}
    out = _run(bytes.fromhex("dbf1"), state)
    assert _lazy_flags(out) == (0, 0x01)          # CF only
    assert out["x87_status_word"] & TOP == 6 << 11


def test_fcomi_equal_sets_zf():
    state = {**TWO_STACK, "x87_control_word": CW, **COPY_FLAGS,
             "x87_st6": TWO}
    out = _run(bytes.fromhex("dbf1"), state)
    assert _lazy_flags(out) == (0, 0x40)          # ZF only


def test_fucomi_unordered_masks_invalid_all_ones():
    state = {**TWO_STACK, "x87_control_word": CW, **COPY_FLAGS,
             "x87_st6": 0x7FFF8000000000000001}   # SNaN in ST0
    out = _run(bytes.fromhex("dbe9"), state)
    assert _lazy_flags(out) == (0, 0x45)          # ZF|PF|CF unordered
    assert out["x87_status_word"] & 0x01          # IE recorded in SW


def test_fucomip_pops_and_sets_flags():
    state = {**TWO_STACK, "x87_control_word": CW, **COPY_FLAGS}
    out = _run(bytes.fromhex("dfe9"), state)
    assert _lazy_flags(out) == (0, 0x01)
    assert out["x87_status_word"] & TOP == 7 << 11    # popped


def test_fcmovb_moves_only_when_cf_set():
    state = {**TWO_STACK, "x87_control_word": CW, **COPY_FLAGS,
             "cc_dep1": 1}
    out = _run(bytes.fromhex("dac1"), state)
    assert out["x87_st6"] == TWO                  # ST1 copied over ST0
    state["cc_dep1"] = 0
    out = _run(bytes.fromhex("dac1"), state)
    assert out["x87_st6"] == ONE                  # condition false: no move


def test_fcmov_masked_stack_fault_moves_indefinite():
    """Empty source + masked IM: move proceeds with QNaN indefinite."""
    state = {"x87_status_word": 6 << 11, "x87_control_word": CW,
             "x87_tag_word": _tags(0, 0, 0, 0, 0, 0, 0, 3),  # phys7 empty
             "x87_st6": ONE, "cc_op": 0, "cc_dep1": 1,
             "cc_dep2": 0, "cc_ndep": 0}
    out = _run(bytes.fromhex("dac1"), state)      # fcmovb st(1)=phys7
    assert out["x87_st6"] == INDEF
    assert out["x87_status_word"] & 0x41 == 0x41  # IE|SF


def _ext80(value: float) -> int:
    """Minimal ext80 encoder for finite test constants."""
    import math
    if value == 0:
        return 0
    sign = 1 if value < 0 else 0
    mant, exp = math.frexp(abs(value))       # value = mant * 2^exp, .5<=mant<1
    return (sign << 79) | ((0x3FFF + exp - 1) << 64) | int(mant * (1 << 64))


def test_decode_admits_bcd_forms():
    i = decode_native_x87(bytes.fromhex("df20"))
    assert isinstance(i, BcdMem) and i.kind == "bld"
    i = decode_native_x87(bytes.fromhex("df30"))
    assert isinstance(i, BcdMem) and i.kind == "bstp"


def test_fbld_pushes_bcd_integer():
    """FBLD df /4: packed bytes 56 34 12 -> 123456.0 pushed."""
    mem = _mem_bytes(0x200, bytes([0x56, 0x34, 0x12] + [0] * 7))
    state = {"x87_status_word": 0, "x87_control_word": CW,
             "x87_tag_word": _tags(), "eax": 0x200, "mem": mem}
    out = _run(bytes.fromhex("df20"), state)
    assert out["x87_st7"] == _ext80(123456.0)
    assert out["x87_status_word"] & TOP == 7 << 11


def test_fbld_sign_byte_negates():
    mem = _mem_bytes(0x200, bytes([0x56, 0x34, 0x12] + [0] * 6 + [0x80]))
    state = {"x87_status_word": 0, "x87_control_word": CW,
             "x87_tag_word": _tags(), "eax": 0x200, "mem": mem}
    out = _run(bytes.fromhex("df20"), state)
    assert out["x87_st7"] == _ext80(-123456.0)


def test_fbstp_roundtrips_decimal():
    """FBSTP df /6: 123456.0 -> bytes 56 34 12, pops."""
    state = {"x87_status_word": 0, "x87_control_word": CW,
             "x87_tag_word": _tags(0), "x87_st0": _ext80(123456.0),
             "eax": 0x200}
    out = _run(bytes.fromhex("df30"), state)
    memory = out["memory"]
    got = [z3.simplify(z3.Select(memory, z3.BitVecVal(0x200 + i, 32))).as_long()
           for i in range(10)]
    assert got == [0x56, 0x34, 0x12, 0, 0, 0, 0, 0, 0, 0]
    assert out["x87_status_word"] & TOP == 1 << 11      # popped


def test_fbstp_negative_half_ties_even_with_pe():
    """-123456.5 under RNE -> 123456 (ties even), sign byte 0x80, PE set."""
    state = {"x87_status_word": 0, "x87_control_word": CW,
             "x87_tag_word": _tags(0), "x87_st0": _ext80(-123456.5),
             "eax": 0x200}
    out = _run(bytes.fromhex("df30"), state)
    memory = out["memory"]
    got = [z3.simplify(z3.Select(memory, z3.BitVecVal(0x200 + i, 32))).as_long()
           for i in range(10)]
    assert got[0] == 0x56 and got[9] == 0x80
    assert out["x87_status_word"] & 0x20              # PE


def test_fbstp_nan_stores_indefinite_masked():
    state = {"x87_status_word": 0, "x87_control_word": CW,
             "x87_tag_word": _tags(0),
             "x87_st0": 0xFFFFC000000000000000, "eax": 0x200}
    out = _run(bytes.fromhex("df30"), state)
    memory = out["memory"]
    got = [z3.simplify(z3.Select(memory, z3.BitVecVal(0x200 + i, 32))).as_long()
           for i in range(10)]
    # Pinned Bochs FBSTP: indefinite image = FFFF C000000000000000 (hi word
    # 0xFFFF, low qword 0xC0..), not all-FF.
    assert got == [0, 0, 0, 0, 0, 0, 0, 0xC0, 0xFF, 0xFF]
    assert out["x87_status_word"] & 0x01              # IE


def test_fnsave_fstor_logical_order_nonzero_top():
    """Bochs: register image slots are logical ST(n), not physical R(n).

    TOP=3, phys3=ST0=10.0, phys4=ST1=20.0: FNSAVE slot0=ST0, slot1=ST1;
    an FRSTOR image with stored SW TOP=5 puts slot n into phys (5+n)&7.
    """
    state = {"x87_status_word": 3 << 11, "x87_control_word": CW,
             "x87_tag_word": _tags(3, 3, 3, 0, 0, 3, 3, 3),
             "x87_st3": _ext80(10.0), "x87_st4": _ext80(20.0),
             "x87_fip": 0xAA, "x87_fcs_op": 0, "x87_fdp": 0xBB,
             "x87_fds": 0, "eax": 0x200}
    out = _run(bytes.fromhex("dd30"), state)   # fnsave [eax]
    memory = out["memory"]
    for slot in range(2):
        got = z3.simplify(z3.Concat(*[z3.Select(
            memory, z3.BitVecVal(0x200 + 28 + 10 * slot + i, 32))
            for i in reversed(range(10))])).as_long()
        assert got == _ext80(10.0 + 10 * slot)   # slot0=ST0=10, slot1=ST1=20
    # FRSTOR: stored env TOP=5, slot0=3.0 lands at phys5 (new ST0), slot1 at phys6.
    dwords = [0x0000037F, 0x00002800, 0x00000000, 0x0000F1F1,
              0x00D90011, 0x0000F2F2, 0x0000F3F3]
    mem: dict[int, int] = {}
    for i, dword in enumerate(dwords):
        mem.update(_mem_bytes(0x200 + 4 * i, dword.to_bytes(4, "little")))
    mem.update(_mem_bytes(0x200 + 28, _ext80(3.0).to_bytes(10, "little")))
    mem.update(_mem_bytes(0x200 + 38, _ext80(4.0).to_bytes(10, "little")))
    state = {"x87_status_word": 0, "x87_control_word": CW,
             "x87_tag_word": _tags(), "eax": 0x200, "mem": mem}
    out = _run(bytes.fromhex("dd20"), state)    # frstor [eax]
    assert out["x87_st5"] == _ext80(3.0)          # logical slot0 -> phys5
    assert out["x87_st6"] == _ext80(4.0)
    assert out["x87_status_word"] & TOP == 5 << 11
    # tag recompute: stored tag phys5 empty(3) keeps empty; phys6 0 -> tagof.
    # stored tw = 0: all pairs "valid" -> tags recompute from values.
    assert (out["x87_tag_word"] >> 10) & 3 == 0   # phys5 tag = valid


class TestFCMovHardwareMatrix:
    """FCMOVcc against host probed exception completion.

    Host evidence (parent host_fcmov_empty.c): FNINIT;FLD1;CLC;FCMOVB
    ST0,ST1 leaves SW=0x3841 and ST0=indefinite although CF=0 — the operand
    fetch precedes the condition, so an empty source stack-faults and the
    masked response writes the indefinite regardless of the move outcome.
    """

    # TOP=7: ST0 = phys7 = 1.0, phys0..6 empty.
    _BASE: ClassVar[dict[str, object]] = {"x87_status_word": 0x3800, "x87_control_word": CW,
             "x87_tag_word": _tags(3, 3, 3, 3, 3, 3, 3, 0),
             "x87_st7": ONE, "cc_op": 0, "cc_dep2": 0, "cc_ndep": 0}

    def test_host_counterexample_untaken_empty_source(self):
        out = _run(bytes.fromhex("dac1"), dict(self._BASE, cc_dep1=0))
        assert out["x87_st7"] == INDEF
        assert out["x87_status_word"] == 0x3841    # TOP7 | IE | SF

    def test_taken_empty_source_same_response(self):
        out = _run(bytes.fromhex("dac1"), dict(self._BASE, cc_dep1=1))
        assert out["x87_st7"] == INDEF
        assert out["x87_status_word"] == 0x3841

    def test_unmasked_suppresses_write_and_pop(self):
        state = dict(self._BASE, cc_dep1=0, x87_control_word=CW & ~1)
        out = _run(bytes.fromhex("dac1"), state)
        assert out["x87_st7"] == ONE               # write suppressed
        assert out["x87_status_word"] == 0xB8C1    # B|ES|TOP7|SF|IE

    def test_valid_source_taken_and_untaken(self):
        state = dict(self._BASE, x87_tag_word=_tags(0, 3, 3, 3, 3, 3, 3, 0),
                     x87_st0=TWO, cc_dep1=1)
        assert _run(bytes.fromhex("dac1"), state)["x87_st7"] == TWO
        state["cc_dep1"] = 0
        assert _run(bytes.fromhex("dac1"), state)["x87_st7"] == ONE

    @pytest.mark.parametrize("raw,dep1,moves", [
        ("dac1", 0x01, True), ("dac1", 0x00, False),    # B  = CF
        ("dac9", 0x40, True), ("dac9", 0x00, False),    # E  = ZF
        ("dad1", 0x41, True), ("dad1", 0x00, False),    # BE = CF|ZF
        ("dad9", 0x04, True), ("dad9", 0x00, False),    # U  = PF
        ("dbc1", 0x00, True), ("dbc1", 0x01, False),    # NB = !CF
        ("dbc9", 0x00, True), ("dbc9", 0x40, False),    # NE = !ZF
        ("dbd1", 0x00, True), ("dbd1", 0x41, False),    # NBE= !(CF|ZF)
        ("dbd9", 0x00, True), ("dbd9", 0x04, False),    # NU = !PF
    ])
    def test_all_eight_conditions(self, raw, dep1, moves):
        state = dict(self._BASE, x87_tag_word=_tags(0, 3, 3, 3, 3, 3, 3, 0),
                     x87_st0=TWO, cc_dep1=dep1)
        out = _run(bytes.fromhex(raw), state)
        assert out["x87_st7"] == (TWO if moves else ONE)
        assert out["x87_status_word"] == 0x3800


def test_fcmov_symbolic_cc_op_stays_typed_unknown():
    """Symbolic lazy-flag producer: condition must not fold to a constant."""
    instruction = decode_native_x87(bytes.fromhex("dac1"))
    body = native_x87_body(instruction, continuation=0x1000,
                           registers=REGS, address=0x800)
    import json
    text = json.dumps(body["assignments"])
    assert "summary_x86g_calculate_condition" in text


class TestFisttp:
    """FISTTP m16/m32/m64: truncate toward zero, always pop, SSE3 opcode."""

    def test_fisttp_m64_truncates_positive(self):
        state = {"x87_status_word": 0, "x87_control_word": CW,
                 "x87_tag_word": _tags(0), "x87_st0": _ext80(3.9),
                 "eax": 0x200}
        out = _run(bytes.fromhex("dd08"), state)
        memory = out["memory"]
        got = [z3.simplify(z3.Select(memory, z3.BitVecVal(0x200 + i, 32))).as_long()
               for i in range(8)]
        assert int.from_bytes(bytes(got), "little", signed=True) == 3
        assert out["x87_status_word"] & TOP == 1 << 11     # popped

    def test_fisttp_m64_truncates_negative(self):
        state = {"x87_status_word": 0, "x87_control_word": CW,
                 "x87_tag_word": _tags(0), "x87_st0": _ext80(-3.9),
                 "eax": 0x200}
        out = _run(bytes.fromhex("dd08"), state)
        memory = out["memory"]
        got = [z3.simplify(z3.Select(memory, z3.BitVecVal(0x200 + i, 32))).as_long()
               for i in range(8)]
        assert int.from_bytes(bytes(got), "little", signed=True) == -3

    def test_fisttp_m32_ignores_rc_field(self):
        # CW.RC = round-up (0x0800): FISTTP still truncates.
        state = {"x87_status_word": 0, "x87_control_word": CW | 0x0800,
                 "x87_tag_word": _tags(0), "x87_st0": _ext80(3.2),
                 "eax": 0x200}
        out = _run(bytes.fromhex("db08"), state)
        memory = out["memory"]
        got = [z3.simplify(z3.Select(memory, z3.BitVecVal(0x200 + i, 32))).as_long()
               for i in range(4)]
        assert int.from_bytes(bytes(got), "little", signed=True) == 3

    def test_fisttp_m16(self):
        state = {"x87_status_word": 0, "x87_control_word": CW,
                 "x87_tag_word": _tags(0), "x87_st0": _ext80(-1.7),
                 "eax": 0x200}
        out = _run(bytes.fromhex("df08"), state)
        memory = out["memory"]
        got = [z3.simplify(z3.Select(memory, z3.BitVecVal(0x200 + i, 32))).as_long()
               for i in range(2)]
        assert int.from_bytes(bytes(got), "little", signed=True) == -1


class TestTranscendentals:
    """Typed-UF transcendental effects: stack/flags/C2 are architectural."""

    _BASE: ClassVar[dict[str, object]] = {"x87_status_word": 0, "x87_control_word": CW,
             "x87_tag_word": _tags(0, 0), "x87_st0": ONE, "x87_st1": TWO}

    def test_yl2x_zero_divide_zero(self):
        out = _run(bytes.fromhex("d9f1"), dict(self._BASE, x87_st0=0))
        assert out["x87_st1"] == 0xFFFF8000000000000000   # 2*log2(0) = -inf
        assert out["x87_status_word"] == (1 << 11) | 0x04  # pop + ZE

    def test_yl2x_negative_invalid(self):
        out = _run(bytes.fromhex("d9f1"),
                   dict(self._BASE, x87_st0=0xBFFF8000000000000000))
        assert out["x87_st1"] == INDEF
        assert out["x87_status_word"] == (1 << 11) | 0x01  # pop + IE

    def test_yl2xp1_minus_one_returns_operand_with_pe(self):
        # Pinned bochs-ref/fyl2x.cc: negative x with |x|>=1 returns the
        # operand unchanged after raising inexact (documented hardware
        # behaviour for the undefined domain), NOT the -inf boundary.
        out = _run(bytes.fromhex("d9f9"),
                   dict(self._BASE, x87_st0=0xBFFF8000000000000000))
        assert out["x87_st1"] == 0xBFFF8000000000000000
        assert out["x87_status_word"] == (1 << 11) | 0x20

    def test_yl2xp1_below_minus_one_returns_operand_with_pe(self):
        out = _run(bytes.fromhex("d9f9"),
                   dict(self._BASE, x87_st0=0xC0008000000000000000))
        assert out["x87_st1"] == 0xC0008000000000000000
        assert out["x87_status_word"] == (1 << 11) | 0x20

    def test_fsin_out_of_range_keeps_source_sets_c2(self):
        huge = 0x4A4A8000000000000000    # |x| >= 2**63, finite
        out = _run(bytes.fromhex("d9fe"), dict(self._BASE, x87_st0=huge))
        assert out["x87_st0"] == huge
        assert out["x87_status_word"] == 0x0400            # C2 only

    def test_fsin_infinite_masked_invalid(self):
        out = _run(bytes.fromhex("d9fe"),
                   dict(self._BASE, x87_st0=0x7FFF8000000000000000))
        assert out["x87_st0"] == INDEF
        assert out["x87_status_word"] == 0x0401            # C2|IE masked

    def test_sincos_writes_sin_pushes_cos(self):
        # Pinned Bochs fpu_trans.cc FSINCOS: ST(0)<-sin, push cos.
        state = dict(self._BASE, x87_st0=0x3FFE8000000000000000,
                     x87_tag_word=_tags(0, 3))
        out = _run(bytes.fromhex("d9fb"), state)
        assert str(z3.simplify(out["x87_st0"])).startswith("x87_trans_sin")
        assert str(z3.simplify(out["x87_st7"])).startswith("x87_trans_cos")
        assert out["x87_status_word"] & TOP == 7 << 11

    def test_sincos_masked_push_overflow_double_indefinite(self):
        # Bochs: any masked stack fault writes INDEF to ST(0) and pushes
        # another; overflow additionally sets C1.
        state = dict(self._BASE, x87_tag_word=_tags(*([0] * 8)))
        out = _run(bytes.fromhex("d9fb"), state)
        assert out["x87_st0"] == INDEF
        assert out["x87_st7"] == INDEF
        assert out["x87_status_word"] == (7 << 11) | 0x41 | 0x200

    def test_xtract_masked_push_overflow_double_indefinite(self):
        # Pinned Bochs FXTRACT: masked push overflow -> INDEF in both slots,
        # NOT the computed exponent in ST(0).
        state = dict(self._BASE, x87_tag_word=_tags(*([0] * 8)),
                     x87_st0=0x4002C000000000000000)
        out = _run(bytes.fromhex("d9f4"), state)
        assert out["x87_st0"] == INDEF
        assert out["x87_st7"] == INDEF
        assert out["x87_status_word"] == (7 << 11) | 0x41 | 0x200

    def test_fptan_masked_push_overflow_double_indefinite_host(self):
        # Parent host_x87_push_faults matrix: on a full masked stack the
        # hardware response is indefinite in BOTH slots, TW=0x8002.
        # (Pinned Bochs pushes Const_1 -- a documented divergence; the
        # model follows hardware.)
        state = dict(self._BASE, x87_tag_word=_tags(*([0] * 8)),
                     x87_st0=0x3FFE8000000000000000)
        out = _run(bytes.fromhex("d9f2"), state)
        assert out["x87_st0"] == INDEF
        assert out["x87_st7"] == INDEF
        assert out["x87_tag_word"] == 0x8002
        assert out["x87_status_word"] == (7 << 11) | 0x41 | 0x200

    def test_fptan_masked_underflow_double_indefinite_host(self):
        # Host evidence: empty stack masked underflow writes INDEF to
        # ST(0) (tag special) and pushes INDEF; TW=0xBFFE, no C1.
        state = dict(self._BASE, x87_tag_word=_tags())
        out = _run(bytes.fromhex("d9f2"), state)
        assert out["x87_st0"] == INDEF
        assert out["x87_st7"] == INDEF
        assert out["x87_tag_word"] == 0xBFFE
        assert out["x87_status_word"] == (7 << 11) | 0x41

    def test_fptan_masked_combined_underflow_overflow_host(self):
        # Full stack with empty ST(0): both faults; underflow takes
        # precedence (IE|SF, no C1), masked response still double-INDEF.
        state = dict(self._BASE,
                     x87_tag_word=_tags(3, 0, 0, 0, 0, 0, 0, 0))
        out = _run(bytes.fromhex("d9f2"), state)
        assert out["x87_st0"] == INDEF
        assert out["x87_st7"] == INDEF
        assert out["x87_tag_word"] == 0x8002
        assert out["x87_status_word"] == (7 << 11) | 0x41

    def test_fptan_unmasked_overflow_suppresses_writes(self):
        # IM unmasked: exception state recorded, no writes, no push.
        state = dict(self._BASE, x87_tag_word=_tags(*([0] * 8)),
                     x87_control_word=0x037E,
                     x87_st0=0x3FFE8000000000000000)
        out = _run(bytes.fromhex("d9f2"), state)
        assert out["x87_st0"] == 0x3FFE8000000000000000
        assert out["x87_tag_word"] == 0
        assert out["x87_status_word"] == 0x8000 | 0x80 | 0x40 | 0x01 | 0x200

    def test_fptan_pushes_one(self):
        state = dict(self._BASE, x87_st0=0x3FFE8000000000000000,
                     x87_tag_word=_tags(0, 3))
        out = _run(bytes.fromhex("d9f2"), state)
        assert out["x87_st7"] == 0x3FFF8000000000000000    # pushed 1.0

    def test_transcendental_premise_declared(self):
        instruction = decode_native_x87(bytes.fromhex("d9fe"))
        body = native_x87_body(instruction, continuation=0x1000,
                               registers=REGS, address=0x800)
        assert any("uninterpreted" in p.get("effect", "")
                   for p in body["summary"]["premises"])


class TestWaitingForms:
    """9B forms: waiting variants execute as their FN sibling plus the
    pending-exception obligation; a checking op after 9B is refused."""

    def test_fwait_identity_with_obligation(self):
        out = _run(bytes.fromhex("9b"),
                   {"x87_status_word": 0x3800, "x87_control_word": CW})
        assert out["x87_status_word"] == 0x3800
        assert out["x87_control_word"] == CW

    def test_waiting_forms_decode(self):
        assert decode_native_x87(b"\x9b") is not None
        assert decode_native_x87(bytes.fromhex("9bdbe2")) is not None
        assert decode_native_x87(bytes.fromhex("9bdbe3")) is not None
        assert decode_native_x87(bytes.fromhex("9bdd30")) is not None
        assert decode_native_x87(bytes.fromhex("9bd930")) is not None
        # 9B followed by a checking instruction is two instructions.
        assert decode_native_x87(bytes.fromhex("9bd9d0")) is None
        assert decode_native_x87(bytes.fromhex("9bd8c0")) is None

    def test_finit_waiting_effects_and_obligation(self):
        instruction = decode_native_x87(bytes.fromhex("9bdbe3"))
        body = native_x87_body(instruction, continuation=0x1000,
                               registers=REGS, address=0x800)
        assert body["summary"]["kind"].startswith("native_wait_")
        assert body["obligations"]


class TestPendingMfControlFlow:
    """Pending unmasked #MF suppresses a checking instruction's effects.

    Hardware semantics: the instruction delivers #MF before executing, so
    registers/tags/TOP/env/memory are all preserved.  Non-checking FN*
    forms still run.  Models the observable state effect; trap delivery
    itself stays with the typed obligation/verdict owners.
    """

    _PENDING: ClassVar[dict[str, object]] = {
        "x87_status_word": 0x04,             # ZE set, TOP=0
        "x87_control_word": 0x037B,          # ZE unmasked -> pending #MF
        "x87_tag_word": _tags(0, 0),
        "x87_st0": 0x3FFF8000000000000000,
        "x87_st1": 0x3FFF8000000000000000,
    }

    def test_pending_suppresses_register_arith(self):
        out = _run(bytes.fromhex("d8c1"), dict(self._PENDING))  # FADD st0,st1
        assert out["x87_st0"] == 0x3FFF8000000000000000
        assert out["x87_status_word"] == self._PENDING["x87_status_word"]
        assert out["x87_tag_word"] == self._PENDING["x87_tag_word"]

    def test_pending_suppresses_push_pop_and_tags(self):
        out = _run(bytes.fromhex("d9e8"), dict(self._PENDING))  # FLD1
        assert out["x87_status_word"] == self._PENDING["x87_status_word"]
        assert out["x87_tag_word"] == self._PENDING["x87_tag_word"]
        out = _run(bytes.fromhex("ded9"), dict(self._PENDING))  # FCOMPP
        assert out["x87_status_word"] == self._PENDING["x87_status_word"]

    def test_pending_suppresses_memory_store(self):
        state = dict(self._PENDING, eax=0x2000, ebp=0x3000, esi=0x4000)
        suppressed = _run(bytes.fromhex("d910"), state)
        executed = _run(bytes.fromhex("d910"), dict(state,
                                                  x87_control_word=0x037F))
        # FST m32 [eax] of 1.0 would write byte 0x3F at eax+3.
        sup = z3.simplify(z3.Select(suppressed["memory"],
                                    z3.BitVecVal(0x2003, 32)))
        exe = z3.simplify(z3.Select(executed["memory"],
                                    z3.BitVecVal(0x2003, 32)))
        assert sup.as_long() == 0x00  # input memory preserved
        assert exe.as_long() == 0x3F

    def test_masked_pending_executes_normally(self):
        state = dict(self._PENDING, x87_control_word=0x037F)  # ZE masked
        out = _run(bytes.fromhex("d8c1"), state)
        assert out["x87_st0"] == 0x40008000000000000000  # 1.0 + 1.0

    def test_nonchecking_fnclex_runs_under_pending(self):
        out = _run(bytes.fromhex("dbe2"), dict(self._PENDING))
        assert out["x87_status_word"] & 0x3F == 0  # exception bits cleared

    def test_waiting_form_suppressed_under_pending(self):
        # 9B+FNSAVE is a checking waiting form: pending #MF suppresses
        # the inner FNSAVE effects too.
        state = dict(self._PENDING, eax=0x2000, ebp=0x3000, esi=0x4000)
        out = _run(bytes.fromhex("9bdd30"), state)
        assert out["x87_control_word"] == 0x037B  # FINIT reset suppressed
        assert out["x87_status_word"] == self._PENDING["x87_status_word"]

    def test_nonchecking_fnstenv_stores_under_pending(self):
        # Host-verified: FNSTENV runs even with an unmasked pending ZE
        # (host_x87_env.c probe) — it is architecturally nonchecking.
        state = dict(self._PENDING, eax=0x2000)
        out = _run(bytes.fromhex("d930"), state)   # fnstenv [eax]
        assert _mem_dword(out, 0x2000) == 0xFFFF0000 | self._PENDING[
            "x87_control_word"]
        # ...and it still masks all exceptions afterwards.
        assert out["x87_control_word"] == self._PENDING[
            "x87_control_word"] | 0x3F

    def test_nonchecking_fnsave_resets_under_pending(self):
        state = dict(self._PENDING, eax=0x2000)
        out = _run(bytes.fromhex("dd30"), state)   # fnsave [eax]
        assert _mem_dword(out, 0x2000) == 0xFFFF0000 | self._PENDING[
            "x87_control_word"]
        assert out["x87_control_word"] == 0x037F
        assert out["x87_status_word"] == 0
        assert out["x87_tag_word"] == 0xFFFF

    def test_checking_fldenv_suppressed_under_pending(self):
        state = dict(self._PENDING, eax=0x200, mem=_env_mem())
        out = _run(bytes.fromhex("d920"), state)   # fldenv [eax]
        assert out["x87_control_word"] == self._PENDING["x87_control_word"]
        assert out["x87_status_word"] == self._PENDING["x87_status_word"]
        assert out["x87_tag_word"] == self._PENDING["x87_tag_word"]

    def test_checking_frstor_suppressed_under_pending(self):
        state = dict(self._PENDING, eax=0x200, mem=_env_mem())
        out = _run(bytes.fromhex("dd20"), state)   # frstor [eax]
        assert out["x87_control_word"] == self._PENDING["x87_control_word"]
        assert out["x87_tag_word"] == self._PENDING["x87_tag_word"]

    def test_waiting_env_load_refused(self):
        # 9B in front of a checking instruction is FWAIT + that op —
        # two instructions, refused by the single-instruction decoder.
        assert decode_native_x87(bytes.fromhex("9bd920")) is None
        assert decode_native_x87(bytes.fromhex("9bdd20")) is None


    def test_ebp_based_operand_records_ss_in_fds(self):
        # 32-bit ModRM: EBP/ESP-based operands default to SS, so FDS
        # records the ss input rather than ds.
        state = {"x87_status_word": 0x3800, "x87_control_word": CW,
                 "x87_tag_word": _tags(), "ebp": 0x200, "ss": 0x55,
                 "ds": 0x77,
                 "mem": _mem_bytes(0x200, (0x3F800000).to_bytes(4, "little"))}
        out = _run(bytes.fromhex("d94500"), state)   # fld dword [ebp]
        assert out["x87_fds"] == 0x55
        state2 = dict(state, eax=0x200)
        state2.pop("ebp")
        out2 = _run(bytes.fromhex("d900"), state2)   # fld dword [eax]
        assert out2["x87_fds"] == 0x77

    def test_env_load_does_not_write_store_does_not_read(self):
        # FLDENV leaves the destination buffer untouched...
        state = {"x87_status_word": 0, "x87_control_word": CW,
                 "x87_tag_word": _tags(), "eax": 0x200, "mem": _env_mem()}
        out = _run(bytes.fromhex("d920"), state)
        for index, dword in enumerate(_ENV_DWORDS):
            assert _mem_dword(out, 0x200 + 4 * index) == dword
        # ...and FNSTENV produces the stored image from input state only,
        # never loading the destination.
        state = {"x87_status_word": 0x3800, "x87_control_word": 0x037F,
                 "x87_tag_word": 0xFF00, "x87_fip": 0x1234,
                 "x87_fcs_op": 0x00D8001B, "x87_fdp": 0x5000,
                 "x87_fds": 0x22, "eax": 0x200}
        out = _run(bytes.fromhex("d930"), state)
        assert _mem_dword(out, 0x200) == 0xFFFF037F
