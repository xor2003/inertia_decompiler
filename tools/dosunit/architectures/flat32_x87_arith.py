"""Layer: native i386 x87 conversion/arithmetic/compare instruction semantics.

Responsibility: decode and preserve the complete architectural effects of the
x87 numeric families that consume ``x87fp_*`` operators — real/integer loads
and stores (FLD/FILD/FST(P)/FIST(P) m16/32/64), register- and memory-form
arithmetic (FADD/FMUL/FSUB(R)/FDIV(R) and the FI* integer forms, with correct
D8/DC/DE operand order and popping), the FCOM/FUCOM/FICOM/FTST/FXAM compare
families with their condition-code outputs, FSQRT, FRNDINT, and FPREM/FPREM1
with partial-reduction C2 and quotient condition codes.

Semantics follow the pinned SoftFloat3e/86Box evidence and the host-derived
fault contract of the stack owner: every instruction is a checking
instruction (pending-exception obligation), C1 follows the family contract
(0 for compares/stores, the round-up bit for arithmetic), a stack fault on
any read operand raises IE+SF with the ext80 indefinite as the masked
response, and compare stack faults produce the unordered condition code when
masked. FXAM reports the tag class instead of faulting on empty. Unadmitted
forms (FSCALE, FXTRACT, transcendentals, BCD, FISTTP, FCMOVcc/FCOMI, waiting
prefixes) keep refusing through ``unmodeled_x87_status_write``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, TypeIs

import capstone
from capstone.x86_const import X86_OP_MEM

from tools.dosunit.architectures.flat32_control_word import (
    FLDCW_RESERVED_MASK,
    FLDCW_RESERVED_SET,
    ControlWordStore,
    _constant,
    _premise_cpu_policy,
    _premise_pending,
    _word_address,
)
from tools.dosunit.architectures.flat32_x87_stack import (
    X87_DEFAULT_NAN80,
    _and1,
    _and16,
    _env_update,
    _eq,
    _esb,
    _ie_masked,
    _input,
    _ite1,
    _ne,
    _not1,
    _or1,
    _or16,
    _phys,
    _pop,
    _push,
    _set_top,
    _st_at,
    _tag_at,
    _tagof,
    _top,
    _true,
    _write_phys_st,
    _write_phys_tag,
)

# Status-word layout: C0=8, C1=9, C2=10, TOP=11-13, C3=14.
_SW_C1 = 0x0200
_SW_IE_SF = 0x0041
_CC_MASK = 0x4700          # C0,C1,C2,C3
_C0, _C2, _C3 = 0x0100, 0x0400, 0x4000
_TAG_EMPTY = 0x3

# Arithmetic /n codes -> (x87fp kind, reversed operand order).
_ARITH_OPS: dict[int, tuple[str, bool]] = {
    0: ("add", False), 1: ("mul", False),
    4: ("sub", False), 5: ("sub", True),
    6: ("div", False), 7: ("div", True),
}

# Invalid-op masked response per store format.
_STORE_INDEF = {16: 0x8000, 32: 0xFFC00000, 64: 0xFFF8000000000000}


@dataclass(frozen=True)
class ConvLoad:
    """FLD m32/m64: push a widened memory real."""

    source: ControlWordStore
    fmt: int
    opcode: int


@dataclass(frozen=True)
class IntLoad:
    """FILD m16/m32/m64: push an exact integer conversion."""

    source: ControlWordStore
    fmt: int
    opcode: int


@dataclass(frozen=True)
class ConvStore:
    """FST(P) m32/m64: narrowed store of ST(0)."""

    destination: ControlWordStore
    fmt: int
    pop: bool
    opcode: int


@dataclass(frozen=True)
class IntStore:
    """FIST(P) m16/m32/m64 and FISTTP (``trunc`` forces RTZ, always pops)."""

    destination: ControlWordStore
    fmt: int
    pop: bool
    opcode: int
    trunc: bool = False


@dataclass(frozen=True)
class ArithReg:
    """Register-form F<op>.

    ``dest`` is the logical destination index (0 for D8 forms, ``index`` for
    DC/DE forms); ``rev`` swaps sub/div operand order; ``pop`` pops after
    writing (DE forms).
    """

    kind: str
    index: int
    dest: int
    rev: bool
    pop: bool
    opcode: int


@dataclass(frozen=True)
class ArithMem:
    """F<op> m32/m64: ST(0) = ST(0) <op> widened memory real."""

    kind: str
    source: ControlWordStore
    fmt: int
    rev: bool
    opcode: int


@dataclass(frozen=True)
class ArithInt:
    """FI<op> m16/m32: ST(0) = ST(0) <op> converted integer."""

    kind: str
    source: ControlWordStore
    fmt: int
    rev: bool
    opcode: int


@dataclass(frozen=True)
class CompareReg:
    """FCOM/FCOMP ST(i), FCOMPP, FUCOM(P) ST(i), FUCOMPP."""

    kind: str          # "com" or "ucom"
    index: int         # source ST(i); FCOMPP/FUCOMPP compare ST(1)
    pops: int
    opcode: int


@dataclass(frozen=True)
class CompareMem:
    """FCOM(P) m32/m64 and FICOM(P) m16/m32."""

    kind: str          # "com" or "icom"
    source: ControlWordStore
    fmt: int
    pop: bool
    opcode: int


@dataclass(frozen=True)
class TstOrXam:
    """FTST (compare ST(0) with +0.0) or FXAM (tag class into C-bits)."""

    xam: bool
    opcode: int


@dataclass(frozen=True)
class SqrtOrRnd:
    """FSQRT or FRNDINT on ST(0)."""

    sqrt: bool
    opcode: int


@dataclass(frozen=True)
class Remainder:
    """FPREM (ieee=False) or FPREM1 (ieee=True) on ST(0) by ST(1)."""

    ieee: bool
    opcode: int


@dataclass(frozen=True)
class RegPair:
    """Two-register op writing ST(0) from (ST(0), ST(1)): FSCALE (D9 FD)."""

    kind: str
    opcode: int


@dataclass(frozen=True)
class Xtract:
    """FXTRACT (D9 F4): ST(0) <- exponent real; push significand."""

    opcode: int


@dataclass(frozen=True)
class Comi:
    """FCOMI/FUCOMI(P): unordered compare reporting through lazy EFLAGS.

    The integer-flag contract mirrors FCOM: C0->CF, C2->PF, C3->ZF, with a
    masked invalid/stack fault reporting unordered (all three set).  Written
    through the VEX COPY lazy-flag quartet (cc_op=0, cc_dep1=flag word).
    """

    kind: str
    index: int
    pop: bool
    opcode: int


@dataclass(frozen=True)
class FCmov:
    """FCMOVcc: conditional ST(i)->ST(0) move gated by lazy EFLAGS."""

    index: int
    condition: int
    opcode: int


@dataclass(frozen=True)
class Transcend:
    """Transcendental family (D9 F0-F3, F9, FB, FE, FF).

    Result values are typed ext80 uninterpreted terms: every architectural
    effect (TOP/tags/flags/stack faults/pops) is modeled exactly while bit
    equality of the approximation is a declared premise, not an asserted
    identity.  Trig forms gate the write on the 2**63 range check (C2).
    """

    kind: str
    opcode: int


@dataclass(frozen=True)
class BcdMem:
    """FBLD (DF /4) push and FBSTP (DF /6) packed-BCD m80 memory forms."""

    kind: str
    destination: ControlWordStore
    opcode: int


@dataclass(frozen=True)
class EnvLoad:
    """Checking environment load: FLDENV (D9 /4) and FRSTOR (DD /4) in the
    32-bit protected-mode layout — seven dwords
    [CW, SW, TW, FIP, FCS|opcode<<16, FDP, FDS] at the effective address."""

    kind: str
    destination: ControlWordStore
    opcode: int


@dataclass(frozen=True)
class EnvStore:
    """Nonchecking environment store: FNSTENV (D9 /6) and FNSAVE (DD /6),
    same seven-dword layout; FNSAVE also stores the eight registers."""

    kind: str
    destination: ControlWordStore
    opcode: int


type X87ArithInstruction = (
    ConvLoad | IntLoad | ConvStore | IntStore | ArithReg | ArithMem | ArithInt
    | CompareReg | CompareMem | TstOrXam | SqrtOrRnd | Remainder | RegPair
    | Xtract | EnvLoad | EnvStore | Comi | FCmov | BcdMem | Transcend
)

# Instructions whose execution first delivers a pending unmasked x87
# exception.  FNSTENV/FNSAVE are architecturally nonchecking (host-verified:
# a store still runs with an unmasked pending ZE) and only the 9B-prefixed
# waiting forms carry the check, so EnvStore is deliberately absent.
X87_ARITH_CHECKING: tuple[type, ...] = (
    ConvLoad, IntLoad, ConvStore, IntStore, ArithReg, ArithMem, ArithInt,
    CompareReg, CompareMem, TstOrXam, SqrtOrRnd, Remainder, RegPair,
    Xtract, EnvLoad, Comi, FCmov, BcdMem, Transcend,
)

# Every instruction family this owner decodes — checking and nonchecking —
# for the effects dispatcher.
X87_ARITH_INSTRUCTIONS: tuple[type, ...] = (*X87_ARITH_CHECKING, EnvStore)


def is_x87_arith_instruction(instruction: object) -> TypeIs[X87ArithInstruction]:
    """Narrow decoded instructions to this owner's complete effect union."""
    return isinstance(instruction, X87_ARITH_INSTRUCTIONS)


def decode_x87_arith(raw: bytes) -> X87ArithInstruction | None:
    """Decode exactly one admitted numeric instruction.

    Register-space forms match on the 2-byte pattern; memory forms use
    Capstone for ModRM/SIB validation exactly like the stack owner.
    """
    if len(raw) < 2:
        return None
    b0, b1 = raw[0], raw[1]
    opcode = ((b0 & 0x7) << 8) | b1
    if b1 >= 0xC0:
        return _decode_register(b0, b1, opcode)
    return _decode_memory(raw, opcode)


def _decode_register(b0: int, b1: int, opcode: int) -> X87ArithInstruction | None:
    """Decode mod=3 forms across the D8/DA/DC/DD/DE/D9 maps."""
    group = (b1 - 0xC0) >> 3
    if b0 == 0xD8:
        return _decode_d8_register(group, b1, opcode)
    if b0 in (0xDC, 0xDE):
        return _decode_dcde_register(b0, group, b1, opcode)
    if b0 == 0xDD:
        return _decode_dd_register(group, b1, opcode)
    if b0 == 0xDA:
        return _decode_da_register(group, b1, opcode)
    if b0 == 0xDB:
        return _decode_db_register(group, b1, opcode)
    if b0 == 0xDF:
        return _decode_df_register(group, b1, opcode)
    if b0 == 0xD9:
        return _decode_d9_register(b1, opcode)
    return None


def _decode_da_register(group: int, b1: int,
                        opcode: int) -> X87ArithInstruction | None:
    """DA mod=3: FCMOVB/E/BE/U in groups 0-3, DA E9 is FUCOMPP."""
    if b1 == 0xE9:
        return CompareReg("ucom", 1, 2, opcode)
    if group <= 3:
        # FCMOVB/E/BE/U: conditions BELOW, ZERO, BELOW_EQUAL, PARITY.
        return FCmov(b1 & 7, (2, 4, 6, 10)[group], opcode)
    return None


def _decode_db_register(group: int, b1: int,
                        opcode: int) -> X87ArithInstruction | None:
    """DB mod=3: FCMOVNB/NE/NBE/NU in groups 0-3, FUCOMI/FCOMI."""
    if group <= 3:
        return FCmov(b1 & 7, (3, 5, 7, 11)[group], opcode)
    if group == 5:
        return Comi("ucomi", b1 & 7, False, opcode)
    if group == 6:
        return Comi("comi", b1 & 7, False, opcode)
    return None


def _decode_df_register(group: int, b1: int,
                        opcode: int) -> X87ArithInstruction | None:
    """DF mod=3 groups 5/6: FUCOMIP/FCOMIP (DF E0 stays with word decode)."""
    if group == 5:
        return Comi("ucomi", b1 & 7, True, opcode)
    if group == 6:
        return Comi("comi", b1 & 7, True, opcode)
    return None


def _decode_d8_register(group: int, b1: int, opcode: int) -> X87ArithInstruction | None:
    """D8 mod=3: FADD/FMUL/F* ST(i) plus FCOM/FCOMP."""
    entry = _ARITH_OPS.get(group)
    if entry is not None:
        kind, rev = entry
        return ArithReg(kind, b1 & 7, 0, rev, False, opcode)
    if group == 2:
        return CompareReg("com", b1 & 7, 0, opcode)
    if group == 3:
        return CompareReg("com", b1 & 7, 1, opcode)
    return None


def _decode_dcde_register(b0: int, group: int, b1: int,
                          opcode: int) -> X87ArithInstruction | None:
    """DC/DE mod=3: ST(i)-destination arithmetic; DE pops, DE D9 is FCOMPP."""
    entry = _ARITH_OPS.get(group)
    if entry is not None:
        kind, rev = entry
        # DC/DE reg forms write ST(i); the /4-7 names swap relative to D8
        # (DC E0 is FSUBR = ST(i)<-ST(0)-ST(i)), but the *computed* operand
        # order matches D8's: /4 gives ST(0)-ST(i), /5 gives ST(i)-ST(0).
        return ArithReg(kind, b1 & 7, b1 & 7, rev, b0 == 0xDE, opcode)
    if b0 == 0xDE and b1 == 0xD9:
        return CompareReg("com", 1, 2, opcode)
    return None


def _decode_dd_register(group: int, b1: int, opcode: int) -> X87ArithInstruction | None:
    """DD mod=3: FUCOM ST(i) (/4) and FUCOMP ST(i) (/5)."""
    if group == 4:
        return CompareReg("ucom", b1 & 7, 0, opcode)
    if group == 5:
        return CompareReg("ucom", b1 & 7, 1, opcode)
    return None


def _decode_d9_register(b1: int, opcode: int) -> X87ArithInstruction | None:
    """D9 mod=3 numeric singles: FTST/FXAM, FPREM1/FPREM, FSQRT/FRNDINT."""
    if b1 == 0xE4:
        return TstOrXam(False, opcode)
    if b1 == 0xE5:
        return TstOrXam(True, opcode)
    if b1 == 0xF5:
        return Remainder(True, opcode)
    if b1 == 0xF8:
        return Remainder(False, opcode)
    if b1 == 0xFA:
        return SqrtOrRnd(True, opcode)
    if b1 == 0xFC:
        return SqrtOrRnd(False, opcode)
    if b1 == 0xF4:
        return Xtract(opcode)
    if b1 == 0xFD:
        return RegPair("scale", opcode)
    transcend = {0xF0: "f2xm1", 0xF1: "yl2x", 0xF2: "ptan", 0xF3: "atan",
                 0xF9: "yl2xp1", 0xFB: "sincos", 0xFE: "sin", 0xFF: "cos"}
    if b1 in transcend:
        return Transcend(transcend[b1], opcode)
    return None


def _decode_memory(raw: bytes, opcode: int) -> X87ArithInstruction | None:
    """Decode mod<3 memory forms via Capstone."""
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    insn = next(decoder.disasm(raw, 0), None)
    if insn is None or insn.size != len(raw) or not insn.operands:
        return None
    op = insn.operands[0]
    if op.type != X86_OP_MEM or op.mem.segment:
        return None
    mem = op.mem
    source = ControlWordStore(insn.reg_name(mem.base) if mem.base else None,
                              insn.reg_name(mem.index) if mem.index else None,
                              mem.scale, mem.disp)
    b0, n = raw[0], (raw[1] >> 3) & 7
    if b0 == 0xDD and n == 1:
        return IntStore(source, 64, True, opcode, True)
    if b0 in (0xD9, 0xDD):
        return _decode_real_memory(b0, n, source, opcode)
    if b0 in (0xDB, 0xDF):
        return _decode_int_memory(b0, n, source, opcode)
    if b0 in (0xD8, 0xDC):
        return _decode_real_arith_memory(b0, n, source, opcode)
    if b0 in (0xDA, 0xDE):
        return _decode_int_arith_memory(b0, n, source, opcode)
    return None


def _decode_real_memory(b0: int, n: int, source: ControlWordStore,
                        opcode: int) -> X87ArithInstruction | None:
    """D9/DD memory: FLD and FST(P) at the map's real width."""
    fmt = 32 if b0 == 0xD9 else 64
    if n == 0:
        return ConvLoad(source, fmt, opcode)
    if n in (2, 3):
        return ConvStore(source, fmt, n == 3, opcode)
    # Independent Capstone audit (parent-env-opcode-audit.json): /4 loads
    # the environment, /6 stores it — D9 /4=FLDENV, /6=FNSTENV;
    # DD /4=FRSTOR, /6=FNSAVE.
    if n == 4:
        return EnvLoad({0xD9: "lden", 0xDD: "rstor"}[b0], source, opcode)
    if n == 6:
        return EnvStore({0xD9: "sten", 0xDD: "save"}[b0], source, opcode)
    return None


def _decode_int_memory(b0: int, n: int, source: ControlWordStore,
                       opcode: int) -> X87ArithInstruction | None:
    """DB/DF memory: FILD/FIST(P)/FISTTP integer forms."""
    if b0 == 0xDB:
        if n == 0:
            return IntLoad(source, 32, opcode)
        if n == 1:
            return IntStore(source, 32, True, opcode, True)
        if n in (2, 3):
            return IntStore(source, 32, n == 3, opcode)
        return None
    return _decode_df_memory(n, source, opcode)


def _decode_df_memory(n: int, source: ControlWordStore,
                      opcode: int) -> X87ArithInstruction | None:
    """DF memory: FILD m16/m64, FIST(P) m16/m64, FISTTP m16, FBLD/FBSTP."""
    if n == 0:
        return IntLoad(source, 16, opcode)
    if n == 1:
        return IntStore(source, 16, True, opcode, True)
    if n in (2, 3):
        return IntStore(source, 16, n == 3, opcode)
    if n == 5:
        return IntLoad(source, 64, opcode)
    if n in (4, 6):
        return BcdMem("bld" if n == 4 else "bstp", source, opcode)
    if n == 7:
        return IntStore(source, 64, True, opcode)
    return None


def _decode_real_arith_memory(b0: int, n: int, source: ControlWordStore,
                              opcode: int) -> X87ArithInstruction | None:
    """D8/DC memory: F<op> m32/m64 real arithmetic and FCOM(P)."""
    fmt = 32 if b0 == 0xD8 else 64
    entry = _ARITH_OPS.get(n)
    if entry is not None:
        kind, rev = entry
        return ArithMem(kind, source, fmt, rev, opcode)
    if n in (2, 3):
        return CompareMem("com", source, fmt, n == 3, opcode)
    return None


def _decode_int_arith_memory(b0: int, n: int, source: ControlWordStore,
                             opcode: int) -> X87ArithInstruction | None:
    """DA/DE memory: FI<op> m32/m16 integer arithmetic and FICOM(P)."""
    fmt = 32 if b0 == 0xDA else 16
    entry = _ARITH_OPS.get(n)
    if entry is not None:
        kind, rev = entry
        return ArithInt(kind, source, fmt, rev, opcode)
    if n in (2, 3):
        return CompareMem("icom", source, fmt, n == 3, opcode)
    return None


# ---------------------------------------------------------------------------
# Effects
# ---------------------------------------------------------------------------

def apply_x87_arith_effects(
    instruction: X87ArithInstruction, state: dict[str, dict[str, Any]],
    memory: dict[str, Any], summary: dict[str, Any], address: int,
) -> None:
    """Write one admitted numeric instruction's architectural effects."""
    sw0 = _input("x87_status_word", 16)
    cw = _input("x87_control_word", 16)
    state["x87_tag_word"] = _input("x87_tag_word", 16)
    sw = _and16(sw0, _constant(0xFFFF & ~_SW_C1, 16))
    ctx = {"state": state, "memory": memory, "sw0": sw0, "cw": cw,
           "top": _top(sw0), "masked": _ie_masked(cw), "sw": sw}
    ea = _arith_effects(instruction, ctx)
    if not isinstance(instruction, (EnvLoad, EnvStore)):
        _env_update(state, address, instruction.opcode, ea,
                    segment=_operand_segment(_memory_operand(instruction)))
    summary["premises"] = [_premise_cpu_policy(
        "x87 numeric semantics follow the pinned SoftFloat3e/86Box engine: "
        "single-round exact-BV arithmetic to CW.PC, masked responses, "
        "denormal/pseudo-denormal normalization, FPREM partial reduction")]
    if isinstance(instruction, X87_ARITH_CHECKING):
        summary["premises"].insert(0, _premise_pending())
    if isinstance(instruction, Transcend):
        # The result bits are typed ext80 uninterpreted terms: equal inputs
        # produce equal outputs, but bit equivalence to any real
        # implementation is an unresolved numerical assumption that must
        # stay visible in every verdict, cache and identity proof.
        summary["premises"].append(_premise_cpu_policy(
            "transcendental result values are uninterpreted x87_trans_* "
            "terms: instruction equivalence is conditional on both sides "
            "sharing an identical approximation, not unconditional "
            "hardware equality"))


def _arith_effects_simple(instruction: X87ArithInstruction,
                          ctx: dict[str, Any]) -> dict[str, Any] | None:
    """Dispatch compare/test/sqrt/remainder families to their writers."""
    if isinstance(instruction, (CompareReg, CompareMem)):
        return _compare_family(instruction, ctx)
    if isinstance(instruction, TstOrXam):
        _tst_xam(instruction, ctx)
        return None
    if isinstance(instruction, SqrtOrRnd):
        _sqrt_rnd(instruction, ctx)
        return None
    if isinstance(instruction, Remainder):
        _remainder(instruction, ctx)
        return None
    if isinstance(instruction, RegPair):
        _regpair(instruction, ctx)
        return None
    return None


def _arith_effects_misc(instruction: X87ArithInstruction,
                        ctx: dict[str, Any]) -> dict[str, Any] | None:
    """Dispatch FXTRACT/env/compare-flags/BCD families to their writers."""
    if isinstance(instruction, Xtract):
        _xtract(instruction, ctx)
        return None
    if isinstance(instruction, (EnvLoad, EnvStore)):
        return _env_mem(instruction, ctx)
    if isinstance(instruction, Comi):
        _comi(instruction, ctx)
        return None
    if isinstance(instruction, FCmov):
        _fcmov(instruction, ctx)
        return None
    if isinstance(instruction, BcdMem):
        return _bcd_mem(instruction, ctx)
    if isinstance(instruction, Transcend):
        _transcend(instruction, ctx)
        return None
    return None


def _arith_effects(instruction: X87ArithInstruction,
                   ctx: dict[str, Any]) -> dict[str, Any] | None:
    """Dispatch a decoded numeric instruction to its effect writer."""
    if isinstance(instruction, (ConvLoad, IntLoad)):
        return _load_family(instruction, ctx)
    if isinstance(instruction, (ConvStore, IntStore)):
        return _store_family(instruction, ctx)
    if isinstance(instruction, (ArithReg, ArithMem, ArithInt)):
        return _arith_family(instruction, ctx)
    return (_arith_effects_simple(instruction, ctx)
            or _arith_effects_misc(instruction, ctx))


# --- shared helpers --------------------------------------------------------

def _term(op: str, width: int, args: list[dict[str, Any]]) -> dict[str, Any]:
    """Operator term at an explicit width."""
    return {"op": op, "width": width, "args": args}


def _flags(op: str, args: list[dict[str, Any]]) -> dict[str, Any]:
    """Width-16 ``x87fp_flags_*`` term: exception bits plus C1 for arith."""
    return _term(f"x87fp_flags_{op}", 16, args)


def _empty(ctx: dict[str, Any], index: int) -> dict[str, Any]:
    """Underflow predicate: logical ST(index)'s tag is empty."""
    tw = ctx["state"]["x87_tag_word"]
    return _eq(_tag_at(_phys(index, ctx["sw0"]), tw), _TAG_EMPTY, 16)


def _faulted(ctx: dict[str, Any], fault: dict[str, Any]) -> dict[str, Any]:
    """Width-1 allowed-to-execute condition given the IE mask."""
    return _or1(_not1(fault), ctx["masked"])


def _unmasked(ctx: dict[str, Any], flags: dict[str, Any],
              fault: dict[str, Any]) -> dict[str, Any]:
    """Unmasked numeric exception predicate for this instruction.

    Any exception bit in ``flags`` not masked by the CW aborts the
    instruction's destination write and pop (host: FDIV ST0,ST1 with ZE
    unmasked leaves ST0 unchanged, ES|B|ZE set — host-unmasked-divide.json).
    While a stack fault is active the numeric result is never evaluated, so
    garbage-operand flag bits must not gate completion.
    """
    notcw = {"op": "not", "width": 16, "args": [ctx["cw"]]}
    raised = _and16(flags, _and16(notcw, _constant(0x3F, 16)))
    return _and1(_not1(fault), _ne(raised, 0, 16))


def _allowed(ctx: dict[str, Any], fault: dict[str, Any],
             flags: dict[str, Any]) -> dict[str, Any]:
    """Completion predicate: masked stack fault or masked numeric flags."""
    return _and1(_faulted(ctx, fault),
                 _not1(_unmasked(ctx, flags, fault)))


def _sw_flags(ctx: dict[str, Any], flags: dict[str, Any],
              fault: dict[str, Any], extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """Merge exception bits (+C1 when present in flags) and fault flags.

    A stack fault reports only IE|SF: the operation never evaluates operand
    values, so flag bits computed from a garbage empty-register payload would
    be spurious.  Exception bits are recorded whether masked or not.
    """
    parts = [ctx["sw"], _term("ite", 16, [fault, _constant(_SW_IE_SF, 16),
                                          _and16(flags, _constant(0x3F | _SW_C1, 16))])]
    if extra is not None:
        parts.append(extra)
    return _or16(*parts)


def _sw_cc(ctx: dict[str, Any], flags: dict[str, Any], fault: dict[str, Any],
           cc: dict[str, Any], allowed: dict[str, Any]) -> dict[str, Any]:
    """SW with C0-C3 replaced by a 16-bit CC-masked term under ``allowed``."""
    base = _and16(_or16(ctx["sw"], _term("ite", 16, [fault, _constant(_SW_IE_SF, 16),
                                                     _and16(flags, _constant(0x3F, 16))])),
                  _constant(0xFFFF & ~_CC_MASK, 16))
    return _or16(base, _term("ite", 16, [allowed, cc, _constant(0, 16)]))


def _store_le(state: dict[str, dict[str, Any]], memory: dict[str, Any],
              ea: dict[str, Any], width: int, value: dict[str, Any],
              cond: dict[str, Any]) -> None:
    """Conditional LE store of ``width`` bits at ``ea``."""
    old = _term("loadle", width, [memory, ea])
    chosen = _term("ite", width, [cond, value, old])
    state["memory"] = _term("storele", 0, [memory, ea, chosen])


def _pop2(state: dict[str, dict[str, Any]], ctx: dict[str, Any],
          cond: dict[str, Any]) -> None:
    """Second pop for FCOMPP/FUCOMPP after the first ``_pop`` rewrote TOP."""
    cw = ctx["cw"]
    sw = state["x87_status_word"]
    top = _top(sw)
    _write_phys_tag(top, cond, _constant(_TAG_EMPTY, 16), state)
    new_top = _term("ite", 16, [cond,
                                _and16(_term("add", 16, [top, _constant(1, 16)]),
                                       _constant(7, 16)),
                                top])
    state["x87_status_word"] = _set_top(new_top, _esb(sw, cw))


# --- family effect writers -------------------------------------------------

def _load_family(instruction: ConvLoad | IntLoad,
                 ctx: dict[str, Any]) -> dict[str, Any]:
    """FLD m32/m64 and FILD m16/m32/m64: converted push or stack fault."""
    state, sw0, sw = ctx["state"], ctx["sw0"], ctx["sw"]
    cw = ctx["cw"]
    tw = state["x87_tag_word"]
    ea = _word_address(instruction.source)
    raw = _term("loadle", instruction.fmt, [ctx["memory"], ea])
    op = "x87fp_widen" if isinstance(instruction, ConvLoad) else "x87fp_i2f"
    value = _term(op, 80, [raw])
    load_flags = _flags("load", [raw]) if isinstance(instruction, ConvLoad) \
        else _constant(0, 16)
    overflow = _ne(_tag_at(_phys(-1, sw0), tw), _TAG_EMPTY, 16)
    # Pinned Bochs FLD_SINGLE/DOUBLE_REAL: the push is suppressed only when
    # the *invalid* exception is unmasked — an unmasked denormal flag still
    # completes the push (Bochs `if (!(unmasked & FPU_CW_Invalid))`).
    notcw = {"op": "not", "width": 16, "args": [cw]}
    unmasked_ie = _and1(_not1(overflow),
                        _ne(_and16(load_flags,
                                   _and16(notcw, _constant(1, 16))), 0, 16))
    allowed = _and1(_faulted(ctx, overflow), _not1(unmasked_ie))
    pushed = _term("ite", 80, [overflow, _constant(X87_DEFAULT_NAN80, 80), value])
    new_sw = _or16(sw, _term("ite", 16, [overflow, _constant(_SW_IE_SF | _SW_C1, 16),
                                         _and16(load_flags, _constant(0x3F, 16))]))
    _push(ctx, pushed, allowed, new_sw)
    return ea


def _store_family(instruction: ConvStore | IntStore,
                  ctx: dict[str, Any]) -> dict[str, Any]:
    """FST(P) m32/m64 and FIST(P): narrowed/rounded store, optional pop."""
    state, sw0, cw = ctx["state"], ctx["sw0"], ctx["cw"]
    ea = _word_address(instruction.destination)
    st0 = _st_at(0, sw0)
    if isinstance(instruction, ConvStore):
        op, flag_op = "x87fp_narrow", f"narrow{instruction.fmt}"
        eff_cw = cw
    else:
        op, flag_op = "x87fp_f2i", f"f2i{instruction.fmt}"
        # FISTTP rounds with truncation regardless of CW.RC (SDM); the f2i
        # engine consumes the RC bits, so force RC=11 on the used copy.
        eff_cw = _or16(cw, _constant(0x0C00, 16)) if instruction.trunc else cw
    value = _term(op, instruction.fmt, [eff_cw, st0])
    flags = _flags(flag_op, [eff_cw, st0])
    underflow = _empty(ctx, 0)
    allowed = _allowed(ctx, underflow, flags)
    out = _term("ite", instruction.fmt,
                [underflow, _constant(_STORE_INDEF[instruction.fmt], instruction.fmt),
                 value])
    _store_le(state, ctx["memory"], ea, instruction.fmt, out, allowed)
    sw2 = _sw_flags(ctx, flags, underflow)
    if instruction.pop:
        _pop(ctx, allowed, sw2)
    else:
        state["x87_status_word"] = _esb(sw2, cw)
    return ea


def _arith_family(instruction: ArithReg | ArithMem | ArithInt,
                  ctx: dict[str, Any]) -> dict[str, Any] | None:
    """FADD/FMUL/FSUB(R)/FDIV(R) and FI* register/memory forms."""
    state, sw0, cw = ctx["state"], ctx["sw0"], ctx["cw"]
    st0 = _st_at(0, sw0)
    if isinstance(instruction, ArithReg):
        src = _st_at(instruction.index, sw0)
        fault = _or1(_empty(ctx, 0), _empty(ctx, instruction.index))
        ea = None
    else:
        ea = _word_address(instruction.source)
        raw = _term("loadle", instruction.fmt, [ctx["memory"], ea])
        op = "x87fp_widen" if isinstance(instruction, ArithMem) else "x87fp_i2f"
        src = _term(op, 80, [raw])
        fault = _empty(ctx, 0)
    args = [cw, src, st0] if instruction.rev else [cw, st0, src]
    result = _term(f"x87fp_{instruction.kind}", 80, args)
    flags = _flags(instruction.kind, args)
    allowed = _allowed(ctx, fault, flags)
    out = _term("ite", 80, [fault, _constant(X87_DEFAULT_NAN80, 80), result])
    dest = _phys(instruction.dest if isinstance(instruction, ArithReg) else 0,
                 sw0)
    _write_phys_st(dest, allowed, out, state)
    _write_phys_tag(dest, allowed, _tagof(out), state)
    sw2 = _sw_flags(ctx, flags, fault)
    if isinstance(instruction, ArithReg) and instruction.pop:
        _pop(ctx, allowed, sw2)
    else:
        state["x87_status_word"] = _esb(sw2, cw)
    return ea


def _cmp_cc(a: dict[str, Any], b: dict[str, Any], fault: dict[str, Any]) -> dict[str, Any]:
    """C0/C2/C3 mask term for a compare (unordered on fault or NaN)."""
    lt = _term("x87fp_com_lt", 1, [a, b])
    eq = _term("x87fp_com_eq", 1, [a, b])
    uno = _or1(_term("x87fp_com_uno", 1, [a, b]), fault)
    c0 = _or1(lt, uno)
    c3 = _or1(eq, uno)
    return _or16(_ite1(c0, _C0, 0), _ite1(c3, _C3, 0), _ite1(uno, _C2, 0))


def _compare_family(instruction: CompareReg | CompareMem,
                    ctx: dict[str, Any]) -> dict[str, Any] | None:
    """FCOM(P)(P)/FUCOM(P)(P)/FICOM(P): condition codes plus optional pops."""
    state, sw0, cw = ctx["state"], ctx["sw0"], ctx["cw"]
    st0 = _st_at(0, sw0)
    if isinstance(instruction, CompareReg):
        src = _st_at(instruction.index, sw0)
        fault = _or1(_empty(ctx, 0), _empty(ctx, instruction.index))
        ea = None
    else:
        ea = _word_address(instruction.source)
        raw = _term("loadle", instruction.fmt, [ctx["memory"], ea])
        op = "x87fp_i2f" if instruction.kind == "icom" else "x87fp_widen"
        src = _term(op, 80, [raw])
        fault = _empty(ctx, 0)
    flags_op = "ucom" if instruction.kind == "ucom" else "com"
    flags = _flags(flags_op, [st0, src])
    allowed = _allowed(ctx, fault, flags)
    sw2 = _sw_cc(ctx, flags, fault, _cmp_cc(st0, src, fault), allowed)
    pops = instruction.pops if isinstance(instruction, CompareReg) \
        else int(instruction.pop)
    if pops == 0:
        state["x87_status_word"] = _esb(sw2, cw)
    else:
        _pop(ctx, allowed, sw2)
        if pops == 2:
            _pop2(state, ctx, allowed)
    return ea


def _tst_xam(instruction: TstOrXam, ctx: dict[str, Any]) -> None:
    """FTST (unordered-compare with +0.0) or FXAM (class code into C-bits)."""
    state, sw0, cw, sw = ctx["state"], ctx["sw0"], ctx["cw"], ctx["sw"]
    st0 = _st_at(0, sw0)
    if not instruction.xam:
        fault = _empty(ctx, 0)
        zero = _constant(0, 80)
        flags = _flags("ucom", [st0, zero])
        allowed = _allowed(ctx, fault, flags)
        sw2 = _sw_cc(ctx, flags, fault, _cmp_cc(st0, zero, fault), allowed)
        state["x87_status_word"] = _esb(sw2, cw)
        return
    # FXAM is checking but never stack-faults: it reports class 101 (empty).
    tag = _tag_at(ctx["top"], state["x87_tag_word"])
    sign = _ne(_term("and", 80, [st0, _constant(1 << 79, 80)]), 0, 80)
    exp15 = _and16(_term("trunc", 16,
                         [_term("lshr", 80, [st0, _constant(64, 80)])]),
                   _constant(0x7FFF, 16))
    sig = _term("and", 80, [st0, _constant(0xFFFFFFFFFFFFFFFF, 80)])
    jbit = _ne(_term("and", 80, [st0, _constant(0x8000000000000000, 80)]), 0, 80)
    # Class codes (SDM FXAM): unsupported 000, NaN 001, normal 010, inf 011,
    # zero 100, empty 101, denormal 110.
    nan = _and1(_eq(exp15, 0x7FFF, 16), _ne(sig, 0, 80))
    inf = _and1(_eq(exp15, 0x7FFF, 16), _eq(sig, _SIG_INF_LOW, 80))
    zero_c = _and1(_eq(exp15, 0, 16), _eq(sig, 0, 80))
    denorm = _and1(_eq(exp15, 0, 16), _ne(sig, 0, 80))
    normal = _and1(_not1(_eq(exp15, 0x7FFF, 16)), _and1(_ne(exp15, 0, 16), jbit))
    code = _or16(
        _ite1(nan, 0b001, 0), _ite1(inf, 0b011, 0), _ite1(zero_c, 0b100, 0),
        _ite1(denorm, 0b110, 0), _ite1(normal, 0b010, 0))
    code = _term("ite", 16, [_eq(tag, _TAG_EMPTY, 16), _constant(0b101, 16), code])
    cc = _or16(_ite1(sign, _SW_C1, 0),
               _term("shl", 16, [_and16(code, _constant(1, 16)), _constant(8, 16)]),
               _term("shl", 16, [_and16(code, _constant(2, 16)), _constant(9, 16)]),
               _term("shl", 16, [_and16(code, _constant(4, 16)), _constant(12, 16)]))
    sw2 = _or16(_and16(sw, _constant(0xFFFF & ~_CC_MASK, 16)), cc)
    state["x87_status_word"] = _esb(sw2, cw)


_SIG_INF_LOW = 0x8000000000000000


def _sqrt_rnd(instruction: SqrtOrRnd, ctx: dict[str, Any]) -> None:
    """FSQRT/FRNDINT on ST(0): masked fault writes the indefinite."""
    state, sw0, cw = ctx["state"], ctx["sw0"], ctx["cw"]
    st0 = _st_at(0, sw0)
    fault = _empty(ctx, 0)
    op = "sqrt" if instruction.sqrt else "rnd"
    result = _term(f"x87fp_{op}", 80, [cw, st0])
    flags = _flags(op, [cw, st0])
    allowed = _allowed(ctx, fault, flags)
    out = _term("ite", 80, [fault, _constant(X87_DEFAULT_NAN80, 80), result])
    top = _phys(0, sw0)
    _write_phys_st(top, allowed, out, state)
    _write_phys_tag(top, allowed, _tagof(out), state)
    sw2 = _sw_flags(ctx, flags, fault)
    state["x87_status_word"] = _esb(sw2, cw)


def _remainder(instruction: Remainder, ctx: dict[str, Any]) -> None:
    """FPREM/FPREM1: exact remainder into ST(0), quotient CC into SW."""
    state, sw0, cw = ctx["state"], ctx["sw0"], ctx["cw"]
    st0, st1 = _st_at(0, sw0), _st_at(1, sw0)
    fault = _or1(_empty(ctx, 0), _empty(ctx, 1))
    kind = "rem1" if instruction.ieee else "rem"
    result = _term(f"x87fp_{kind}", 80, [st0, st1])
    cc_op = "x87fp_remcc1" if instruction.ieee else "x87fp_remcc"
    cc = _term(cc_op, 16, [st0, st1])
    flags = _flags(kind, [st0, st1])
    allowed = _allowed(ctx, fault, flags)
    out = _term("ite", 80, [fault, _constant(X87_DEFAULT_NAN80, 80), result])
    top = _phys(0, sw0)
    _write_phys_st(top, allowed, out, state)
    _write_phys_tag(top, allowed, _tagof(out), state)
    # remcc packs {C0:0, C1:1, C2:2, C3:3}; map to SW bits 8,9,10,14.
    cc_sw = _or16(
        _term("shl", 16, [_and16(cc, _constant(1, 16)), _constant(8, 16)]),
        _term("shl", 16, [_and16(cc, _constant(2, 16)), _constant(8, 16)]),
        _term("shl", 16, [_and16(cc, _constant(4, 16)), _constant(8, 16)]),
        _term("shl", 16, [_and16(cc, _constant(8, 16)), _constant(11, 16)]))
    sw2 = _sw_cc(ctx, flags, fault, cc_sw, allowed)
    state["x87_status_word"] = _esb(sw2, cw)


def _regpair(instruction: RegPair, ctx: dict[str, Any]) -> None:
    """FSCALE: ST(0) <- ST(0) * 2^trunc(ST(1)); masked fault writes indefinite."""
    state, sw0, cw = ctx["state"], ctx["sw0"], ctx["cw"]
    st0, st1 = _st_at(0, sw0), _st_at(1, sw0)
    fault = _or1(_empty(ctx, 0), _empty(ctx, 1))
    result = _term(f"x87fp_{instruction.kind}", 80, [cw, st0, st1])
    flags = _flags(instruction.kind, [cw, st0, st1])
    allowed = _allowed(ctx, fault, flags)
    out = _term("ite", 80, [fault, _constant(X87_DEFAULT_NAN80, 80), result])
    top = _phys(0, sw0)
    _write_phys_st(top, allowed, out, state)
    _write_phys_tag(top, allowed, _tagof(out), state)
    sw2 = _sw_flags(ctx, flags, fault)
    state["x87_status_word"] = _esb(sw2, cw)


def _xtract(instruction: Xtract, ctx: dict[str, Any]) -> None:
    """FXTRACT: exponent-real into ST(0), normalized significand pushed.

    Fault precedence: empty operand and push overflow are both stack faults
    (IE|SF; C1 only on overflow).  Pinned Bochs fpu_trans.cc FXTRACT: ANY
    masked stack fault writes the indefinite to ST(0) AND pushes another —
    underflow checked before overflow, so a combined fault reports IE|SF
    without C1.
    """
    state, sw0 = ctx["state"], ctx["sw0"]
    tw = state["x87_tag_word"]
    st0 = _st_at(0, sw0)
    fault = _empty(ctx, 0)
    overflow = _ne(_tag_at(_phys(-1, sw0), tw), _TAG_EMPTY, 16)
    any_fault = _or1(fault, overflow)
    flags = _flags("xtract", [st0])
    allowed = _allowed(ctx, any_fault, flags)
    # Bochs fpu_trans.cc FXTRACT: ANY masked stack fault (underflow or
    # push overflow) writes the indefinite to ST(0) and pushes another.
    exp_out = _term("ite", 80, [any_fault, _constant(X87_DEFAULT_NAN80, 80),
                                _term("x87fp_xtract_e", 80, [st0])])
    sig_out = _term("ite", 80, [any_fault, _constant(X87_DEFAULT_NAN80, 80),
                                _term("x87fp_xtract_s", 80, [st0])])
    top = _phys(0, sw0)
    _write_phys_st(top, allowed, exp_out, state)
    _write_phys_tag(top, allowed, _tagof(exp_out), state)
    eff = _term("ite", 16, [fault, _constant(_SW_IE_SF, 16),
                            _term("ite", 16, [overflow,
                                              _constant(_SW_IE_SF | _SW_C1, 16),
                                              _and16(flags, _constant(0x3F, 16))])])
    sw2 = _or16(ctx["sw"], eff)
    _push(ctx, sig_out, allowed, sw2)


def _lazy_condition(condition: int) -> dict[str, Any]:
    """Width-1 predicate for an X86Condition over the lazy flag quartet."""
    return _term("summary_x86g_calculate_condition", 1,
                 [_constant(condition, 32), _input("cc_op", 32),
                  _input("cc_dep1", 32), _input("cc_dep2", 32),
                  _input("cc_ndep", 32)])


def _write_lazy_flags(cond: dict[str, Any], flag_word: dict[str, Any],
                      state: dict[str, dict[str, Any]]) -> None:
    """Write the VEX COPY lazy-flag quartet under ``cond`` (preserve else)."""
    zero = _constant(0, 32)
    for name, value in (("cc_op", zero), ("cc_dep1", flag_word),
                        ("cc_dep2", zero), ("cc_ndep", zero)):
        state[name] = _term("ite", 32, [cond, value, _input(name, 32)])


def _comi(instruction: Comi, ctx: dict[str, Any]) -> None:
    """FCOMI/FUCOMI(P): compare ST(0) vs ST(i), result into EFLAGS.

    x87 SW keeps its exception bits (IE/DE) but NOT C0-C3; the comparison
    lands only on the integer flag side.  Unmasked exceptions suppress the
    EFLAGS write and the pop entirely.
    """
    state, sw0, cw = ctx["state"], ctx["sw0"], ctx["cw"]
    st0 = _st_at(0, sw0)
    src = _st_at(instruction.index, sw0)
    fault = _or1(_empty(ctx, 0), _empty(ctx, instruction.index))
    flags = _flags("ucom" if instruction.kind == "ucomi" else "com", [st0, src])
    allowed = _allowed(ctx, fault, flags)
    lt = _term("x87fp_com_lt", 1, [st0, src])
    eq = _term("x87fp_com_eq", 1, [st0, src])
    uno = _or1(_term("x87fp_com_uno", 1, [st0, src]), fault)
    flag_word = _term("or", 32, [
        _term("or", 32, [
            _term("ite", 32, [_or1(lt, uno), _constant(1, 32), _constant(0, 32)]),
            _term("ite", 32, [uno, _constant(4, 32), _constant(0, 32)])]),
        _term("ite", 32, [_or1(eq, uno), _constant(0x40, 32),
                          _constant(0, 32)])])
    _write_lazy_flags(allowed, flag_word, state)
    sw2 = _sw_flags(ctx, flags, fault)
    if instruction.pop:
        _pop(ctx, allowed, sw2)
    else:
        state["x87_status_word"] = _esb(sw2, cw)


def _fcmov(instruction: FCmov, ctx: dict[str, Any]) -> None:
    """FCMOVcc: move ST(i) into ST(0) when the lazy-flag condition holds.

    Source-empty is a stack fault; the masked response supplies the
    indefinite NaN as the moved value (tag 2 = special) and clears C1.
    C0/C2/C3 are architecturally undefined on FCMOVcc and left untouched.
    """
    state, sw0, cw = ctx["state"], ctx["sw0"], ctx["cw"]
    src = _st_at(instruction.index, sw0)
    cond = _lazy_condition(instruction.condition)
    # Hardware fetches both operands before the condition: an empty
    # destination or source stack-faults even when the move is untaken, and
    # the masked response delivers the indefinite to ST(0) regardless of
    # the condition outcome (host probe: FNINIT;FLD1;CLC;FCMOVB ST0,ST1
    # leaves SW=0x3841 and ST0=indefinite with CF=0).
    fault = _or1(_empty(ctx, 0), _empty(ctx, instruction.index))
    flags = _constant(0, 16)
    allowed = _allowed(ctx, fault, flags)
    write = _and1(allowed, _or1(fault, cond))
    value = _term("ite", 80, [fault, _constant(X87_DEFAULT_NAN80, 80), src])
    moved_tag = _term("ite", 16, [fault, _constant(2, 16),
                                  _tag_at(_phys(instruction.index, sw0),
                                          state["x87_tag_word"])])
    _write_phys_st(_phys(0, sw0), write, value, state)
    _write_phys_tag(_phys(0, sw0), write, moved_tag, state)
    state["x87_status_word"] = _esb(_sw_flags(ctx, flags, fault), cw)


def _bcd_mem(instruction: BcdMem, ctx: dict[str, Any]) -> dict[str, Any]:
    """FBLD/FBSTP packed-BCD m80 decimal memory effects.

    FBLD pushes the decoded integer (stack overflow is the only fault);
    FBSTP stores the RC-rounded packed-BCD image, suppressed on unmasked
    exceptions, and pops.
    """
    state, sw0, sw, cw = ctx["state"], ctx["sw0"], ctx["sw"], ctx["cw"]
    ea = _word_address(instruction.destination)
    memory = ctx["memory"]
    if instruction.kind == "bld":
        tw = state["x87_tag_word"]
        packed = _term("loadle", 80, [memory, ea])
        value = _term("x87fp_fbld", 80, [packed])
        overflow = _ne(_tag_at(_phys(-1, sw0), tw), _TAG_EMPTY, 16)
        allowed = _faulted(ctx, overflow)
        pushed = _term("ite", 80, [overflow,
                                   _constant(X87_DEFAULT_NAN80, 80), value])
        new_sw = _or16(sw, _ite1(overflow, _SW_IE_SF | _SW_C1, 0))
        _push(ctx, pushed, allowed, new_sw)
        return ea
    st0 = _st_at(0, sw0)
    fault = _empty(ctx, 0)
    flags = _flags("fbst", [cw, st0])
    allowed = _allowed(ctx, fault, flags)
    image = _term("x87fp_fbst", 80, [cw, st0])
    _store_le(state, memory, ea, 80, image, allowed)
    sw2 = _sw_flags(ctx, flags, fault)
    _pop(ctx, allowed, sw2)
    return ea


def _trans_term(k: str, st0: dict[str, Any], st1: dict[str, Any],
                cw: dict[str, Any], indef: dict[str, Any]) -> dict[str, Any]:
    """Result term for one transcendental kind (UF values, exact edges)."""
    if k == "yl2x" or k == "yl2xp1":
        # Whole-instruction summary: operand classes, boundary products
        # and the invalid cases are evaluated inside x87fp_yl2x(p1)
        # rather than composed from a rounded log UF plus x87fp_mul,
        # which would invent intermediate rounding.
        return _term(f"x87fp_{k}", 80, [cw, st1, st0])
    if k == "atan":
        return _term("x87fp_atan2", 80, [cw, st1, st0])
    if k == "sincos":
        # Bochs FSINCOS: ST(0) gets the sine, the cosine is pushed.
        return _term("x87fp_sin", 80, [cw, st0])
    return _term("x87fp_tan" if k == "ptan" else f"x87fp_{k}", 80,
                 [cw, st0])


def _transcend(instruction: Transcend, ctx: dict[str, Any]) -> None:
    """Transcendental family effects with typed-UF result values.

    The approximation bits are opaque (x87_trans_* uninterpreted ext80
    functions) so instruction-level equality is conditional on a shared
    transcendental implementation — never silently claimed.  Stack faults,
    range C2, flags, pushes and pops follow the SDM table; masked responses
    write the negative indefinite.
    """
    state, sw0, cw = ctx["state"], ctx["sw0"], ctx["cw"]
    tw = state["x87_tag_word"]
    st0 = _st_at(0, sw0)
    k = instruction.kind
    trig = k in ("sin", "cos", "sincos", "ptan")
    binary = k in ("atan", "yl2x", "yl2xp1")
    pusher = k in ("sincos", "ptan")
    fault = _empty(ctx, 0)
    if binary:
        fault = _or1(fault, _empty(ctx, 1))
    overflow = _ne(_tag_at(_phys(-1, sw0), tw), _TAG_EMPTY, 16) if pusher \
        else _constant(0, 16)
    any_fault = _or1(fault, _ne(overflow, 0, 16))
    st1 = _st_at(1, sw0)
    flags = _flags(k, [st0, st1] if binary else [st0])
    allowed = _allowed(ctx, any_fault, flags)
    # Masked-invalid operands (NaN/inf/unsupported) deliver the indefinite
    # NaN, distinct from a finite out-of-range trig operand (kept, C2=1).
    bad = _term("x87fp_badop", 1, [st0])
    if binary:
        bad = _or1(bad, _term("x87fp_badop", 1, [st1]))
    in_range = _term("x87fp_range63", 1, [st0]) if trig else _constant(1, 1)
    # The write applies whenever the op completes; the class-aware term
    # itself yields the operand-class result (quiet NaN for NaN operands,
    # indefinite for inf/unsupported).  A finite out-of-range trig operand
    # keeps its source with C2=1 and writes nothing.
    apply = _or1(in_range, bad)
    go = _and1(allowed, apply)
    indef = _constant(X87_DEFAULT_NAN80, 80)
    top = _phys(0, sw0)
    term = _trans_term(k, st0, st1, cw, indef)
    # Bochs: ANY masked stack fault (operand empty or push overflow)
    # delivers the indefinite; operand classes, domain and boundary
    # cases all resolve through the class-aware term.
    out = _term("ite", 80, [any_fault, indef,
                _term("ite", 80, [apply, term, st0])])
    if binary:
        dest = _phys(1, sw0)
        _write_phys_st(dest, allowed, out, state)
        _write_phys_tag(dest, allowed, _tagof(out), state)
        sw2 = _sw_flags(ctx, flags, fault)
        _pop(ctx, allowed, sw2)
        return
    if pusher:
        # Masked stack-fault response is DOUBLE-INDEFINITE for both
        # pushers: write INDEF to ST(0) and push another INDEF.  This is
        # the observed hardware response (parent host_x87_push_faults
        # matrix: full stack TW=0x8002, empty stack TW=0xBFFE, combined
        # underflow+overflow identical) and matches Bochs for FXTRACT and
        # FSINCOS.  Pinned Bochs FPTAN instead pushes Const_1 and leaves
        # ST(0) untouched -- a documented emulator/hardware divergence;
        # this model follows the hardware evidence.
        # Normal path: FSINCOS -> ST(0)=sin, push cos; FPTAN ->
        # ST(0)=tan, push 1.0 (also on a masked-invalid operand; NaN
        # payload propagation for FSINCOS is a documented gap).
        # A masked stack fault completes the masked response regardless of
        # the (symbolic) operand range/bad-op checks.
        fault_go = _and1(allowed, any_fault)
        if k == "sincos":
            # Pushed operand is cosine; the term quiets a NaN source or
            # delivers indefinite for inf/unsupported on its own.
            normal = _term("x87fp_cos", 80, [cw, st0])
            bad_push = normal
        else:
            normal = _constant(0x3FFF8000000000000000, 80)
            bad_push = normal
        pushed_val = _term("ite", 80, [any_fault, indef,
                                       _term("ite", 80, [bad, bad_push,
                                                         normal])])
        _write_phys_st(top, _or1(go, fault_go), out, state)
        _write_phys_tag(top, _or1(go, fault_go), _tagof(out), state)
        eff = _term("ite", 16, [fault, _constant(_SW_IE_SF, 16),
                                _term("ite", 16,
                                      [_ne(overflow, 0, 16),
                                       _constant(_SW_IE_SF | _SW_C1, 16),
                                       _and16(flags, _constant(0x3F, 16))])])
        sw2 = _or16(ctx["sw"], eff)
        sw2 = _or16(sw2, _term("ite", 16, [_not1(in_range),
                                          _constant(0x0400, 16),
                                          _constant(0, 16)]))
        _push(ctx, pushed_val, _or1(go, fault_go), sw2)
        return
    _write_phys_st(top, go, out, state)
    _write_phys_tag(top, go, _tagof(out), state)
    sw2 = _sw_flags(ctx, flags, fault)
    if trig:
        sw2 = _or16(sw2, _term("ite", 16, [_not1(in_range),
                                          _constant(0x0400, 16),
                                          _constant(0, 16)]))
    state["x87_status_word"] = _esb(sw2, cw)


_ENV_FIELDS: tuple[str, ...] = (
    "x87_control_word", "x87_status_word", "x87_tag_word",
    "x87_fip", "x87_fcs_op", "x87_fdp", "x87_fds")


def _memory_operand(instruction: X87ArithInstruction) -> ControlWordStore | None:
    """Return the ControlWordStore memory operand for memory-bearing forms."""
    if isinstance(instruction, (ConvLoad, IntLoad, ArithMem, ArithInt,
                                CompareMem)):
        return instruction.source
    if isinstance(instruction, (ConvStore, IntStore, EnvLoad, EnvStore,
                                BcdMem)):
        return instruction.destination
    return None


def _operand_segment(source: ControlWordStore | None) -> str:
    """Default data segment for an x87 memory operand.

    32-bit ModRM addressing defaults to SS when EBP or ESP is the base
    register, DS otherwise; segment-override prefixes are not admitted.
    """
    if source is not None and source.base in ("ebp", "esp"):
        return "ss"
    return "ds"


def _env_store_word(name: str, index: int) -> dict[str, Any]:
    """Serialize a protected-mode environment word with reserved padding."""
    if index < 3:
        low = _term("zext", 32, [_input(name, 16)])
    elif name == "x87_fds":
        low = _term("and", 32, [_input(name, 32), _constant(0xFFFF, 32)])
    else:
        return _input(name, 32)
    return _term("or", 32, [low, _constant(0xFFFF0000, 32)])


def _env_load_word(name: str, index: int, raw: dict[str, Any]) -> dict[str, Any]:
    """Discard image padding when restoring architectural state fields."""
    if index < 3:
        return _term("trunc", 16, [raw])
    if name == "x87_fds":
        return _term("and", 32, [raw, _constant(0xFFFF, 32)])
    return raw


def _env_mem(instruction: EnvLoad | EnvStore, ctx: dict[str, Any]) -> dict[str, Any]:
    """FLDENV/FNSTENV and FRSTOR/FNSAVE env+register memory effects.

    The 32-bit layout stores CW/SW/TW into the low halves of dword slots
    with the reserved upper 16 bits filled with 0xFFFF (host-observed on
    the test silicon; older generations may differ — declared premise).
    The eight-register image is in logical stack order (slot n = ST(n)
    under the relevant TOP), matching Bochs FNSAVE/FRSTOR.  FNSTENV then
    masks all six exceptions in CW (SDM; host-verified) while FNSAVE
    applies the full FINIT reset.  FLDENV recomputes ES|B from the loaded
    flags and the reserved-bit-normalized loaded CW; FRSTOR recomputes
    tags from loaded values unless the stored tag says empty.  Env
    instructions do not update FIP/FCS-op/FDP/FDS themselves.
    """
    state = ctx["state"]
    memory = ctx["memory"]
    ea = _word_address(instruction.destination)
    one = _true()
    if instruction.kind in ("sten", "save"):
        for index, name in enumerate(_ENV_FIELDS):
            addr = _term("add", 32, [ea, _constant(4 * index, 32)])
            value = _env_store_word(name, index)
            _store_le(state, memory, addr, 32, value, one)
            memory = state["memory"]
        if instruction.kind == "sten":
            # FNSTENV masks all six FP exceptions after storing (SDM;
            # host-verified: CW 0x0370 -> 0x037F), no other state change.
            state["x87_control_word"] = _or16(
                _input("x87_control_word", 16), _constant(0x003F, 16))
        if instruction.kind == "save":
            # Bochs FNSAVE: "save all registers in stack order" — slot n at
            # ea+28+10n holds the logical register ST(n) = phys(TOP+n).
            for reg in range(8):
                addr = _term("add", 32, [ea, _constant(28 + 10 * reg, 32)])
                _store_le(state, memory, addr, 80,
                          _st_at(reg, ctx["sw0"]), one)
                memory = state["memory"]
            state["x87_control_word"] = _constant(0x037F, 16)
            state["x87_status_word"] = _constant(0, 16)
            state["x87_tag_word"] = _constant(0xFFFF, 16)
            for name in _ENV_FIELDS[3:]:
                state[name] = _constant(0, 32)
    else:
        loaded: dict[str, dict[str, Any]] = {}
        for index, name in enumerate(_ENV_FIELDS):
            addr = _term("add", 32, [ea, _constant(4 * index, 32)])
            raw = _term("loadle", 32, [memory, addr])
            loaded[name] = _env_load_word(name, index, raw)
        # Bochs fpu_load_environment applies the FLDCW reserved-bit policy to
        # the loaded CW: (word & ~FPU_CW_Reserved_Bits) | 0x0040.
        loaded["x87_control_word"] = _or16(
            _and16(loaded["x87_control_word"],
                   _constant(FLDCW_RESERVED_MASK, 16)),
            _constant(FLDCW_RESERVED_SET, 16))
        loaded["x87_status_word"] = _esb(loaded["x87_status_word"],
                                         loaded["x87_control_word"])
        state.update(loaded)
        if instruction.kind == "rstor":
            # Bochs FRSTOR: image slot n restores logical ST(n) under the
            # loaded TOP; the stored physical tag pair empty -> tag stays
            # empty, otherwise the tag recomputes from the loaded value.
            new_top = _top(loaded["x87_status_word"])
            for reg in range(8):
                addr = _term("add", 32, [ea, _constant(28 + 10 * reg, 32)])
                value = _term("loadle", 80, [memory, addr])
                phys = _and16(_term("add", 16, [new_top, _constant(reg, 16)]),
                              _constant(7, 16))
                stored_tag = _tag_at(phys, loaded["x87_tag_word"])
                new_tag = _term("ite", 16, [_eq(stored_tag, _TAG_EMPTY, 16),
                                            _constant(_TAG_EMPTY, 16),
                                            _tagof(value)])
                _write_phys_st(phys, one, value, state)
                _write_phys_tag(phys, one, new_tag, state)
    return ea


def _conv_kind(instruction: ConvLoad | IntLoad | ConvStore | IntStore) -> str:
    """Name a conversion-family instruction for provenance records."""
    if isinstance(instruction, ConvLoad):
        return f"native_fld_m{instruction.fmt}"
    if isinstance(instruction, IntLoad):
        return f"native_fild_m{instruction.fmt}"
    if isinstance(instruction, ConvStore):
        verb = "fstp" if instruction.pop else "fst"
        return f"native_{verb}_m{instruction.fmt}"
    verb = "fistp" if instruction.pop else "fist"
    return f"native_{verb}_m{instruction.fmt}"


def _compare_kind(instruction: CompareReg | CompareMem) -> str:
    """Name a compare-family instruction for provenance records."""
    if isinstance(instruction, CompareReg):
        base = "fucom" if instruction.kind == "ucom" else "fcom"
        return f"native_{base}{'p' * instruction.pops}_sti"
    base = "ficom" if instruction.kind == "icom" else "fcom"
    return f"native_{base}{'p' if instruction.pop else ''}_m{instruction.fmt}"


def _arith_family_kind(instruction: ArithReg | ArithMem | ArithInt) -> str:
    """Name register/memory/integer arithmetic instruction forms."""
    if isinstance(instruction, ArithReg):
        pop = "p" if instruction.pop else ""
        return f"native_f{instruction.kind}{pop}_sti"
    if isinstance(instruction, ArithMem):
        return f"native_f{instruction.kind}_m{instruction.fmt}"
    return f"native_fi{instruction.kind}_m{instruction.fmt}"


def _misc_kind(instruction: X87ArithInstruction) -> str:
    """Name compare/auxiliary/env/BCD instruction forms."""
    if isinstance(instruction, TstOrXam):
        return "native_fxam" if instruction.xam else "native_ftst"
    if isinstance(instruction, SqrtOrRnd):
        return "native_fsqrt" if instruction.sqrt else "native_frndint"
    if isinstance(instruction, Remainder):
        return "native_fprem1" if instruction.ieee else "native_fprem"
    if isinstance(instruction, Comi):
        return f"native_f{instruction.kind}p" if instruction.pop \
            else f"native_f{instruction.kind}"
    if isinstance(instruction, FCmov):
        return f"native_fcmov{instruction.condition}"
    if isinstance(instruction, BcdMem):
        return f"native_f{instruction.kind}"
    if isinstance(instruction, (EnvLoad, EnvStore)):
        return f"native_f{instruction.kind}"
    if isinstance(instruction, RegPair):
        return f"native_f{instruction.kind}"
    return "native_fxtract"


def x87_arith_kind(instruction: X87ArithInstruction) -> str:
    """Name the admitted numeric instruction family for provenance records."""
    if isinstance(instruction, (ConvLoad, IntLoad, ConvStore, IntStore)):
        return _conv_kind(instruction)
    if isinstance(instruction, (ArithReg, ArithMem, ArithInt)):
        return _arith_family_kind(instruction)
    if isinstance(instruction, (CompareReg, CompareMem)):
        return _compare_kind(instruction)
    return _misc_kind(instruction)
