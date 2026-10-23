"""Layer: native i386 x87 register-stack instruction semantics.

Responsibility: decode and preserve the complete architectural effects of the
x87 data-stack family — TOP, per-register tags and the eight 80-bit physical
registers — for the instructions that move or load/store whole ext80 values
without arithmetic rounding (FLD ST(i)/m80, FST(P) ST(i), FSTP m80, FXCH,
FFREE, FINCSTP/FDECSTP, FLD constants, FCHS/FABS). Real32/real64/integer/BCD
conversions and arithmetic that depend on CW rounding precision live in
later owners; unadmitted forms keep refusing through
``unmodeled_x87_status_write``.

Semantics follow the pinned Bochs model (fpu_load_store.cc, fpu.cc
``FPU_tagof``) and the Intel SDM fault contract: every instruction is a
checking instruction (pending-exception obligation), C1 is cleared at entry,
a stack overflow or underflow raises IE+SF (+C1 on overflow), and the masked
response is the ext80 default QNaN. A conversion-free load/store cannot raise
arithmetic exceptions.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, TypeIs

import capstone
from capstone.x86_const import X86_INS_FLD, X86_INS_FSTP, X86_OP_MEM

from tools.dosunit.architectures.flat32_control_word import (
    X87_SW_EXCEPTION_MASK,
    ControlWordStore,
    _constant,
    _premise_cpu_policy,
    _premise_pending,
    _word_address,
)


@dataclass(frozen=True)
class StackLoad:
    """FLD ST(i); push the logical register onto the data stack."""

    index: int
    opcode: int


@dataclass(frozen=True)
class StackLoadMemory80:
    """FLD m80; push an 80-bit memory value without conversion."""

    source: ControlWordStore
    opcode: int


@dataclass(frozen=True)
class StackStore:
    """FST/FSTP ST(i); copy ST(0) into ST(i), optionally popping."""

    index: int
    pop: bool
    opcode: int


@dataclass(frozen=True)
class StackStoreMemory80:
    """FSTP m80; store the raw 80-bit ST(0) and pop."""

    destination: ControlWordStore
    opcode: int


@dataclass(frozen=True)
class StackExchange:
    """FXCH ST(i); swap ST(0) with ST(i)."""

    index: int
    opcode: int


@dataclass(frozen=True)
class StackFree:
    """FFREE ST(i); mark the physical register empty.  ``pop`` selects the
    undocumented-but-real FFREEP encoding (DF C0+i), which also pops."""

    index: int
    opcode: int
    pop: bool = False


@dataclass(frozen=True)
class StackTopStep:
    """FINCSTP/FDECSTP; move TOP without changing tags or values."""

    delta: int
    opcode: int


@dataclass(frozen=True)
class StackConstant:
    """FLD1/FLDZ/FLDPI/FLDL2T/FLDL2E/FLDLG2/FLDLN2; push a constant rounded by CW.RC."""

    value: int
    mnemonic: str
    opcode: int


@dataclass(frozen=True)
class StackSignOp:
    """FCHS (``absolute=False``) or FABS (``absolute=True``) on ST(0)."""

    absolute: bool
    opcode: int


type X87StackInstruction = (
    StackLoad | StackLoadMemory80 | StackStore | StackStoreMemory80
    | StackExchange | StackFree | StackTopStep | StackConstant | StackSignOp
)

# Every stack instruction is a checking instruction (Bochs
# FPU_check_pending_exceptions): the FN* non-checking exemption set does not
# cover any member of this family.
X87_STACK_CHECKING: tuple[type, ...] = (
    StackLoad, StackLoadMemory80, StackStore, StackStoreMemory80,
    StackExchange, StackFree, StackTopStep, StackConstant, StackSignOp,
)

def is_x87_stack_instruction(instruction: object) -> TypeIs[X87StackInstruction]:
    """Narrow a decoded instruction to the native stack-effect union."""
    return isinstance(instruction, X87_STACK_CHECKING)


# Status-word bits exercised by the stack family.
_SW_C1 = 0x0200
_SW_IE_SF = 0x0041
_TOP_KEEP = 0xC7FF
_ES_B_SET = 0x8080
_ES_B_CLEAR = 0x7F7F
_TAG_EMPTY = 0x3

# ext80 encodings. The masked stack-fault response is the x87 QNaN real
# indefinite: signExp 0xFFFF (negative) with only the integer and quiet bits
# of the significand set. Confirmed on real hardware: FNINIT + eight FLD1 +
# FLDZ leaves SW 0x3A41 (TOP 7, IE+SF+C1) and stores ffffc000000000000000.
X87_DEFAULT_NAN80: int = 0xFFFFC000000000000000

# Architectural ext80 constants (Bochs fpu_load_store/SDM FLDcon encodings;
# sign-exp field followed by the 64-bit significand).
_X87_CONSTANTS: dict[int, tuple[int, str]] = {
    0xE8: (0x3FFF8000000000000000, "fld1"),
    0xE9: (0x4000D49A784BCD1B8AFE, "fldl2t"),
    0xEA: (0x3FFFB8AA3B295C17F0BC, "fldl2e"),
    0xEB: (0x4000C90FDAA22168C235, "fldpi"),
    0xEC: (0x3FFD9A209A84FBCFF799, "fldlg2"),
    0xED: (0x3FFEB17217F7D1CF79AC, "fldln2"),
    0xEE: (0x00000000000000000000, "fldz"),
}


def decode_x87_stack(raw: bytes) -> X87StackInstruction | None:
    """Decode exactly one admitted register-stack instruction.

    Only default-size unprefixed forms are admitted; memory forms keep
    Capstone ModRM/SIB validation identical to the word owners. The recorded
    ``opcode`` is the 11-bit last-instruction field: low three bits of the
    map selector followed by the ModRM byte.
    """
    opcode = ((raw[0] & 0x7) << 8) | raw[1] if len(raw) >= 2 else 0
    if len(raw) == 2 and raw[0] == 0xD9:
        return _decode_d9(raw[1], opcode)
    if len(raw) == 2 and raw[0] == 0xDD:
        return _decode_dd(raw[1], opcode)
    if len(raw) == 2 and raw[0] == 0xDF and 0xC0 <= raw[1] <= 0xC7:
        return StackFree(raw[1] - 0xC0, opcode, True)
    if raw and raw[0] == 0xDB:
        memory = _decode_m80_memory(raw, X86_INS_FLD)
        if memory is not None:
            return StackLoadMemory80(memory, opcode)
        memory = _decode_m80_memory(raw, X86_INS_FSTP)
        if memory is not None:
            return StackStoreMemory80(memory, opcode)
    return None


def _decode_d9(modrm: int, opcode: int) -> X87StackInstruction | None:
    """Decode one D9-map register-form stack instruction."""
    if 0xC0 <= modrm <= 0xC7:
        return StackLoad(modrm - 0xC0, opcode)
    if 0xC8 <= modrm <= 0xCF:
        return StackExchange(modrm - 0xC8, opcode)
    if 0xD8 <= modrm <= 0xDF:
        # FSTPNCE ST(i): documented alias family that stores ST(0) into
        # ST(i) WITHOUT popping (host-verified: TOP unchanged, empty
        # destination still produces the masked-invalid indefinite).
        return StackStore(modrm - 0xD8, False, opcode)
    if modrm == 0xF6:
        return StackTopStep(-1, opcode)
    if modrm == 0xF7:
        return StackTopStep(1, opcode)
    if modrm == 0xE0:
        return StackSignOp(False, opcode)
    if modrm == 0xE1:
        return StackSignOp(True, opcode)
    constant = _X87_CONSTANTS.get(modrm)
    if constant is not None:
        value, mnemonic = constant
        return StackConstant(value, mnemonic, opcode)
    return None


def _decode_dd(modrm: int, opcode: int) -> X87StackInstruction | None:
    """Decode one DD-map register-form stack instruction."""
    if 0xC0 <= modrm <= 0xC7:
        return StackFree(modrm - 0xC0, opcode)
    if 0xD0 <= modrm <= 0xD7:
        return StackStore(modrm - 0xD0, False, opcode)
    if 0xD8 <= modrm <= 0xDF:
        return StackStore(modrm - 0xD8, True, opcode)
    return None


def _decode_m80_memory(raw: bytes, instruction_id: int) -> ControlWordStore | None:
    """Extract a complete m80 memory operand's default flat32 address."""
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    instruction = next(decoder.disasm(raw, 0), None)
    if instruction is None or instruction.id != instruction_id or instruction.size != len(raw):
        return None
    operand = instruction.operands[0]
    if operand.type != X86_OP_MEM or operand.mem.segment:
        return None
    memory = operand.mem
    return ControlWordStore(instruction.reg_name(memory.base) if memory.base else None,
                            instruction.reg_name(memory.index) if memory.index else None,
                            memory.scale, memory.disp)


# ---------------------------------------------------------------------------
# Term helpers over the serialized state
# ---------------------------------------------------------------------------

def _input(name: str, width: int) -> dict[str, Any]:
    """Reference an architectural input of the owning body."""
    return {"op": "input", "width": width, "name": name}


def _and(term: dict[str, Any], arg: dict[str, Any], width: int) -> dict[str, Any]:
    """Single ``and`` term at an explicit width."""
    return {"op": "and", "width": width, "args": [term, arg]}


def _and16(*args: dict[str, Any]) -> dict[str, Any]:
    """Chain width-16 ``and`` terms."""
    term = args[0]
    for arg in args[1:]:
        term = _and(term, arg, 16)
    return term


def _or16(*args: dict[str, Any]) -> dict[str, Any]:
    """Chain width-16 ``or`` terms."""
    term = args[0]
    for arg in args[1:]:
        term = {"op": "or", "width": 16, "args": [term, arg]}
    return term


def _eq(term: dict[str, Any], value: int, width: int) -> dict[str, Any]:
    """Width-1 equality against a constant."""
    return {"op": "eq", "width": 1, "args": [term, _constant(value, width)]}


def _ne(term: dict[str, Any], value: int, width: int) -> dict[str, Any]:
    """Width-1 inequality against a constant."""
    return {"op": "ne", "width": 1, "args": [term, _constant(value, width)]}


def _ite1(cond: dict[str, Any], yes: int, no: int) -> dict[str, Any]:
    """Width-16 select between two constants."""
    return {"op": "ite", "width": 16,
            "args": [cond, _constant(yes, 16), _constant(no, 16)]}


def _and1(*args: dict[str, Any]) -> dict[str, Any]:
    """Chain width-1 ``and`` terms."""
    term = args[0]
    for arg in args[1:]:
        term = _and(term, arg, 1)
    return term


def _or1(*args: dict[str, Any]) -> dict[str, Any]:
    """Chain width-1 ``or`` terms."""
    term = args[0]
    for arg in args[1:]:
        term = {"op": "or", "width": 1, "args": [term, arg]}
    return term


def _not1(term: dict[str, Any]) -> dict[str, Any]:
    """Width-1 boolean complement."""
    return {"op": "not", "width": 1, "args": [term]}


def _top(sw: dict[str, Any]) -> dict[str, Any]:
    """Extract TOP (status bits 11-13) as a width-16 index term."""
    return _and16({"op": "lshr", "width": 16, "args": [sw, _constant(11, 16)]}, _constant(7, 16))


def _phys(index: int, sw: dict[str, Any]) -> dict[str, Any]:
    """Physical register number of logical ST(index) (index may be -1)."""
    return _and16({"op": "add", "width": 16,
                   "args": [_top(sw), _constant(index & 0xFFFF, 16)]}, _constant(7, 16))


def _tag_at(phys: dict[str, Any], tw: dict[str, Any]) -> dict[str, Any]:
    """2-bit tag class of the physical register selected by ``phys``."""
    term: dict[str, Any] = _constant(0, 16)
    for reg in range(8):
        field = _and16({"op": "lshr", "width": 16,
                        "args": [tw, _constant(2 * reg, 16)]}, _constant(3, 16))
        term = {"op": "ite", "width": 16,
                "args": [_eq(phys, reg, 16), field, term]}
    return term


def _st_at(index: int, sw: dict[str, Any]) -> dict[str, Any]:
    """80-bit value of logical ST(index) selected by symbolic TOP."""
    phys = _phys(index, sw)
    term: dict[str, Any] = _input("x87_st0", 80)
    for reg in range(8):
        term = {"op": "ite", "width": 80,
                "args": [_eq(phys, reg, 16), _input(f"x87_st{reg}", 80), term]}
    return term


def _write_phys_st(phys: dict[str, Any], cond: dict[str, Any],
                   value: dict[str, Any], state: dict[str, dict[str, Any]]) -> None:
    """Write ``value`` into the physical register ``phys`` under ``cond``."""
    for reg in range(8):
        guard = _and1(cond, _eq(phys, reg, 16))
        previous = state.get(f"x87_st{reg}", _input(f"x87_st{reg}", 80))
        state[f"x87_st{reg}"] = {"op": "ite", "width": 80,
                                 "args": [guard, value, previous]}


def _write_phys_tag(phys: dict[str, Any], cond: dict[str, Any],
                    tag2: dict[str, Any], state: dict[str, dict[str, Any]]) -> None:
    """Write the 2-bit tag of physical register ``phys`` under ``cond``."""
    for reg in range(8):
        guard = _and1(cond, _eq(phys, reg, 16))
        cleared = _and16(state["x87_tag_word"], _constant(0xFFFF & ~(0x3 << (2 * reg)), 16))
        inserted = {"op": "shl", "width": 16,
                    "args": [_and16(tag2, _constant(3, 16)), _constant(2 * reg, 16)]}
        state["x87_tag_word"] = {"op": "ite", "width": 16,
                                 "args": [guard, _or16(cleared, inserted), state["x87_tag_word"]]}


def _set_top(top: dict[str, Any], sw: dict[str, Any]) -> dict[str, Any]:
    """Replace the TOP field of a status-word term."""
    shifted = {"op": "shl", "width": 16,
               "args": [_and16(top, _constant(7, 16)), _constant(11, 16)]}
    return _or16(_and16(sw, _constant(_TOP_KEEP, 16)), shifted)


def _tagof(value: dict[str, Any]) -> dict[str, Any]:
    """FPU_tagof over an ext80 value: 0 valid, 1 zero, 2 special."""
    exponent = _and({"op": "lshr", "width": 80,
                     "args": [value, _constant(64, 80)]}, _constant(0x7FFF, 80), 80)
    significand = {"op": "and", "width": 80,
                   "args": [value, _constant(0xFFFFFFFFFFFFFFFF, 80)]}
    msb = _ne({"op": "and", "width": 80,
               "args": [value, _constant(0x8000000000000000, 80)]}, 0, 80)
    inner = {"op": "ite", "width": 16,
             "args": [_eq(significand, 0, 80), _constant(1, 16), _constant(2, 16)]}
    outer = {"op": "ite", "width": 16,
             "args": [_eq(exponent, 0x7FFF, 80), _constant(2, 16),
                      {"op": "ite", "width": 16,
                       "args": [msb, _constant(0, 16), _constant(2, 16)]}]}
    return {"op": "ite", "width": 16,
            "args": [_eq(exponent, 0, 80), inner, outer]}


def _esb(sw: dict[str, Any], cw: dict[str, Any]) -> dict[str, Any]:
    """Recompute ES and B from the pending unmasked exceptions in ``sw``."""
    unmasked = _and16(sw, {"op": "and", "width": 16, "args": [
        {"op": "not", "width": 16, "args": [cw]}, _constant(X87_SW_EXCEPTION_MASK, 16)]})
    pending = _ne(unmasked, 0, 16)
    return _or16(_and16(sw, _constant(_ES_B_CLEAR, 16)),
                 _ite1(pending, _ES_B_SET, 0))


def _ie_masked(cw: dict[str, Any]) -> dict[str, Any]:
    """Width-1 predicate: the invalid-operation mask bit of the CW is set."""
    return _ne({"op": "and", "width": 16, "args": [cw, _constant(1, 16)]}, 0, 16)


def _true() -> dict[str, Any]:
    """Width-1 constant true."""
    return _constant(1, 1)


def _env_update(state: dict[str, dict[str, Any]], address: int, opcode_field: int,
                ea: dict[str, Any] | None = None, *, segment: str = "ds") -> None:
    """Record FIP/FCS-op (and FDP/FDS for memory forms) like Bochs.

    ``segment`` is the architectural default segment of the operand —
    ``"ss"`` when the effective address is EBP/ESP-based, ``"ds"``
    otherwise (override prefixes are not admitted).
    """
    state["x87_fip"] = _constant(address)
    state["x87_fcs_op"] = {"op": "or", "width": 32, "args": [
        _constant(opcode_field << 16), {"op": "zext", "width": 32, "args": [_input("cs", 16)]}]}
    if ea is not None:
        state["x87_fdp"] = ea
        state["x87_fds"] = {"op": "zext", "width": 32, "args": [_input(segment, 16)]}


def _operand_segment(instruction: X87StackInstruction) -> str:
    """Default data segment for the memory operand.

    32-bit ModRM addressing defaults to SS when EBP or ESP is the base
    register, DS otherwise (segment-override prefixes are not admitted, so
    the architectural default always applies).
    """
    if isinstance(instruction, StackLoadMemory80):
        base = instruction.source.base
    elif isinstance(instruction, StackStoreMemory80):
        base = instruction.destination.base
    else:
        return "ds"
    return "ss" if base in ("ebp", "esp") else "ds"


def _premises(instruction: X87StackInstruction) -> list[dict[str, str]]:
    """Serialize the checking and CPU-policy premises for this family."""
    premises = [_premise_pending(), _premise_cpu_policy(
        "stack fault responses (IE+SF flags, C1 on overflow, ext80 default QNaN "
        "on masked underflow, tag=tagof on write) follow the declared "
        "Pentium-class Bochs model"
    )]
    if isinstance(instruction, StackFree):
        premises.append(_premise_cpu_policy(
            "FFREE/FFREEP condition codes are undefined per the SDM; this model preserves C1"
        ))
    return premises


# ---------------------------------------------------------------------------
# Effects
# ---------------------------------------------------------------------------

def apply_x87_stack_effects(
    instruction: X87StackInstruction, state: dict[str, dict[str, Any]],
    memory: dict[str, Any], summary: dict[str, Any], address: int,
) -> None:
    """Write one admitted stack instruction's architectural effects.

    ``state`` maps output names to terms over the body's inputs; ``memory``
    is the input byte array. Only the named outputs change. A stack fault
    completes the instruction with the indefinite masked response when IE is
    masked and aborts it (flags only) when unmasked — the inverse of the
    session-5 draft, confirmed against real hardware (masked-overflow-audit).
    """
    sw0 = _input("x87_status_word", 16)
    cw = _input("x87_control_word", 16)
    state["x87_tag_word"] = _input("x87_tag_word", 16)
    sw = _and16(sw0, _constant(0xFFFF & ~_SW_C1, 16))
    ctx = {"state": state, "memory": memory, "sw0": sw0, "cw": cw,
           "top": _top(sw0), "masked": _ie_masked(cw), "sw": sw}
    if isinstance(instruction, (StackLoad, StackLoadMemory80, StackConstant)):
        ea = _load_effects(instruction, ctx)
    elif isinstance(instruction, (StackStore, StackStoreMemory80)):
        ea = _store_effects(instruction, ctx)
    else:
        _register_effects(instruction, ctx)
        ea = None
    _env_update(state, address, instruction.opcode, ea,
                segment=_operand_segment(instruction))
    summary["premises"] = _premises(instruction)


def _push(ctx: dict[str, Any], value: dict[str, Any], cond: dict[str, Any],
          sw: dict[str, Any]) -> None:
    """Push ``value`` under ``cond``: TOP-1, register and tag writes."""
    state = ctx["state"]
    destination = _phys(-1, ctx["sw0"])
    _write_phys_st(destination, cond, value, state)
    _write_phys_tag(destination, cond, _tagof(value), state)
    new_top = {"op": "ite", "width": 16, "args": [cond, destination, ctx["top"]]}
    state["x87_status_word"] = _set_top(new_top, _esb(sw, ctx["cw"]))


def _pop(ctx: dict[str, Any], cond: dict[str, Any], sw: dict[str, Any]) -> None:
    """Pop under ``cond``: empty the old tag and move TOP+1."""
    state = ctx["state"]
    top = ctx["top"]
    _write_phys_tag(top, cond, _constant(_TAG_EMPTY, 16), state)
    new_top = {"op": "ite", "width": 16, "args": [
        cond, _and16({"op": "add", "width": 16,
                      "args": [top, _constant(1, 16)]}, _constant(7, 16)), top]}
    state["x87_status_word"] = _set_top(new_top, _esb(sw, ctx["cw"]))


def _rounded_constant(instruction: StackConstant) -> dict[str, Any]:
    """Select the architectural constant using RC; PC does not affect FLDcon.

    All seven constants are nonnegative. The encoded value is nearest-even;
    the adjacent directed values are exact ext80 encodings validated against
    hardware. Loading a constant does not raise the precision exception.
    """
    opcode = instruction.opcode & 0xFF
    nearest = instruction.value
    if opcode in (0xE8, 0xEE):
        return _constant(nearest, 80)
    lower = nearest if opcode == 0xE9 else nearest - 1
    upper = lower + 1
    rc = _and16(_input("x87_control_word", 16), _constant(0x0C00, 16))
    downward = _or1(_eq(rc, 0x0400, 16), _eq(rc, 0x0C00, 16))
    return {"op": "ite", "width": 80, "args": [
        downward, _constant(lower, 80),
        {"op": "ite", "width": 80, "args": [
            _eq(rc, 0x0800, 16), _constant(upper, 80), _constant(nearest, 80)]}]}


def _load_effects(instruction: StackLoad | StackLoadMemory80 | StackConstant, ctx: dict[str, Any]) -> dict[str, Any] | None:
    """Model FLD ST(i)/m80/constants: push or fault with indefinite."""
    state = ctx["state"]
    sw0, masked, sw = ctx["sw0"], ctx["masked"], ctx["sw"]
    tw = state["x87_tag_word"]
    overflow = _ne(_tag_at(_phys(-1, sw0), tw), _TAG_EMPTY, 16)
    ea = None
    if isinstance(instruction, StackLoad):
        underflow = _eq(_tag_at(_phys(instruction.index, sw0), tw), _TAG_EMPTY, 16)
        source = _st_at(instruction.index, sw0)
        fault = _or1(overflow, underflow)
        faults = {"op": "ite", "width": 16, "args": [
            overflow, _constant(_SW_IE_SF | _SW_C1, 16),
            _ite1(underflow, _SW_IE_SF, 0)]}
    elif isinstance(instruction, StackConstant):
        source = _rounded_constant(instruction)
        fault = overflow
        faults = _ite1(overflow, _SW_IE_SF | _SW_C1, 0)
    else:
        ea = _word_address(instruction.source)
        low = {"op": "loadle", "width": 64, "args": [ctx["memory"], ea]}
        high = {"op": "loadle", "width": 16, "args": [
            ctx["memory"], {"op": "add", "width": 32, "args": [ea, _constant(8)]}]}
        source = {"op": "concat", "width": 80, "args": [high, low]}
        fault = overflow
        faults = _ite1(overflow, _SW_IE_SF | _SW_C1, 0)
    allowed = _or1(_not1(fault), masked)
    value = {"op": "ite", "width": 80,
             "args": [fault, _constant(X87_DEFAULT_NAN80, 80), source]}
    _push(ctx, value, allowed, _or16(sw, faults))
    return ea


def _store_effects(instruction: StackStore | StackStoreMemory80, ctx: dict[str, Any]) -> dict[str, Any] | None:
    """Model FST/FSTP ST(i) and FSTP m80: store ST(0) or the indefinite."""
    state = ctx["state"]
    sw0, masked, sw = ctx["sw0"], ctx["masked"], ctx["sw"]
    underflow = _eq(_tag_at(ctx["top"], state["x87_tag_word"]), _TAG_EMPTY, 16)
    value = {"op": "ite", "width": 80, "args": [
        underflow, _constant(X87_DEFAULT_NAN80, 80), _st_at(0, sw0)]}
    allowed = _or1(_not1(underflow), masked)
    sw = _or16(sw, _ite1(underflow, _SW_IE_SF, 0))
    if isinstance(instruction, StackStore):
        destination = _phys(instruction.index, sw0)
        _write_phys_st(destination, allowed, value, state)
        _write_phys_tag(destination, allowed, _tagof(value), state)
        if instruction.pop:
            _pop(ctx, allowed, sw)
        else:
            state["x87_status_word"] = _esb(sw, ctx["cw"])
        return None
    ea = _word_address(instruction.destination)
    memory = ctx["memory"]
    low = {"op": "ite", "width": 64, "args": [
        allowed, {"op": "trunc", "width": 64, "args": [value]},
        {"op": "loadle", "width": 64, "args": [memory, ea]}]}
    high_addr = {"op": "add", "width": 32, "args": [ea, _constant(8)]}
    high = {"op": "ite", "width": 16, "args": [
        allowed, {"op": "trunc", "width": 16, "args": [
            {"op": "lshr", "width": 80, "args": [value, _constant(64, 80)]}]},
        {"op": "loadle", "width": 16, "args": [memory, high_addr]}]}
    stored = {"op": "storele", "width": 0, "args": [memory, ea, low]}
    state["memory"] = {"op": "storele", "width": 0, "args": [stored, high_addr, high]}
    _pop(ctx, allowed, sw)
    return ea


def _register_effects(instruction: X87StackInstruction, ctx: dict[str, Any]) -> None:
    """Model FXCH/FFREE/FINCSTP/FDECSTP/FCHS/FABS (no memory operand)."""
    state = ctx["state"]
    sw0, masked, sw = ctx["sw0"], ctx["masked"], ctx["sw"]
    tw = state["x87_tag_word"]
    if isinstance(instruction, StackExchange):
        empty0 = _eq(_tag_at(ctx["top"], tw), _TAG_EMPTY, 16)
        emptyi = _eq(_tag_at(_phys(instruction.index, sw0), tw), _TAG_EMPTY, 16)
        underflow = _or1(empty0, emptyi)
        allowed = _or1(_not1(underflow), masked)
        sw = _or16(sw, _ite1(underflow, _SW_IE_SF, 0))
        v0 = {"op": "ite", "width": 80, "args": [
            empty0, _constant(X87_DEFAULT_NAN80, 80), _st_at(0, sw0)]}
        vi = {"op": "ite", "width": 80, "args": [
            emptyi, _constant(X87_DEFAULT_NAN80, 80), _st_at(instruction.index, sw0)]}
        _write_phys_st(ctx["top"], allowed, vi, state)
        _write_phys_tag(ctx["top"], allowed, _tagof(vi), state)
        _write_phys_st(_phys(instruction.index, sw0), allowed, v0, state)
        _write_phys_tag(_phys(instruction.index, sw0), allowed, _tagof(v0), state)
        state["x87_status_word"] = _esb(sw, ctx["cw"])
        return None
    if isinstance(instruction, StackFree):
        _write_phys_tag(_phys(instruction.index, sw0), _true(),
                        _constant(_TAG_EMPTY, 16), state)
        if instruction.pop:
            stepped = _and16({"op": "add", "width": 16,
                              "args": [ctx["top"], _constant(1, 16)]},
                             _constant(7, 16))
            state["x87_status_word"] = _set_top(stepped, _esb(sw, ctx["cw"]))
            return None
        state["x87_status_word"] = _esb(sw, ctx["cw"])
        return None
    if isinstance(instruction, StackTopStep):
        stepped = _and16({"op": "add", "width": 16,
                          "args": [ctx["top"], _constant(instruction.delta & 0xFFFF, 16)]},
                         _constant(7, 16))
        state["x87_status_word"] = _set_top(stepped, _esb(sw, ctx["cw"]))
        return None
    if isinstance(instruction, StackSignOp):
        underflow = _eq(_tag_at(ctx["top"], tw), _TAG_EMPTY, 16)
        allowed = _or1(_not1(underflow), masked)
        sw = _or16(sw, _ite1(underflow, _SW_IE_SF, 0))
        current = _st_at(0, sw0)
        if instruction.absolute:
            modified = {"op": "and", "width": 80,
                        "args": [current, _constant(0x7FFFFFFFFFFFFFFFFFFF, 80)]}
        else:
            modified = {"op": "xor", "width": 80,
                        "args": [current, _constant(0x80000000000000000000, 80)]}
        value = {"op": "ite", "width": 80, "args": [
            underflow, _constant(X87_DEFAULT_NAN80, 80), modified]}
        _write_phys_st(ctx["top"], allowed, value, state)
        _write_phys_tag(ctx["top"], allowed, _tagof(value), state)
        state["x87_status_word"] = _esb(sw, ctx["cw"])
        return None
    raise ValueError(f"unsupported native x87 stack instruction: {instruction!r}")


def x87_stack_kind(instruction: X87StackInstruction) -> str:
    """Name the admitted stack instruction family for provenance records."""
    if isinstance(instruction, StackLoad):
        return "native_fld_sti"
    if isinstance(instruction, StackLoadMemory80):
        return "native_fld_m80"
    if isinstance(instruction, StackStore):
        return "native_fstp_sti" if instruction.pop else "native_fst_sti"
    if isinstance(instruction, StackStoreMemory80):
        return "native_fstp_m80"
    if isinstance(instruction, StackExchange):
        return "native_fxch"
    if isinstance(instruction, StackFree):
        return "native_ffreep" if instruction.pop else "native_ffree"
    if isinstance(instruction, StackTopStep):
        return "native_fincstp" if instruction.delta > 0 else "native_fdecstp"
    if isinstance(instruction, StackConstant):
        return f"native_{instruction.mnemonic}"
    return "native_fabs" if instruction.absolute else "native_fchs"
