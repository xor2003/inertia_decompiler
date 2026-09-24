"""Classify borrowed real-mode instruction cases for exhaustive verification.

Layer: Frontend verification.
Responsibility: decide whether a corpus case needs hardware-state verification,
is already symbolically proven by pyvex comparison, or has undefined results.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .coverage_manifest import COMPARE_VERIFIED_MOO_OPCODES


class BorrowCaseDisposition(StrEnum):
    """Required verification treatment for one borrowed hardware case."""

    PYVEX_PROVEN = "pyvex_proven"
    HARDWARE_REQUIRED = "hardware_required"
    UNDEFINED_EXCLUDED = "undefined_excluded"
    OUT_OF_SCOPE_EXCLUDED = "out_of_scope_excluded"
    ORACLE_DEFECT_EXCLUDED = "oracle_defect_excluded"


@dataclass(frozen=True, slots=True)
class BorrowCaseClassification:
    """Typed classification and durable reason for one corpus case."""

    disposition: BorrowCaseDisposition
    reason: str


_PREFIX_BYTES = frozenset({0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3})
_DOUBLE_SHIFT_IMMEDIATE = frozenset({0xA4, 0xAC})
_DOUBLE_SHIFT_CL = frozenset({0xA5, 0xAD})
_LOCKABLE_RMW_MNEMONICS = frozenset(
    {"adc", "add", "and", "btc", "btr", "bts", "cmpxchg", "dec", "inc", "neg", "not", "or", "sbb", "sub", "xadd", "xchg", "xor"}
)
_PREFIX_GROUPS = (
    frozenset({0xF0, 0xF2, 0xF3}),
    frozenset({0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65}),
    frozenset({0x66}),
    frozenset({0x67}),
)


def _instruction_opcode(case: dict[str, Any]) -> tuple[int, int | None]:
    """Return the first architectural opcode byte and optional 0F extension."""
    raw = bytes(int(value) for value in case.get("bytes", []))
    index = 0
    while index < len(raw) and raw[index] in _PREFIX_BYTES:
        index += 1
    first = raw[index] if index < len(raw) else -1
    second = raw[index + 1] if first == 0x0F and index + 1 < len(raw) else None
    return first, second


def _has_unusable_lock_prefix(case: dict[str, Any]) -> bool:
    """Return whether LOCK is applied to a form ordinary DOS code cannot use."""
    raw = bytes(int(value) for value in case.get("bytes", []))
    index = 0
    has_lock = False
    while index < len(raw) and raw[index] in _PREFIX_BYTES:
        has_lock |= raw[index] == 0xF0
        index += 1
    if not has_lock:
        return False
    words = str(case.get("name", "")).lower().split()
    try:
        lock_index = words.index("lock")
    except ValueError:
        return True
    if lock_index + 1 >= len(words):
        return True
    mnemonic = words[lock_index + 1]
    destination = " ".join(words[lock_index + 2 :]).split(",", maxsplit=1)[0]
    return mnemonic not in _LOCKABLE_RMW_MNEMONICS or "[" not in destination


def _has_duplicate_prefix_group(case: dict[str, Any]) -> bool:
    """Return whether the instruction repeats a prefix from one architectural group."""
    raw = bytes(int(value) for value in case.get("bytes", []))
    counts = [0] * len(_PREFIX_GROUPS)
    for value in raw:
        if value not in _PREFIX_BYTES:
            break
        for index, group in enumerate(_PREFIX_GROUPS):
            if value in group:
                counts[index] += 1
                break
    return any(count > 1 for count in counts)


def _has_pathological_enter_frame_overlap(case: dict[str, Any]) -> bool:
    """Return whether nested ENTER copies from the stack slots it is creating."""
    raw = bytes(int(value) for value in case.get("bytes", []))
    opcode_index = 0
    while opcode_index < len(raw) and raw[opcode_index] in _PREFIX_BYTES:
        opcode_index += 1
    if opcode_index + 3 >= len(raw) or raw[opcode_index] != 0xC8:
        return False
    nesting_level = raw[opcode_index + 3] & 0x1F
    if nesting_level <= 1:
        return False
    registers = case.get("initial", {}).get("regs", {})
    bp = int(registers.get("ebp", registers.get("bp", -1))) & 0xFFFF
    sp = int(registers.get("esp", registers.get("sp", -2))) & 0xFFFF
    return bp == sp


def _far_pointer_crosses_segment_end(case: dict[str, Any]) -> bool:
    """Return whether an address-size-16 far pointer object straddles offset FFFFh."""
    raw = bytes(int(value) for value in case.get("bytes", []))
    opcode_index = 0
    address_size_32 = False
    operand_size_32 = False
    while opcode_index < len(raw) and raw[opcode_index] in _PREFIX_BYTES:
        address_size_32 |= raw[opcode_index] == 0x67
        operand_size_32 |= raw[opcode_index] == 0x66
        opcode_index += 1
    if address_size_32 or opcode_index + 1 >= len(raw) or raw[opcode_index] != 0xFF:
        return False
    modrm = raw[opcode_index + 1]
    mode = modrm >> 6
    extension = (modrm >> 3) & 0x7
    rm = modrm & 0x7
    if mode == 3 or extension not in {3, 5}:
        return False

    registers = case.get("initial", {}).get("regs", {})
    bases: tuple[tuple[str, ...], ...] = (
        ("bx", "si"),
        ("bx", "di"),
        ("bp", "si"),
        ("bp", "di"),
        ("si",),
        ("di",),
        ("bp",),
        ("bx",),
    )
    cursor = opcode_index + 2
    if mode == 0 and rm == 6:
        if cursor + 1 >= len(raw):
            return False
        offset = raw[cursor] | (raw[cursor + 1] << 8)
    else:
        offset = sum(int(registers.get(name, 0)) for name in bases[rm])
        if mode == 1:
            if cursor >= len(raw):
                return False
            displacement = raw[cursor] - 0x100 if raw[cursor] & 0x80 else raw[cursor]
            offset += displacement
        elif mode == 2:
            if cursor + 1 >= len(raw):
                return False
            displacement = raw[cursor] | (raw[cursor + 1] << 8)
            offset += displacement - 0x10000 if displacement & 0x8000 else displacement
    pointer_size = 6 if operand_size_32 else 4
    return (offset & 0xFFFF) > 0x10000 - pointer_size


def _double_shift_width_and_count(case: dict[str, Any]) -> tuple[int, int] | None:
    """Return SHLD/SHRD operand width and masked count, or ``None``."""
    raw = bytes(int(value) for value in case.get("bytes", []))
    if raw.endswith(b"\xf4"):
        raw = raw[:-1]
    index = 0
    operand32 = False
    while index < len(raw) and raw[index] in _PREFIX_BYTES:
        if raw[index] == 0x66:
            operand32 = not operand32
        index += 1
    if index + 1 >= len(raw) or raw[index] != 0x0F:
        return None
    opcode = raw[index + 1]
    if opcode not in _DOUBLE_SHIFT_IMMEDIATE | _DOUBLE_SHIFT_CL:
        return None
    width = 32 if operand32 else 16
    count = (
        raw[-1] & 0x1F
        if opcode in _DOUBLE_SHIFT_IMMEDIATE
        else int(case["initial"]["regs"]["ecx"]) & 0x1F
    )
    return width, count


def _has_suppressed_sib_index_oracle_defect(case: dict[str, Any]) -> bool:
    """Return whether a 386E witness incorrectly materializes SIB index field 100."""
    raw = bytes(int(value) for value in case.get("bytes", []))
    index = 0
    address32 = False
    while index < len(raw) and raw[index] in _PREFIX_BYTES:
        if raw[index] == 0x67:
            address32 = not address32
        index += 1
    if not address32 or index >= len(raw):
        return False
    one_byte_opcodes = {0x83, 0x87, 0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3, 0xF6, 0xF7}
    two_byte_opcodes = {0xA3, 0xAB, 0xB3, 0xBA, 0xBB}
    if raw[index] == 0x0F:
        if index + 3 >= len(raw) or raw[index + 1] not in two_byte_opcodes:
            return False
        modrm_index = index + 2
    else:
        if index + 2 >= len(raw) or raw[index] not in one_byte_opcodes:
            return False
        modrm_index = index + 1
    modrm = raw[modrm_index]
    if (modrm >> 6) == 3 or (modrm & 7) != 4:
        return False
    sib = raw[modrm_index + 1]
    return ((sib >> 3) & 7) == 4


def _idiv8_divisor_byte_8616(
    case: dict[str, Any], modrm: int, regs: dict[str, Any]
) -> int | None:
    """Resolve the raw unsigned divisor byte for one IDIV r/m8 form."""
    if (modrm >> 6) == 3:
        register_values = (
            int(regs.get("eax", 0)),
            int(regs.get("ecx", 0)),
            int(regs.get("edx", 0)),
            int(regs.get("ebx", 0)),
        )
        register_code = modrm & 7
        register_value = register_values[register_code & 3]
        return (register_value >> (8 if register_code >= 4 else 0)) & 0xFF
    initial = case.get("initial", {})
    effective_address = initial.get("ea")
    if not isinstance(effective_address, dict) or "p_addr" not in effective_address:
        return None
    ram = dict(initial.get("ram", []))
    divisor = ram.get(int(effective_address["p_addr"]))
    if divisor is None:
        return None
    return int(divisor) & 0xFF


def _idiv8_quotient_overflows_8616(divisor_raw: int, dividend_raw: int) -> bool:
    """Return whether signed IDIV8 semantics must fault for these operands."""
    divisor_signed = divisor_raw - 0x100 if divisor_raw & 0x80 else divisor_raw
    dividend_signed = dividend_raw - 0x10000 if dividend_raw & 0x8000 else dividend_raw
    if divisor_signed == 0:
        return True
    quotient = abs(dividend_signed) // abs(divisor_signed)
    if (dividend_signed < 0) != (divisor_signed < 0):
        quotient = -quotient
    return not -0x80 <= quotient <= 0x7F


def _has_missing_idiv8_fault_oracle_defect(case: dict[str, Any]) -> bool:
    """Return whether a 386E IDIV8 trace omits a mandatory divide error."""
    raw = bytes(int(value) for value in case.get("bytes", []))
    index = 0
    while index < len(raw) and raw[index] in _PREFIX_BYTES:
        index += 1
    if index + 1 >= len(raw) or raw[index] != 0xF6:
        return False
    modrm = raw[index + 1]
    if ((modrm >> 3) & 7) != 7:
        return False
    exception = case.get("exception")
    if isinstance(exception, dict) and int(exception.get("number", -1)) == 0:
        return False

    initial = case.get("initial", {})
    regs = initial.get("regs", {})
    if not isinstance(regs, dict) or "eax" not in regs:
        return False
    divisor_raw = _idiv8_divisor_byte_8616(case, modrm, regs)
    if divisor_raw is None:
        return False
    dividend_raw = int(regs["eax"]) & 0xFFFF
    return _idiv8_quotient_overflows_8616(divisor_raw, dividend_raw)


def _classify_scope_exclusion_8616(
    case: dict[str, Any],
) -> BorrowCaseClassification | None:
    """Return the out-of-scope or undefined exclusion that applies, if any."""
    if _has_unusable_lock_prefix(case):
        return BorrowCaseClassification(
            BorrowCaseDisposition.OUT_OF_SCOPE_EXCLUDED,
            "LOCK form is invalid or not usable by ordinary real-mode DOS code",
        )
    if _has_duplicate_prefix_group(case):
        return BorrowCaseClassification(
            BorrowCaseDisposition.UNDEFINED_EXCLUDED,
            "multiple prefixes from one architectural prefix group have undefined selection",
        )
    if _has_pathological_enter_frame_overlap(case):
        return BorrowCaseClassification(
            BorrowCaseDisposition.OUT_OF_SCOPE_EXCLUDED,
            "nested ENTER frame source overlaps the stack slots being created",
        )
    if _far_pointer_crosses_segment_end(case):
        return BorrowCaseClassification(
            BorrowCaseDisposition.OUT_OF_SCOPE_EXCLUDED,
            "far-pointer object straddles the 64 KiB end of its segment",
        )
    return None


def _classify_80386_case_8616(
    case: dict[str, Any],
) -> BorrowCaseClassification | None:
    """Return the 80386-specific oracle defect or scope verdict, if any."""
    if _has_missing_idiv8_fault_oracle_defect(case):
        return BorrowCaseClassification(
            BorrowCaseDisposition.ORACLE_DEFECT_EXCLUDED,
            "386E trace omits the mandatory signed-byte divide error",
        )
    if _has_suppressed_sib_index_oracle_defect(case):
        return BorrowCaseClassification(
            BorrowCaseDisposition.ORACLE_DEFECT_EXCLUDED,
            "386E trace applies a SIB index that architectural decoding suppresses",
        )
    first_opcode, second_opcode = _instruction_opcode(case)
    if 0xD8 <= first_opcode <= 0xDF:
        return BorrowCaseClassification(
            BorrowCaseDisposition.OUT_OF_SCOPE_EXCLUDED,
            "x87 coprocessor instructions are deferred to a separate implementation",
        )
    if first_opcode == 0x0F and second_opcode in {0x20, 0x21, 0x22, 0x23, 0x24, 0x26}:
        return BorrowCaseClassification(
            BorrowCaseDisposition.OUT_OF_SCOPE_EXCLUDED,
            "control, debug, and test registers are outside DOS real-mode scope",
        )
    double_shift = _double_shift_width_and_count(case)
    if double_shift is not None:
        width, count = double_shift
        if count > width:
            return BorrowCaseClassification(
                BorrowCaseDisposition.UNDEFINED_EXCLUDED,
                f"double-shift count {count} exceeds {width}-bit operand width",
            )
    if first_opcode == 0x0F and second_opcode in {0xBC, 0xBD}:
        source = int(case["initial"].get("src", 1))
        if source == 0:
            return BorrowCaseClassification(
                BorrowCaseDisposition.UNDEFINED_EXCLUDED,
                "BSF/BSR destination is undefined for a zero source",
            )
    return None


def classify_borrow_case(cpu: str, opcode: str, case: dict[str, Any]) -> BorrowCaseClassification:
    """Classify one 80286 or 80386 corpus case without executing it."""
    normalized_cpu = cpu.strip().lower()
    normalized_opcode = opcode.upper()
    scope_exclusion = _classify_scope_exclusion_8616(case)
    if scope_exclusion is not None:
        return scope_exclusion
    if normalized_cpu == "80286" and normalized_opcode in COMPARE_VERIFIED_MOO_OPCODES:
        return BorrowCaseClassification(
            BorrowCaseDisposition.PYVEX_PROVEN,
            "opcode family has symbolic upstream-pyvex comparison coverage",
        )
    if normalized_cpu == "80386":
        classified = _classify_80386_case_8616(case)
        if classified is not None:
            return classified
    exception = case.get("exception")
    if isinstance(exception, dict) and int(exception.get("number", -1)) not in {-1, 0}:
        return BorrowCaseClassification(
            BorrowCaseDisposition.OUT_OF_SCOPE_EXCLUDED,
            f"fault vector {int(exception['number'])} is outside the practical DOS audit scope",
        )
    return BorrowCaseClassification(
        BorrowCaseDisposition.HARDWARE_REQUIRED,
        "architecturally defined case requires hardware-state comparison",
    )


__all__ = [
    "BorrowCaseClassification",
    "BorrowCaseDisposition",
    "classify_borrow_case",
]
