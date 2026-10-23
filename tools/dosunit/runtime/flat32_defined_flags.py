"""Layer: dosunit concrete execution admission.

Responsibility: track architecturally undefined integer flags along an executed
path so emulator-specific values cannot justify a concrete counterexample.
"""

from __future__ import annotations

from enum import StrEnum

import capstone
from capstone import x86_const as x86

CF: int = 0x001
PF: int = 0x004
AF: int = 0x010
ZF: int = 0x040
SF: int = 0x080
OF: int = 0x800
ARITHMETIC_FLAGS: int = CF | PF | AF | ZF | SF | OF
_READS: dict[int, int] = {
    x86.X86_INS_JA: CF | ZF, x86.X86_INS_JAE: CF,
    x86.X86_INS_JB: CF, x86.X86_INS_JBE: CF | ZF,
    x86.X86_INS_JE: ZF, x86.X86_INS_JNE: ZF,
    x86.X86_INS_JG: ZF | SF | OF, x86.X86_INS_JGE: SF | OF,
    x86.X86_INS_JL: SF | OF, x86.X86_INS_JLE: ZF | SF | OF,
    x86.X86_INS_JO: OF, x86.X86_INS_JNO: OF,
    x86.X86_INS_JS: SF, x86.X86_INS_JNS: SF,
    x86.X86_INS_JP: PF, x86.X86_INS_JNP: PF,
}
_DEFINES: dict[int, int] = {
    x86.X86_INS_ADD: ARITHMETIC_FLAGS, x86.X86_INS_SUB: ARITHMETIC_FLAGS,
    x86.X86_INS_CMP: ARITHMETIC_FLAGS,
    x86.X86_INS_INC: ARITHMETIC_FLAGS & ~CF, x86.X86_INS_DEC: ARITHMETIC_FLAGS & ~CF,
    x86.X86_INS_AND: ARITHMETIC_FLAGS & ~AF, x86.X86_INS_OR: ARITHMETIC_FLAGS & ~AF,
    x86.X86_INS_XOR: ARITHMETIC_FLAGS & ~AF, x86.X86_INS_TEST: ARITHMETIC_FLAGS & ~AF,
    x86.X86_INS_IMUL: CF | OF,
}
_UNDEFINES: dict[int, int] = {
    x86.X86_INS_AND: AF, x86.X86_INS_OR: AF, x86.X86_INS_XOR: AF, x86.X86_INS_TEST: AF,
    x86.X86_INS_IMUL: PF | AF | ZF | SF,
}


class FlagAdmissionReason(StrEnum):
    """Why a narrowed concrete execution cannot supply deterministic evidence."""

    UNDEFINED_INPUT = 'undefined_integer_flag_consumed'
    UNSUPPORTED_EFFECT = 'integer_flag_effect_not_admitted'


def _sar_flags(instruction: capstone.CsInsn, undefined: int) -> tuple[int, FlagAdmissionReason | None]:
    """Handle immediate SAR, including masked zero counts and narrow operands."""
    operands = instruction.operands
    if len(operands) != 2 or operands[1].type != x86.X86_OP_IMM:
        return undefined, FlagAdmissionReason.UNSUPPORTED_EFFECT
    width = operands[0].size * 8
    if width not in (8, 16, 32):
        return undefined, FlagAdmissionReason.UNSUPPORTED_EFFECT
    count = operands[1].imm & 31
    if not count:
        return undefined, None
    # Conservatively exclude CF at counts >= width even where a particular
    # processor supplies the sign bit. OF is defined only for count one.
    newly_undefined = AF | (OF if count != 1 else 0) | (CF if count >= width else 0)
    return (undefined & ~ARITHMETIC_FLAGS) | newly_undefined, None


def advance_integer_flags(
    instruction: capstone.CsInsn, undefined: int,
) -> tuple[int, FlagAdmissionReason | None]:
    """Check flag reads, then propagate definitions for the admitted instruction.

    Entry flags are concrete inputs. An undefined value stays tainted through
    preserving instructions until a defined write replaces it. This contract
    only guards narrowed integer replay; it does not modify guest execution.
    """
    identity = instruction.id
    if identity in _READS:
        reason = FlagAdmissionReason.UNDEFINED_INPUT if _READS[identity] & undefined else None
        return undefined, reason
    if identity == x86.X86_INS_SAR:
        return _sar_flags(instruction, undefined)
    if identity in _DEFINES:
        return (undefined & ~_DEFINES[identity]) | _UNDEFINES.get(identity, 0), None
    if instruction.eflags:
        return undefined, FlagAdmissionReason.UNSUPPORTED_EFFECT
    return undefined, None
