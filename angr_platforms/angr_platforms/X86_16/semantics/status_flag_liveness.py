"""Typed status-flag liveness for decoded x86 instructions.

Layer: Semantics.
Responsibility: classify decoded instruction status-flag reads and definite
overwrites, then prove when an earlier flag definition dies before any use.
Consumes frontend decoder metadata only; never inspects assembly or rendered C.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, cast

from capstone import CS_OP_IMM

from .status_flag_contracts import (
    INCDEC_STATUS_FLAG_WRITES_8616,
    LOGICAL_STATUS_FLAG_WRITES_8616,
    SHIFT_COUNT_ONE_STATUS_FLAG_WRITES_8616,
    STATUS_FLAGS_8616,
    DecodedStatusFlagInstruction8616,
    StatusFlag8616,
    StatusFlagEffect8616,
    StatusFlagLivenessDecision8616,
    StatusFlagLivenessStats8616,
    StatusFlagLivenessVerdict8616,
)


class _CapstoneOperandBoundary8616(Protocol):
    """Third-party Capstone operand fields used by the decode adapter."""

    type: int
    imm: int


class _CapstoneInstructionBoundary8616(Protocol):
    """Third-party Capstone instruction fields used by the decode adapter."""

    mnemonic: str
    operands: Sequence[object]


class _FutureInstructionBoundary8616(Protocol):
    """Third-party pyvex future-instruction wrapper used by the frontend."""

    cs: _CapstoneInstructionBoundary8616


_TRANSPARENT_MNEMONICS_8616 = frozenset(
    {
        "bswap",
        "cbw",
        "cdq",
        "cld",
        "cli",
        "cwd",
        "cwde",
        "enter",
        "in",
        "ins",
        "insb",
        "insw",
        "lea",
        "leave",
        "lds",
        "les",
        "lfs",
        "lgs",
        "lods",
        "lodsb",
        "lodsw",
        "lss",
        "mov",
        "movs",
        "movsb",
        "movsw",
        "movsx",
        "movzx",
        "nop",
        "not",
        "out",
        "outs",
        "outsb",
        "outsw",
        "pop",
        "push",
        "ret",
        "retf",
        "retn",
        "std",
        "sti",
        "stos",
        "stosb",
        "stosw",
        "xchg",
        "xlat",
    }
)
_FULL_WRITER_MNEMONICS_8616 = frozenset(
    {"add", "cmp", "cmps", "cmpsb", "cmpsw", "neg", "scas", "scasb", "scasw", "sub"}
)
_LOGICAL_WRITER_MNEMONICS_8616 = frozenset({"and", "or", "test", "xor"})
_COUNTED_SHIFT_MNEMONICS_8616 = frozenset({"sal", "sar", "shl", "shld", "shr", "shrd"})
_COUNTED_ROTATE_MNEMONICS_8616 = frozenset({"rcl", "rcr", "rol", "ror"})
_MNEMONIC_PREFIXES_8616 = frozenset({"bnd", "lock", "rep", "repe", "repne", "repnz", "repz"})
_LAHF_FLAGS_8616 = (
    StatusFlag8616.CARRY
    | StatusFlag8616.PARITY
    | StatusFlag8616.AUXILIARY
    | StatusFlag8616.ZERO
    | StatusFlag8616.SIGN
)


def decoded_status_flag_instruction_8616(instruction: object) -> DecodedStatusFlagInstruction8616 | None:
    """Project a pyvex/Capstone instruction boundary into typed evidence."""
    try:
        decoded = cast(_FutureInstructionBoundary8616, instruction).cs
        mnemonic_parts = str(decoded.mnemonic).lower().split()
    except (AttributeError, TypeError, ValueError):
        return None
    while mnemonic_parts and mnemonic_parts[0] in _MNEMONIC_PREFIXES_8616:
        mnemonic_parts.pop(0)
    if not mnemonic_parts:
        return None
    mnemonic = mnemonic_parts[0]
    immediate_count: int | None = None
    if mnemonic in _COUNTED_SHIFT_MNEMONICS_8616 | _COUNTED_ROTATE_MNEMONICS_8616:
        try:
            operands = tuple(decoded.operands)
        except (AttributeError, TypeError):
            operands = ()
        if len(operands) >= 2:
            count_operand = cast(_CapstoneOperandBoundary8616, operands[-1])
            try:
                if count_operand.type == CS_OP_IMM:
                    immediate_count = int(count_operand.imm)
            except (AttributeError, TypeError, ValueError):
                immediate_count = None
    return DecodedStatusFlagInstruction8616(mnemonic, immediate_count)


def binop_status_flag_writes_8616(op_name: str) -> StatusFlag8616 | None:
    """Return status bits written by one simple-lifter binary operation."""
    if op_name in {"add", "sub"}:
        return STATUS_FLAGS_8616
    if op_name in {"and", "or", "xor"}:
        return LOGICAL_STATUS_FLAG_WRITES_8616
    return None


def _condition_reads_8616(mnemonic: str) -> StatusFlag8616 | None:
    """Return status bits read by a Jcc, SETcc, or CMOVcc mnemonic."""
    suffix: str | None = None
    if mnemonic.startswith("cmov"):
        suffix = mnemonic[4:]
    elif mnemonic.startswith("set"):
        suffix = mnemonic[3:]
    elif mnemonic.startswith("j") and mnemonic not in {"jmp", "jcxz", "jecxz"}:
        suffix = mnemonic[1:]
    if suffix is None:
        return None
    groups = (
        ({"o", "no"}, StatusFlag8616.OVERFLOW),
        ({"b", "c", "nae", "nb", "nc", "ae"}, StatusFlag8616.CARRY),
        ({"e", "z", "ne", "nz"}, StatusFlag8616.ZERO),
        ({"be", "na", "a", "nbe"}, StatusFlag8616.CARRY | StatusFlag8616.ZERO),
        ({"s", "ns"}, StatusFlag8616.SIGN),
        ({"p", "pe", "np", "po"}, StatusFlag8616.PARITY),
        ({"l", "nge", "ge", "nl"}, StatusFlag8616.SIGN | StatusFlag8616.OVERFLOW),
        (
            {"le", "ng", "g", "nle"},
            StatusFlag8616.ZERO | StatusFlag8616.SIGN | StatusFlag8616.OVERFLOW,
        ),
    )
    for aliases, reads in groups:
        if suffix in aliases:
            return reads
    return None


def status_flag_effect_8616(instruction: DecodedStatusFlagInstruction8616) -> StatusFlagEffect8616 | None:
    """Classify one decoded instruction, refusing unknown flag behavior."""
    mnemonic = instruction.mnemonic
    condition_reads = _condition_reads_8616(mnemonic)
    if condition_reads is not None:
        return StatusFlagEffect8616(reads=condition_reads)
    if mnemonic in _TRANSPARENT_MNEMONICS_8616 or mnemonic in {"jcxz", "jecxz", "jmp", "loop"}:
        return StatusFlagEffect8616()
    if mnemonic in _FULL_WRITER_MNEMONICS_8616:
        return StatusFlagEffect8616(overwrites=STATUS_FLAGS_8616)
    if mnemonic in _LOGICAL_WRITER_MNEMONICS_8616:
        return StatusFlagEffect8616(overwrites=LOGICAL_STATUS_FLAG_WRITES_8616)
    if mnemonic in {"adc", "sbb"}:
        return StatusFlagEffect8616(reads=StatusFlag8616.CARRY, overwrites=STATUS_FLAGS_8616)
    if mnemonic in {"inc", "dec"}:
        return StatusFlagEffect8616(overwrites=INCDEC_STATUS_FLAG_WRITES_8616)
    if mnemonic in _COUNTED_SHIFT_MNEMONICS_8616:
        return _counted_shift_effect_8616(instruction)
    if mnemonic in _COUNTED_ROTATE_MNEMONICS_8616:
        return _counted_rotate_effect_8616(instruction)
    return _fixed_mnemonic_effect_8616(mnemonic)


def _counted_shift_effect_8616(
    instruction: DecodedStatusFlagInstruction8616,
) -> StatusFlagEffect8616:
    """Classify one counted shift's flag writes."""
    if instruction.immediate_count is None:
        return StatusFlagEffect8616()
    count = instruction.immediate_count & 0x1F
    if count == 0:
        return StatusFlagEffect8616()
    writes = (
        StatusFlag8616.CARRY | StatusFlag8616.PARITY | StatusFlag8616.ZERO | StatusFlag8616.SIGN
    )
    if count == 1:
        writes |= StatusFlag8616.OVERFLOW
    return StatusFlagEffect8616(overwrites=writes)


def _counted_rotate_effect_8616(
    instruction: DecodedStatusFlagInstruction8616,
) -> StatusFlagEffect8616 | None:
    """Classify one counted rotate's flag reads and writes."""
    mnemonic = instruction.mnemonic
    if instruction.immediate_count is None:
        return None if mnemonic in {"rcl", "rcr"} else StatusFlagEffect8616()
    count = instruction.immediate_count & 0x1F
    if count == 0:
        return StatusFlagEffect8616()
    reads = StatusFlag8616.CARRY if mnemonic in {"rcl", "rcr"} else StatusFlag8616.NONE
    writes = StatusFlag8616.CARRY
    if count == 1:
        writes |= StatusFlag8616.OVERFLOW
    return StatusFlagEffect8616(reads=reads, overwrites=writes)


_FIXED_MNEMONIC_EFFECTS_8616 = {
    "clc": StatusFlagEffect8616(overwrites=StatusFlag8616.CARRY),
    "stc": StatusFlagEffect8616(overwrites=StatusFlag8616.CARRY),
    "cmc": StatusFlagEffect8616(
        reads=StatusFlag8616.CARRY,
        overwrites=StatusFlag8616.CARRY,
    ),
    "lahf": StatusFlagEffect8616(reads=_LAHF_FLAGS_8616),
    "sahf": StatusFlagEffect8616(overwrites=_LAHF_FLAGS_8616),
    "pushf": StatusFlagEffect8616(reads=STATUS_FLAGS_8616),
    "pushfd": StatusFlagEffect8616(reads=STATUS_FLAGS_8616),
    "popf": StatusFlagEffect8616(overwrites=STATUS_FLAGS_8616),
    "popfd": StatusFlagEffect8616(overwrites=STATUS_FLAGS_8616),
    "iret": StatusFlagEffect8616(overwrites=STATUS_FLAGS_8616),
    "iretd": StatusFlagEffect8616(overwrites=STATUS_FLAGS_8616),
    "loope": StatusFlagEffect8616(reads=StatusFlag8616.ZERO),
    "loopz": StatusFlagEffect8616(reads=StatusFlag8616.ZERO),
    "loopne": StatusFlagEffect8616(reads=StatusFlag8616.ZERO),
    "loopnz": StatusFlagEffect8616(reads=StatusFlag8616.ZERO),
    "into": StatusFlagEffect8616(reads=StatusFlag8616.OVERFLOW),
}


def _fixed_mnemonic_effect_8616(mnemonic: str) -> StatusFlagEffect8616 | None:
    """Return the fixed flag effect for one mnemonic, if any."""
    return _FIXED_MNEMONIC_EFFECTS_8616.get(mnemonic)


def _status_flag_liveness_decision_8616(
    written: StatusFlag8616,
    remaining: StatusFlag8616,
    verdict: StatusFlagLivenessVerdict8616,
    *,
    failed: bool = False,
) -> StatusFlagLivenessDecision8616:
    """Materialize one final typed decision with closed evidence accounting."""
    return StatusFlagLivenessDecision8616(
        written=written,
        remaining=remaining,
        verdict=verdict,
        stats=StatusFlagLivenessStats8616(1, 1, 1, 1, int(failed)),
    )


def decide_status_flag_liveness_8616(
    written: StatusFlag8616,
    future_instructions: Sequence[DecodedStatusFlagInstruction8616],
) -> StatusFlagLivenessDecision8616:
    """Classify and materialize one conservative keep-or-suppress decision."""
    remaining = written & STATUS_FLAGS_8616
    if int(remaining) == 0:
        return _status_flag_liveness_decision_8616(
            written,
            remaining,
            StatusFlagLivenessVerdict8616.SUPPRESS_DEAD,
        )
    for instruction in future_instructions:
        effect = status_flag_effect_8616(instruction)
        if effect is None:
            return _status_flag_liveness_decision_8616(
                written,
                remaining,
                StatusFlagLivenessVerdict8616.KEEP_UNKNOWN,
                failed=True,
            )
        if effect.reads & remaining:
            return _status_flag_liveness_decision_8616(
                written,
                remaining,
                StatusFlagLivenessVerdict8616.KEEP_LIVE,
            )
        remaining &= ~effect.overwrites
        if int(remaining) == 0:
            return _status_flag_liveness_decision_8616(
                written,
                remaining,
                StatusFlagLivenessVerdict8616.SUPPRESS_DEAD,
            )
    return _status_flag_liveness_decision_8616(
        written,
        remaining,
        StatusFlagLivenessVerdict8616.KEEP_LIVE,
    )


def status_flags_dead_before_use_8616(
    written: StatusFlag8616,
    future_instructions: Sequence[DecodedStatusFlagInstruction8616],
) -> bool:
    """Return whether the closed liveness decision suppresses the flag write."""
    return bool(decide_status_flag_liveness_8616(written, future_instructions).suppresses_write)


__all__ = [
    "INCDEC_STATUS_FLAG_WRITES_8616",
    "LOGICAL_STATUS_FLAG_WRITES_8616",
    "SHIFT_COUNT_ONE_STATUS_FLAG_WRITES_8616",
    "STATUS_FLAGS_8616",
    "DecodedStatusFlagInstruction8616",
    "StatusFlag8616",
    "StatusFlagEffect8616",
    "binop_status_flag_writes_8616",
    "decide_status_flag_liveness_8616",
    "decoded_status_flag_instruction_8616",
    "status_flag_effect_8616",
    "status_flags_dead_before_use_8616",
]
