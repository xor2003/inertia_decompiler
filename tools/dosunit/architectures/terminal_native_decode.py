"""Bounded native instruction decoding for terminal proof evidence.

Layer: dosunit native proof intake.
Responsibility: share exact instruction-boundary decoding and its existing
resource limits between terminal intake and retained-evidence verification.
"""

from __future__ import annotations

from dataclasses import dataclass

import capstone

from tools.dosunit.compare.terminal_memory_effects import TerminalRefusal, TerminalRefusalKind

TERMINAL_MAX_BLOCKS: int = 8
TERMINAL_MAX_BLOCK_BYTES: int = 4096
TERMINAL_MAX_INSTRUCTIONS: int = 256


@dataclass(frozen=True, slots=True)
class NativeDecodeLimits:
    """Shared finite native budgets retained from intake through verification.

    Defaults preserve the ordinary resource envelope. Explicit caller budgets
    remain authoritative; a zero budget admits no corresponding work.
    """

    max_blocks: int = TERMINAL_MAX_BLOCKS
    max_block_bytes: int = TERMINAL_MAX_BLOCK_BYTES
    max_instructions: int = TERMINAL_MAX_INSTRUCTIONS


DEFAULT_NATIVE_LIMITS: NativeDecodeLimits = NativeDecodeLimits()
"""Immutable default shared by direct helper callers and ordinary terminal intake."""


def decode_terminal_block(
    code: bytes, address: int, *, mode: int, limits: NativeDecodeLimits = DEFAULT_NATIVE_LIMITS,
) -> tuple[capstone.CsInsn, ...]:
    """Decode a complete bounded block; never infer opcodes from byte suffixes."""
    if not code or len(code) > limits.max_block_bytes or limits.max_instructions <= 0:
        raise TerminalRefusal(TerminalRefusalKind.DECODE, "native block exceeds byte budget or is empty")
    decoder = capstone.Cs(capstone.CS_ARCH_X86, mode)
    decoder.detail = True
    instructions = tuple(decoder.disasm(code, address, count=limits.max_instructions + 1))
    if len(instructions) > limits.max_instructions:
        raise TerminalRefusal(TerminalRefusalKind.DECODE, "native block exceeds instruction budget")
    if sum(instruction.size for instruction in instructions) != len(code):
        raise TerminalRefusal(TerminalRefusalKind.DECODE, "decoded instructions do not cover lifted bytes")
    return instructions
