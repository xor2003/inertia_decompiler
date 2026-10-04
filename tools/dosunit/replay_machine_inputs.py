"""Shared admission for x86 instructions consuming undeclared machine inputs.

Layer: dosunit concrete execution contracts.
Responsibility: identify binary-decoded clock, CPU, entropy and control-state
reads absent from replay environments. Both architecture tracks consume this
owner; backend defaults never discharge missing environment evidence.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from capstone import x86_const as decoded_ids
else:
    try:
        from capstone import x86_const as decoded_ids
    except ImportError:
        decoded_ids = None  # type: ignore[assignment]


class ReplayInstructionReason(StrEnum):
    """Stable missing instruction evidence shared by concrete executors."""

    DECODE = "instruction_decode_failed"
    EXTERNAL = "external_or_privileged_instruction"
    ENVIRONMENT = "undeclared_machine_input"
    REGISTER_FILE = "unmodeled_register_file"


MACHINE_INPUT_INSTRUCTION_IDS: frozenset[int] = frozenset({
    decoded_ids.X86_INS_CPUID,
    decoded_ids.X86_INS_RDTSC,
    decoded_ids.X86_INS_RDTSCP,
    decoded_ids.X86_INS_RDRAND,
    decoded_ids.X86_INS_RDSEED,
    decoded_ids.X86_INS_XGETBV,
}) if decoded_ids is not None else frozenset()
"""Decode identities, independent of operand size or Capstone privilege tags."""
