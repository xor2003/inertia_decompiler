"""Layer: Frontend/runtime.

Responsibility: define emulator exception constants and raising helpers.
Forbidden: decompiler validation decisions, semantic recovery, or output repair.
"""

from __future__ import annotations

from collections.abc import Callable

__all__ = [
    "EXCEPTION",
    "EXCEPTION_WITH",
    "EXP_AC",
    "EXP_BP",
    "EXP_BR",
    "EXP_DB",
    "EXP_DE",
    "EXP_DF",
    "EXP_GP",
    "EXP_MC",
    "EXP_MF",
    "EXP_NM",
    "EXP_NP",
    "EXP_OF",
    "EXP_PF",
    "EXP_SS",
    "EXP_SX",
    "EXP_TS",
    "EXP_UD",
    "EXP_VE",
    "EXP_XF",
]

# Exception types
EXP_DE: int = 0  # Divide Error
EXP_DB: int = 1  # Debug
EXP_BP: int = 3  # Breakpoint
EXP_OF: int = 4  # Overflow
EXP_BR: int = 5  # BOUND Range Exceeded
EXP_UD: int = 6  # Invalid Opcode
EXP_NM: int = 7  # Device Not Available
EXP_DF: int = 8  # Double Fault
EXP_TS: int = 10  # Invalid TSS
EXP_NP: int = 11  # Segment Not Present
EXP_SS: int = 12  # Stack-Segment Fault
EXP_GP: int = 13  # General Protection
EXP_PF: int = 14  # Page Fault
EXP_MF: int = 16  # x87 FPU Floating-Point Error
EXP_AC: int = 17  # Alignment Check
EXP_MC: int = 18  # Machine Check
EXP_XF: int = 19  # SIMD Floating-Point Exception
EXP_VE: int = 20  # Virtualization Exception
EXP_SX: int = 30  # Security Exception

# Helper functions for raising exceptions


def EXCEPTION(n: int, c: object) -> None:
    """Raise the emulator exception number when the condition is truthy."""
    if c:
        print(f"WARN: Exception interrupt {n} ({c})")
        raise Exception(n)


def EXCEPTION_WITH(n: int, c: object, e: Callable[[], object]) -> None:
    """Run a callback and raise the emulator exception when the condition is truthy."""
    if c:
        print(f"WARN: Exception interrupt {n} ({c})")
        e()
        raise Exception(n)
