# cython: language_level=3, infer_types=True
"""Layer: Frontend/runtime.

Responsibility: define emulator exception constants and raising helpers.
Forbidden: decompiler validation decisions, semantic recovery, or output repair.
"""

from __future__ import annotations
import typing
import cython

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
EXP_DE: cython.longlong = 0  # Divide Error
EXP_DB: cython.longlong = 1  # Debug
EXP_BP: cython.longlong = 3  # Breakpoint
EXP_OF: cython.longlong = 4  # Overflow
EXP_BR: cython.longlong = 5  # BOUND Range Exceeded
EXP_UD: cython.longlong = 6  # Invalid Opcode
EXP_NM: cython.longlong = 7  # Device Not Available
EXP_DF: cython.longlong = 8  # Double Fault
EXP_TS: cython.longlong = 10  # Invalid TSS
EXP_NP: cython.longlong = 11  # Segment Not Present
EXP_SS: cython.longlong = 12  # Stack-Segment Fault
EXP_GP: cython.longlong = 13  # General Protection
EXP_PF: cython.longlong = 14  # Page Fault
EXP_MF: cython.longlong = 16  # x87 FPU Floating-Point Error
EXP_AC: cython.longlong = 17  # Alignment Check
EXP_MC: cython.longlong = 18  # Machine Check
EXP_XF: cython.longlong = 19  # SIMD Floating-Point Exception
EXP_VE: cython.longlong = 20  # Virtualization Exception
EXP_SX: cython.longlong = 30  # Security Exception

# Helper functions for raising exceptions


@cython.ccall
def EXCEPTION(n: cython.longlong, c: object) -> None:
    """Raise the emulator exception number when the condition is truthy."""
    if c:
        print(f"WARN: Exception interrupt {n} ({c})")
        raise Exception(n)


@cython.ccall
def EXCEPTION_WITH(n: cython.longlong, c: object, e: Callable[[], object]) -> None:
    """Run a callback and raise the emulator exception when the condition is truthy."""
    if c:
        print(f"WARN: Exception interrupt {n} ({c})")
        e()
        raise Exception(n)
