# cython: language_level=3, infer_types=True
"""Layer: Frontend/runtime.

Responsibility: model control-register state needed by the emulator surface.
Forbidden: protected-mode recovery shortcuts, decompiler semantics, or rewrite cleanup.
"""

from __future__ import annotations
import typing
import cython

from typing import TYPE_CHECKING
VexValue = typing.TypeVar("VexValue")

if TYPE_CHECKING:
    from pyvex.lifting.util.syntax_wrapper import VexValue

__all__ = ["CR"]


class CR:
    """Frontend control-register state used by emulator and lifter code."""
    cr0: object
    cr1: cython.longlong
    cr2: object
    cr3: object
    cr4: cython.longlong

    def __init__(self) -> None:
        """Initialize the real-mode control-register surface."""
        self.cr0: cython.longlong = 0
        self.cr1: cython.longlong = 0
        self.cr2: cython.longlong = 0
        self.cr3: cython.longlong = 0
        self.cr4: cython.longlong = 0

    def get_crn(self, n: cython.longlong) -> int | VexValue:
        """Read concrete register state; lifting overrides may return a VEX value."""
        if n == 0:
            return self.cr0
        elif n == 1:
            return self.cr1
        elif n == 2:
            return self.cr2
        elif n == 3:
            return self.cr3
        elif n == 4:
            return self.cr4
        else:
            raise ValueError(f"Invalid CR index: {n}")

    def set_crn(self, n: cython.longlong, value: cython.longlong) -> None:
        """Write an architecturally available 80386 control register."""
        if n == 0:
            self.cr0 = value & 0xFFFFFFFF
        elif n == 2:
            self.cr2 = value & 0xFFFFFFFF
        elif n == 3:
            self.cr3 = value & 0xFFFFFFFF
        else:
            raise ValueError(f"Invalid 80386 CR index: {n}")

    def is_protected(self) -> cython.bint:
        """Return whether protected mode is modeled by this real-mode frontend."""
        return False

    def is_ena_paging(self) -> cython.bint:
        """Return whether the paging bit is set in the modeled CR0 value."""
        return bool(self.cr0 & (1 << 31))  # PG bit

    def get_pdir_base(self) -> cython.longlong:
        """Return the page-directory base represented by the modeled CR3 value."""
        return (self.cr3 >> 12) & 0xFFFFF000  # Page Directory Base
