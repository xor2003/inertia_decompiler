# cython: language_level=3, infer_types=True
"""Layer: Helper boundary.

Responsibility: define typed device and memory I/O interfaces used by frontend execution.
Forbidden: recovering decompiler semantics from device side effects or host I/O names.
"""

from __future__ import annotations
import typing
import cython

from abc import ABC, abstractmethod

from inertia.frontend.x86_16.memory import Memory

__all__ = ("MemoryIO", "PortIO")


class PortIO(ABC):
    """Define byte-wide port I/O operations for frontend devices."""

    @abstractmethod
    def in8(self, addr: cython.longlong) -> cython.longlong:
        """Reads an 8-bit value from the specified port address."""

    @abstractmethod
    def out8(self, addr: cython.longlong, value: cython.longlong) -> None:
        """Writes an 8-bit value to the specified port address."""


class MemoryIO(ABC):
    """Define memory-mapped I/O helpers for frontend devices."""

    def __init__(self) -> None:
        """Initialize an unattached memory-mapped device view."""
        self.memory: Memory | None = None
        self.paddr: cython.longlong = 0
        self.size: cython.longlong = 0

    def set_mem(self, mem: Memory, addr: cython.longlong, length: cython.longlong) -> None:
        """Sets the memory object, base address, and size for the device."""
        self.memory = mem
        self.paddr = addr
        self.size = length

    def read32(self, offset: cython.longlong) -> cython.longlong:
        """Reads a 32-bit value from the specified offset."""
        value = 0
        for i in range(4):
            value += self.read8(offset + i) << (8 * i)
        return value

    def read16(self, offset: cython.longlong) -> cython.longlong:
        """Reads a 16-bit value from the specified offset."""
        value = 0
        for i in range(2):
            value += self.read8(offset + i) << (8 * i)
        return value

    @abstractmethod
    def read8(self, offset: cython.longlong) -> cython.longlong:
        """Reads an 8-bit value from the specified offset."""

    def write32(self, offset: cython.longlong, value: cython.longlong) -> None:
        """Writes a 32-bit value to the specified offset."""
        for i in range(4):
            self.write8(offset + i, (value >> (8 * i)) & 0xFF)

    def write16(self, offset: cython.longlong, value: cython.longlong) -> None:
        """Writes a 16-bit value to the specified offset."""
        for i in range(2):
            self.write8(offset + i, (value >> (8 * i)) & 0xFF)

    @abstractmethod
    def write8(self, offset: cython.longlong, value: cython.longlong) -> None:
        """Writes an 8-bit value to the specified offset."""
