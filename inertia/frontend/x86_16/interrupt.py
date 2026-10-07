"""Layer: Frontend/runtime.

Responsibility: model interrupt dispatch state for the 16-bit emulator surface.
Forbidden: DOS API semantic recovery, helper signature repair, or postprocess cleanup.
"""

from __future__ import annotations

from typing import Never

from inertia.frontend.x86_16.access import DataAccess

# Constants for descriptor table registers
IDTR: int = 1
TR: int = 3

__all__ = ("IDTR", "TR", "Interrupt")


class Interrupt(DataAccess):
    """Provide the interrupt-related frontend runtime surface."""

    def __init__(self, size: int = 0) -> None:
        """Initialize the interrupt bridge without enabling dispatch support."""
        super().__init__(size)

    def set_pic(self, _pic: object, _master: bool) -> Never:
        """Reject PIC installation until interrupt dispatch is implemented."""
        raise NotImplementedError

    def handle_interrupt(self) -> Never:
        """Reject interrupt dispatch until the frontend model implements it."""
        raise NotImplementedError

    def chk_irq(self) -> Never:
        """Reject IRQ polling until interrupt dispatch is implemented."""
        raise NotImplementedError

    def save_regs(self, _chpl: object, cs: object) -> None:
        """Push flags, CS, and IP for an interrupt-like control transfer."""
        self.push16(self.get_flags())
        self.push16(cs)
        self.push16(self.get_ip())
