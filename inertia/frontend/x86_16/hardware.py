"""Layer: Frontend/runtime.

Responsibility: compose processor, memory, and IO emulator state.
Forbidden: decompiler semantic recovery, alias/type ownership, or rewrite cleanup.
"""

from __future__ import annotations

from .cr import CR
from .io import IO
from .memory import Memory
from .processor import Processor

__all__ = ["Hardware"]


class Hardware(Processor, Memory, IO):  # type: ignore[misc, unused-ignore] # intentional frontend mixin state
    """Frontend runtime state composed from processor, memory, and IO surfaces."""

    def __init__(self, size: int = 0) -> None:
        """Initialize processor state, backing memory size, and IO maps."""
        super().__init__()  # Processor
        super(CR, self).__init__(size)  # Memory
        super(Memory, self).__init__(self)  # IO
