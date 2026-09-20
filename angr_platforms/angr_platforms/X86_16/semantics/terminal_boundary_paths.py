"""Adapt closed Frontend boundaries to the existing terminal-path proof.

Layer: Semantics.
Responsibility: consume typed executable extents and successor edges without
requiring a mutable angr graph. Instruction loading and effect interpretation
remain with the existing callbacks and terminal-path proof.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Protocol, cast

from ..frontend_function_boundary import ExactFunctionRangeBoundary8616

if TYPE_CHECKING:
    from .terminal_call_paths import TerminalCallPathCallbacks8616


class _BlockSurface(Protocol):
    """Decoded Frontend block coordinates at the decoder boundary."""

    addr: int
    size: int


def boundary_terminal_callbacks_8616(
    function: object, callbacks: TerminalCallPathCallbacks8616,
) -> TerminalCallPathCallbacks8616:
    """Replace only the CFG view when an owned closed boundary is supplied."""
    if not isinstance(function, ExactFunctionRangeBoundary8616):
        return callbacks
    ranges = tuple((cast(_BlockSurface, block).addr, cast(_BlockSurface, block).size) for block in function.blocks)

    def successors(block_addr: int) -> tuple[int, ...]:
        """Read exact owned edges, refusing requests outside the boundary."""
        if block_addr not in function.block_addrs_set:
            raise ValueError(f"terminal path block is outside caller boundary: {block_addr:#x}")
        return tuple(target for source, target in function.successor_edges if source == block_addr)

    return replace(callbacks, function_block_ranges=lambda: ranges, successor_addrs=successors)
