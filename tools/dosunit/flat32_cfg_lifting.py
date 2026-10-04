"""Lift closed flat-i386 CFG blocks at machine conditional boundaries.

Layer: dosunit binary CFG frontend adapter.
Responsibility: split a VEX block at the instruction containing its first
conditional exit, then relift the exact byte prefix. Data effects after an
exit inside that instruction remain the driver's explicit refusal; no state
is deleted, assumed unchanged or repaired after SSA lowering.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING

import pyvex

if TYPE_CHECKING:
    import angr


class CfgLiftingReason(StrEnum):
    """A missing or inconsistent conditional instruction-boundary obligation."""

    MODEL = "non_vex_lifter"
    MARKER = "conditional_instruction_boundary_missing"
    RANGE = "conditional_instruction_boundary_outside_range"
    PREFIX = "conditional_relift_prefix_changed"


class CfgLiftingRefusal(Exception):
    """Retain the typed reason a byte-exact block boundary cannot be established."""

    def __init__(self, reason: CfgLiftingReason) -> None:
        """Publish the exact missing boundary obligation and its cause."""
        self.reason = reason
        super().__init__(reason.value)


def _conditional_size(irsb: pyvex.IRSB, address: int, maximum: int) -> int | None:
    """Find the end of the first exit's enclosing typed instruction marker."""
    mark: pyvex.stmt.IMark | None = None
    for statement in irsb.statements:
        if isinstance(statement, pyvex.stmt.IMark):
            mark = statement
        elif isinstance(statement, pyvex.stmt.Exit):
            if mark is None:
                raise CfgLiftingRefusal(CfgLiftingReason.MARKER)
            # PyVEX exposes marker fields dynamically; validate before arithmetic.
            marker_address, marker_length, marker_delta = mark.addr, mark.len, mark.delta
            if (not isinstance(marker_address, int) or not isinstance(marker_length, int)
                    or marker_length <= 0 or marker_delta != 0):
                raise CfgLiftingRefusal(CfgLiftingReason.MARKER)
            size = marker_address + marker_length - address
            if not 0 < size <= maximum:
                raise CfgLiftingRefusal(CfgLiftingReason.RANGE)
            return size
    return None


def lift_cfg_block(project: angr.Project, address: int, maximum: int) -> pyvex.IRSB:
    """Lift an exact byte prefix ending at the first conditional instruction.

    The CFG consumer follows both successors, so all later instruction effects
    remain in separately lifted reachable blocks. Relifting cannot authorize
    dropping effects after a conditional exit within the same instruction.
    """
    if project.arch.name != "X86":
        raise CfgLiftingRefusal(CfgLiftingReason.MODEL)
    if maximum <= 0:
        raise CfgLiftingRefusal(CfgLiftingReason.RANGE)
    block = project.factory.block(address, size=maximum, opt_level=0)
    irsb = block.vex
    if not isinstance(irsb, pyvex.IRSB):
        raise CfgLiftingRefusal(CfgLiftingReason.MODEL)
    size = _conditional_size(irsb, address, maximum)
    if size is None or size >= irsb.size:
        return irsb
    prefix = project.factory.block(address, size=size, opt_level=0)
    prefix_irsb = prefix.vex
    if not isinstance(prefix_irsb, pyvex.IRSB):
        raise CfgLiftingRefusal(CfgLiftingReason.MODEL)
    original_bytes, prefix_bytes = block.bytes, prefix.bytes
    if (original_bytes is None or prefix_bytes is None or prefix_bytes != original_bytes[:size]
            or prefix_irsb.size != size):
        raise CfgLiftingRefusal(CfgLiftingReason.PREFIX)
    return prefix_irsb
