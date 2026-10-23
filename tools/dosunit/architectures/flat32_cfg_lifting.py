"""Lift closed flat-i386 CFG blocks at machine conditional boundaries.

Layer: dosunit binary CFG frontend adapter.
Responsibility: split a VEX block at its first conditional instruction or
before an admitted REP summary, then relift the exact byte prefix. Unsupported
effects after an exit remain the driver's explicit refusal; no state is
deleted, assumed unchanged or repaired after SSA lowering.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING

import pyvex

from tools.dosunit.architectures.flat32_control_word import decode_native_x87, unmodeled_x87_status_write
from tools.dosunit.contracts.repeat_string_contracts import RepeatArchitecture, decode_repeat_summary

if TYPE_CHECKING:
    import angr
    from angr.block import Block


class CfgLiftingReason(StrEnum):
    """A missing or inconsistent conditional instruction-boundary obligation."""

    MODEL = "non_vex_lifter"
    MARKER = "conditional_instruction_boundary_missing"
    RANGE = "conditional_instruction_boundary_outside_range"
    PREFIX = "conditional_relift_prefix_changed"
    EFFECT = "effect_after_conditional_exit"
    EXCEPTION = "exception_edge"
    TARGET = "indirect_exit_target"
    X87_EXCEPTION = "x87_pending_exception_unmodeled"
    X87_STATUS = "x87_status_update_unmodeled"


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


def validate_ordinary_exits(irsb: pyvex.IRSB) -> None:
    """Refuse effects inside an exiting instruction that need path guarding."""
    ip_offset = irsb.arch.ip_offset
    if ip_offset is None:
        raise CfgLiftingRefusal(CfgLiftingReason.MODEL)
    seen_exit = False
    for statement in irsb.statements:
        if isinstance(statement, pyvex.stmt.Exit):
            seen_exit = True
            if statement.jumpkind != "Ijk_Boring":
                raise CfgLiftingRefusal(CfgLiftingReason.EXCEPTION)
            if not isinstance(statement.dst.value, int):
                raise CfgLiftingRefusal(CfgLiftingReason.TARGET)
        elif (
            seen_exit
            and statement.tag not in {"Ist_IMark", "Ist_WrTmp", "Ist_NoOp"}
            and not (isinstance(statement, pyvex.stmt.Put) and statement.offset == ip_offset)
        ):
            raise CfgLiftingRefusal(CfgLiftingReason.EFFECT)


def _native_summary_boundary_size(irsb: pyvex.IRSB, data: bytes | None, address: int) -> int | None:
    """Isolate REP or FNSTCW/FNSTSW and retain the pending-exception obligation of WAIT."""
    if data is None:
        return None
    for statement in irsb.statements:
        if not isinstance(statement, pyvex.stmt.IMark) or statement.len <= 0 or statement.delta != 0:
            continue
        offset: int = statement.addr - address
        if not 0 <= offset <= len(data) - statement.len:
            raise CfgLiftingRefusal(CfgLiftingReason.RANGE)
        raw = data[offset:offset + statement.len]
        if raw.startswith(b"\x9b") and decode_native_x87(raw) is None:
            raise CfgLiftingRefusal(CfgLiftingReason.X87_EXCEPTION)
        if unmodeled_x87_status_write(raw):
            raise CfgLiftingRefusal(CfgLiftingReason.X87_STATUS)
        if decode_native_x87(raw) is not None:
            return offset or statement.len
        instruction = {"bytes": raw.hex(), "size": statement.len}
        if decode_repeat_summary([instruction], architecture=RepeatArchitecture.FLAT32) is not None:
            return offset or statement.len
    return None


def reblock_cfg_block(project: angr.Project, block: Block, address: int, maximum: int) -> Block:
    """Retain a byte-verified conditional prefix and its matching decode records.

    The CFG consumer follows both successors, so all later instruction effects
    remain in separately lifted reachable blocks. Relifting cannot authorize
    dropping effects after a conditional exit within the same instruction.
    Returning the block keeps Capstone instruction evidence and VEX coherent.
    Effect admission remains with the consumer. The region scanner first
    checks its typed instruction summaries, then validates ordinary exits.
    """
    if project.arch.name != "X86":
        raise CfgLiftingRefusal(CfgLiftingReason.MODEL)
    if maximum <= 0:
        raise CfgLiftingRefusal(CfgLiftingReason.RANGE)
    irsb = block.vex
    if not isinstance(irsb, pyvex.IRSB):
        raise CfgLiftingRefusal(CfgLiftingReason.MODEL)
    size = _conditional_size(irsb, address, maximum)
    repeat_size = _native_summary_boundary_size(irsb, block.bytes, address)
    if repeat_size is not None:
        size = min(size, repeat_size) if size is not None else repeat_size
    if size is not None and size < irsb.size:
        prefix = project.factory.block(address, size=size, opt_level=0)
        prefix_irsb = prefix.vex
        if not isinstance(prefix_irsb, pyvex.IRSB):
            raise CfgLiftingRefusal(CfgLiftingReason.MODEL)
        original_bytes, prefix_bytes = block.bytes, prefix.bytes
        if (original_bytes is None or prefix_bytes is None or prefix_bytes != original_bytes[:size]
                or prefix_irsb.size != size):
            raise CfgLiftingRefusal(CfgLiftingReason.PREFIX)
        block, irsb = prefix, prefix_irsb
    return block


def lift_cfg_block(project: angr.Project, address: int, maximum: int) -> pyvex.IRSB:
    """Lift the same checked boundary used by cached region discovery."""
    block = project.factory.block(address, size=maximum, opt_level=0)
    return reblock_cfg_block(project, block, address, maximum).vex
