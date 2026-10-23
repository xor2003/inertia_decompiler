"""Layer: native call-composition admission.

Responsibility: isolate byte-verified nonwaiting x87 instructions and compose
their complete native effects, preserving every surrounding instruction and
continuation.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

import pyvex

from tools.dosunit.architectures.flat32_control_word import (
    decode_native_x87,
    native_x87_body,
    unmodeled_x87_status_write,
)
from tools.dosunit.compare.flat32_call_contracts import CallCompositionRefusal, _LiftedBlock

if TYPE_CHECKING:
    from tools.dosunit.compare.flat32_call_contracts import _ComposeSession


def control_word_boundary_count(session: _ComposeSession, irsb: pyvex.IRSB) -> int | None:
    """Stop before a native x87 instruction, or isolate it at the start of a block."""
    marks = [stmt for stmt in irsb.statements if isinstance(stmt, pyvex.stmt.IMark)]
    for index, mark in enumerate(marks):
        if mark.delta != 0 or mark.len <= 0:
            continue
        raw = bytes(session.project.loader.memory.load(mark.addr, mark.len))
        if raw.startswith(b"\x9b") and decode_native_x87(raw) is None:
            raise CallCompositionRefusal("x87_pending_exception_unmodeled")
        if unmodeled_x87_status_write(raw):
            # VEX erases or narrows x87 state updates that remain observable
            # through native FNSTSW/FNSTENV and cannot be discarded.
            raise CallCompositionRefusal("x87_status_update_unmodeled")
        if decode_native_x87(raw) is not None:
            return index or 1
    return None


def lower_control_word_block(
    session: _ComposeSession, function_entry: int, address: int, irsb: pyvex.IRSB,
) -> _LiftedBlock | None:
    """Admit only one complete native x87 instruction with its exact byte extent."""
    marks = [stmt for stmt in irsb.statements if isinstance(stmt, pyvex.stmt.IMark)]
    if len(marks) != 1 or irsb.jumpkind != "Ijk_Boring":
        return None
    mark = marks[0]
    if mark.addr != address or mark.len != irsb.size or mark.delta != 0:
        return None
    raw = bytes(session.project.loader.memory.load(address, irsb.size))
    instruction = decode_native_x87(raw)
    if instruction is None:
        return None
    fallthrough = address + irsb.size
    body = native_x87_body(instruction, continuation=fallthrough,
                           registers=session.reg_widths, address=address)
    part = {
        "entry": {"linear": hex(address)}, "function_entry": {"linear": hex(function_entry)},
        "source": {"ir": "vex", "jumpkind": "Ijk_Boring", "machine_code_size": irsb.size,
                   "conditional_exit_count": 0,
                   "transfer": {"kind": "direct_successors", "summary": body["summary"]["kind"],
                                "successors": [{"linear": hex(fallthrough)}]}},
        **body,
    }
    return _LiftedBlock(address=address, irsb=irsb, part=part, jumpkind="Ijk_Boring",
                        successors=(fallthrough,), call_target=None, fallthrough=None,
                        tail_targets=frozenset())
