"""Layer: validation lowering.

Responsibility: admit complete i386 leaf blocks with explicit architecture state.
"""

from __future__ import annotations

from typing import Any

import angr
import pyvex

from tools.dosunit.architectures.flat32 import flat32_register_architecture
from tools.dosunit.architectures.flat32_control_word import _x87_opcode_byte
from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.contracts.model import stable_id


def _flat32_leaf_x87_reason(project: angr.Project, irsb: pyvex.IRSB) -> str | None:
    """Refuse leaf blocks containing x87 effects the leaf engine cannot model.

    The leaf lane lowers one VEX block wholesale; it has no per-instruction
    native boundary, so any x87-family instruction must refuse rather than inherit VEX's erased or narrowed
    projection. Callers lowering a raw IRSB directly must run this scan
    themselves when they can reach the instruction bytes.
    """
    for mark in (stmt for stmt in irsb.statements if isinstance(stmt, pyvex.stmt.IMark)):
        if mark.delta != 0 or mark.len <= 0:
            continue
        raw = bytes(project.loader.memory.load(mark.addr, mark.len))
        if raw.startswith(b"\x9b"):
            return "x87_pending_exception_unmodeled"
        if _x87_opcode_byte(raw) is not None:
            return "x87_status_update_unmodeled"
    return None


def lower_flat32_leaf_block(
    irsb: pyvex.IRSB, *, output_regs: tuple[str, ...], max_assignments_per_function: int,
) -> dict[str, Any] | S.LowerFailure:
    """Refuse branch prefixes and calls, then lower a complete near-return block."""
    if irsb.jumpkind != "Ijk_Ret" or any(statement.tag == "Ist_Exit" for statement in irsb.statements):
        return S.LowerFailure(
            "flat32_control_flow",
            "requires a complete single-block near return; calls/CFG/loops need a 32-bit region owner",
        )
    return S._lower_irsb(
        irsb, output_regs=output_regs, max_assignments_per_function=max_assignments_per_function,
        architecture=flat32_register_architecture(),
    )


def lower_flat32_leaf_function(
    *,
    project: angr.Project,
    linked_base: int,
    function: dict[str, Any],
    output_regs: tuple[str, ...],
    scan_limit: int,
    max_assignments_per_function: int,
    **_limits: object,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    """Own flat addresses and complete-body metadata instead of truncating DOS IPs."""
    start = linked_base + int(function["entry"]["offset"], 0)
    size = min(function["size"], scan_limit)
    block = project.factory.block(start, size=size, opt_level=0)
    x87_reason = _flat32_leaf_x87_reason(project, block.vex)
    if x87_reason is not None:
        return [], [S._refusal(function, x87_reason, "leaf blocks cannot model x87 state updates")], 1
    lowered = lower_flat32_leaf_block(
        block.vex, output_regs=output_regs, max_assignments_per_function=max_assignments_per_function
    )
    if isinstance(lowered, S.LowerFailure):
        return [], [S._refusal(function, lowered.reason, lowered.message)], 1
    entry = {"linear": hex(start)}
    body = {
        "function": {"id": function["id"], "name": function["names"][0]},
        "part": {"kind": "block", "index": 0, "entry_delta": "0x0"},
        "function_entry": entry,
        "entry": entry,
        "source": {"ir": "vex", "jumpkind": block.vex.jumpkind, "machine_code_size": block.size},
        **lowered,
    }
    body["id"] = stable_id("ssa-function", body)
    return [body], [], 1
