"""Bind native near-transfer geometry to every original caller CFG edge.

Layer: IR.
Responsibility: consume byte-derived coordinates only against the original CFG
and retained native census. CALL continuation and RET shape are checked here;
callee return offset, stack and memory effects remain ordinary proof obligations.
"""
from __future__ import annotations

from collections.abc import Set as AbstractSet
from typing import TYPE_CHECKING

from inertia.frontend.x86_16.control_transfer_geometry import (
    ControlCheck8616,
    ControlKind8616,
    ControlVerdict8616,
    check_control_transfer_8616,
)

from .core import IRBlock, IRInstr

if TYPE_CHECKING:
    from .near_return_continuation_view import ScopedNearReturnContinuationView8616
    from .real16_invocation_domain import Real16InvocationDomain8616


def check_bound_control_8616(
    block: IRBlock, instr: IRInstr, encoded: bytes,
    cs: int | None, target: int | None, census: AbstractSet[int],
) -> ControlCheck8616:
    """Require exact original edges, including pending native terminals."""
    result = check_control_transfer_8616(
        addr=instr.addr if type(instr.addr) is int else -1,
        encoded=encoded, known_cs=-1 if cs is None else cs,
        ir_op=instr.op, successors=block.successor_addrs,
        call_target=target, census_addrs=census,
    )
    if result.verdict is ControlVerdict8616.REFUSED:
        return result
    detail = _edge_failure(result, block, census)
    if detail is None:
        return result
    return ControlCheck8616(ControlVerdict8616.REFUSED, result.kind,
                            result.addr, result.target, result.fallthrough, detail)


def _edge_failure(
    result: ControlCheck8616, block: IRBlock, census: AbstractSet[int],
) -> str | None:
    """A selector capability never invents a missing continuation or edge."""
    if result.kind is ControlKind8616.CALL:
        if frozenset(block.successor_addrs) != frozenset({result.fallthrough}):
            return "call_continuation_cfg_mismatch"
        return None
    if result.kind is ControlKind8616.RET:
        return "return_has_cfg_successor" if block.successor_addrs else None
    edges = {edge for edge in (result.target, result.fallthrough) if edge is not None}
    return None if edges <= census else "edge_not_retained"


def check_scoped_return_control_8616(
    view: ScopedNearReturnContinuationView8616,
    scope: Real16InvocationDomain8616,
    block: IRBlock, instruction: IRInstr, encoded: bytes,
    cs: int | None, census: AbstractSet[int],
) -> ControlCheck8616:
    """Consume a native indirect return only through its authenticated view.

    The native bytes remain indirect-JMP bytes. The separate view proves their
    continuation identity; this adapter adds fetch/selector geometry and grants
    the same CS-only return obligation as the ordinary native RET checker.
    """
    from inertia.frontend.x86_16.instruction_fetch_geometry import (
        FetchVerdict8616,
        check_instruction_fetch_8616,
    )

    from .near_return_continuation_view import ScopedNearReturnContinuationView8616
    from .real16_invocation_domain import Real16InvocationDomain8616, _loaded_bytes_8616

    address = instruction.addr if type(instruction.addr) is int else -1
    refused = ControlCheck8616(ControlVerdict8616.REFUSED, ControlKind8616.RET,
                               address, None, None, "scoped_return_unbound")
    if (type(view) is not ScopedNearReturnContinuationView8616
            or type(scope) is not Real16InvocationDomain8616
            or not any(raw is block for raw in view.source_artifact.blocks)):
        return refused
    if (not block.instrs or block.instrs[-1] is not instruction
            or instruction.op != "JMP" or address not in census):
        return refused
    if view.premise is None or type(cs) is not int:
        return refused
    if (_loaded_bytes_8616(view.boundary.project, address, len(encoded)) != encoded
            or check_instruction_fetch_8616(address, encoded, cs).verdict is not FetchVerdict8616.CLOSED
            or not (cs << 4) <= view.premise.return_addr <= (cs << 4) + 0xFFFF):
        return refused
    projection = view.cfg_projection_for(scope)
    if projection is None or projection.source_artifact is not view.source_artifact:
        return refused
    effective = tuple(row for row in projection.blocks if row.addr == block.addr)
    if (len(effective) != 1 or projection.pending.get(block.addr)
            or projection.successors.get(block.addr) != ()
            or block.addr not in view.proven_block_addrs):
        return refused
    if (not effective[0].instrs or effective[0].instrs[-1].op != "RET"
            or effective[0].instrs[-1].addr != address):
        return refused
    return ControlCheck8616(ControlVerdict8616.RETURN_OBLIGATION, ControlKind8616.RET,
                            address, None, None, "scoped_near_return_cs_only")
