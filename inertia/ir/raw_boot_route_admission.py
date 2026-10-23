"""Layer: IR.
Responsibility: decline record-free startup routes behind an ordinary call.

This is only admission to the initial raw route, never an unreachability proof.
Call-backed retries retain their existing semantics. Unknown control keeps the
original attempt; live bytes are decoded again rather than trusting sidecars.
"""
from __future__ import annotations

from enum import Enum
from typing import cast

from capstone import CS_GRP_CALL, CS_GRP_IRET, CS_GRP_JUMP, CS_GRP_RET, CsInsn

from inertia.frontend.x86_16.frontend_capstone_block import DirectCapstoneBlock8616, DirectCapstoneInstruction8616
from inertia.frontend.x86_16.frontend_capstone_decode import decode_bounded_capstone_block_8616
from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616

_MAX_PREFIX_BYTES = 512
_MAX_PREFIX_BLOCKS = 16


class RawBootRouteAdmission8616(Enum):
    """An optimization decision; neither alternative grants a proof."""

    RETAIN_ATTEMPT = "retain_attempt"
    ORDINARY_CALL_BARRIER = "ordinary_call_barrier"
    CONTINUE_PREFIX = "continue_prefix"


def _prefix_block_8616(block: DirectCapstoneBlock8616, callsite_addr: int) -> RawBootRouteAdmission8616:
    """Inspect one freshly decoded linear block without crossing a branch."""
    for row in block.instructions:
        if type(row) is not DirectCapstoneInstruction8616 or type(row.insn) is not CsInsn:
            return RawBootRouteAdmission8616.RETAIN_ATTEMPT
        if row.address == callsite_addr:
            return RawBootRouteAdmission8616.RETAIN_ATTEMPT
        groups = cast(CsInsn, row.insn).groups
        if CS_GRP_CALL in groups:
            return RawBootRouteAdmission8616.ORDINARY_CALL_BARRIER
        if any(group in groups for group in (CS_GRP_JUMP, CS_GRP_RET, CS_GRP_IRET)):
            return RawBootRouteAdmission8616.RETAIN_ATTEMPT
    # A returning declared INT can carry the raw census to its fallthrough;
    # an undeclared/terminating INT cannot create a successful later proof.
    return RawBootRouteAdmission8616.CONTINUE_PREFIX


def raw_boot_route_admission_8616(
    project: object, boundary: ExactFunctionRangeBoundary8616, callsite_addr: int,
) -> RawBootRouteAdmission8616:
    """Skip only a bounded straight-line prefix ending in a prior ordinary CALL.

The raw route supplies no call-preservation records, so it cannot cross that
CALL. Branches, decode failures, continuation premises and exhausted scanning
retain the existing attempt. No result is cached and no call-backed route uses
this admission decision.
    """
    if boundary.project is not project or boundary.near_return_continuations is not None:
        return RawBootRouteAdmission8616.RETAIN_ATTEMPT
    if callsite_addr not in boundary.reachable_instruction_addrs:
        return RawBootRouteAdmission8616.RETAIN_ATTEMPT
    address = boundary.addr
    end = min(boundary.addr + boundary.size, boundary.addr + _MAX_PREFIX_BYTES)
    for _ in range(_MAX_PREFIX_BLOCKS):
        if address >= end:
            break
        decoded = decode_bounded_capstone_block_8616(project, address, end)
        block = decoded.block
        if not decoded.complete or block is None or block.size <= 0:
            break
        admission = _prefix_block_8616(block, callsite_addr)
        if admission is not RawBootRouteAdmission8616.CONTINUE_PREFIX:
            return admission
        address += block.size
    return RawBootRouteAdmission8616.RETAIN_ATTEMPT
