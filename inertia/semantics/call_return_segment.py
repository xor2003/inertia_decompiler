# cython: language_level=3, infer_types=True
"""Prove separately pushed return segments for linked near calls.

Layer: Semantics.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.
Responsibility: join an adjacent decoded PUSH CS / near CALL to a closed
callee far-return census and exact VEX push effects. Adjacency alone is not
proof: CS may be an ordinary argument. Unknown exits, cleanup, widths and
ambiguous projections refuse. Consumers must retain the whole refused group.
No rendered text, source names, stack-variable recovery or C mutation belongs
here. This adapter uses native CFG endpoints or complete binary reachability
for bodyless callees, never sidecar labels. Return kind alone is insufficient:
operand width and explicit cleanup must agree on every terminal path.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from itertools import pairwise
from typing import Protocol, cast

from angr import Project
from angr.knowledge_plugins.functions.function import Function
from capstone import CsInsn
from capstone.x86_const import X86_INS_CALL, X86_INS_PUSH, X86_INS_RET, X86_INS_RETF, X86_OP_IMM, X86_OP_REG, X86_REG_CS
from pyvex.stmt import IMark, Put, Store

from .call_return_frame_effects import CallReturnFrameEffectRole8616
from .terminal_stack_cleanup import (
    TerminalReturnFrameKind8616,
    TerminalStackCleanupEvidence8616,
    terminal_stack_cleanup_at_address_8616,
)
import dataclasses
import operator
import builtins


class ReturnSegmentRefusal8616(StrEnum):
    """Reason a candidate cannot transfer its pushed CS into a source call."""

    NO_PREFIX = "no_prefix"
    UNKNOWN_CALLEE = "unknown_callee"
    RETURN_MISMATCH = "return_mismatch"
    UNSUPPORTED_WIDTH_OR_CLEANUP = "unsupported_width_or_cleanup"
    AMBIGUOUS_EFFECTS = "ambiguous_effects"


@dataclasses.dataclass(frozen=True, )
class ReturnSegmentEffect8616:
    """One exact instruction-owned projection of the separately pushed CS."""

    source_addr: cython.longlong
    vex_block_addr: cython.longlong
    vex_stmt_idx: cython.longlong
    role: CallReturnFrameEffectRole8616


@dataclasses.dataclass(frozen=True, )
class ReturnSegmentFrame8616:
    """Call owner, exact prefix effects and a closed outcome for one candidate."""

    callsite_addr: cython.longlong
    effects: tuple[ReturnSegmentEffect8616, ...] = ()
    refusal: ReturnSegmentRefusal8616 | None = None

    @property
    def additional_return_bytes(self) -> int | None:
        """Return the proven 16-bit CS slot consumed beyond the near CALL frame."""
        if self.refusal is not None or not self.effects:
            return None
        # The producer refuses every non-16-bit or explicit-cleanup return.
        return 16 // 8


@dataclasses.dataclass(frozen=True, )
class ReturnFrame8616:
    """Decoded machine return frame, distinct from optional argument cleanup."""

    source_addr: cython.longlong
    operand_bits: cython.longlong
    far: cython.bint
    cleanup_bytes: cython.longlong

    @property
    def frame_bytes(self) -> cython.longlong:
        """Return the IP/EIP and optional segment slots consumed by RET."""
        return (self.operand_bits // 8) * (2 if self.far else 1)


@cython.ccall
def _real_function_8616(function: Function) -> cython.bint:
    """Return whether the node is a real function, not a simprocedure/PLT."""
    return not function.is_simprocedure and not function.is_plt


@cython.ccall
def _resolved_exits_8616(function: Function) -> cython.bint:
    """Return whether the function graph has no unresolved exits."""
    return (
        not function.has_unresolved_jumps
        and not function.has_unresolved_calls
        and not function.jumpout_sites
        and not function.callout_sites
    )


@cython.ccall
def _closed_return_graph_8616(function: Function, returns: object) -> cython.bint:
    """Return whether every endpoint is a known return site."""
    return bool(returns) and operator.eq(set(function.endpoints), returns) and _resolved_exits_8616(function)


def collect_function_return_frames_8616(project: Project, function: Function) -> object:
    """Decode every closed function endpoint, refusing unknown control exits."""
    site: object
    returns = set(function.ret_sites)
    if not _real_function_8616(function) or not _closed_return_graph_8616(function, returns):
        return None
    result: list[ReturnFrame8616] = []
    for site in sorted(returns, key=lambda node: node.addr):
        instructions = project.factory.block(site.addr, size=site.size, opt_level=0).capstone.insns
        if not instructions or instructions[-1].insn.id not in {X86_INS_RET, X86_INS_RETF}:
            return None
        ret = instructions[-1].insn
        if ret.operands and (len(ret.operands) != 1 or operator.ne(ret.operands[0].type, X86_OP_IMM)):
            return None
        result.append(ReturnFrame8616(
            ret.address, 32 if 0x66 in ret.prefix else 16, operator.eq(ret.id, X86_INS_RETF),
            int(ret.operands[0].imm) if ret.operands else 0,
        ))
    return tuple(result)


class _OriginalProjectBoundary8616(Protocol):
    """Exact source mapping published by the rebased analysis-image loader."""

    _inertia_original_project: Project
    _inertia_original_linear_delta: cython.longlong


@cython.ccall
def callee_return_evidence_8616(project: Project, target: cython.longlong) -> TerminalStackCleanupEvidence8616:
    """Use mapped bytes or the exact original location of an out-of-slice callee."""
    if project.loader.find_object_containing(target) is None:
        boundary = cast(_OriginalProjectBoundary8616, project)
        try:
            original = boundary._inertia_original_project
            delta = boundary._inertia_original_linear_delta
        except AttributeError:
            pass
        else:
            if isinstance(original, Project) and isinstance(delta, int) and not isinstance(delta, bool):
                return terminal_stack_cleanup_at_address_8616(original, target + delta)
    return terminal_stack_cleanup_at_address_8616(project, target)


def _callee_refusal_8616(project: Project, target: cython.longlong) -> ReturnSegmentRefusal8616 | None:
    """Require all known callee endpoints to be compatible plain far returns."""
    callee: object
    frames: object
    callee = project.kb.functions.get(target)
    if not isinstance(callee, Function):
        return ReturnSegmentRefusal8616.UNKNOWN_CALLEE
    if not callee.is_simprocedure and not callee.is_plt and not callee.block_addrs_set:
        evidence = callee_return_evidence_8616(project, target)
        if not evidence.complete:
            return ReturnSegmentRefusal8616.UNKNOWN_CALLEE
        if evidence.consistent_return_frame_kind is not TerminalReturnFrameKind8616.FAR:
            return ReturnSegmentRefusal8616.RETURN_MISMATCH
        if evidence.consistent_return_operand_bits != 16 or evidence.consistent_cleanup != 0:
            return ReturnSegmentRefusal8616.UNSUPPORTED_WIDTH_OR_CLEANUP
        return None
    frames = collect_function_return_frames_8616(project, callee)
    if frames is None:
        return ReturnSegmentRefusal8616.UNKNOWN_CALLEE
    if any(not frame.far for frame in iter(frames)):
        return ReturnSegmentRefusal8616.RETURN_MISMATCH
    if any(frame.operand_bits != 16 or frame.cleanup_bytes != 0 for frame in iter(frames)):
        return ReturnSegmentRefusal8616.UNSUPPORTED_WIDTH_OR_CLEANUP
    return None


@cython.ccall
def _is_cs_push_8616(instruction: CsInsn) -> cython.bint:
    """Recognize the architectural register operand, not its printed spelling."""
    return bool(
        operator.eq(instruction.id, X86_INS_PUSH) and len(instruction.operands) == 1
        and operator.eq(instruction.operands[0].type, X86_OP_REG)
        and operator.eq(instruction.operands[0].reg, X86_REG_CS)
    )


def _push_effects_8616(
    project: Project, block_addr: cython.longlong, block_size: cython.longlong, push_addr: cython.longlong,
) -> tuple[ReturnSegmentEffect8616, ...]:
    """Publish the complete unoptimized VEX effect sequence of one PUSH CS."""
    index: object
    statement: object
    vex = project.factory.block(block_addr, size=block_size, opt_level=0).vex
    current_addr: int | None = None
    effects: list[ReturnSegmentEffect8616] = []
    for index, statement in enumerate(vex.statements):
        if isinstance(statement, IMark):
            current_addr = statement.addr
        elif current_addr == push_addr:
            if isinstance(statement, Put) and operator.eq(statement.offset, project.arch.sp_offset):
                role = CallReturnFrameEffectRole8616.STACK_POINTER_UPDATE
            elif isinstance(statement, Store):
                role = CallReturnFrameEffectRole8616.STACK_STORE
            else:
                continue
            effects.append(ReturnSegmentEffect8616(push_addr, block_addr, index, role))
    sp = CallReturnFrameEffectRole8616.STACK_POINTER_UPDATE
    store = CallReturnFrameEffectRole8616.STACK_STORE
    if tuple(item.role for item in iter(effects)) not in {(sp, store), (sp, store, store)}:
        return ()
    return tuple(effects)


def _push_call_candidates_8616(
    function: Function,
    return_addrs: Mapping[cython.longlong, cython.longlong],
    block_addr: object,
) -> object:
    """Census every push+immediate-call pair feeding a known return address."""
    block: object
    call: object
    push: object
    candidates: dict[cython.longlong, list[tuple[cython.longlong, cython.longlong, CsInsn, CsInsn]]] = {}
    blocks = function.blocks if block_addr is None else (
        tuple((function.get_block(block_addr),)) if block_addr in function.block_addrs_set else tuple(())
    )
    for block in blocks:
        if not isinstance(block.size, int) or block.size <= 0:
            continue
        instructions = tuple(wrapper.insn for wrapper in iter(block.capstone.insns))
        for push, call in pairwise(instructions):
            if call.address in return_addrs and _is_cs_push_8616(push):
                candidates.setdefault(call.address, []).append((block.addr, block.size, push, call))
    return candidates


@cython.ccall
def _call_frame_outcome_8616(
    project: Project,
    address: cython.longlong,
    return_addr: cython.longlong,
    matches: object,
) -> tuple[ReturnSegmentRefusal8616 | None, tuple[ReturnSegmentEffect8616, ...]]:
    """Classify one call's prefix candidates into a refusal or effects."""
    refusal: object
    if not matches:
        return ReturnSegmentRefusal8616.NO_PREFIX, ()
    if len(matches) != 1:
        return ReturnSegmentRefusal8616.AMBIGUOUS_EFFECTS, ()
    block_addr, block_size, push, call = matches[0]
    if (
        operator.ne(call.id, X86_INS_CALL) or len(call.operands) != 1
        or operator.ne(call.operands[0].type, X86_OP_IMM)
        or operator.ne(push.address + push.size, address) or operator.ne(address + call.size, return_addr)
    ):
        return ReturnSegmentRefusal8616.UNKNOWN_CALLEE, ()
    if 0x66 in push.prefix or 0x66 in call.prefix:
        return ReturnSegmentRefusal8616.UNSUPPORTED_WIDTH_OR_CLEANUP, ()
    refusal = _callee_refusal_8616(project, call.operands[0].imm)
    if refusal is not None:
        return refusal, ()
    effects = _push_effects_8616(project, block_addr, block_size, push.address)
    if not effects:
        return ReturnSegmentRefusal8616.AMBIGUOUS_EFFECTS, ()
    return None, effects


def collect_return_segment_frames_8616(
    project: object, function: object, return_addrs: Mapping[cython.longlong, cython.longlong],
    *, block_addr: int | None = None,
) -> tuple[ReturnSegmentFrame8616, ...]:
    """Return one explicit outcome per call using decoded prefix and exit proof."""
    address: object
    return_addr: object
    if not isinstance(project, Project) or not isinstance(function, Function):
        return tuple(ReturnSegmentFrame8616(addr, refusal=ReturnSegmentRefusal8616.UNKNOWN_CALLEE)
                     for addr in builtins.iter(sorted(return_addrs)))
    candidates = _push_call_candidates_8616(function, return_addrs, block_addr)
    result: list[ReturnSegmentFrame8616] = []
    for address, return_addr in sorted(tuple(return_addrs.items())):
        refusal, effects = _call_frame_outcome_8616(
            project, address, return_addr, candidates.get(address, [])
        )
        result.append(ReturnSegmentFrame8616(address, effects, refusal))
    return tuple(result)
