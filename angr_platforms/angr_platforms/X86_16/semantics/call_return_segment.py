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


class ReturnSegmentRefusal8616(StrEnum):
    """Reason a candidate cannot transfer its pushed CS into a source call."""

    NO_PREFIX = "no_prefix"
    UNKNOWN_CALLEE = "unknown_callee"
    RETURN_MISMATCH = "return_mismatch"
    UNSUPPORTED_WIDTH_OR_CLEANUP = "unsupported_width_or_cleanup"
    AMBIGUOUS_EFFECTS = "ambiguous_effects"


@dataclass(frozen=True, slots=True)
class ReturnSegmentEffect8616:
    """One exact instruction-owned projection of the separately pushed CS."""

    source_addr: int
    vex_block_addr: int
    vex_stmt_idx: int
    role: CallReturnFrameEffectRole8616


@dataclass(frozen=True, slots=True)
class ReturnSegmentFrame8616:
    """Call owner, exact prefix effects and a closed outcome for one candidate."""

    callsite_addr: int
    effects: tuple[ReturnSegmentEffect8616, ...] = ()
    refusal: ReturnSegmentRefusal8616 | None = None


@dataclass(frozen=True, slots=True)
class ReturnFrame8616:
    """Decoded machine return frame, distinct from optional argument cleanup."""

    source_addr: int
    operand_bits: int
    far: bool
    cleanup_bytes: int

    @property
    def frame_bytes(self) -> int:
        """Return the IP/EIP and optional segment slots consumed by RET."""
        return (self.operand_bits // 8) * (2 if self.far else 1)


def collect_function_return_frames_8616(project: Project, function: Function) -> tuple[ReturnFrame8616, ...] | None:
    """Decode every closed function endpoint, refusing unknown control exits."""
    returns = set(function.ret_sites)
    if (
        function.is_simprocedure or function.is_plt
        or not returns or set(function.endpoints) != returns
        or function.has_unresolved_jumps or function.has_unresolved_calls
        or function.jumpout_sites or function.callout_sites
    ):
        return None
    result: list[ReturnFrame8616] = []
    for site in sorted(returns, key=lambda node: node.addr):
        instructions = project.factory.block(site.addr, size=site.size, opt_level=0).capstone.insns
        if not instructions or instructions[-1].insn.id not in {X86_INS_RET, X86_INS_RETF}:
            return None
        ret = instructions[-1].insn
        if ret.operands and (len(ret.operands) != 1 or ret.operands[0].type != X86_OP_IMM):
            return None
        result.append(ReturnFrame8616(
            ret.address, 32 if 0x66 in ret.prefix else 16, ret.id == X86_INS_RETF,
            int(ret.operands[0].imm) if ret.operands else 0,
        ))
    return tuple(result)


class _OriginalProjectBoundary8616(Protocol):
    """Exact source mapping published by the rebased analysis-image loader."""

    _inertia_original_project: Project
    _inertia_original_linear_delta: int


def callee_return_evidence_8616(project: Project, target: int) -> TerminalStackCleanupEvidence8616:
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


def _callee_refusal_8616(project: Project, target: int) -> ReturnSegmentRefusal8616 | None:
    """Require all known callee endpoints to be compatible plain far returns."""
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
    if any(not frame.far for frame in frames):
        return ReturnSegmentRefusal8616.RETURN_MISMATCH
    if any(frame.operand_bits != 16 or frame.cleanup_bytes != 0 for frame in frames):
        return ReturnSegmentRefusal8616.UNSUPPORTED_WIDTH_OR_CLEANUP
    return None


def _is_cs_push_8616(instruction: CsInsn) -> bool:
    """Recognize the architectural register operand, not its printed spelling."""
    return bool(
        instruction.id == X86_INS_PUSH and len(instruction.operands) == 1
        and instruction.operands[0].type == X86_OP_REG
        and instruction.operands[0].reg == X86_REG_CS
    )


def _push_effects_8616(
    project: Project, block_addr: int, block_size: int, push_addr: int,
) -> tuple[ReturnSegmentEffect8616, ...]:
    """Publish the complete unoptimized VEX effect sequence of one PUSH CS."""
    vex = project.factory.block(block_addr, size=block_size, opt_level=0).vex
    current_addr: int | None = None
    effects: list[ReturnSegmentEffect8616] = []
    for index, statement in enumerate(vex.statements):
        if isinstance(statement, IMark):
            current_addr = statement.addr
        elif current_addr == push_addr:
            if isinstance(statement, Put) and statement.offset == project.arch.sp_offset:
                role = CallReturnFrameEffectRole8616.STACK_POINTER_UPDATE
            elif isinstance(statement, Store):
                role = CallReturnFrameEffectRole8616.STACK_STORE
            else:
                continue
            effects.append(ReturnSegmentEffect8616(push_addr, block_addr, index, role))
    sp = CallReturnFrameEffectRole8616.STACK_POINTER_UPDATE
    store = CallReturnFrameEffectRole8616.STACK_STORE
    if tuple(item.role for item in effects) not in {(sp, store), (sp, store, store)}:
        return ()
    return tuple(effects)


def collect_return_segment_frames_8616(
    project: object, function: object, return_addrs: Mapping[int, int],
) -> tuple[ReturnSegmentFrame8616, ...]:
    """Return one explicit outcome per call using decoded prefix and exit proof."""
    if not isinstance(project, Project) or not isinstance(function, Function):
        return tuple(ReturnSegmentFrame8616(addr, refusal=ReturnSegmentRefusal8616.UNKNOWN_CALLEE)
                     for addr in sorted(return_addrs))
    candidates: dict[int, list[tuple[int, int, CsInsn, CsInsn]]] = {}
    for block in function.blocks:
        if not isinstance(block.size, int) or block.size <= 0:
            continue
        instructions = tuple(wrapper.insn for wrapper in block.capstone.insns)
        for push, call in pairwise(instructions):
            if call.address in return_addrs and _is_cs_push_8616(push):
                candidates.setdefault(call.address, []).append((block.addr, block.size, push, call))
    result: list[ReturnSegmentFrame8616] = []
    for address, return_addr in sorted(return_addrs.items()):
        matches = candidates.get(address, [])
        refusal: ReturnSegmentRefusal8616 | None = None
        effects: tuple[ReturnSegmentEffect8616, ...] = ()
        if not matches:
            refusal = ReturnSegmentRefusal8616.NO_PREFIX
        elif len(matches) != 1:
            refusal = ReturnSegmentRefusal8616.AMBIGUOUS_EFFECTS
        else:
            block_addr, block_size, push, call = matches[0]
            if (
                call.id != X86_INS_CALL or len(call.operands) != 1
                or call.operands[0].type != X86_OP_IMM
                or push.address + push.size != address or address + call.size != return_addr
            ):
                refusal = ReturnSegmentRefusal8616.UNKNOWN_CALLEE
            elif 0x66 in push.prefix or 0x66 in call.prefix:
                refusal = ReturnSegmentRefusal8616.UNSUPPORTED_WIDTH_OR_CLEANUP
            else:
                refusal = _callee_refusal_8616(project, call.operands[0].imm)
                if refusal is None:
                    effects = _push_effects_8616(project, block_addr, block_size, push.address)
                    if not effects:
                        refusal = ReturnSegmentRefusal8616.AMBIGUOUS_EFFECTS
        result.append(ReturnSegmentFrame8616(address, effects, refusal))
    return tuple(result)
