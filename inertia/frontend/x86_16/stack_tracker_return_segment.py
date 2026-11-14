# cython: language_level=3, infer_types=True
"""Consume proven machine frames and return segments in native stack tracking.

Layer: Frontend/angr compatibility.
Responsibility: apply authoritative Semantics return-frame and cleanup proofs after
angr accounts for one architecture word of return address. Do not infer far returns
from PUSH CS alone or alter aliases, C storage, or rendered output.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, cast

import pyvex
from angr import Project
from angr.analyses.stack_pointer_tracker import (
    Constant,
    CouldNotResolveException,
    OffsetVal,
    StackPointerTracker,
    StackPointerTrackerState,
)
from angr.calling_conventions import SimStackArg
from angr.errors import SimEngineError, SimTranslationError
from angr.utils.types import dereference_simtype_by_lib

from inertia.ir import IRBlock, IRInstr
from inertia.ir.vex_import import _block_to_ir
from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from inertia.semantics.call_return_frame_effects import MachineCallFrame8616, decode_machine_call_frame_8616
from inertia.semantics.call_return_segment import callee_return_evidence_8616, collect_return_segment_frames_8616
from inertia.semantics.direct_near_call_target_binding import (
    DirectNearCallTargetBindingFailure8616,
    prove_direct_near_call_target_binding_from_decoded_8616,
)
from inertia.semantics.terminal_stack_cleanup import TerminalReturnFrameKind8616

from .frontend_block_inventory import collect_decoded_block_evidence_8616
from .frontend_direct_callsite_index import DecodedDirectCallsite8616
import dataclasses
import operator

_WORD_BITS = 16


@dataclasses.dataclass(frozen=True, )
class NativeMachineCallFrameResult8616:
    """Closed census for one native machine-frame reconciliation."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong
    frame: MachineCallFrame8616 | None
    adjustment: int | None


@cython.ccall
def apply_native_machine_call_frame_8616(
    tracker: StackPointerTracker, vex: pyvex.IRSB,
    state: StackPointerTrackerState, callsite: object,
) -> NativeMachineCallFrameResult8616:
    """Replace native fixed-word return popping with the encoded CALL frame.

    This accounts only for the machine frame on the existing returning-call
    transfer. It proves neither callee argument cleanup nor register preservation.
    """
    current: object
    frame: object
    arch = tracker.project.arch
    if arch.name != "86_16" or vex.jumpkind != "Ijk_Call" or arch.sp_offset not in tracker.reg_offsets:
        return NativeMachineCallFrameResult8616(0, 0, 0, 0, 0, None, None)
    frame = None if callsite is None else decode_machine_call_frame_8616(tracker.project, callsite)
    if frame is None or operator.ne(frame.return_addr, vex.addr + vex.size):
        state.put(arch.sp_offset, None, force=True)
        return NativeMachineCallFrameResult8616(1, 0, 0, 0, 1, frame, None)
    adjustment = frame.frame_bytes - (arch.bytes if arch.call_pushes_ret else 0)
    try:
        current = state.get(arch.sp_offset)
    except CouldNotResolveException:
        return NativeMachineCallFrameResult8616(1, 1, 0, 0, 1, frame, adjustment)
    if not isinstance(current, (OffsetVal, Constant)):
        return NativeMachineCallFrameResult8616(1, 1, 0, 0, 1, frame, adjustment)
    if adjustment:
        state.put(arch.sp_offset, current + Constant(adjustment), force=True)
    return NativeMachineCallFrameResult8616(1, 1, 1, 1, 0, frame, adjustment)


class _ExactSliceBoundary8616(Protocol):
    """Original-image attachment identifying an exact-region project."""

    _inertia_original_project: Project
    _inertia_original_linear_delta: cython.longlong


@dataclasses.dataclass(frozen=True, )
class _NativeBlock8616:
    """Existing VEX block surface for the owned IR importer; never relift."""

    addr: cython.longlong
    vex: pyvex.IRSB


class _DecodedCallsiteInstruction8616(Protocol):
    """Decoded native instruction fields consumed at the Capstone boundary."""

    address: cython.longlong
    size: cython.longlong
    mnemonic: object
    bytes: object
    insn: object


class _RawInsnOperands8616(Protocol):
    """Raw Capstone instruction operand sequence."""

    operands: Sequence[object]


class _DecodedImmediateOperand8616(Protocol):
    """Raw Capstone operand fields for one immediate coordinate."""

    type: cython.longlong
    imm: cython.longlong


def _imported_terminal_call_8616(vex: pyvex.IRSB) -> object:
    """Import the tracker's own VEX block and expose its terminal CALL.

    The importer stamps block-``next`` origin provenance on the terminal
    instruction, so the IR is always built from the exact IRSB the tracker
    processed — a relift could renumber the temporaries the binding proof
    compares against.
    """
    block, _transport, _terminal_evidence = _block_to_ir(_NativeBlock8616(vex.addr, vex))
    calls = tuple(instruction for instruction in iter(block.instrs) if instruction.op == "CALL")
    if len(calls) != 1 or calls[0] is not block.instrs[-1]:
        return None
    return block, calls[0]


def _decoded_callsite_entry_8616(
    project: Project, callsite: cython.longlong,
) -> DecodedDirectCallsite8616 | None:
    """Retain the decoded direct-call coordinate fact for one callsite.

    The target coordinate is the instruction's own decoded immediate —
    never a canonicalized or caller-asserted address — so the binding owner
    can independently re-verify it against the operand DAG and the mapped
    ``E8`` bytes. Indirect and far forms return ``None``.
    """
    instruction: object
    try:
        evidence = collect_decoded_block_evidence_8616(project, callsite, opt_level=0)
    except (KeyError, SimEngineError, SimTranslationError, ValueError):
        return None
    instruction = next(
        (
            insn
            for insn in iter(evidence.instructions)
            if operator.eq(cast(_DecodedCallsiteInstruction8616, insn).address, callsite)
        ),
        None,
    )
    if instruction is None:
        return None
    if resolve_direct_call_target_from_instruction_8616(project, instruction) is None:
        return None
    decoded = cast(_DecodedCallsiteInstruction8616, instruction)
    operands = cast(_RawInsnOperands8616, decoded.insn).operands
    if len(operands) != 1:
        return None
    operand = cast(_DecodedImmediateOperand8616, operands[0])
    if operand.type != 2 or type(operand.imm) is not int or operand.imm < 0:
        return None
    return DecodedDirectCallsite8616(
        caller_start=callsite,
        instructions=(instruction,),
        instruction_index=0,
        callsite_addr=callsite,
        target_addr=operand.imm,
        is_far=decoded.mnemonic == "lcall",
    )


@cython.ccall
def _bound_terminal_direct_call_8616(
    project: Project, vex: pyvex.IRSB,
) -> object:
    """Import the terminal CALL and return its proven active-domain target.

    A symbolic CALL operand is admitted only when the direct-near binding
    owner re-verifies the retained operand DAG, its block-``next`` origin
    provenance, the native re-lift, the selector fetch window and the
    mapped ``E8`` bytes. An unproven or foreign operand returns ``None``
    untouched; a decoded address alone is never evidence.
    """
    decoded: object
    imported: object
    imported = _imported_terminal_call_8616(vex)
    if imported is None:
        return None
    block, instruction = imported
    callsite = instruction.addr
    if type(callsite) is not int:
        return None
    decoded = _decoded_callsite_entry_8616(project, callsite)
    if decoded is None:
        return None
    binding = prove_direct_near_call_target_binding_from_decoded_8616(
        project, block=block, instruction=instruction, decoded=decoded,
    )
    if binding.complete and type(binding.target_addr) is int:
        return block, instruction, binding.target_addr
    if binding.failure is not DirectNearCallTargetBindingFailure8616.TARGET_BYTES_MISMATCH:
        return None
    return _original_image_bound_target_8616(project, callsite, decoded, block, instruction)


@cython.ccall
def _original_image_bound_target_8616(
    project: Project,
    callsite: cython.longlong,
    decoded: DecodedDirectCallsite8616,
    block: IRBlock,
    instruction: IRInstr,
) -> object:
    """Prove an exact-slice call through the authenticated original image.

    Reaching this stage means the slice-domain binding verified the
    operand DAG, origin provenance, native re-lift, shape and selector
    window and refused only on mapped bytes: the decoded target lies
    outside the slice image. The declared slice→original correspondence
    is then authenticated at this exact callsite by identical instruction
    encodings, and the original-domain binding must close on the
    original's own imported block. The returned target stays in the
    slice's coordinate domain so downstream evidence owners rebase the
    address exactly once.
    """
    imported: object
    original_decoded: object
    boundary = cast(_ExactSliceBoundary8616, project)
    try:
        original = boundary._inertia_original_project
        delta = boundary._inertia_original_linear_delta
    except AttributeError:
        return None
    if not isinstance(original, Project) or type(delta) is not int:
        return None
    original_callsite = callsite + delta
    if original_callsite < 0:
        return None
    original_decoded = _decoded_callsite_entry_8616(original, original_callsite)
    if original_decoded is None:
        return None
    slice_encoding = bytes(
        cast(
            _DecodedCallsiteInstruction8616,
            decoded.instructions[decoded.instruction_index],
        ).bytes
    )
    original_encoding = bytes(
        cast(
            _DecodedCallsiteInstruction8616,
            original_decoded.instructions[original_decoded.instruction_index],
        ).bytes
    )
    if slice_encoding != original_encoding:
        return None
    try:
        native = original.factory.block(original_callsite).vex
    except (KeyError, SimEngineError, SimTranslationError, ValueError):
        return None
    if not isinstance(native, pyvex.IRSB):
        return None
    imported = _imported_terminal_call_8616(native)
    if imported is None:
        return None
    original_block, original_instruction = imported
    binding = prove_direct_near_call_target_binding_from_decoded_8616(
        original,
        block=original_block,
        instruction=original_instruction,
        decoded=original_decoded,
    )
    if (
        not binding.complete
        or operator.ne(binding.target_addr, decoded.target_addr + delta)
    ):
        return None
    return block, instruction, decoded.target_addr


@cython.ccall
def _cleanup_target_8616(project: Project, vex: pyvex.IRSB) -> int | None:
    """Return the proven direct-call target in the active coordinate domain.

    A symbolic operand is admitted only after the direct-near binding
    proof re-verifies the imported operand DAG, its block-``next`` origin,
    the native re-lift and the mapped ``E8`` bytes; an exact-slice call
    additionally requires the authenticated original-image binding so the
    downstream evidence owner still rebases the target exactly once.
    """
    bound: object
    try:
        original = cast(_ExactSliceBoundary8616, project)._inertia_original_project
    except AttributeError:
        original = None
    if isinstance(original, Project) and isinstance(vex.next, pyvex.expr.Const):
        # Exact-region targets are slice-relative; return evidence rebases once.
        return int(vex.next.con.value)
    bound = _bound_terminal_direct_call_8616(project, vex)
    if bound is None:
        return None
    _block, _instruction, target = bound
    return target


def _native_cleanup_bytes(tracker: StackPointerTracker, node: object) -> cython.longlong:
    """Mirror the installed angr cleanup projection so it is not counted twice.

    This is backend compatibility, not evidence of the binary's convention.
    angr selects the first callee with a cleanup convention and a prototype.
    """
    convention: object
    prototype: object
    callee: object
    callees = [] if tracker._func is None else tracker._find_callees(node)
    for callee in callees:
        convention = callee.calling_convention
        prototype = callee.prototype
        if convention is None or not convention.CALLEE_CLEANUP or prototype is None:
            continue
        if callee.prototype_libname:
            prototype = dereference_simtype_by_lib(prototype, callee.prototype_libname)
        locations = convention.arg_locs(prototype)
        return int(tracker.project.arch.bytes) * sum(isinstance(location, SimStackArg) for location in iter(locations))
    return 0


@cython.ccall
def apply_native_argument_cleanup_8616(
    tracker: StackPointerTracker, node: object, vex: pyvex.IRSB,
    state: StackPointerTrackerState,
) -> None:
    """Replace prototype-derived near cleanup with a complete binary proof."""
    cleanup: object
    current: object
    target: object
    if tracker.project.arch.name != "86_16" or vex.jumpkind != "Ijk_Call":
        return
    sp_offset = tracker.project.arch.sp_offset
    if sp_offset not in tracker.reg_offsets or vex.next is None:
        return
    target = _cleanup_target_8616(tracker.project, vex)
    if target is None:
        return
    evidence = callee_return_evidence_8616(tracker.project, target)
    compatible_frame = (
        evidence.complete
        and evidence.consistent_return_frame_kind is TerminalReturnFrameKind8616.NEAR
        and operator.eq(evidence.consistent_return_operand_bits, _WORD_BITS)
    )
    cleanup = evidence.consistent_cleanup
    if not compatible_frame or cleanup is None:
        return
    adjustment = cleanup - _native_cleanup_bytes(tracker, node)
    if adjustment == 0:
        return
    try:
        current = state.get(sp_offset)
    except CouldNotResolveException:
        return
    if isinstance(current, (OffsetVal, Constant)):
        state.put(sp_offset, current + Constant(adjustment), force=True)


@cython.ccall
def apply_native_return_segment_8616(
    tracker: StackPointerTracker, vex: pyvex.IRSB,
    state: StackPointerTrackerState, callsite: object,
) -> None:
    """Consume a proved extra CS slot without repeating return-kind inference."""
    adjustment: object
    current: object
    if tracker.project.arch.name != "86_16" or vex.jumpkind != "Ijk_Call" or callsite is None:
        return
    sp_offset = tracker.project.arch.sp_offset
    if sp_offset not in tracker.reg_offsets or tracker._func is None:
        return
    frames = collect_return_segment_frames_8616(
        tracker.project, tracker._func, {callsite: vex.addr + vex.size},
        block_addr=vex.addr,
    )
    if len(frames) != 1:
        return
    adjustment = frames[0].additional_return_bytes
    if adjustment is None:
        return
    try:
        current = state.get(sp_offset)
    except CouldNotResolveException:
        return
    if isinstance(current, (OffsetVal, Constant)):
        state.put(sp_offset, current + Constant(adjustment), force=True)
