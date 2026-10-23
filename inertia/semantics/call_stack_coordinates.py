"""Prove per-call machine-SP coordinates from binary terminal evidence.

Layer: Semantics.
Responsibility: bind the admitted IR CALL, the caller block's decoded head
inventory, the terminal callee cleanup census, and linked return-segment
frames into the IR coordinate contract. Summary or prototype hints alone
never prove callee purge, caller cleanup, or argument extent, and a caller
post-call cleanup instruction never proves a zero callee purge.
``IRCallStackEffect8616.net_stack_delta`` remains the owned SP projection
this proof derives and validates.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
Forbidden: source/COD/name evidence, rendered-text recovery, or prototype repair.
"""

from __future__ import annotations

from typing import Any, cast

from angr.errors import SimEngineError, SimTranslationError

from inertia.frontend.x86_16.frontend_block_inventory import (
    decoded_block_instructions_8616,
)
from inertia.frontend.x86_16.frontend_instruction_kinds import (
    is_x86_16_call_mnemonic_8616,
)
from inertia.ir.call_stack_coordinates import (
    CALL_STACK_COORDINATE_SLOTS_8616,
    CallArgumentAnchorKind8616,
    CallStackCoordinateRefusal8616,
    IRCallArgumentTop8616,
    IRCallStackCoordinates8616,
)
from inertia.ir.core import IRBlock, IRInstr, IRValue, MemSpace

from .call_return_segment import ReturnSegmentFrame8616
from .call_stack_coordinate_source import CallStackCoordinateSource8616
from .callee_stack_effects import CalleeStackCallResult8616, prove_direct_callee_stack_effect_8616
from .callsite_summary import (
    CallsiteMachineFrameKind8616,
    CallsiteSummary8616,
    callsite_machine_frame_kind_8616,
)
from .direct_near_call_target_binding import prove_direct_near_call_target_binding_8616
from .terminal_return_contract import (
    TerminalReturnFrameKind8616,
    decoded_return_operand_bits_8616,
)
from .terminal_stack_cleanup import (
    TerminalStackCleanupEvidence8616,
    terminal_stack_cleanup_at_address_8616,
)

__all__ = ["prove_call_stack_coordinates_8616"]


_WORD_SP_MASK_8616: int = 0xFFFF
_WORD_SP_SIGN_BIT_8616: int = 0x8000
_OPERAND_BITS_WORD_8616: int = 16
_IMM_OPERAND_TYPE_8616: int = 2

# Typed terminal-frame to callsite-frame correspondence: the machine return
# shape a callee census must agree with for the admitted call frame kind.
_TERMINAL_TO_CALLSITE_FRAME_8616: dict[
    TerminalReturnFrameKind8616, CallsiteMachineFrameKind8616
] = {
    TerminalReturnFrameKind8616.NEAR: CallsiteMachineFrameKind8616.NEAR,
    TerminalReturnFrameKind8616.FAR: CallsiteMachineFrameKind8616.FAR,
}


def _inner_instruction_8616(insn: object) -> object:
    """Return a dynamic Capstone instruction beneath an optional angr wrapper."""
    try:
        return cast(Any, insn).insn
    except AttributeError:
        return cast(Any, insn)


def _mnemonic_8616(insn: object) -> str:
    """Return a normalized mnemonic across the dynamic Capstone boundary."""
    try:
        return str(cast(Any, insn).mnemonic or "").lower()
    except AttributeError:
        try:
            return str(cast(Any, _inner_instruction_8616(insn)).mnemonic or "").lower()
        except AttributeError:
            return ""


def _instruction_addr_8616(insn: object) -> int | None:
    """Return one instruction address across the dynamic Capstone boundary."""
    for candidate in (insn, _inner_instruction_8616(insn)):
        try:
            address = cast(Any, candidate).address
        except AttributeError:
            continue
        if isinstance(address, int) and not isinstance(address, bool):
            return address
    return None


def _instruction_size_8616(insn: object) -> int | None:
    """Return the decoded instruction byte length across the Capstone boundary."""
    for candidate in (insn, _inner_instruction_8616(insn)):
        try:
            size = cast(Any, candidate).size
        except AttributeError:
            continue
        if isinstance(size, int) and not isinstance(size, bool) and size > 0:
            return size
    return None


def _operands_8616(insn: object) -> tuple[object, ...]:
    """Return decoded operand objects across the dynamic Capstone boundary."""
    try:
        return tuple(cast(Any, _inner_instruction_8616(insn)).operands or ())
    except AttributeError:
        return ()


def _imm_operand_value_8616(insn: object) -> int | None:
    """Return the single immediate operand value, or None when not unary-imm."""
    operands = _operands_8616(insn)
    if len(operands) != 1:
        return None
    operand = operands[0]
    try:
        operand_type = cast(Any, operand).type
        imm = cast(Any, operand).imm
    except AttributeError:
        return None
    if operand_type != _IMM_OPERAND_TYPE_8616:
        return None
    return imm if isinstance(imm, int) and not isinstance(imm, bool) else None


def _signed_word_delta_8616(byte_count: int) -> int:
    """Project a modular 16-bit SP byte delta into the affine offset model."""
    masked = byte_count & _WORD_SP_MASK_8616
    return masked - 0x10000 if masked >= _WORD_SP_SIGN_BIT_8616 else masked


def _caller_block_heads_8616(
    project: object,
    block: IRBlock,
) -> tuple[object, ...] | None:
    """Decode the real head inventory of the CALL's own IR block."""
    try:
        return tuple(decoded_block_instructions_8616(project, block.addr, opt_level=0))
    except (
        AttributeError, KeyError, RuntimeError, SimEngineError,
        SimTranslationError, TypeError, ValueError,
    ):
        return None


def _admitted_call_head_8616(
    heads: tuple[object, ...],
    instruction: IRInstr,
    summary: CallsiteSummary8616,
    refusals: list[CallStackCoordinateRefusal8616],
) -> bool:
    """Bind the summary's return edge to the decoded CALL head.

    The callsite must be a real decoded head, decode as a machine CALL, and
    the summary's ``return_addr`` must equal the physical fallthrough of that
    head. A wrong return hint cannot ride along to the SP projection.
    """
    call_head = next(
        (insn for insn in heads if _instruction_addr_8616(insn) == summary.callsite_addr),
        None,
    )
    if call_head is None or not is_x86_16_call_mnemonic_8616(_mnemonic_8616(call_head)):
        refusals.append(CallStackCoordinateRefusal8616.CALL_HEAD_NOT_FOUND)
        return False
    operand_bits = decoded_return_operand_bits_8616(_inner_instruction_8616(call_head))
    if operand_bits != _OPERAND_BITS_WORD_8616:
        refusals.append(CallStackCoordinateRefusal8616.CALL_OPERAND_WIDTH_UNPROVEN)
        return False
    size = _instruction_size_8616(call_head)
    if size is None or summary.return_addr != summary.callsite_addr + size:
        refusals.append(CallStackCoordinateRefusal8616.RETURN_ADDRESS_MISMATCH)
        return False
    if instruction.addr != summary.callsite_addr:
        refusals.append(CallStackCoordinateRefusal8616.CALL_IDENTITY_UNPROVEN)
        return False
    return True


def _bound_target_8616(
    project: object,
    heads: tuple[object, ...],
    instruction: IRInstr,
    block: IRBlock,
    summary: CallsiteSummary8616,
    refusals: list[CallStackCoordinateRefusal8616],
) -> bool:
    """Authenticate the summary target against the real decoded CALL."""
    if summary.target_addr is None:
        refusals.append(CallStackCoordinateRefusal8616.CALL_TARGET_UNRESOLVED)
        return False
    call_head = next(
        (insn for insn in heads if _instruction_addr_8616(insn) == summary.callsite_addr),
        None,
    )
    imm_target = None if call_head is None else _imm_operand_value_8616(call_head)
    if imm_target is not None:
        bound = imm_target == summary.target_addr
    else:
        arg = instruction.args[0] if instruction.args else None
        bound = (
            isinstance(arg, IRValue)
            and arg.space is MemSpace.CONST
            and type(arg.const) is int
            and arg.const == summary.target_addr
        )
        if not bound:
            binding = prove_direct_near_call_target_binding_8616(
                project, block=block, instruction=instruction, summary=summary,
            )
            bound = binding.complete
    if not bound:
        refusals.append(CallStackCoordinateRefusal8616.CALL_TARGET_CONFLICT)
    return bound


def _callee_purge_and_frame_extra_8616(
    terminal: TerminalStackCleanupEvidence8616 | None,
    frame_kind: CallsiteMachineFrameKind8616 | None,
    return_frame: ReturnSegmentFrame8616 | None,
    summary: CallsiteSummary8616,
    refusals: list[CallStackCoordinateRefusal8616],
) -> tuple[int | None, int | None]:
    """Classify callee purge and linked return extra from terminal evidence.

    The caller's own post-call cleanup can never prove a zero callee purge;
    only the closed callee return census establishes ``callee_purged_bytes``.
    """
    if terminal is None:
        refusals.append(
            CallStackCoordinateRefusal8616.CALLEE_TERMINAL_EVIDENCE_UNAVAILABLE
        )
        return None, None
    if not terminal.complete:
        refusals.append(
            CallStackCoordinateRefusal8616.CALLEE_TERMINAL_EVIDENCE_INCOMPLETE
        )
        return None, None
    if terminal.consistent_return_operand_bits != _OPERAND_BITS_WORD_8616:
        refusals.append(
            CallStackCoordinateRefusal8616.CALLEE_RETURN_OPERAND_WIDTH_UNPROVEN
        )
        return None, None
    terminal_kind = terminal.consistent_return_frame_kind
    purge = terminal.consistent_cleanup
    if not isinstance(purge, int) or isinstance(purge, bool):
        refusals.append(
            CallStackCoordinateRefusal8616.CALLEE_TERMINAL_EVIDENCE_INCOMPLETE
        )
        return None, None
    if _TERMINAL_TO_CALLSITE_FRAME_8616.get(cast(TerminalReturnFrameKind8616, terminal_kind)) is None:
        refusals.append(CallStackCoordinateRefusal8616.RETURN_FRAME_KIND_UNSUPPORTED)
        return None, None
    if frame_kind is None:
        # The callsite frame refusal is recorded by the caller; the purge
        # amount is still independently proven by the terminal census.
        return purge, None
    if _TERMINAL_TO_CALLSITE_FRAME_8616[cast(TerminalReturnFrameKind8616, terminal_kind)] is frame_kind:
        return purge, 0
    if (
        frame_kind is CallsiteMachineFrameKind8616.NEAR
        and terminal_kind is TerminalReturnFrameKind8616.FAR
        and return_frame is not None
        and return_frame.callsite_addr == summary.callsite_addr
        and return_frame.refusal is None
    ):
        extra = return_frame.additional_return_bytes
        if extra is not None:
            return purge, extra
    refusals.append(CallStackCoordinateRefusal8616.RETURN_FRAME_KIND_CONFLICT)
    return purge, None


def _decoded_add_sp_amount_8616(head: object | None) -> int | None:
    """Return the proven immediate of a decoded ``add sp, imm`` head."""
    if head is None or _mnemonic_8616(head) != "add":
        return None
    operands = _operands_8616(head)
    if len(operands) != 2:
        return None
    try:
        inner = cast(Any, _inner_instruction_8616(head))
        reg_name = str(inner.reg_name(cast(Any, operands[0]).reg)).lower()
    except (AttributeError, TypeError):
        reg_name = ""
    if reg_name not in {"sp", "esp"}:
        return None
    try:
        amount = cast(Any, operands[1]).imm
    except AttributeError:
        return None
    if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
        return None
    return amount


def _caller_cleanup_8616(
    project: object | None,
    summary: CallsiteSummary8616,
    return_bound: bool,
    refusals: list[CallStackCoordinateRefusal8616],
) -> tuple[int | None, int | None]:
    """Classify caller post-call cleanup from the decoded return-edge head.

    The reclaim amount is proven only when the real head at the admitted
    return address decodes as ``add sp, imm`` and the summary claim agrees on
    both the instruction address and the amount. Anything else is refused.
    """
    if project is None or not return_bound or summary.return_addr is None:
        refusals.append(CallStackCoordinateRefusal8616.CALLER_CLEANUP_UNPROVEN)
        return None, None
    try:
        edge_heads = decoded_block_instructions_8616(
            project, summary.return_addr, opt_level=0,
        )
    except (
        AttributeError, KeyError, RuntimeError, SimEngineError,
        SimTranslationError, TypeError, ValueError,
    ):
        edge_heads = ()
    head = edge_heads[0] if edge_heads else None
    decoded_amount = _decoded_add_sp_amount_8616(head) if head is not None else None
    claimed_addr = summary.stack_cleanup_instruction_addr
    if claimed_addr is None:
        if decoded_amount is None:
            refusals.append(CallStackCoordinateRefusal8616.CALLER_CLEANUP_UNPROVEN)
            return None, None
        return decoded_amount, summary.return_addr
    if (
        claimed_addr != summary.return_addr
        or decoded_amount is None
        or summary.stack_cleanup != decoded_amount
    ):
        refusals.append(CallStackCoordinateRefusal8616.CALLER_CLEANUP_EVIDENCE_CONFLICT)
        return None, None
    return decoded_amount, claimed_addr


def _argument_window_push_width_8616(insn: object) -> int | None:
    """Return the proven stack width of one decoded single-operand PUSH head."""
    if _mnemonic_8616(insn) != "push" or len(_operands_8616(insn)) != 1:
        return None
    operand_bits = decoded_return_operand_bits_8616(_inner_instruction_8616(insn))
    if not isinstance(operand_bits, int) or isinstance(operand_bits, bool):
        return None
    return operand_bits // 8


def _argument_top_8616(
    heads: tuple[object, ...] | None,
    summary: CallsiteSummary8616,
    refusals: list[CallStackCoordinateRefusal8616],
) -> IRCallArgumentTop8616 | None:
    """Prove the contiguous argument-region top above caller-entry SP.

    The region is proven only against the caller block's real head inventory:
    every decoded head between the earliest recorded PUSH and the CALL must
    itself be a recorded argument PUSH head whose decoded operand width agrees
    with the summary width, in execution order. Operand-interior addresses,
    group pushes, and hints without head evidence stay unknown.
    """
    arg_count = summary.arg_count
    if arg_count is None:
        refusals.append(CallStackCoordinateRefusal8616.ARGUMENT_COUNT_UNKNOWN)
        return None
    if heads is None:
        refusals.append(CallStackCoordinateRefusal8616.ARGUMENT_WINDOW_DECODE_REFUSED)
        return None
    call_index = next(
        (index for index, insn in enumerate(heads)
         if _instruction_addr_8616(insn) == summary.callsite_addr),
        None,
    )
    if call_index is None:
        refusals.append(CallStackCoordinateRefusal8616.CALL_HEAD_NOT_FOUND)
        return None
    if arg_count == 0:
        # A summary's zero is not an arity proof. Arguments can have been
        # prepared before intervening instructions or with stack stores.
        refusals.append(CallStackCoordinateRefusal8616.ARGUMENT_ZERO_ARITY_UNPROVEN)
        return None
    push_addrs = summary.push_arg_instruction_addrs
    widths = summary.arg_widths
    if (
        len(push_addrs) != arg_count
        or len(widths) != arg_count
        or arg_count > call_index
    ):
        refusals.append(CallStackCoordinateRefusal8616.ARGUMENT_SETUP_INCOMPLETE)
        return None
    window = heads[call_index - arg_count:call_index]
    extent = _proven_window_extent_8616(window, push_addrs, widths, refusals)
    if extent is None:
        return None
    return IRCallArgumentTop8616(
        MemSpace.SS,
        CallArgumentAnchorKind8616.CALLER_SP_BEFORE_CALL,
        0,
        extent,
        push_addrs,
    )


def _proven_window_extent_8616(
    window: tuple[object, ...],
    push_addrs: tuple[int, ...],
    widths: tuple[int, ...],
    refusals: list[CallStackCoordinateRefusal8616],
) -> int | None:
    """Verify the head window is exactly the recorded contiguous PUSH run."""
    extent = 0
    for index, insn in enumerate(window):
        if _instruction_addr_8616(insn) != push_addrs[index]:
            refusals.append(CallStackCoordinateRefusal8616.ARGUMENT_REGION_AMBIGUOUS)
            return None
        push_width = _argument_window_push_width_8616(insn)
        if push_width is None:
            refusals.append(CallStackCoordinateRefusal8616.ARGUMENT_OPERAND_WIDTH_UNPROVEN)
            return None
        if push_width != widths[index]:
            refusals.append(CallStackCoordinateRefusal8616.ARGUMENT_REGION_AMBIGUOUS)
            return None
        extent += push_width
    return extent


def _admitted_body_sp_proof_8616(
    project: object | None, summary: CallsiteSummary8616,
    frame_kind: CallsiteMachineFrameKind8616 | None, target_bound: bool,
    retained: CalleeStackCallResult8616 | None,
    recheck_retained: bool,
) -> CalleeStackCallResult8616 | None:
    """Produce body evidence once; rechecks consume only the retained scope."""
    if project is None or not target_bound:
        return None
    if recheck_retained:
        if retained is None or retained.project is not project:
            return None
        if (retained.callsite_addr, retained.return_addr, retained.target_addr, retained.frame_kind) != (
            summary.callsite_addr, summary.return_addr, summary.target_addr, frame_kind,
        ):
            return None
        return retained
    return prove_direct_callee_stack_effect_8616(
        project, summary.callsite_addr, summary.return_addr, summary.target_addr, frame_kind,
    )


def prove_call_stack_coordinates_8616(
    project: object | None,
    summary: CallsiteSummary8616,
    *,
    instruction: IRInstr | None = None,
    block: IRBlock | None = None,
    return_frame: ReturnSegmentFrame8616 | None = None,
    _retained_body_sp_proof: CalleeStackCallResult8616 | None = None,
    _recheck_retained_body: bool = False,
) -> IRCallStackCoordinates8616:
    """Prove independently evidenced SP coordinates for one exact CALL.

    Every field derives from its own evidence owner: the callee purge from
    the closed terminal census at the admitted call target, the caller
    cleanup from the decoded head at the authenticated return address, the
    return-frame width from the callsite machine frame kind, and the
    argument top from the caller block's real head inventory. Without the
    actual CALL instruction and its block, hint fields are not re-certified.
    """
    refusals: list[CallStackCoordinateRefusal8616] = []

    frame_kind = callsite_machine_frame_kind_8616(summary)

    heads: tuple[object, ...] | None = None
    call_bound = False
    target_bound = False
    admitted_ir = bool(
        instruction is not None and block is not None
        and instruction.op == "CALL"
        and any(row is instruction for row in block.instrs)
    )
    if project is not None and instruction is not None and block is not None and admitted_ir:
        heads = _caller_block_heads_8616(project, block)
        if heads is None:
            refusals.append(CallStackCoordinateRefusal8616.CALL_HEAD_DECODE_REFUSED)
        else:
            call_bound = _admitted_call_head_8616(heads, instruction, summary, refusals)
            if call_bound:
                target_bound = _bound_target_8616(
                    project, heads, instruction, block, summary, refusals,
                )
    elif project is not None:
        refusals.append(CallStackCoordinateRefusal8616.CALL_IDENTITY_UNPROVEN)

    # The frame width is published only once the call is admitted; a bare
    # summary kind spelling is not physical return-frame proof.
    return_frame_bytes: int | None = None
    if frame_kind is None:
        refusals.append(CallStackCoordinateRefusal8616.CALL_FRAME_KIND_UNKNOWN)
    elif call_bound:
        return_frame_bytes = frame_kind.return_frame_width

    caller_cleanup_bytes, caller_cleanup_addr = _caller_cleanup_8616(
        project, summary, call_bound, refusals,
    )

    if project is None:
        refusals.append(
            CallStackCoordinateRefusal8616.CALLEE_TERMINAL_EVIDENCE_UNAVAILABLE
        )
    terminal = (
        terminal_stack_cleanup_at_address_8616(project, summary.target_addr)
        if target_bound and project is not None and summary.target_addr is not None
        else None
    )
    callee_purged, additional_return = _callee_purge_and_frame_extra_8616(
        terminal, frame_kind, return_frame, summary, refusals,
    )

    callee_sp_proof = _admitted_body_sp_proof_8616(
        project, summary, frame_kind, target_bound,
        _retained_body_sp_proof, _recheck_retained_body,
    )
    callee_return_delta = None if callee_sp_proof is None else callee_sp_proof.return_sp_delta
    if callee_return_delta is None:
        refusals.append(CallStackCoordinateRefusal8616.CALLEE_STACK_EFFECT_UNPROVEN)
    net_sp_delta: int | None = None
    if callee_return_delta is not None and return_frame_bytes is not None and additional_return is not None:
        net_sp_delta = _signed_word_delta_8616(callee_return_delta - return_frame_bytes)

    argument_top = _argument_top_8616(heads, summary, refusals)

    slots = (
        return_frame_bytes,
        callee_purged,
        caller_cleanup_bytes,
        additional_return,
        net_sp_delta,
        argument_top,
        callee_return_delta,
    )
    materialized = sum(slot is not None for slot in slots)
    return IRCallStackCoordinates8616(
        callsite_addr=summary.callsite_addr,
        target_addr=summary.target_addr,
        return_addr=summary.return_addr,
        return_frame_bytes=return_frame_bytes,
        callee_purged_bytes=callee_purged,
        caller_cleanup_bytes=caller_cleanup_bytes,
        caller_cleanup_instruction_addr=caller_cleanup_addr,
        additional_return_bytes=additional_return,
        net_sp_delta=net_sp_delta,
        argument_top=argument_top,
        callee_sp_proof=callee_sp_proof,
        source=CallStackCoordinateSource8616(project, summary, instruction, block, return_frame),
        refusals=tuple(dict.fromkeys(refusals)),
        raw_fact_count=CALL_STACK_COORDINATE_SLOTS_8616,
        normalized_fact_count=CALL_STACK_COORDINATE_SLOTS_8616,
        classified_fact_count=materialized,
        materialized_count=materialized,
        failure_count=CALL_STACK_COORDINATE_SLOTS_8616 - materialized,
    )
