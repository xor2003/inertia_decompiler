# cython: language_level=3, infer_types=True
"""Prove near callback constants from callee calls and exact caller storage.

Layer: Types/Lowering.
Responsibility: join binary indirect-call parameter facts, caller push sources,
and a decoded near-code target before publishing a function-pointer value.
Only exact 16-bit same-code-segment targets are accepted; unknown evidence
remains a refusal, never a symbol guessed from numeric proximity.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, cast

from capstone import CsError, CsInsn
from capstone.x86_const import (
    X86_INS_CALL,
    X86_INS_IRET,
    X86_INS_LCALL,
    X86_INS_MOV,
    X86_INS_PUSH,
    X86_INS_RET,
    X86_INS_RETF,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_BP,
    X86_REG_INVALID,
    X86_REG_SP,
)

from inertia.semantics.callsite_summary import (
    CallsiteSummary8616,
    callsite_summary_inventory_8616,
    summarize_x86_16_callsite,
)

from .function_pointer_parameter_evidence import (
    FunctionPointerParameterFact8616,
    collect_function_pointer_parameter_evidence_8616,
)
import dataclasses
import operator

_RETURN_IDS_8616: frozenset[cython.longlong] = frozenset({X86_INS_RET, X86_INS_RETF, X86_INS_IRET})
_INDIRECT_CALL_IDS_8616: frozenset[cython.longlong] = frozenset({X86_INS_CALL, X86_INS_LCALL})
_MAX_CALLEE_BYTES_8616: cython.longlong = 256


class BinaryCallbackTargetStatus8616(StrEnum):
    """Typed result of a source-free callback-address proof."""

    PROVEN = "proven"
    NO_CALLER_USE = "no_caller_use"
    NO_CALLEE_PROOF = "no_callee_proof"
    NO_CODE_TARGET = "no_code_target"
    CONFLICTING_USE = "conflicting_use"


@dataclasses.dataclass(frozen=True, )
class BinaryCallbackTargetProof8616:
    """Exact same-segment function identity with its callee-owned ABI type."""

    addr: cython.longlong
    name: object
    callee_addr: cython.longlong
    caller_callsite_addr: cython.longlong
    parameter_fact: FunctionPointerParameterFact8616


@dataclasses.dataclass(frozen=True, )
class BinaryCallbackTargetResult8616:
    """Carry a typed verdict without converting missing proof into a target."""

    status: BinaryCallbackTargetStatus8616
    proof: BinaryCallbackTargetProof8616 | None = None


@dataclasses.dataclass(frozen=True, )
class _BinaryCalleeView8616:
    """Minimal function boundary accepted by the binary callsite summarizer."""

    project: object
    addr: cython.longlong
    blocks: tuple[object, ...] = ()


@cython.ccall
def _instruction_8616(value: object) -> CsInsn:
    """Unwrap angr's optional Capstone wrapper at the external boundary."""
    wrapped = cast(Any, value)
    return cast(CsInsn, wrapped.insn if hasattr(wrapped, "insn") else wrapped)


def _decoded_prefix_through_return_8616(project: object, address: cython.longlong) -> tuple[CsInsn, ...]:
    """Decode a bounded positive callee prefix, refusing an open function end."""
    insn: object
    if address < 0:
        return ()
    try:
        block = cast(Any, project).factory.block(
            address, size=_MAX_CALLEE_BYTES_8616, opt_level=0
        )
        decoded = tuple(_instruction_8616(item) for item in iter(block.capstone.insns))
    except (AttributeError, KeyError, TypeError, ValueError, CsError):
        return ()
    prefix: list[CsInsn] = []
    for insn in decoded:
        prefix.append(insn)
        if insn.id in _RETURN_IDS_8616:
            return tuple(prefix)
    return ()


@cython.ccall
def _is_bp_frame_setup_8616(push: CsInsn, frame_mov: CsInsn) -> cython.bint:
    """Recognize an exact PUSH BP; MOV BP, SP pair from decoded operands."""
    if operator.ne(push.id, X86_INS_PUSH) or operator.ne(frame_mov.id, X86_INS_MOV):
        return False
    push_operands = tuple(push.operands)
    mov_operands = tuple(frame_mov.operands)
    push_bp = (
        len(push_operands) == 1
        and operator.eq(push_operands[0].type, X86_OP_REG)
        and operator.eq(push_operands[0].reg, X86_REG_BP)
    )
    mov_bp_sp = (
        len(mov_operands) == 2
        and operator.eq(mov_operands[0].type, X86_OP_REG)
        and operator.eq(mov_operands[0].reg, X86_REG_BP)
        and operator.eq(mov_operands[1].type, X86_OP_REG)
        and operator.eq(mov_operands[1].reg, X86_REG_SP)
    )
    return push_bp and mov_bp_sp


@cython.ccall
def _stable_bp_frame_8616(instructions: object) -> cython.bint:
    """Require a conventional frame stable until its last indirect call."""
    insn: object
    if len(instructions) < 3:
        return False
    if not _is_bp_frame_setup_8616(*instructions[:2]):
        return False
    indirect_calls = _bp_indirect_call_addrs_8616(instructions)
    if not indirect_calls:
        return False
    last_call_addr = indirect_calls[-1]
    for insn in instructions[2:]:
        if insn.address > last_call_addr:
            break
        try:
            _reads, writes = insn.regs_access()
        except (AttributeError, CsError):
            return False
        if X86_REG_BP in writes:
            return False
    return True


@cython.ccall
def _bp_indirect_call_addrs_8616(instructions: object) -> tuple[cython.longlong, ...]:
    """Retain only structured BP-memory indirect calls from the closed prefix."""
    insn: object
    addresses: list[cython.longlong] = []
    for insn in instructions:
        if insn.id not in _INDIRECT_CALL_IDS_8616:
            continue
        operands = tuple(insn.operands)
        if len(operands) != 1:
            continue
        operand = operands[0]
        if (
            operator.eq(operand.type, X86_OP_MEM)
            and operator.eq(operand.mem.base, X86_REG_BP)
            and operator.eq(operand.mem.index, X86_REG_INVALID)
            and operand.mem.disp >= 4
            and operand.size in {2, 4}
        ):
            addresses.append(int(insn.address))
    return tuple(addresses)


@cython.ccall
def binary_function_pointer_parameter_evidence_8616(
    project: object, callee_addr: cython.longlong
) -> object:
    """Recover one consistent BP function-pointer parameter from binary calls."""
    summary: object
    callsite_addr: object
    instructions = _decoded_prefix_through_return_8616(project, callee_addr)
    if not instructions or not _stable_bp_frame_8616(instructions):
        return None
    callsite_addrs = _bp_indirect_call_addrs_8616(instructions)
    if not callsite_addrs:
        return None
    view = _BinaryCalleeView8616(project, callee_addr)
    summaries: list[CallsiteSummary8616] = []
    for callsite_addr in callsite_addrs:
        summary = summarize_x86_16_callsite(view, callsite_addr)
        if summary is None:
            return None
        summaries.append(summary)
    evidence = collect_function_pointer_parameter_evidence_8616(summaries)
    if evidence.failure_count or len(evidence.facts) != 1:
        return None
    fact = evidence.facts[0]
    if operator.ne(fact.callsite_addresses, callsite_addrs):
        return None
    return fact, tuple(summaries)


@cython.ccall
def _first_near_pointer_parameter_8616(
    project: object, callee_addr: cython.longlong
) -> FunctionPointerParameterFact8616 | None:
    """Select an exact first near callback parameter from binary evidence."""
    classified: object
    classified = binary_function_pointer_parameter_evidence_8616(project, callee_addr)
    if classified is None:
        return None
    fact, _summaries = classified
    return fact if fact.stack_offset == 4 and fact.pointer_width == 2 else None


@cython.ccall
def _caller_first_arg_source_8616(summary: CallsiteSummary8616) -> object:
    """Return an exact physical first-argument push source, if complete."""
    if (
        not summary.arg_widths
        or summary.arg_widths[-1] != 2
        or operator.ne(len(summary.push_arg_sources), len(summary.arg_widths))
        or operator.ne(summary.stack_cleanup, sum(summary.arg_widths))
    ):
        return None
    source = summary.push_arg_sources[-1]
    if (
        not isinstance(source, tuple)
        or len(source) != 3
        or source[0] != "bp"
        or not isinstance(source[1], int)
        or source[2] != 2
    ):
        return None
    return ("bp", source[1], 2)


@cython.ccall
def _binary_code_entry_8616(
    project: object, candidate_project: object, candidate_addr: cython.longlong, offset: cython.longlong,
    callee_addr: cython.longlong,
) -> cython.bint:
    """Require an exact same-image near offset and a closed code-entry decode."""
    if candidate_project is not project:
        return False
    try:
        main = cast(Any, project).loader.main_object
        image_base = int(main.min_addr)
        image_end = int(main.max_addr)
    except (AttributeError, TypeError, ValueError):
        return False
    if not (
        0 <= offset <= 0xFFFF
        and operator.eq(candidate_addr, image_base + offset)
        and image_base <= callee_addr <= image_end
        and image_base <= candidate_addr <= image_end
        and callee_addr - image_base <= 0xFFFF
    ):
        return False
    instructions = _decoded_prefix_through_return_8616(project, candidate_addr)
    return bool(
        instructions
        and operator.eq(instructions[0].address, candidate_addr)
        and operator.eq(instructions[0].id, X86_INS_PUSH)
        and len(instructions[0].operands) == 1
        and operator.eq(instructions[0].operands[0].type, X86_OP_REG)
        and operator.eq(instructions[0].operands[0].reg, X86_REG_BP)
    )


@cython.ccall
def prove_binary_near_callback_target_8616(
    project: object,
    codegen: object,
    *,
    stack_offset: cython.longlong,
    source_value: cython.longlong,
    candidates: Sequence[tuple[object, cython.longlong]],
) -> BinaryCallbackTargetResult8616:
    """Join an exact BP source, callee ABI proof, and same-segment code offset."""
    fact: object
    source: object
    callee_addr: object
    candidate_addr: object
    candidate_project: object
    summary: object
    inventory = callsite_summary_inventory_8616(codegen)
    matching: list[tuple[CallsiteSummary8616, cython.longlong, FunctionPointerParameterFact8616]] = []
    for summary in inventory.values():
        source = _caller_first_arg_source_8616(summary)
        if source is None or operator.ne(source[1], stack_offset):
            continue
        if not isinstance(summary.target_addr, int):
            return BinaryCallbackTargetResult8616(BinaryCallbackTargetStatus8616.CONFLICTING_USE)
        fact = _first_near_pointer_parameter_8616(project, summary.target_addr)
        if fact is None:
            return BinaryCallbackTargetResult8616(BinaryCallbackTargetStatus8616.NO_CALLEE_PROOF)
        matching.append((summary, summary.target_addr, fact))
    if not matching:
        return BinaryCallbackTargetResult8616(BinaryCallbackTargetStatus8616.NO_CALLER_USE)
    signatures = {
        (fact.pointer_width, fact.argument_widths, fact.return_width)
        for _summary, _callee_addr, fact in iter(matching)
    }
    if len(signatures) != 1:
        return BinaryCallbackTargetResult8616(BinaryCallbackTargetStatus8616.CONFLICTING_USE)
    for summary, callee_addr, fact in matching:
        for candidate_project, candidate_addr in candidates:
            if _binary_code_entry_8616(
                project, candidate_project, candidate_addr, source_value, callee_addr
            ):
                return BinaryCallbackTargetResult8616(
                    BinaryCallbackTargetStatus8616.PROVEN,
                    BinaryCallbackTargetProof8616(
                        addr=candidate_addr,
                        name=f"sub_{candidate_addr:x}",
                        callee_addr=callee_addr,
                        caller_callsite_addr=summary.callsite_addr,
                        parameter_fact=fact,
                    ),
                )
    return BinaryCallbackTargetResult8616(BinaryCallbackTargetStatus8616.NO_CODE_TARGET)
