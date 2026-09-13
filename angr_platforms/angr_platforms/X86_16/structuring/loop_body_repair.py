"""Structuring-owned repairs for loop bodies and pretest guards.

Layer: Structuring.
Responsibility: owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Dynamic boundary: wraps angr codegen C AST and CFG compatibility objects while
owned evidence stays in typed dataclasses and enums.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.

This module consumes binary CFG/instruction evidence to repair AST shapes that
the generic structurer cannot express correctly for common MS C 16-bit loops.
It may move or invert structured control-flow nodes, but it must not use
rendered C text or source declarations as proof.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from enum import Enum
from types import SimpleNamespace
from typing import Any, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CDoWhileLoop,
    CExpressionStatement,
    CForLoop,
    CFunctionCall,
    CIfBreak,
    CIfElse,
    CReturn,
    CStatements,
    CSwitchCase,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616, _same_c_expression_8616
from ..ir.condition_ir import inverted_comparison_op_8616
from ..semantics.alias_query import describe_alias_storage
from .loop_break_jcc import loop_branch_guard_facts_8616
from .shared_loop_exit_publication import publish_shared_loop_exit_report_8616
from .simple_loop_recovery import InsnSummary8616, _function_instruction_summaries_8616, _summarize_capstone_insn_8616

log: logging.Logger = logging.getLogger(__name__)


def _dynamic_int_8616(value: object) -> int | None:
    """Return an int from a dynamic angr/C AST payload only when it is explicit."""
    if isinstance(value, int):
        return value
    return None


def _dynamic_sequence_8616(value: object) -> tuple[object, ...]:
    """Return a tuple for dynamic angr/C AST sequence payloads."""
    if isinstance(value, tuple):
        return value
    if isinstance(value, list):
        return tuple(value)
    return ()


def _codegen_cfunc_8616(codegen: object) -> object | None:
    """Return the dynamic angr codegen C function payload."""
    if codegen is None:
        return None
    return getattr(cast(Any, codegen), "cfunc", None)


class LoopBodyRepairDecision8616(Enum):
    """Decision states for empty counted-loop body repair."""

    MATERIALIZED = "materialized"
    REFUSED_NO_EVIDENCE = "refused_no_evidence"
    REFUSED_NO_CFUNC = "refused_no_cfunc"
    REFUSED_NO_STATEMENTS = "refused_no_statements"
    REFUSED_NONEMPTY_BODY = "refused_nonempty_body"
    REFUSED_NO_FOLLOWING_UPDATE = "refused_no_following_update"
    REFUSED_SLOT_MISMATCH = "refused_slot_mismatch"


class ConditionalContinueRepairDecision8616(Enum):
    """Decision states for conditional-continue guard repair."""

    MATERIALIZED = "materialized"
    REFUSED_NO_EVIDENCE = "refused_no_evidence"
    REFUSED_NO_CFUNC = "refused_no_cfunc"
    REFUSED_NO_COMPLEMENTARY_GUARD = "refused_no_complementary_guard"


class HoistedJccTargetCopyRepairDecision8616(Enum):
    """Decision states for displaced JCC target-copy repair."""

    MATERIALIZED = "materialized"
    REFUSED_NO_EVIDENCE = "refused_no_evidence"
    REFUSED_NO_CFUNC = "refused_no_cfunc"
    REFUSED_NO_MATCHING_IF = "refused_no_matching_if"
    REFUSED_NO_HOISTED_COPY = "refused_no_hoisted_copy"
    REFUSED_AMBIGUOUS_COPY = "refused_ambiguous_copy"
    REFUSED_BODY_TARGET_UNPROVEN = "refused_body_target_unproven"


class PretestLoopGuardRepairDecision8616(Enum):
    """Decision states for pretest loop break-guard repair."""

    MATERIALIZED = "materialized"
    REFUSED_NO_EVIDENCE = "refused_no_evidence"
    REFUSED_NO_CFUNC = "refused_no_cfunc"
    REFUSED_NO_MATCHING_LOOP = "refused_no_matching_loop"
    REFUSED_BODY_TARGET_UNPROVEN = "refused_body_target_unproven"


class RedundantLoopBreakCarrierDecision8616(Enum):
    """Decision states for pruning a duplicate break guard through exact carrier definitions."""

    MATERIALIZED = "materialized"
    REFUSED_NO_CFUNC = "refused_no_cfunc"
    REFUSED_NO_CANDIDATE = "refused_no_candidate"
    REFUSED_UNPROVEN_EQUIVALENCE = "refused_unproven_equivalence"


class SwitchLoopExitReturnRepairDecision8616(Enum):
    """Decision states for switch loop-exit return repair."""

    MATERIALIZED = "materialized"
    REFUSED_NO_EVIDENCE = "refused_no_evidence"
    REFUSED_NO_CFUNC = "refused_no_cfunc"
    REFUSED_NO_STATEMENTS = "refused_no_statements"
    REFUSED_NO_MATCHING_LOOP = "refused_no_matching_loop"
    REFUSED_AMBIGUOUS_LOOP = "refused_ambiguous_loop"
    REFUSED_LOOP_HAS_BREAK = "refused_loop_has_break"
    REFUSED_NO_SWITCH = "refused_no_switch"
    REFUSED_CASE_ALREADY_PRESENT = "refused_case_already_present"


class SyntheticInternalCallRepairDecision8616(Enum):
    """Decision states for pruning synthetic internal-target calls."""

    MATERIALIZED = "materialized"
    REFUSED_NO_EVIDENCE = "refused_no_evidence"
    REFUSED_NO_CFUNC = "refused_no_cfunc"
    REFUSED_NO_STATEMENTS = "refused_no_statements"
    REFUSED_NO_CALLSITE_EVIDENCE = "refused_no_callsite_evidence"
    REFUSED_NO_MATCHING_CALL = "refused_no_matching_call"


@dataclass(frozen=True, slots=True)
class StackAccumulatorLoopEvidence8616:
    """Binary evidence for a counted loop that updates a stack accumulator."""

    induction_disp: int
    accumulator_disp: int
    step: int
    accumulator_zero_initialized: bool


@dataclass(frozen=True, slots=True)
class ConditionalContinueEvidence8616:
    """Binary evidence proving a conditional branch skips to loop continue."""

    branch_addr: int
    body_target: int
    continue_target: int


@dataclass(frozen=True, slots=True)
class HoistedJccTargetCopyEvidence8616:
    """Binary evidence for a stack-slot copy at a JCC body target."""

    branch_addr: int
    body_target: int
    copy_addr: int
    dest_disp: int
    src_disp: int


@dataclass(frozen=True, slots=True)
class PretestLoopGuardEvidence8616:
    """Binary evidence for a pretest branch whose taken edge enters the loop body."""

    branch_addr: int
    body_target: int
    exit_target: int
    mnemonic: str = ""
    body_condition_op: str | None = None


@dataclass(slots=True)
class RedundantLoopBreakCarrierStats8616:
    """Closed-loop counters for duplicate loop break-carrier pruning."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    decision_counts: dict[RedundantLoopBreakCarrierDecision8616, int] = field(default_factory=dict)

    def record(self, decision: RedundantLoopBreakCarrierDecision8616) -> None:
        """Record one typed terminal decision."""
        self.decision_counts[decision] = self.decision_counts.get(decision, 0) + 1
        if decision is RedundantLoopBreakCarrierDecision8616.MATERIALIZED:
            self.materialized_count += 1
        elif decision is not RedundantLoopBreakCarrierDecision8616.REFUSED_NO_CANDIDATE:
            self.failure_count += 1


@dataclass(frozen=True, slots=True)
class SwitchLoopExitReturnEvidence8616:
    """Binary evidence for a switch case whose target exits an unconditional loop."""

    case_value: int
    case_target: int
    exit_target: int


@dataclass(slots=True)
class LoopBodyRepairStats8616:
    """Evidence-loop counters for empty counted-loop body repair."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    refused_no_evidence: int = 0
    refused_no_cfunc: int = 0
    refused_no_statements: int = 0
    refused_nonempty_body: int = 0
    refused_no_following_update: int = 0
    refused_slot_mismatch: int = 0

    def record(self, decision: LoopBodyRepairDecision8616) -> None:
        """Record one repair decision."""
        if decision is LoopBodyRepairDecision8616.MATERIALIZED:
            self.materialized_count += 1
            return
        self.failure_count += 1
        if decision is LoopBodyRepairDecision8616.REFUSED_NO_EVIDENCE:
            self.refused_no_evidence += 1
        elif decision is LoopBodyRepairDecision8616.REFUSED_NO_CFUNC:
            self.refused_no_cfunc += 1
        elif decision is LoopBodyRepairDecision8616.REFUSED_NO_STATEMENTS:
            self.refused_no_statements += 1
        elif decision is LoopBodyRepairDecision8616.REFUSED_NONEMPTY_BODY:
            self.refused_nonempty_body += 1
        elif decision is LoopBodyRepairDecision8616.REFUSED_NO_FOLLOWING_UPDATE:
            self.refused_no_following_update += 1
        elif decision is LoopBodyRepairDecision8616.REFUSED_SLOT_MISMATCH:
            self.refused_slot_mismatch += 1


@dataclass(slots=True)
class ConditionalContinueRepairStats8616:
    """Evidence-loop counters for conditional-continue repair."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    refused_no_evidence: int = 0
    refused_no_cfunc: int = 0
    refused_no_complementary_guard: int = 0

    def record(self, decision: ConditionalContinueRepairDecision8616) -> None:
        """Record one repair decision."""
        if decision is ConditionalContinueRepairDecision8616.MATERIALIZED:
            self.materialized_count += 1
            return
        self.failure_count += 1
        if decision is ConditionalContinueRepairDecision8616.REFUSED_NO_EVIDENCE:
            self.refused_no_evidence += 1
        elif decision is ConditionalContinueRepairDecision8616.REFUSED_NO_CFUNC:
            self.refused_no_cfunc += 1
        elif decision is ConditionalContinueRepairDecision8616.REFUSED_NO_COMPLEMENTARY_GUARD:
            self.refused_no_complementary_guard += 1


@dataclass(slots=True)
class HoistedJccTargetCopyRepairStats8616:
    """Evidence-loop counters for displaced JCC target-copy repair."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    refused_no_evidence: int = 0
    refused_no_cfunc: int = 0
    refused_no_matching_if: int = 0
    refused_no_hoisted_copy: int = 0
    refused_ambiguous_copy: int = 0
    refused_body_target_unproven: int = 0

    def record(self, decision: HoistedJccTargetCopyRepairDecision8616) -> None:
        """Record one repair decision."""
        if decision is HoistedJccTargetCopyRepairDecision8616.MATERIALIZED:
            self.materialized_count += 1
            return
        self.failure_count += 1
        if decision is HoistedJccTargetCopyRepairDecision8616.REFUSED_NO_EVIDENCE:
            self.refused_no_evidence += 1
        elif decision is HoistedJccTargetCopyRepairDecision8616.REFUSED_NO_CFUNC:
            self.refused_no_cfunc += 1
        elif decision is HoistedJccTargetCopyRepairDecision8616.REFUSED_NO_MATCHING_IF:
            self.refused_no_matching_if += 1
        elif decision is HoistedJccTargetCopyRepairDecision8616.REFUSED_NO_HOISTED_COPY:
            self.refused_no_hoisted_copy += 1
        elif decision is HoistedJccTargetCopyRepairDecision8616.REFUSED_AMBIGUOUS_COPY:
            self.refused_ambiguous_copy += 1
        elif decision is HoistedJccTargetCopyRepairDecision8616.REFUSED_BODY_TARGET_UNPROVEN:
            self.refused_body_target_unproven += 1


@dataclass(slots=True)
class PretestLoopGuardRepairStats8616:
    """Evidence-loop counters for pretest loop guard repair."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    refused_no_evidence: int = 0
    refused_no_cfunc: int = 0
    refused_no_matching_loop: int = 0
    refused_body_target_unproven: int = 0
    iterator_moved_count: int = 0
    call_return_carriers_removed_count: int = 0

    def record(self, decision: PretestLoopGuardRepairDecision8616) -> None:
        """Record one repair decision."""
        if decision is PretestLoopGuardRepairDecision8616.MATERIALIZED:
            self.materialized_count += 1
            return
        self.failure_count += 1
        if decision is PretestLoopGuardRepairDecision8616.REFUSED_NO_EVIDENCE:
            self.refused_no_evidence += 1
        elif decision is PretestLoopGuardRepairDecision8616.REFUSED_NO_CFUNC:
            self.refused_no_cfunc += 1
        elif decision is PretestLoopGuardRepairDecision8616.REFUSED_NO_MATCHING_LOOP:
            self.refused_no_matching_loop += 1
        elif decision is PretestLoopGuardRepairDecision8616.REFUSED_BODY_TARGET_UNPROVEN:
            self.refused_body_target_unproven += 1


@dataclass(slots=True)
class SwitchLoopExitReturnRepairStats8616:
    """Evidence-loop counters for switch loop-exit return repair."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    trailing_unreachable_pruned_count: int = 0
    refused_no_evidence: int = 0
    refused_no_cfunc: int = 0
    refused_no_statements: int = 0
    refused_no_matching_loop: int = 0
    refused_ambiguous_loop: int = 0
    refused_loop_has_break: int = 0
    refused_no_switch: int = 0
    refused_case_already_present: int = 0
    preserved_shared_exit_count: int = 0

    def record(self, decision: SwitchLoopExitReturnRepairDecision8616) -> None:
        """Record one repair decision."""
        if decision is SwitchLoopExitReturnRepairDecision8616.MATERIALIZED:
            self.materialized_count += 1
            return
        self.failure_count += 1
        if decision is SwitchLoopExitReturnRepairDecision8616.REFUSED_NO_EVIDENCE:
            self.refused_no_evidence += 1
        elif decision is SwitchLoopExitReturnRepairDecision8616.REFUSED_NO_CFUNC:
            self.refused_no_cfunc += 1
        elif decision is SwitchLoopExitReturnRepairDecision8616.REFUSED_NO_STATEMENTS:
            self.refused_no_statements += 1
        elif decision is SwitchLoopExitReturnRepairDecision8616.REFUSED_NO_MATCHING_LOOP:
            self.refused_no_matching_loop += 1
        elif decision is SwitchLoopExitReturnRepairDecision8616.REFUSED_AMBIGUOUS_LOOP:
            self.refused_ambiguous_loop += 1
        elif decision is SwitchLoopExitReturnRepairDecision8616.REFUSED_LOOP_HAS_BREAK:
            self.refused_loop_has_break += 1
        elif decision is SwitchLoopExitReturnRepairDecision8616.REFUSED_NO_SWITCH:
            self.refused_no_switch += 1
        elif decision is SwitchLoopExitReturnRepairDecision8616.REFUSED_CASE_ALREADY_PRESENT:
            self.refused_case_already_present += 1


@dataclass(slots=True)
class SyntheticInternalCallRepairStats8616:
    """Evidence-loop counters for synthetic internal-target call pruning."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    refused_no_evidence: int = 0
    refused_no_cfunc: int = 0
    refused_no_statements: int = 0
    refused_no_callsite_evidence: int = 0
    refused_no_matching_call: int = 0

    def record(self, decision: SyntheticInternalCallRepairDecision8616) -> None:
        """Record one repair decision."""
        if decision is SyntheticInternalCallRepairDecision8616.MATERIALIZED:
            self.materialized_count += 1
            return
        self.failure_count += 1
        if decision is SyntheticInternalCallRepairDecision8616.REFUSED_NO_EVIDENCE:
            self.refused_no_evidence += 1
        elif decision is SyntheticInternalCallRepairDecision8616.REFUSED_NO_CFUNC:
            self.refused_no_cfunc += 1
        elif decision is SyntheticInternalCallRepairDecision8616.REFUSED_NO_STATEMENTS:
            self.refused_no_statements += 1
        elif decision is SyntheticInternalCallRepairDecision8616.REFUSED_NO_CALLSITE_EVIDENCE:
            self.refused_no_callsite_evidence += 1
        elif decision is SyntheticInternalCallRepairDecision8616.REFUSED_NO_MATCHING_CALL:
            self.refused_no_matching_call += 1


def recover_stack_accumulator_loop_evidence_8616(
    summaries: list[InsnSummary8616],
) -> tuple[StackAccumulatorLoopEvidence8616, ...]:
    """Recover stack accumulator loop evidence from normalized instructions."""
    zero_inits: set[int] = set()
    inc_slots: set[int] = set()
    dec_slots: set[int] = set()
    add_pairs: set[tuple[int, int]] = set()
    previous_ax_load: int | None = None

    for insn in summaries:
        mnemonic = insn.mnemonic.lower()
        op0_int = _dynamic_int_8616(insn.op0_value)
        op1_int = _dynamic_int_8616(insn.op1_value)
        if (
            mnemonic == "mov"
            and insn.op0_kind == "bp_mem"
            and insn.op1_kind == "imm"
            and op1_int == 0
            and (insn.op0_size in {None, 2})
            and op0_int is not None
        ):
            zero_inits.add(op0_int)
            previous_ax_load = None
            continue
        if mnemonic == "inc" and insn.op0_kind == "bp_mem" and (insn.op0_size in {None, 2}) and op0_int is not None:
            inc_slots.add(op0_int)
            previous_ax_load = None
            continue
        if mnemonic == "dec" and insn.op0_kind == "bp_mem" and (insn.op0_size in {None, 2}) and op0_int is not None:
            dec_slots.add(op0_int)
            previous_ax_load = None
            continue
        if (
            mnemonic == "mov"
            and insn.op0_kind == "reg"
            and insn.op0_value == "ax"
            and insn.op1_kind == "bp_mem"
            and op1_int is not None
        ):
            previous_ax_load = op1_int
            continue
        if (
            mnemonic == "add"
            and insn.op0_kind == "bp_mem"
            and insn.op1_kind == "reg"
            and insn.op1_value == "ax"
            and previous_ax_load is not None
            and op0_int is not None
        ):
            add_pairs.add((op0_int, previous_ax_load))
            previous_ax_load = None
            continue
        if mnemonic not in {"cmp", "jmp", "jb", "jbe", "ja", "jae", "je", "jne"}:
            previous_ax_load = None

    recovered: list[StackAccumulatorLoopEvidence8616] = []
    for accumulator_disp, induction_disp in sorted(add_pairs):
        if accumulator_disp >= 0 or induction_disp >= 0 or accumulator_disp == induction_disp:
            continue
        if accumulator_disp not in zero_inits:
            continue
        if induction_disp in inc_slots:
            recovered.append(
                StackAccumulatorLoopEvidence8616(
                    induction_disp=induction_disp,
                    accumulator_disp=accumulator_disp,
                    step=1,
                    accumulator_zero_initialized=True,
                )
            )
        if induction_disp in dec_slots:
            recovered.append(
                StackAccumulatorLoopEvidence8616(
                    induction_disp=induction_disp,
                    accumulator_disp=accumulator_disp,
                    step=-1,
                    accumulator_zero_initialized=True,
                )
            )
    return tuple(recovered)


def recover_hoisted_jcc_target_copy_evidence_8616(
    project: object,
    function: object,
) -> tuple[HoistedJccTargetCopyEvidence8616, ...]:
    """Recover JCC target blocks that start with a stack-slot copy.

    MS C commonly emits:
        cmp ...
        jcc body
        jmp skip
      body:
        mov ax, [bp+src]
        mov [bp+dst], ax

    If structuring hoists the target copy before the guarded if-body, the copy
    must be moved back under the JCC guard. This evidence is binary-derived and
    later consumed by AST repair; rendered C text is not consulted.
    """
    insns = _linear_capstone_insns_8616(project, function)
    recovered: list[HoistedJccTargetCopyEvidence8616] = []
    if len(insns) < 2:
        return ()
    function_start = getattr(function, "addr", None)
    function_size = getattr(function, "size", None)
    function_end = (
        int(function_start) + int(function_size)
        if isinstance(function_start, int) and isinstance(function_size, int)
        else None
    )
    for insn in insns:
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        if mnemonic not in _CONDITIONAL_BRANCH_MNEMONICS_8616:
            continue
        body_target = _branch_target_imm_from_capstone_8616(insn)
        if body_target is None:
            continue
        function_start_int = _dynamic_int_8616(function_start)
        body_target_int = _dynamic_int_8616(body_target)
        if body_target_int is None:
            continue
        if function_end is not None and function_start_int is not None and not (function_start_int <= body_target_int < function_end):
            continue
        target_insns = _block_insns_8616(project, body_target_int)
        copy = _leading_stack_slot_copy_8616(target_insns)
        if copy is None:
            continue
        copy_addr, dest_disp, src_disp = copy
        recovered.append(
            HoistedJccTargetCopyEvidence8616(
                branch_addr=int(getattr(insn, "address", 0) or 0),
                body_target=body_target_int,
                copy_addr=int(copy_addr),
                dest_disp=int(dest_disp),
                src_disp=int(src_disp),
            )
        )
    return tuple(recovered)


def recover_conditional_continue_evidence_8616(
    project: object,
    function: object,
) -> tuple[ConditionalContinueEvidence8616, ...]:
    """Recover MS C false-path-to-loop-iterator branch evidence.

    Pattern:
        cmp ...
        jcc body
        jmp loop_iterator

    This distinguishes a skipped if-body from a real loop break. The AST repair
    consumes only the count of proven conditional-continue sites; the semantic
    branch target proof comes from binary instructions, not rendered C.
    """
    insns = _linear_capstone_insns_8616(project, function)
    recovered: list[ConditionalContinueEvidence8616] = []
    if len(insns) < 3:
        return ()
    function_start = getattr(function, "addr", None)
    function_size = getattr(function, "size", None)
    function_end = (
        int(function_start) + int(function_size)
        if isinstance(function_start, int) and isinstance(function_size, int)
        else None
    )
    for idx, insn in enumerate(insns[:-1]):
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        if mnemonic not in _CONDITIONAL_BRANCH_MNEMONICS_8616:
            continue
        fallthrough_jmp = insns[idx + 1]
        if str(getattr(fallthrough_jmp, "mnemonic", "")).lower() not in _UNCONDITIONAL_JMP_MNEMONICS_8616:
            continue
        body_target = _branch_target_imm_from_capstone_8616(insn)
        skip_target = _branch_target_imm_from_capstone_8616(fallthrough_jmp)
        if body_target is None or skip_target is None:
            continue
        function_start_int = _dynamic_int_8616(function_start)
        body_target_int = _dynamic_int_8616(body_target)
        skip_target_int = _dynamic_int_8616(skip_target)
        if body_target_int is None or skip_target_int is None:
            continue
        if function_end is not None and function_start_int is not None and not (function_start_int <= body_target_int < function_end):
            continue
        continue_target = _resolve_unconditional_jmp_chain_8616(project, skip_target_int)
        if continue_target is None:
            continue
        if not _target_starts_with_iterator_update_8616(project, continue_target):
            continue
        recovered.append(
            ConditionalContinueEvidence8616(
                branch_addr=int(getattr(insn, "address", 0) or 0),
                body_target=body_target_int,
                continue_target=continue_target,
            )
        )
    return tuple(recovered)


def _cfg_node_containing_addr_8616(graph: object, addr: int) -> object | None:
    """Return the unique CFG node containing an instruction address."""
    nodes = tuple(cast(Any, graph).nodes or ())
    matches: list[object] = []
    for node in nodes:
        node_addr = _dynamic_int_8616(cast(Any, node).addr)
        node_size = _dynamic_int_8616(cast(Any, node).size)
        if node_addr is None:
            continue
        if node_addr == addr or (node_size is not None and node_size > 0 and node_addr <= addr < node_addr + node_size):
            matches.append(node)
    return matches[0] if len(matches) == 1 else None


def _cfg_node_reaches_8616(graph: object, source: object, target: object) -> bool:
    """Return whether a CFG path exists using the graph successor contract."""
    successors = cast(Any, graph).successors
    if not callable(successors):
        return False
    pending = [source]
    seen: set[object] = set()
    while pending:
        node = pending.pop()
        if node == target:
            return True
        if node in seen:
            continue
        seen.add(node)
        try:
            next_nodes = successors(node)
        except Exception:
            return False
        if not isinstance(next_nodes, Iterable):
            return False
        pending.extend(next_nodes)
    return False


def _classify_pretest_targets_from_cfg_8616(
    function: object,
    branch_addr: int,
    jcc_target: int,
    jump_target: int,
) -> tuple[int, int] | None:
    """Return ``(body, exit)`` only when CFG cycle reachability proves both roles."""
    graph = getattr(cast(Any, function), "graph", None)
    if graph is None:
        return None
    branch_node = _cfg_node_containing_addr_8616(graph, branch_addr)
    jcc_node = _cfg_node_containing_addr_8616(graph, jcc_target)
    jump_node = _cfg_node_containing_addr_8616(graph, jump_target)
    if branch_node is None or jcc_node is None or jump_node is None:
        return None
    jcc_reaches_test = _cfg_node_reaches_8616(graph, jcc_node, branch_node)
    jump_reaches_test = _cfg_node_reaches_8616(graph, jump_node, branch_node)
    if jcc_reaches_test == jump_reaches_test:
        return None
    return (jcc_target, jump_target) if jcc_reaches_test else (jump_target, jcc_target)


def recover_pretest_loop_guard_evidence_8616(
    project: object,
    function: object,
) -> tuple[PretestLoopGuardEvidence8616, ...]:
    """Recover pre-test loop branches where the JCC target is the loop body.

    MS C commonly emits:
        jmp test
      iterator:
        inc [bp+i]
      test:
        cmp [bp+i], limit
        jcc body
        jmp exit
      body:
        ...
        jmp iterator

    If structuring emits ``while (true) { if (body_cond) break; body; }``, the
    break guard has the body-edge condition instead of the exit-edge condition.
    This function only recovers the binary edge fact; AST mutation is separate.
    """
    insns = _linear_capstone_insns_8616(project, function)
    recovered: list[PretestLoopGuardEvidence8616] = []
    if len(insns) < 3:
        return ()
    function_start = getattr(function, "addr", None)
    function_size = getattr(function, "size", None)
    function_end = (
        int(function_start) + int(function_size)
        if isinstance(function_start, int) and isinstance(function_size, int)
        else None
    )
    for idx, insn in enumerate(insns[:-1]):
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        if mnemonic not in _CONDITIONAL_BRANCH_MNEMONICS_8616:
            continue
        fallthrough_jmp = insns[idx + 1]
        if str(getattr(fallthrough_jmp, "mnemonic", "")).lower() not in _UNCONDITIONAL_JMP_MNEMONICS_8616:
            continue
        jcc_target = _branch_target_imm_from_capstone_8616(insn)
        jump_target = _branch_target_imm_from_capstone_8616(fallthrough_jmp)
        if jcc_target is None or jump_target is None:
            continue
        function_start_int = _dynamic_int_8616(function_start)
        jcc_target_int = _dynamic_int_8616(jcc_target)
        jump_target_int = _dynamic_int_8616(jump_target)
        branch_addr = _dynamic_int_8616(getattr(insn, "address", None))
        if jcc_target_int is None or jump_target_int is None or branch_addr is None:
            continue
        classified_targets = _classify_pretest_targets_from_cfg_8616(
            function,
            branch_addr,
            jcc_target_int,
            jump_target_int,
        )
        if classified_targets is None:
            continue
        body_target_int, exit_target_int = classified_targets
        if function_end is not None:
            if function_start_int is not None and not (function_start_int <= body_target_int < function_end):
                continue
            if function_start_int is not None and not (function_start_int <= exit_target_int <= function_end):
                continue
        taken_op = _JCC_TAKEN_COMPARISON_OPS_8616.get(mnemonic)
        body_condition_op = taken_op if body_target_int == jcc_target_int else _complementary_cmp_op_8616(taken_op)
        if body_condition_op is None:
            continue
        recovered.append(
            PretestLoopGuardEvidence8616(
                branch_addr=branch_addr,
                body_target=body_target_int,
                exit_target=exit_target_int,
                mnemonic=mnemonic,
                body_condition_op=body_condition_op,
            )
        )
    return tuple(recovered)


def _recover_short_circuit_pretest_guard_evidence_8616(
    project: object,
    function: object,
    seed_evidence: tuple[PretestLoopGuardEvidence8616, ...],
) -> tuple[PretestLoopGuardEvidence8616, ...]:
    """Recover predecessor predicates that share a proven loop-exit edge.

    A short-circuit ``and`` may branch to the next predicate instead of the
    loop body. The predecessor is still a body-edge guard when its other edge
    is the exact exit of a typed downstream predicate in that target block.
    """
    graph = getattr(cast(Any, function), "graph", None)
    if graph is None or not seed_evidence:
        return ()
    insns = _linear_capstone_insns_8616(project, function)
    known = {item.branch_addr: item for item in seed_evidence}
    recovered: list[PretestLoopGuardEvidence8616] = []
    progress = True
    while progress:
        progress = False
        for index, insn in enumerate(insns[:-1]):
            mnemonic = str(getattr(insn, "mnemonic", "")).lower()
            branch_addr = _dynamic_int_8616(getattr(insn, "address", None))
            if mnemonic not in _CONDITIONAL_BRANCH_MNEMONICS_8616 or branch_addr is None:
                continue
            if branch_addr in known:
                continue
            fallthrough_jmp = insns[index + 1]
            if str(getattr(fallthrough_jmp, "mnemonic", "")).lower() not in _UNCONDITIONAL_JMP_MNEMONICS_8616:
                continue
            body_target = _branch_target_imm_from_capstone_8616(insn)
            exit_target = _branch_target_imm_from_capstone_8616(fallthrough_jmp)
            if body_target is None or exit_target is None:
                continue
            continuation_node = _cfg_node_containing_addr_8616(graph, body_target)
            if continuation_node is None:
                continue
            downstream = tuple(
                item
                for item in known.values()
                if item.exit_target == exit_target
                and _cfg_node_containing_addr_8616(graph, item.branch_addr) == continuation_node
            )
            if len(downstream) != 1:
                continue
            body_condition_op = _JCC_TAKEN_COMPARISON_OPS_8616.get(mnemonic)
            if body_condition_op is None:
                continue
            fact = PretestLoopGuardEvidence8616(
                branch_addr=branch_addr,
                body_target=body_target,
                exit_target=exit_target,
                mnemonic=mnemonic,
                body_condition_op=body_condition_op,
            )
            known[branch_addr] = fact
            recovered.append(fact)
            progress = True
    return tuple(recovered)


def recover_switch_loop_exit_return_evidence_8616(
    project: object,
    function: object,
) -> tuple[SwitchLoopExitReturnEvidence8616, ...]:
    """Recover switch dispatch cases that jump directly to a function exit.

    MS C 6 may lower a switch case like ``case ESC: return;`` as a subtract
    dispatch candidate whose case target is only a jump to the shared epilogue:

        sub ax, 27
        jne next_case
        jmp case_27
      case_27:
        jmp epilogue
      epilogue:
        ... ret

    The returned fact is still only CFG evidence.  The AST mutation below owns
    the structuring decision, and rendered C text is never consulted.
    """
    function_addr = getattr(function, "addr", None)
    function_size = getattr(function, "size", None)
    scan_function = function
    if isinstance(function_addr, int) and isinstance(function_size, int) and function_size > 0:
        # angr's function size may end just before a shared epilogue. Read only
        # enough tail to prove the RET, while keeping recovered targets inside
        # the original function boundary below.
        scan_function = SimpleNamespace(addr=function_addr, size=min(function_size + 0x20, 0x300))
    summaries = _function_instruction_summaries_8616(project, scan_function)
    recovered = list(_recover_switch_loop_exit_return_evidence_from_summaries_8616(summaries))
    if isinstance(function_addr, int) and isinstance(function_size, int) and function_size > 0:
        function_end = function_addr + function_size
        recovered = [
            item
            for item in recovered
            if function_addr <= item.case_target < function_end
            and function_addr <= item.exit_target < function_end
        ]
    if recovered:
        return tuple(recovered)
    recovered.extend(_recover_switch_loop_exit_return_evidence_from_original_slice_8616(project, function))
    return tuple(_dedupe_switch_loop_exit_return_evidence_8616(recovered))


def _recover_switch_loop_exit_return_evidence_from_summaries_8616(
    summaries: list[InsnSummary8616],
) -> tuple[SwitchLoopExitReturnEvidence8616, ...]:
    by_addr = {summary.address: summary for summary in summaries if isinstance(summary.address, int)}
    recovered: list[SwitchLoopExitReturnEvidence8616] = []
    seen: set[tuple[int, int, int]] = set()
    for index, summary in enumerate(summaries[:-2]):
        if not _is_sub_ax_immediate_8616(summary):
            continue
        branch = summaries[index + 1]
        if str(branch.mnemonic).lower() not in {"jne", "jnz"}:
            continue
        jump = summaries[index + 2]
        if str(jump.mnemonic).lower() not in _UNCONDITIONAL_JMP_MNEMONICS_8616 or jump.op0_kind != "imm":
            continue
        case_value = _dynamic_int_8616(summary.op1_value)
        case_target = _dynamic_int_8616(jump.op0_value)
        if case_value is None or case_target is None:
            continue
        case_entry = by_addr.get(case_target)
        if case_entry is None or str(case_entry.mnemonic).lower() not in _UNCONDITIONAL_JMP_MNEMONICS_8616:
            continue
        if case_entry.op0_kind != "imm" or not isinstance(case_entry.op0_value, int):
            continue
        exit_target = int(case_entry.op0_value)
        if not _instruction_stream_reaches_ret_8616(summaries, exit_target):
            continue
        key = (case_value, case_target, exit_target)
        if key in seen:
            continue
        seen.add(key)
        recovered.append(
            SwitchLoopExitReturnEvidence8616(
                case_value=case_value,
                case_target=case_target,
                exit_target=exit_target,
            )
        )
    return tuple(recovered)


def _recover_switch_loop_exit_return_evidence_from_original_slice_8616(
    project: object,
    function: object,
) -> tuple[SwitchLoopExitReturnEvidence8616, ...]:
    original_project = getattr(project, "_inertia_original_project", None)
    delta = getattr(project, "_inertia_original_linear_delta", None)
    active_addr = getattr(function, "addr", None)
    if original_project is None or not isinstance(delta, int) or not isinstance(active_addr, int):
        return ()
    original_addr = active_addr + int(delta)
    active_size = getattr(function, "size", None)
    size = int(active_size) if isinstance(active_size, int) and active_size > 0 else 0x300
    recovered: list[SwitchLoopExitReturnEvidence8616] = []
    for prologue_bytes in range(0x21):
        start = original_addr - prologue_bytes
        if start < 0:
            continue
        candidate = SimpleNamespace(addr=start, size=size + prologue_bytes + 0x40)
        evidence = _recover_switch_loop_exit_return_evidence_from_summaries_8616(
            _function_instruction_summaries_8616(original_project, candidate)
        )
        recovered.extend(
            item
            for item in evidence
            if original_addr <= item.case_target <= original_addr + size + 0x40
            and original_addr <= item.exit_target <= original_addr + size + 0x40
        )
        if recovered:
            break
    return tuple(_dedupe_switch_loop_exit_return_evidence_8616(recovered))


def _dedupe_switch_loop_exit_return_evidence_8616(
    evidence: list[SwitchLoopExitReturnEvidence8616],
) -> tuple[SwitchLoopExitReturnEvidence8616, ...]:
    seen: set[tuple[int, int, int]] = set()
    deduped: list[SwitchLoopExitReturnEvidence8616] = []
    for item in evidence:
        key = (item.case_value, item.case_target, item.exit_target)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return tuple(deduped)


def repair_hoisted_jcc_target_copies_from_evidence_8616(project: object, codegen: object) -> bool:
    """Move displaced stack-slot copies back under their proven JCC target body.

    angr may place the leading target-block copy on either side of the
    structured guard. The binary branch target, instruction tag, and stack-slot
    identities must identify exactly one sibling before it can be moved.
    """
    stats = HoistedJccTargetCopyRepairStats8616()
    function = _active_function_8616(project, codegen)
    evidence = recover_hoisted_jcc_target_copy_evidence_8616(project, function) if function is not None else ()
    stats.raw_fact_count = len(evidence)
    stats.normalized_fact_count = len(evidence)
    stats.classified_fact_count = len(evidence)
    if not evidence:
        stats.record(HoistedJccTargetCopyRepairDecision8616.REFUSED_NO_EVIDENCE)
        _store_hoisted_jcc_target_copy_stats_8616(codegen, stats)
        return False
    cfunc = _codegen_cfunc_8616(codegen)
    if cfunc is None:
        stats.record(HoistedJccTargetCopyRepairDecision8616.REFUSED_NO_CFUNC)
        _store_hoisted_jcc_target_copy_stats_8616(codegen, stats)
        return False
    changed = False
    for root in _cfunc_roots_8616(cfunc):
        changed = _repair_hoisted_jcc_target_copy_in_node_8616(root, tuple(evidence), stats) or changed
    if not changed:
        stats.record(HoistedJccTargetCopyRepairDecision8616.REFUSED_NO_MATCHING_IF)
    _store_hoisted_jcc_target_copy_stats_8616(codegen, stats)
    return changed


def repair_conditional_continue_guards_from_evidence_8616(project: object, codegen: object) -> bool:
    """Remove false loop-break guards when CFG evidence proves continue."""
    stats = ConditionalContinueRepairStats8616()
    function = _active_function_8616(project, codegen)
    evidence = recover_conditional_continue_evidence_8616(project, function) if function is not None else ()
    stats.raw_fact_count = len(evidence)
    stats.normalized_fact_count = len(evidence)
    stats.classified_fact_count = len(evidence)
    if not evidence:
        stats.record(ConditionalContinueRepairDecision8616.REFUSED_NO_EVIDENCE)
        _store_conditional_continue_stats_8616(codegen, stats)
        return False
    cfunc = _codegen_cfunc_8616(codegen)
    if cfunc is None:
        stats.record(ConditionalContinueRepairDecision8616.REFUSED_NO_CFUNC)
        _store_conditional_continue_stats_8616(codegen, stats)
        return False
    remaining_repairs = len(evidence)
    changed = False
    for root in _cfunc_roots_8616(cfunc):
        local_changed, remaining_repairs = _repair_conditional_continue_in_node_8616(
            root,
            remaining_repairs,
            stats,
        )
        changed = local_changed or changed
        if remaining_repairs <= 0:
            break
    if not changed:
        stats.record(ConditionalContinueRepairDecision8616.REFUSED_NO_COMPLEMENTARY_GUARD)
    _store_conditional_continue_stats_8616(codegen, stats)
    return changed


def repair_switch_loop_exit_returns_from_evidence_8616(project: object, codegen: object) -> bool:
    """Preserve proven shared exits or add missing exact switch-return cases."""
    stats = SwitchLoopExitReturnRepairStats8616()
    cfunc = _codegen_cfunc_8616(codegen)
    if cfunc is None:
        stats.record(SwitchLoopExitReturnRepairDecision8616.REFUSED_NO_CFUNC)
        _store_switch_loop_exit_return_stats_8616(codegen, stats)
        return False
    roots = _cfunc_roots_8616(cfunc)
    if not roots:
        stats.record(SwitchLoopExitReturnRepairDecision8616.REFUSED_NO_STATEMENTS)
        _store_switch_loop_exit_return_stats_8616(codegen, stats)
        return False
    function = _active_function_8616(project, codegen)
    evidence = recover_switch_loop_exit_return_evidence_8616(project, function) if function is not None else ()
    cast(Any, codegen)._inertia_structuring_switch_loop_exit_return_evidence_8616 = evidence
    stats.raw_fact_count = len(evidence)
    stats.normalized_fact_count = len(evidence)
    stats.classified_fact_count = len(evidence)
    if not evidence:
        stats.record(SwitchLoopExitReturnRepairDecision8616.REFUSED_NO_EVIDENCE)
        _store_switch_loop_exit_return_stats_8616(codegen, stats)
        return False
    shared = publish_shared_loop_exit_report_8616(project, codegen, evidence)
    if shared.materialized_count == len(evidence):
        stats = SwitchLoopExitReturnRepairStats8616(preserved_shared_exit_count=shared.materialized_count)
        _store_switch_loop_exit_return_stats_8616(codegen, stats)
        return False
    candidate_count = _switch_loop_exit_return_candidate_count_8616(roots)
    if candidate_count != 1:
        decision = (
            SwitchLoopExitReturnRepairDecision8616.REFUSED_AMBIGUOUS_LOOP
            if candidate_count > 1
            else SwitchLoopExitReturnRepairDecision8616.REFUSED_NO_MATCHING_LOOP
        )
        stats.record(decision)
        _store_switch_loop_exit_return_stats_8616(codegen, stats)
        return False
    changed = False
    for root in roots:
        changed = _repair_switch_loop_exit_return_in_statement_list_8616(root, tuple(evidence), stats, codegen) or changed
    if changed:
        cast(Any, codegen)._inertia_switch_loop_exit_return_materialized_8616 = True
    else:
        stats.record(SwitchLoopExitReturnRepairDecision8616.REFUSED_NO_MATCHING_LOOP)
    _store_switch_loop_exit_return_stats_8616(codegen, stats)
    return changed


def _switch_loop_exit_return_candidate_count_8616(roots: tuple[object, ...]) -> int:
    """Count unique loop bodies that could own one proven switch exit."""
    candidate_ids: set[int] = set()
    for root in roots:
        for node in _iter_node_and_children_8616(root):
            loop = _statement_as_single_wrapped_while_loop_8616(node)
            if loop is None:
                continue
            body = getattr(loop, "body", None)
            if any(isinstance(child, CSwitchCase) for child in _iter_node_and_children_8616(body)):
                candidate_ids.add(id(loop))
    return len(candidate_ids)


def repair_pretest_loop_break_guards_from_evidence_8616(project: object, codegen: object) -> bool:
    """Invert pretest body-edge break guards using binary branch evidence."""
    stats = PretestLoopGuardRepairStats8616()
    function = _active_function_8616(project, codegen)
    recovered_evidence = recover_pretest_loop_guard_evidence_8616(project, function) if function is not None else ()
    typed_evidence = _typed_pretest_loop_guard_evidence_8616(codegen)
    evidence_by_branch = {item.branch_addr: item for item in recovered_evidence}
    evidence_by_branch.update({item.branch_addr: item for item in typed_evidence})
    if function is not None:
        short_circuit_evidence = _recover_short_circuit_pretest_guard_evidence_8616(
            project,
            function,
            tuple(evidence_by_branch.values()),
        )
        evidence_by_branch.update({item.branch_addr: item for item in short_circuit_evidence})
    evidence = tuple(evidence_by_branch.values())
    stats.raw_fact_count = len(evidence)
    stats.normalized_fact_count = len(evidence)
    stats.classified_fact_count = len(evidence)
    if not evidence:
        stats.record(PretestLoopGuardRepairDecision8616.REFUSED_NO_EVIDENCE)
        _store_pretest_loop_guard_stats_8616(codegen, stats)
        return False
    cfunc = _codegen_cfunc_8616(codegen)
    if cfunc is None:
        stats.record(PretestLoopGuardRepairDecision8616.REFUSED_NO_CFUNC)
        _store_pretest_loop_guard_stats_8616(codegen, stats)
        return False
    changed = False
    for root in _cfunc_roots_8616(cfunc):
        _debug_pretest_loop_shape_8616(root)
        changed = _repair_pretest_loop_guard_in_node_8616(root, tuple(evidence), stats, codegen) or changed
    if not changed:
        stats.record(PretestLoopGuardRepairDecision8616.REFUSED_NO_MATCHING_LOOP)
    _store_pretest_loop_guard_stats_8616(codegen, stats)
    return changed


def prune_redundant_loop_break_carriers_8616(codegen: object) -> bool:
    """Prune adjacent equivalent loop breaks proven through exact carrier definitions.

    This pass owns only structured control-flow redundancy. Alias supplies
    storage identity, widening supplies any prior value joins, and the typed
    condition IR supplies comparison inversion. The pass preserves all carrier
    assignments so evidence-aware DCE can decide whether they are dead later.
    """
    stats = RedundantLoopBreakCarrierStats8616()
    cfunc = _codegen_cfunc_8616(codegen)
    if cfunc is None:
        stats.record(RedundantLoopBreakCarrierDecision8616.REFUSED_NO_CFUNC)
        _store_redundant_loop_break_carrier_stats_8616(codegen, stats)
        return False

    changed = False
    for root in _cfunc_roots_8616(cfunc):
        for node in tuple(_iter_node_and_children_8616(root)):
            if not isinstance(node, (CWhileLoop, CDoWhileLoop, CForLoop)):
                continue
            body = node.body
            if isinstance(body, CStatements):
                changed = _prune_redundant_breaks_in_loop_body_8616(body, stats) or changed

    if not changed and stats.raw_fact_count == 0:
        stats.record(RedundantLoopBreakCarrierDecision8616.REFUSED_NO_CANDIDATE)
    _store_redundant_loop_break_carrier_stats_8616(codegen, stats)
    return changed


def _prune_redundant_breaks_in_loop_body_8616(
    body: CStatements,
    stats: RedundantLoopBreakCarrierStats8616,
) -> bool:
    """Remove only the second guard in each proven adjacent duplicate pair."""
    statements = body.statements
    if not isinstance(statements, list):
        return False
    changed = False
    index = 0
    while index + 1 < len(statements):
        first_condition = _ifbreak_condition_8616(statements[index])
        second_condition = _ifbreak_condition_8616(statements[index + 1])
        if first_condition is None or second_condition is None:
            index += 1
            continue
        stats.raw_fact_count += 1
        first_comparison = _canonical_break_comparison_8616(first_condition, ())
        second_comparison = _canonical_break_comparison_8616(second_condition, ())
        equivalent = (
            first_comparison is not None
            and second_comparison is not None
            and _canonical_comparisons_are_equivalent_8616(first_comparison, second_comparison)
        )
        if not equivalent:
            definitions = _ordered_pure_carrier_definitions_8616(statements[:index])
            first_comparison = _canonical_break_comparison_8616(first_condition, definitions)
            second_comparison = _canonical_break_comparison_8616(second_condition, definitions)
            equivalent = (
                first_comparison is not None
                and second_comparison is not None
                and _canonical_comparisons_are_equivalent_8616(first_comparison, second_comparison)
            )
        if not equivalent:
            stats.record(RedundantLoopBreakCarrierDecision8616.REFUSED_UNPROVEN_EQUIVALENCE)
            index += 1
            continue
        stats.normalized_fact_count += 1
        stats.classified_fact_count += 1
        del statements[index + 1]
        stats.record(RedundantLoopBreakCarrierDecision8616.MATERIALIZED)
        changed = True
    return changed


def _ordered_pure_carrier_definitions_8616(
    prefix: list[object],
) -> tuple[tuple[CVariable, object], ...] | None:
    """Collect ordered local/register definitions or refuse an effectful prefix."""
    definitions: list[tuple[CVariable, object]] = []

    def collect(node: object) -> bool:
        """Collect assignments from transparent statement wrappers."""
        if isinstance(node, CStatements):
            return all(collect(child) for child in node.statements or ())
        if not isinstance(node, CAssignment) or not isinstance(node.lhs, CVariable):
            return False
        variable = node.lhs.variable
        if not isinstance(variable, (SimRegisterVariable, SimStackVariable)):
            return False
        if _node_contains_effectful_call_8616(node.rhs):
            return False
        definitions.append((node.lhs, node.rhs))
        return True

    return tuple(definitions) if all(collect(node) for node in prefix) else None


def _canonical_break_comparison_8616(
    condition: object,
    definitions: tuple[tuple[CVariable, object], ...] | None,
) -> tuple[str, object, object] | None:
    """Normalize one pure break comparison and resolve exact SSA carriers."""
    if definitions is None or _node_contains_effectful_call_8616(condition):
        return None
    comparison = condition
    inverted = False
    if isinstance(comparison, CUnaryOp) and comparison.op == "Not":
        comparison = comparison.operand
        inverted = True
    if not isinstance(comparison, CBinaryOp):
        return None
    op = inverted_comparison_op_8616(comparison.op) if inverted else comparison.op
    if op is None or not op.startswith("Cmp"):
        return None
    lhs = _resolve_exact_carrier_definition_8616(comparison.lhs, definitions)
    rhs = _resolve_exact_carrier_definition_8616(comparison.rhs, definitions)
    if lhs is None or rhs is None:
        return None
    return op, lhs, rhs


def _resolve_exact_carrier_definition_8616(
    expression: object,
    definitions: tuple[tuple[CVariable, object], ...],
    *,
    active: frozenset[int] = frozenset(),
) -> object | None:
    """Resolve a variable through preceding exact definitions without guessing."""
    if not isinstance(expression, CVariable):
        return expression
    marker = id(expression.variable)
    if marker in active:
        return None
    for definition_index in range(len(definitions) - 1, -1, -1):
        lhs, rhs = definitions[definition_index]
        if not _same_c_expression_8616(lhs, expression):
            continue
        return _resolve_exact_carrier_definition_8616(
            rhs,
            definitions[:definition_index],
            active=active | {marker},
        )
    return cast(object, expression)


def _canonical_comparisons_are_equivalent_8616(
    left: tuple[str, object, object],
    right: tuple[str, object, object],
) -> bool:
    """Return whether canonical comparisons have identical proven operands."""
    return (
        left[0] == right[0]
        and _carrier_expressions_are_equivalent_8616(left[1], right[1])
        and _carrier_expressions_are_equivalent_8616(left[2], right[2])
    )


def _carrier_expressions_are_equivalent_8616(left: object, right: object) -> bool:
    """Compare expressions using exact shape or explicit alias storage identity."""
    if _same_c_expression_8616(left, right):
        return True
    if isinstance(left, CVariable) and isinstance(right, CVariable):
        left_facts = describe_alias_storage(left)
        right_facts = describe_alias_storage(right)
        return (
            left_facts.identity is not None
            and left_facts.identity == right_facts.identity
            and left_facts.domain.space == right_facts.domain.space
        )
    if isinstance(left, CConstant) and isinstance(right, CConstant):
        left_value = cast(object, left.value)
        right_value = cast(object, right.value)
        return bool(left_value == right_value)
    if isinstance(left, CUnaryOp) and isinstance(right, CUnaryOp):
        return left.op == right.op and _carrier_expressions_are_equivalent_8616(left.operand, right.operand)
    if isinstance(left, CBinaryOp) and isinstance(right, CBinaryOp):
        return (
            left.op == right.op
            and _carrier_expressions_are_equivalent_8616(left.lhs, right.lhs)
            and _carrier_expressions_are_equivalent_8616(left.rhs, right.rhs)
        )
    return False


def _store_redundant_loop_break_carrier_stats_8616(
    codegen: object,
    stats: RedundantLoopBreakCarrierStats8616,
) -> None:
    """Store typed pass evidence on the dynamic angr codegen boundary."""
    if codegen is not None:
        cast(Any, codegen)._inertia_redundant_loop_break_carrier_stats_8616 = stats


def _debug_pretest_loop_shape_8616(root: object) -> None:
    if not os.environ.get("INERTIA_DEBUG_PRETEST_LOOP_GUARD_REPAIR_VERBOSE"):
        return
    rows: list[str] = []

    def visit(node: object, depth: int) -> None:
        """Collect a bounded structural debug view of nested loop nodes."""
        if node is None or depth > 11 or len(rows) >= 420:
            return
        row = f"{'  ' * depth}{type(node).__name__}"
        if isinstance(node, CStatements):
            children = tuple(node.statements or ())
            row += f" statements={len(children)}"
            rows.append(row)
            for child in children[:16]:
                visit(child, depth + 1)
            return
        if isinstance(node, (CWhileLoop, CDoWhileLoop, CForLoop)):
            body = node.body
            row += f" body={type(body).__name__}"
            rows.append(row)
            visit(body, depth + 1)
            return
        if isinstance(node, CIfElse):
            pairs = _dynamic_sequence_8616(node.condition_and_nodes)
            row += f" pairs={len(pairs)} else={type(node.else_node).__name__}"
            rows.append(row)
            for pair in pairs[:4]:
                if not isinstance(pair, tuple) or len(pair) < 2:
                    continue
                body = pair[1]
                visit(body, depth + 1)
            visit(node.else_node, depth + 1)
            return
        if isinstance(node, CIfBreak):
            row += f" condition={type(node.condition).__name__}"
            rows.append(row)
            return
        rows.append(row)

    visit(root, 0)
    if rows:
        log.warning("[pretest-loop-guard-repair] ast-shape\n%s", "\n".join(rows))


def repair_empty_counted_loop_body_from_evidence_8616(project: object, codegen: object) -> bool:
    """Move proven accumulator updates into empty counted-loop bodies."""
    stats = LoopBodyRepairStats8616()
    function = _active_function_8616(project, codegen)
    summaries = _function_instruction_summaries_8616(project, function) if function is not None else []
    stats.raw_fact_count = len(summaries)
    evidence = recover_stack_accumulator_loop_evidence_8616(summaries)
    stats.normalized_fact_count = len(evidence)
    stats.classified_fact_count = len(evidence)
    if not evidence:
        stats.record(LoopBodyRepairDecision8616.REFUSED_NO_EVIDENCE)
        _store_stats_8616(codegen, stats)
        return False

    cfunc = _codegen_cfunc_8616(codegen)
    if cfunc is None:
        stats.record(LoopBodyRepairDecision8616.REFUSED_NO_CFUNC)
        _store_stats_8616(codegen, stats)
        return False
    changed = False
    roots = _cfunc_roots_8616(cfunc)
    if not roots:
        stats.record(LoopBodyRepairDecision8616.REFUSED_NO_STATEMENTS)
    for root in roots:
        changed = _repair_statement_list_8616(root, tuple(evidence), stats, codegen) or changed
    _store_stats_8616(codegen, stats)
    return changed


def repair_synthetic_internal_calls_from_evidence_8616(project: object, codegen: object) -> bool:
    """Remove synthetic call nodes that target internal CFG ranges.

    Generic structuring can model a split 16-bit function fragment as a call to
    an address inside the same function. That node is not a real call when
    decoded callsite evidence has no matching call target, so prune it before
    call-argument cleanup treats surrounding loop state as call arguments.
    """
    stats = SyntheticInternalCallRepairStats8616()
    cfunc = _codegen_cfunc_8616(codegen)
    if cfunc is None:
        stats.record(SyntheticInternalCallRepairDecision8616.REFUSED_NO_CFUNC)
        _store_synthetic_internal_call_stats_8616(codegen, stats)
        return False
    roots = _cfunc_roots_8616(cfunc)
    if not roots:
        stats.record(SyntheticInternalCallRepairDecision8616.REFUSED_NO_STATEMENTS)
        _store_synthetic_internal_call_stats_8616(codegen, stats)
        return False
    function = _active_function_8616(project, codegen)
    callsite_targets = _function_callsite_targets_8616(function)
    if callsite_targets is None:
        stats.record(SyntheticInternalCallRepairDecision8616.REFUSED_NO_CALLSITE_EVIDENCE)
        _store_synthetic_internal_call_stats_8616(codegen, stats)
        return False
    internal_ranges = _function_block_ranges_8616(project, function)
    if not internal_ranges:
        stats.record(SyntheticInternalCallRepairDecision8616.REFUSED_NO_EVIDENCE)
        _store_synthetic_internal_call_stats_8616(codegen, stats)
        return False
    summary_node_ids = {
        int(node_id)
        for node_id in (getattr(codegen, "_inertia_callsite_summaries", {}) or {})
        if isinstance(node_id, int)
    }
    function_addr = getattr(function, "addr", None)
    candidates = tuple(
        call
        for root in roots
        for call in _iter_synthetic_internal_call_candidates_8616(
            root,
            internal_ranges=internal_ranges,
            callsite_targets=callsite_targets,
            summary_node_ids=summary_node_ids,
            function_addr=function_addr if isinstance(function_addr, int) else None,
        )
    )
    stats.raw_fact_count = len(candidates)
    stats.normalized_fact_count = len(candidates)
    stats.classified_fact_count = len(candidates)
    if not candidates:
        stats.record(SyntheticInternalCallRepairDecision8616.REFUSED_NO_MATCHING_CALL)
        _store_synthetic_internal_call_stats_8616(codegen, stats)
        return False
    candidate_ids = {id(call) for call in candidates}
    changed = False
    for root in roots:
        changed = _prune_call_expression_statements_8616(root, candidate_ids, stats) or changed
    if not changed:
        stats.record(SyntheticInternalCallRepairDecision8616.REFUSED_NO_MATCHING_CALL)
    _store_synthetic_internal_call_stats_8616(codegen, stats)
    return changed


def _active_function_8616(project: object, codegen: object) -> object | None:
    cfunc = _codegen_cfunc_8616(codegen)
    addr = getattr(cfunc, "addr", None)
    if not isinstance(addr, int):
        return None
    prepared = getattr(project, "_inertia_current_decompile_function_8616", None)
    if prepared is not None and getattr(prepared, "addr", None) == addr:
        return cast(object, prepared)
    functions = getattr(getattr(project, "kb", None), "functions", None)
    if functions is None:
        return SimpleNamespace(addr=addr, size=getattr(cfunc, "size", None), name=getattr(cfunc, "name", None))
    try:
        function = functions.function(addr=addr, create=False)
    except Exception:
        function = None
    if function is not None:
        return cast(object, function)
    return SimpleNamespace(addr=addr, size=getattr(cfunc, "size", None), name=getattr(cfunc, "name", None))


def _function_callsite_targets_8616(function: object | None) -> frozenset[int] | None:
    """Return decoded call targets for a function, or None when unavailable."""
    if function is None:
        return None
    get_call_sites = getattr(function, "get_call_sites", None)
    get_call_target = getattr(function, "get_call_target", None)
    if not callable(get_call_sites) or not callable(get_call_target):
        return None
    targets: set[int] = set()
    try:
        callsites = _dynamic_sequence_8616(get_call_sites())
    except Exception:
        return None
    for callsite in callsites:
        try:
            target = get_call_target(callsite)
        except Exception:
            continue
        if isinstance(target, int):
            targets.add(target)
    return frozenset(targets)


def _function_block_ranges_8616(project: object, function: object | None) -> tuple[tuple[int, int], ...]:
    """Return byte ranges for blocks owned by the current function."""
    if function is None:
        return ()
    ranges: list[tuple[int, int]] = []
    factory = getattr(project, "factory", None)
    block_lifter = getattr(factory, "block", None)
    for raw_addr in sorted(getattr(function, "block_addrs_set", ()) or ()):
        if not isinstance(raw_addr, int):
            continue
        size = 1
        if callable(block_lifter):
            try:
                block = block_lifter(raw_addr, opt_level=0)
                block_size = getattr(block, "size", None)
                if isinstance(block_size, int) and block_size > 0:
                    size = block_size
            except Exception:
                size = 1
        ranges.append((raw_addr, raw_addr + size))
    return tuple(ranges)


def _call_target_addr_8616(call: CFunctionCall) -> int | None:
    """Return a structured call target address when the AST carries one."""
    callee_func = getattr(call, "callee_func", None)
    callee_addr = getattr(callee_func, "addr", None)
    if isinstance(callee_addr, int):
        return callee_addr
    target = getattr(call, "callee_target", None)
    return target if isinstance(target, int) else None


def _addr_in_ranges_8616(addr: int, ranges: tuple[tuple[int, int], ...]) -> bool:
    """Return whether an address belongs to any owned function block range."""
    return any(start <= addr < end for start, end in ranges)


def _iter_synthetic_internal_call_candidates_8616(
    node: object,
    *,
    internal_ranges: tuple[tuple[int, int], ...],
    callsite_targets: frozenset[int],
    summary_node_ids: set[int],
    function_addr: int | None,
) -> Iterator[CFunctionCall]:
    """Yield no-summary call nodes proven to target current-function ranges."""
    for child in _iter_node_and_children_8616(node):
        if not isinstance(child, CFunctionCall):
            continue
        if id(child) in summary_node_ids:
            continue
        target_addr = _call_target_addr_8616(child)
        if not isinstance(target_addr, int):
            continue
        if target_addr == function_addr:
            continue
        if target_addr in callsite_targets:
            continue
        if _addr_in_ranges_8616(target_addr, internal_ranges):
            yield child


def _prune_call_expression_statements_8616(
    node: object,
    candidate_ids: set[int],
    stats: SyntheticInternalCallRepairStats8616,
) -> bool:
    """Remove expression statements whose expression is a proven synthetic call."""
    changed = False
    statements = getattr(node, "statements", None)
    if isinstance(statements, list):
        retained: list[object] = []
        for stmt in statements:
            expr = getattr(stmt, "expr", None) if isinstance(stmt, CExpressionStatement) else None
            if isinstance(expr, CFunctionCall) and id(expr) in candidate_ids:
                stats.record(SyntheticInternalCallRepairDecision8616.MATERIALIZED)
                changed = True
                continue
            retained.append(stmt)
        if changed:
            cast(Any, node).statements = retained
    elif isinstance(statements, tuple):
        retained_tuple: list[object] = []
        for stmt in statements:
            expr = getattr(stmt, "expr", None) if isinstance(stmt, CExpressionStatement) else None
            if isinstance(expr, CFunctionCall) and id(expr) in candidate_ids:
                stats.record(SyntheticInternalCallRepairDecision8616.MATERIALIZED)
                changed = True
                continue
            retained_tuple.append(stmt)
        if changed:
            cast(Any, node).statements = tuple(retained_tuple)
    for child in _iter_node_and_children_8616(node):
        if child is node:
            continue
        child_statements = getattr(child, "statements", None)
        if isinstance(child_statements, (list, tuple)):
            changed = _prune_call_expression_statements_8616(child, candidate_ids, stats) or changed
    return changed


def _store_stats_8616(codegen: object, stats: LoopBodyRepairStats8616) -> None:
    if codegen is not None:
        cast(Any, codegen)._inertia_structuring_loop_body_repair_stats_8616 = stats
    if os.environ.get("INERTIA_DEBUG_LOOP_BODY_REPAIR"):
        log.warning(
            "[loop-body-repair] raw=%d normalized=%d classified=%d materialized=%d failures=%d no_evidence=%d no_cfunc=%d no_statements=%d nonempty_body=%d no_following=%d slot_mismatch=%d",
            stats.raw_fact_count,
            stats.normalized_fact_count,
            stats.classified_fact_count,
            stats.materialized_count,
            stats.failure_count,
            stats.refused_no_evidence,
            stats.refused_no_cfunc,
            stats.refused_no_statements,
            stats.refused_nonempty_body,
            stats.refused_no_following_update,
            stats.refused_slot_mismatch,
        )


def _store_synthetic_internal_call_stats_8616(
    codegen: object,
    stats: SyntheticInternalCallRepairStats8616,
) -> None:
    """Store synthetic internal-call repair counters on the codegen object."""
    if codegen is not None:
        cast(Any, codegen)._inertia_structuring_synthetic_internal_call_stats_8616 = stats
    if os.environ.get("INERTIA_DEBUG_SYNTHETIC_INTERNAL_CALL_REPAIR"):
        log.warning(
            "[synthetic-internal-call-repair] raw=%d normalized=%d classified=%d materialized=%d "
            "failures=%d no_evidence=%d no_cfunc=%d no_statements=%d no_callsites=%d no_match=%d",
            stats.raw_fact_count,
            stats.normalized_fact_count,
            stats.classified_fact_count,
            stats.materialized_count,
            stats.failure_count,
            stats.refused_no_evidence,
            stats.refused_no_cfunc,
            stats.refused_no_statements,
            stats.refused_no_callsite_evidence,
            stats.refused_no_matching_call,
        )


_CONDITIONAL_BRANCH_MNEMONICS_8616 = frozenset(
    {
        "ja",
        "jae",
        "jb",
        "jbe",
        "je",
        "jg",
        "jge",
        "jl",
        "jle",
        "jna",
        "jnae",
        "jnbe",
        "jnc",
        "jne",
        "jng",
        "jnge",
        "jnl",
        "jnle",
        "jno",
        "jnp",
        "jns",
        "jnz",
        "jo",
        "jp",
        "jpe",
        "jpo",
        "js",
        "jz",
    }
)
_UNCONDITIONAL_JMP_MNEMONICS_8616 = frozenset({"jmp", "ljmp"})
_COMPLEMENTARY_COMPARISONS_8616 = {
    ("CmpLE", "CmpGT"),
    ("CmpGT", "CmpLE"),
    ("CmpLT", "CmpGE"),
    ("CmpGE", "CmpLT"),
    ("CmpEQ", "CmpNE"),
    ("CmpNE", "CmpEQ"),
}
_JCC_TAKEN_COMPARISON_OPS_8616 = {
    "ja": "CmpGT",
    "jae": "CmpGE",
    "jb": "CmpLT",
    "jbe": "CmpLE",
    "jc": "CmpLT",
    "je": "CmpEQ",
    "jg": "CmpGT",
    "jge": "CmpGE",
    "jl": "CmpLT",
    "jle": "CmpLE",
    "jna": "CmpLE",
    "jnae": "CmpLT",
    "jnb": "CmpGE",
    "jnbe": "CmpGT",
    "jnc": "CmpGE",
    "jne": "CmpNE",
    "jng": "CmpLE",
    "jnge": "CmpLT",
    "jnl": "CmpGE",
    "jnle": "CmpGT",
    "jnz": "CmpNE",
    "jz": "CmpEQ",
}


def _complementary_cmp_op_8616(op: object) -> str | None:
    """Return the structured comparison operator complement."""
    if not isinstance(op, str):
        return None
    for left, right in _COMPLEMENTARY_COMPARISONS_8616:
        if op == left:
            return right
    return None


def _pretest_body_edge_op_8616(evidence: PretestLoopGuardEvidence8616) -> str | None:
    """Return the comparison operator for the proven taken body edge."""
    if evidence.body_condition_op is not None:
        return evidence.body_condition_op
    mnemonic = str(evidence.mnemonic or "").lower()
    return _JCC_TAKEN_COMPARISON_OPS_8616.get(mnemonic)


def _typed_pretest_loop_guard_evidence_8616(codegen: object) -> tuple[PretestLoopGuardEvidence8616, ...]:
    """Adapt exact loop JCC facts into pretest guard evidence."""
    condition_ops = {
        "eq": "CmpEQ",
        "ne": "CmpNE",
        "slt": "CmpLT",
        "sle": "CmpLE",
        "sgt": "CmpGT",
        "sge": "CmpGE",
        "ult": "CmpLT",
        "ule": "CmpLE",
        "ugt": "CmpGT",
        "uge": "CmpGE",
    }
    recovered: list[PretestLoopGuardEvidence8616] = []
    for fact in loop_branch_guard_facts_8616(codegen):
        condition_ir = fact.condition_ir
        condition_op = getattr(condition_ir, "op", None)
        if not isinstance(condition_op, str):
            continue
        body_condition_op = condition_ops.get(condition_op)
        if body_condition_op is None:
            continue
        if not all(
            isinstance(value, int)
            for value in (fact.jcc_addr, fact.body_target, fact.false_target)
        ):
            continue
        recovered.append(
            PretestLoopGuardEvidence8616(
                branch_addr=fact.jcc_addr,
                body_target=fact.body_target,
                exit_target=fact.false_target,
                mnemonic="typed-jcc",
                body_condition_op=body_condition_op,
            )
        )
    return tuple(recovered)


def _pretest_guard_already_exit_edge_8616(
    condition: object,
    evidence: PretestLoopGuardEvidence8616,
) -> bool:
    """Detect guards already inverted from body-edge condition to exit-edge condition."""
    if isinstance(condition, CUnaryOp) and condition.op == "Not":
        return True
    if not isinstance(condition, CBinaryOp):
        return False
    body_op = _pretest_body_edge_op_8616(evidence)
    if body_op is None:
        return False
    condition_op = cast(str, condition.op)
    return bool(condition_op == _complementary_cmp_op_8616(body_op))


def _store_conditional_continue_stats_8616(codegen: object, stats: ConditionalContinueRepairStats8616) -> None:
    if codegen is not None:
        cast(Any, codegen)._inertia_structuring_conditional_continue_stats_8616 = stats
    if os.environ.get("INERTIA_DEBUG_CONDITIONAL_CONTINUE_REPAIR"):
        log.warning(
            "[conditional-continue-repair] raw=%d normalized=%d classified=%d materialized=%d failures=%d no_evidence=%d no_cfunc=%d no_guard=%d",
            stats.raw_fact_count,
            stats.normalized_fact_count,
            stats.classified_fact_count,
            stats.materialized_count,
            stats.failure_count,
            stats.refused_no_evidence,
            stats.refused_no_cfunc,
            stats.refused_no_complementary_guard,
        )


def _store_hoisted_jcc_target_copy_stats_8616(codegen: object, stats: HoistedJccTargetCopyRepairStats8616) -> None:
    if codegen is not None:
        cast(Any, codegen)._inertia_structuring_hoisted_jcc_target_copy_stats_8616 = stats
    if os.environ.get("INERTIA_DEBUG_HOISTED_JCC_TARGET_COPY_REPAIR"):
        log.warning(
            "[hoisted-jcc-target-copy-repair] raw=%d normalized=%d classified=%d materialized=%d failures=%d no_evidence=%d no_cfunc=%d no_if=%d no_copy=%d ambiguous=%d body_unproven=%d",
            stats.raw_fact_count,
            stats.normalized_fact_count,
            stats.classified_fact_count,
            stats.materialized_count,
            stats.failure_count,
            stats.refused_no_evidence,
            stats.refused_no_cfunc,
            stats.refused_no_matching_if,
            stats.refused_no_hoisted_copy,
            stats.refused_ambiguous_copy,
            stats.refused_body_target_unproven,
        )


def _store_pretest_loop_guard_stats_8616(codegen: object, stats: PretestLoopGuardRepairStats8616) -> None:
    if codegen is not None:
        cast(Any, codegen)._inertia_structuring_pretest_loop_guard_stats_8616 = stats
    if os.environ.get("INERTIA_DEBUG_PRETEST_LOOP_GUARD_REPAIR"):
        log.warning(
            "[pretest-loop-guard-repair] raw=%d normalized=%d classified=%d materialized=%d failures=%d no_evidence=%d no_cfunc=%d no_loop=%d body_unproven=%d iterator_moved=%d call_carriers_removed=%d",
            stats.raw_fact_count,
            stats.normalized_fact_count,
            stats.classified_fact_count,
            stats.materialized_count,
            stats.failure_count,
            stats.refused_no_evidence,
            stats.refused_no_cfunc,
            stats.refused_no_matching_loop,
            stats.refused_body_target_unproven,
            stats.iterator_moved_count,
            stats.call_return_carriers_removed_count,
        )


def _store_switch_loop_exit_return_stats_8616(
    codegen: object,
    stats: SwitchLoopExitReturnRepairStats8616,
) -> None:
    """Publish closed switch-exit evidence counters on the codegen boundary."""
    if codegen is not None:
        cast(Any, codegen)._inertia_structuring_switch_loop_exit_return_stats_8616 = stats
    if os.environ.get("INERTIA_DEBUG_SWITCH_LOOP_EXIT_RETURN_REPAIR"):
        log.warning(
            "[switch-loop-exit-return-repair] raw=%d normalized=%d classified=%d materialized=%d failures=%d "
            "pruned=%d no_evidence=%d no_cfunc=%d no_statements=%d no_loop=%d ambiguous_loop=%d "
            "has_break=%d no_switch=%d case_present=%d",
            stats.raw_fact_count,
            stats.normalized_fact_count,
            stats.classified_fact_count,
            stats.materialized_count,
            stats.failure_count,
            stats.trailing_unreachable_pruned_count,
            stats.refused_no_evidence,
            stats.refused_no_cfunc,
            stats.refused_no_statements,
            stats.refused_no_matching_loop,
            stats.refused_ambiguous_loop,
            stats.refused_loop_has_break,
            stats.refused_no_switch,
            stats.refused_case_already_present,
        )


def _linear_capstone_insns_8616(project: object, function: object) -> tuple[object, ...]:
    addr = getattr(function, "addr", None)
    if not isinstance(addr, int):
        return ()
    size = getattr(function, "size", None)
    if not isinstance(size, int) or size <= 0:
        size = 0x300
    try:
        code = bytes(cast(Any, project).loader.memory.load(addr, min(size, 0x400)))
    except Exception:
        return ()
    capstone = getattr(getattr(project, "arch", None), "capstone", None)
    if capstone is None:
        return ()
    try:
        return tuple(capstone.disasm(code, addr))
    except Exception:
        return ()


def _branch_target_imm_from_capstone_8616(insn: object) -> int | None:
    operands = tuple(getattr(insn, "operands", ()) or ())
    if len(operands) != 1:
        return None
    operand = operands[0]
    if int(getattr(operand, "type", -1)) != 2:
        return None
    value = getattr(operand, "imm", None)
    return int(value) if isinstance(value, int) else None


def _resolve_unconditional_jmp_chain_8616(project: object, target: int) -> int | None:
    current = int(target)
    seen: set[int] = set()
    for _ in range(4):
        if current in seen:
            return None
        seen.add(current)
        insns = _block_insns_8616(project, current)
        if not insns:
            return current
        first = insns[0]
        if str(getattr(first, "mnemonic", "")).lower() not in _UNCONDITIONAL_JMP_MNEMONICS_8616:
            return current
        next_target = _branch_target_imm_from_capstone_8616(first)
        if next_target is None:
            return None
        current = int(next_target)
    return current


def _target_starts_with_iterator_update_8616(project: object, target: int) -> bool:
    insns = _block_insns_8616(project, target)
    if not insns:
        return False
    summary = _summarize_capstone_insn_8616(insns[0])
    if summary.mnemonic in {"inc", "dec"}:
        return summary.op0_kind == "bp_mem" and (summary.op0_size in {None, 2})
    if summary.mnemonic not in {"add", "sub"}:
        return False
    return (
        summary.op0_kind == "bp_mem"
        and summary.op1_kind == "imm"
        and int(summary.op1_value or 0) == 1
        and (summary.op0_size in {None, 2})
    )


def _is_sub_ax_immediate_8616(summary: InsnSummary8616) -> bool:
    return (
        str(summary.mnemonic).lower() == "sub"
        and summary.op0_kind == "reg"
        and str(summary.op0_value).lower() == "ax"
        and summary.op1_kind == "imm"
        and isinstance(summary.op1_value, int)
        and 0 <= int(summary.op1_value) <= 0xFFFF
    )


def _instruction_stream_reaches_ret_8616(summaries: list[InsnSummary8616], start_addr: int) -> bool:
    start_index = next((index for index, summary in enumerate(summaries) if summary.address == start_addr), None)
    if start_index is None:
        return False
    for summary in summaries[start_index : start_index + 12]:
        mnemonic = str(summary.mnemonic).lower()
        if mnemonic in {"ret", "retf", "iret"}:
            return True
        if mnemonic in _CONDITIONAL_BRANCH_MNEMONICS_8616:
            return False
        if mnemonic in _UNCONDITIONAL_JMP_MNEMONICS_8616 and summary.address != start_addr:
            return False
    return False


def _block_insns_8616(project: object, addr: int) -> tuple[object, ...]:
    try:
        block = cast(Any, project).factory.block(addr, opt_level=0)
    except Exception:
        return ()
    return tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ())


def _repair_switch_loop_exit_return_in_statement_list_8616(
    node: object,
    evidence: tuple[SwitchLoopExitReturnEvidence8616, ...],
    stats: SwitchLoopExitReturnRepairStats8616,
    codegen: object,
) -> bool:
    changed = False
    if not isinstance(node, CStatements):
        for child in _iter_node_and_children_8616(node):
            if child is node:
                continue
            changed = _repair_switch_loop_exit_return_in_statement_list_8616(child, evidence, stats, codegen) or changed
        return changed
    statements: list[object] = list(_dynamic_sequence_8616(node.statements))
    if not statements:
        return False
    for index, statement in enumerate(tuple(statements)):
        loop = _statement_as_single_wrapped_while_loop_8616(statement)
        if loop is None:
            changed = _repair_switch_loop_exit_return_in_statement_list_8616(statement, evidence, stats, codegen) or changed
            continue
        decision = _repair_one_switch_loop_exit_return_8616(loop, statements, index, evidence, stats, codegen)
        if decision is SwitchLoopExitReturnRepairDecision8616.MATERIALIZED:
            changed = True
            cast(Any, node).statements = statements
        elif decision is not SwitchLoopExitReturnRepairDecision8616.REFUSED_NO_MATCHING_LOOP:
            stats.record(decision)
    return changed


def _repair_one_switch_loop_exit_return_8616(
    loop: CWhileLoop,
    statements: list[object],
    loop_index: int,
    evidence: tuple[SwitchLoopExitReturnEvidence8616, ...],
    stats: SwitchLoopExitReturnRepairStats8616,
    codegen: object,
) -> SwitchLoopExitReturnRepairDecision8616:
    body = getattr(loop, "body", None)
    if not isinstance(body, CStatements):
        return SwitchLoopExitReturnRepairDecision8616.REFUSED_NO_MATCHING_LOOP
    if _contains_break_8616(body):
        return SwitchLoopExitReturnRepairDecision8616.REFUSED_LOOP_HAS_BREAK
    switch = _first_switch_in_node_8616(body)
    if switch is None:
        return SwitchLoopExitReturnRepairDecision8616.REFUSED_NO_SWITCH
    unconditional_loop = _is_const_true_8616(getattr(loop, "condition", None))
    existing = _switch_case_values_8616(switch)
    missing = [item for item in evidence if item.case_value not in existing]
    if not missing:
        pruned = _prune_trailing_returns_after_loop_8616(statements, loop_index) if unconditional_loop else 0
        if pruned > 0:
            stats.trailing_unreachable_pruned_count += pruned
            stats.record(SwitchLoopExitReturnRepairDecision8616.MATERIALIZED)
            return SwitchLoopExitReturnRepairDecision8616.MATERIALIZED
        return SwitchLoopExitReturnRepairDecision8616.REFUSED_CASE_ALREADY_PRESENT
    for item in missing:
        return_body = CStatements(
            [CReturn(None, codegen=codegen, tags={"ins_addr": item.case_target})],
            addr=item.case_target,
            codegen=codegen,
        )
        _append_switch_case_8616(switch, item.case_value, return_body)
        stats.record(SwitchLoopExitReturnRepairDecision8616.MATERIALIZED)
    if unconditional_loop:
        stats.trailing_unreachable_pruned_count += _prune_trailing_returns_after_loop_8616(statements, loop_index)
    return SwitchLoopExitReturnRepairDecision8616.MATERIALIZED


def _is_const_true_8616(node: object) -> bool:
    return isinstance(node, CConstant) and isinstance(node.value, int) and node.value != 0


def _statement_as_single_wrapped_while_loop_8616(statement: object) -> CWhileLoop | None:
    if isinstance(statement, CWhileLoop):
        return statement
    current = statement
    for _depth in range(4):
        if not isinstance(current, CStatements):
            return None
        children = _dynamic_sequence_8616(current.statements)
        if len(children) != 1:
            return None
        child = children[0]
        if isinstance(child, CWhileLoop):
            return child
        current = child
    return None


def _contains_break_8616(node: object) -> bool:
    return _contains_break_outside_switch_8616(node, inside_switch=False)


def _contains_break_outside_switch_8616(node: object, *, inside_switch: bool) -> bool:
    if node is None:
        return False
    if isinstance(node, CBreak):
        return not inside_switch
    if isinstance(node, CSwitchCase):
        for _case_value, case_body in _iter_switch_case_bodies_8616(node):
            if _contains_break_outside_switch_8616(case_body, inside_switch=True):
                return True
        return _contains_break_outside_switch_8616(node.default, inside_switch=True)
    if isinstance(node, CStatements):
        return any(
            _contains_break_outside_switch_8616(statement, inside_switch=inside_switch)
            for statement in tuple(node.statements or ())
        )
    if isinstance(node, CIfElse):
        pairs = _dynamic_sequence_8616(node.condition_and_nodes)
        if any(
            _contains_break_outside_switch_8616(pair[1], inside_switch=inside_switch)
            for pair in pairs
            if isinstance(pair, tuple) and len(pair) >= 2
        ):
            return True
        return _contains_break_outside_switch_8616(node.else_node, inside_switch=inside_switch)
    if isinstance(node, (CWhileLoop, CDoWhileLoop, CForLoop)):
        return _contains_break_outside_switch_8616(node.body, inside_switch=inside_switch)
    return False


def _first_switch_in_node_8616(node: object) -> CSwitchCase | None:
    if isinstance(node, CSwitchCase):
        return node
    for child in _iter_node_and_children_8616(node):
        if isinstance(child, CSwitchCase):
            return child
    return None


def _switch_case_values_8616(switch: CSwitchCase) -> frozenset[int]:
    cases = getattr(switch, "cases", ()) or ()
    if isinstance(cases, dict):
        return frozenset(int(value) for value in cases if isinstance(value, int))
    values: set[int] = set()
    for item in _dynamic_sequence_8616(cases):
        if not isinstance(item, tuple) or not item:
            continue
        value = item[0]
        if isinstance(value, int):
            values.add(int(value))
    return frozenset(values)


def _iter_switch_case_bodies_8616(switch: CSwitchCase) -> Iterator[tuple[int, object]]:
    cases = getattr(switch, "cases", ()) or ()
    if isinstance(cases, dict):
        for value, body in cases.items():
            if isinstance(value, int):
                yield int(value), body
        return
    for item in _dynamic_sequence_8616(cases):
        if not isinstance(item, tuple) or len(item) < 2:
            continue
        value, body = item[0], item[1]
        if isinstance(value, int):
            yield int(value), body


def _append_switch_case_8616(switch: CSwitchCase, case_value: int, body: CStatements) -> None:
    cases = getattr(switch, "cases", ()) or ()
    if isinstance(cases, dict):
        cases[int(case_value)] = body
        cast(Any, switch).cases = cases
        return
    cast(Any, switch).cases = [*list(_dynamic_sequence_8616(cases)), (int(case_value), body)]


def _prune_trailing_returns_after_loop_8616(statements: list[object], loop_index: int) -> int:
    tail = statements[loop_index + 1 :]
    removable = [statement for statement in tail if _statement_contains_only_returns_8616(statement)]
    if len(removable) != len(tail):
        return 0
    removed = len(tail)
    del statements[loop_index + 1 :]
    return removed


def _statement_contains_only_returns_8616(statement: object) -> bool:
    if isinstance(statement, CReturn):
        return True
    if not isinstance(statement, CStatements):
        return False
    children = _dynamic_sequence_8616(statement.statements)
    return bool(children) and all(_statement_contains_only_returns_8616(child) for child in children)


def _repair_pretest_loop_guard_in_node_8616(
    node: object,
    evidence: tuple[PretestLoopGuardEvidence8616, ...],
    stats: PretestLoopGuardRepairStats8616,
    codegen: object,
) -> bool:
    changed = False
    if isinstance(node, CStatements):
        for stmt in _dynamic_sequence_8616(node.statements):
            changed = _repair_pretest_loop_guard_in_node_8616(stmt, evidence, stats, codegen) or changed
        return changed
    if isinstance(node, CIfElse):
        for pair in _dynamic_sequence_8616(node.condition_and_nodes):
            if not isinstance(pair, tuple) or len(pair) < 2:
                continue
            body = pair[1]
            changed = _repair_pretest_loop_guard_in_node_8616(body, evidence, stats, codegen) or changed
        changed = _repair_pretest_loop_guard_in_node_8616(node.else_node, evidence, stats, codegen) or changed
        return changed
    if not isinstance(node, (CForLoop, CWhileLoop, CDoWhileLoop)):
        return False
    body = node.body
    if not isinstance(body, CStatements):
        return False

    def repair_nested_body() -> bool:
        """Continue searching nested nodes when this loop is not repairable."""
        return _repair_pretest_loop_guard_in_node_8616(body, evidence, stats, codegen)

    raw_statements: list[object] = list(_dynamic_sequence_8616(body.statements))
    statements, flattened_wrappers = _flatten_direct_statement_wrappers_8616(raw_statements)
    if flattened_wrappers:
        cast(Any, body).statements = statements
    if len(statements) < 2:
        return repair_nested_body()
    break_index = _first_pretest_break_guard_index_8616(statements)
    if break_index is None:
        return repair_nested_body()
    guard = statements[break_index]
    break_condition = _ifbreak_condition_8616(guard)
    if break_condition is None:
        return repair_nested_body()
    rest = CStatements(statements[break_index + 1 :], codegen=codegen)
    matched = _pretest_evidence_for_loop_body_8616(break_condition, rest, evidence, guard=guard)
    if matched is None:
        stats.record(PretestLoopGuardRepairDecision8616.REFUSED_BODY_TARGET_UNPROVEN)
        return repair_nested_body()
    if break_index + 1 < len(statements):
        following = statements[break_index + 1]
        following_condition = _single_ifelse_condition_8616(following)
        if (
            following_condition is not None
            and _conditions_are_complementary_8616(break_condition, following_condition)
            and _ifelse_body_is_single_return_8616(following)
        ):
            del statements[break_index]
            body.statements = statements
            stats.record(PretestLoopGuardRepairDecision8616.MATERIALIZED)
            return True
    removed_call_carriers = _remove_pretest_consumed_call_return_carriers_8616(
        statements,
        break_index,
        break_condition,
        rest,
    )
    if removed_call_carriers:
        stats.call_return_carriers_removed_count += removed_call_carriers
        body.statements = statements
        break_index -= removed_call_carriers
        guard = statements[break_index]
    moved_count = _move_pretest_prefix_iterator_updates_to_tail_8616(statements, break_index, break_condition)
    if moved_count:
        stats.iterator_moved_count += moved_count
        body.statements = statements
        break_index -= moved_count
        guard = statements[break_index]
    if _pretest_guard_already_exit_edge_8616(break_condition, matched):
        if removed_call_carriers or moved_count:
            stats.record(PretestLoopGuardRepairDecision8616.MATERIALIZED)
            return True
        return repair_nested_body()
    if not _invert_ifbreak_condition_8616(guard, codegen):
        return repair_nested_body()
    stats.record(PretestLoopGuardRepairDecision8616.MATERIALIZED)
    return True


def _move_pretest_prefix_iterator_updates_to_tail_8616(
    statements: list[object],
    break_index: int,
    break_condition: object,
) -> int:
    if break_index <= 0:
        return 0
    guard_reads = _stack_offsets_read_8616(break_condition)
    if not guard_reads:
        return 0
    moved: list[object] = []
    keep: list[object] = []
    for stmt in statements[:break_index]:
        kept_stmt, moved_from_stmt = _extract_unit_stack_updates_for_slots_8616(stmt, guard_reads)
        moved.extend(moved_from_stmt)
        if kept_stmt is not None:
            keep.append(kept_stmt)
    if not moved:
        return 0
    statements[:break_index] = keep
    statements.extend(moved)
    return len(moved)


def _extract_unit_stack_updates_for_slots_8616(
    stmt: object,
    slots: frozenset[int],
) -> tuple[object | None, tuple[object, ...]]:
    if _assignment_is_unit_stack_update_for_slots_8616(stmt, slots):
        return None, (stmt,)
    if not isinstance(stmt, CStatements):
        return stmt, ()
    children = list(stmt.statements or ())
    if not children:
        return stmt, ()
    kept_children: list[object] = []
    moved: list[object] = []
    for child in children:
        kept_child, moved_child = _extract_unit_stack_updates_for_slots_8616(child, slots)
        moved.extend(moved_child)
        if kept_child is not None:
            kept_children.append(kept_child)
    if not moved:
        return stmt, ()
    if kept_children:
        stmt.statements = kept_children
        return stmt, tuple(moved)
    return None, tuple(moved)


def _assignment_is_unit_stack_update_for_slots_8616(stmt: object, slots: frozenset[int]) -> bool:
    if not isinstance(stmt, CAssignment):
        return False
    lhs_offset = _assignment_lhs_stack_offset_8616(stmt)
    if lhs_offset not in slots:
        return False
    rhs = stmt.rhs
    if not isinstance(rhs, CBinaryOp) or rhs.op not in {"Add", "Sub"}:
        return False
    lhs = getattr(rhs, "lhs", None)
    rhs_node = getattr(rhs, "rhs", None)
    if _stack_offset_8616(lhs) == lhs_offset and _constant_int_8616(rhs_node) == 1:
        return True
    return bool(rhs.op == "Add" and _stack_offset_8616(rhs_node) == lhs_offset and _constant_int_8616(lhs) == 1)


def _constant_int_8616(node: object) -> int | None:
    return int(node.value) if isinstance(node, CConstant) and isinstance(node.value, int) else None


def _first_pretest_break_guard_index_8616(statements: list[object]) -> int | None:
    max_prefix = min(len(statements), 6)
    for index in range(max_prefix):
        condition = _ifbreak_condition_8616(statements[index])
        if condition is not None:
            if _is_inverted_break_guard_condition_8616(condition):
                continue
            prefix = statements[:index]
            prefix_safe = all(
                (
                    isinstance(item, (CAssignment, CStatements))
                    or _is_inverted_break_guard_condition_8616(_ifbreak_condition_8616(item))
                )
                and not _node_contains_effectful_call_8616(item)
                for item in prefix
            )
            if not prefix_safe:
                prefix_safe = all(
                    _is_consumed_call_return_carrier_prefix_8616(item, condition, statements[index + 1 :])
                    for item in prefix
                )
            if os.environ.get("INERTIA_DEBUG_PRETEST_LOOP_GUARD_REPAIR_VERBOSE"):
                log.warning(
                    "[pretest-loop-guard-repair] candidate break index=%d prefix_safe=%s prefix=%r",
                    index,
                    prefix_safe,
                    tuple(
                        (
                            type(item).__name__,
                            _node_contains_call_8616(item),
                            len(tuple(getattr(item, "statements", ()) or ())),
                        )
                        for item in prefix
                    ),
                )
            if prefix_safe:
                return index
            return None
    if os.environ.get("INERTIA_DEBUG_PRETEST_LOOP_GUARD_REPAIR_VERBOSE"):
        log.warning(
            "[pretest-loop-guard-repair] no break guard in prefix body=%r",
            tuple(
                (
                    type(item).__name__,
                    type(_ifbreak_condition_8616(item)).__name__,
                    _node_contains_call_8616(item),
                    len(tuple(getattr(item, "statements", ()) or ())),
                )
                for item in statements[:max_prefix]
            ),
        )
    return None


def _is_inverted_break_guard_condition_8616(condition: object) -> bool:
    return isinstance(condition, CUnaryOp) and condition.op == "Not"


def _pretest_evidence_for_loop_body_8616(
    condition: object,
    body: object,
    evidence: tuple[PretestLoopGuardEvidence8616, ...],
    *,
    guard: object | None = None,
) -> PretestLoopGuardEvidence8616 | None:
    branch_addrs = tuple(
        dict.fromkeys(
            branch_addr
            for candidate in (guard, condition)
            if candidate is not None
            if isinstance(
                branch_addr := _condition_branch_addr_8616(candidate),
                int,
            )
        )
    )
    branch_matches = tuple(
        item for item in evidence if item.branch_addr in branch_addrs
    )
    if len(branch_matches) == 1:
        return branch_matches[0]
    if branch_addrs:
        return None
    exact_body_matches = tuple(item for item in evidence if _node_has_ins_addr_8616(body, item.body_target))
    if len(exact_body_matches) == 1:
        return exact_body_matches[0]
    body_matches = tuple(item for item in evidence if _node_has_ins_addr_in_window_8616(body, item.body_target, 0x80))
    if len(body_matches) == 1:
        return body_matches[0]
    if os.environ.get("INERTIA_DEBUG_PRETEST_LOOP_GUARD_REPAIR_VERBOSE"):
        log.warning(
            "[pretest-loop-guard-repair] body target unproven branch=<none> body_addrs=%r evidence=%r",
            sorted(_node_ins_addrs_8616(body))[:24],
            evidence,
        )
    return None


def _node_is_empty_statements_8616(node: object) -> bool:
    return isinstance(node, CStatements) and not tuple(getattr(node, "statements", ()) or ())


def _remove_pretest_consumed_call_return_carriers_8616(
    statements: list[object],
    break_index: int,
    break_condition: object,
    rest: object,
) -> int:
    if break_index <= 0:
        return 0
    removable_indices: list[int] = []
    for index, stmt in enumerate(statements[:break_index]):
        if _is_consumed_call_return_carrier_prefix_8616(stmt, break_condition, statements[index + 1 : break_index]):
            if not isinstance(stmt, CAssignment):
                continue
            if _carrier_lhs_read_by_nodes_8616(stmt, (break_condition, rest)):
                continue
            removable_indices.append(index)
            continue
        if _node_contains_effectful_call_8616(stmt):
            return 0
    if not removable_indices:
        return 0
    for index in reversed(removable_indices):
        del statements[index]
    return len(removable_indices)


def _is_consumed_call_return_carrier_prefix_8616(
    stmt: object,
    break_condition: object,
    later_prefix: list[object] | tuple[object, ...],
) -> bool:
    if not isinstance(stmt, CAssignment):
        return False
    lhs = stmt.lhs
    if not isinstance(lhs, CVariable):
        return False
    rhs_call = _single_function_call_8616(stmt.rhs)
    if rhs_call is None:
        return False
    condition_call = _matching_condition_call_8616(rhs_call, break_condition)
    if condition_call is None:
        return False
    return not _carrier_lhs_read_by_nodes_8616(stmt, (break_condition, *tuple(later_prefix)))


def _single_function_call_8616(node: object) -> CFunctionCall | None:
    calls = tuple(current for current in _iter_node_and_children_8616(node) if isinstance(current, CFunctionCall))
    return calls[0] if len(calls) == 1 else None


def _matching_condition_call_8616(source_call: CFunctionCall, condition: object) -> CFunctionCall | None:
    source_name = _function_call_name_8616(source_call)
    if source_name is None:
        return None
    source_addrs = _node_ins_addrs_8616(source_call)
    for current in _iter_node_and_children_8616(condition):
        if not isinstance(current, CFunctionCall):
            continue
        if _function_call_name_8616(current) != source_name:
            continue
        current_addrs = _node_ins_addrs_8616(current)
        if source_addrs and current_addrs and not (source_addrs & current_addrs):
            continue
        if source_addrs or current_addrs:
            return current
    return None


def _function_call_name_8616(node: CFunctionCall) -> str | None:
    target = getattr(node, "callee_target", None)
    if isinstance(target, str):
        return target
    func = getattr(node, "callee_func", None)
    name = getattr(func, "name", None) if func is not None else None
    return name if isinstance(name, str) else None


def _carrier_lhs_read_by_nodes_8616(stmt: CAssignment, nodes: tuple[object, ...]) -> bool:
    lhs = getattr(stmt, "lhs", None)
    lhs_key = _variable_key_8616(lhs)
    if lhs_key is None:
        return True
    for node in nodes:
        for current in _iter_node_and_children_8616(node):
            if current is lhs:
                continue
            if _variable_key_8616(current) == lhs_key:
                return True
    return False


def _variable_key_8616(node: object) -> tuple[object, ...] | None:
    if not isinstance(node, CVariable):
        return None
    variable = node.variable
    if isinstance(variable, SimStackVariable):
        return (
            "stack",
            variable.base,
            int(variable.offset or 0),
            int(variable.size or 0),
            variable.name,
        )
    if isinstance(variable, SimRegisterVariable):
        return (
            "register",
            int(variable.reg or 0),
            int(variable.size or 0),
            variable.name,
        )
    name = getattr(variable, "name", None)
    if isinstance(name, str):
        return ("named", name)
    if isinstance(variable, str):
        return ("named", variable)
    return None


def _iter_node_and_children_8616(node: object) -> Iterator[object]:
    if node is None:
        return
    seen: set[int] = set()
    seen.add(id(node))
    yield node
    for child in _iter_c_nodes_deep_8616(node):
        marker = id(child)
        if marker in seen:
            continue
        seen.add(marker)
        yield child


def _invert_ifbreak_condition_8616(node: object, codegen: object) -> bool:
    if isinstance(node, CIfBreak):
        condition = node.condition
        if isinstance(condition, CUnaryOp) and condition.op == "Not":
            return False
        if condition is None:
            return False
        cast(Any, node).condition = CUnaryOp("Not", condition, codegen=codegen, tags=getattr(condition, "tags", None))
        return True
    if not isinstance(node, CIfElse):
        return False
    pairs: list[object] = list(_dynamic_sequence_8616(node.condition_and_nodes))
    if len(pairs) != 1:
        return False
    pair = pairs[0]
    if not isinstance(pair, tuple) or len(pair) < 2:
        return False
    condition, body = pair[0], pair[1]
    if not _body_is_single_break_8616(body):
        return False
    if isinstance(condition, CUnaryOp) and condition.op == "Not":
        return False
    if condition is None:
        return False
    pairs[0] = (CUnaryOp("Not", condition, codegen=codegen, tags=getattr(condition, "tags", None)), body)
    cast(Any, node).condition_and_nodes = pairs
    return True


def _leading_stack_slot_copy_8616(insns: tuple[object, ...]) -> tuple[int, int, int] | None:
    if len(insns) < 2:
        return None
    first = _summarize_capstone_insn_8616(insns[0])
    second = _summarize_capstone_insn_8616(insns[1])
    if first.mnemonic != "mov" or second.mnemonic != "mov":
        return None
    if first.op0_kind != "reg" or first.op1_kind != "bp_mem":
        return None
    if second.op0_kind != "bp_mem" or second.op1_kind != "reg":
        return None
    if first.op0_value != second.op1_value:
        return None
    if first.op1_size not in {None, 2} or second.op0_size not in {None, 2}:
        return None
    copy_addr = getattr(insns[1], "address", None)
    if not isinstance(copy_addr, int):
        return None
    dest_disp = _dynamic_int_8616(second.op0_value)
    src_disp = _dynamic_int_8616(first.op1_value)
    if dest_disp is None or src_disp is None:
        return None
    return copy_addr, dest_disp, src_disp


def _repair_conditional_continue_in_node_8616(
    node: object,
    remaining_repairs: int,
    stats: ConditionalContinueRepairStats8616,
) -> tuple[bool, int]:
    if remaining_repairs <= 0:
        return False, remaining_repairs
    changed = False
    if isinstance(node, CStatements):
        statements = list(node.statements or ())
        idx = 0
        while idx < len(statements) and remaining_repairs > 0:
            stmt = statements[idx]
            local_changed, remaining_repairs = _repair_conditional_continue_in_node_8616(
                stmt,
                remaining_repairs,
                stats,
            )
            changed = local_changed or changed
            idx += 1
        if changed:
            node.statements = statements
        return changed, remaining_repairs
    if isinstance(node, CDoWhileLoop):
        body = node.body
        if not isinstance(body, CStatements):
            return False, remaining_repairs
        return _repair_conditional_continue_in_node_8616(body, remaining_repairs, stats)
    if not isinstance(node, (CForLoop, CWhileLoop)):
        return False, remaining_repairs
    body = node.body
    if not isinstance(body, CStatements):
        return False, remaining_repairs
    raw_body_statements: list[object] = list(_dynamic_sequence_8616(body.statements))
    body_statements, _flattened_wrappers = _flatten_direct_statement_wrappers_8616(raw_body_statements)
    if os.environ.get("INERTIA_DEBUG_CONDITIONAL_CONTINUE_REPAIR_VERBOSE"):
        log.warning(
            "[conditional-continue-repair] loop=%s body_types=%r",
            type(node).__name__,
            tuple(type(stmt).__name__ for stmt in body_statements),
        )
        for dbg_idx, dbg_stmt in enumerate(body_statements):
            dbg_cond_nodes = (
                _dynamic_sequence_8616(getattr(dbg_stmt, "condition_and_nodes", ()))
                if isinstance(dbg_stmt, CIfElse)
                else ()
            )
            dbg_first_pair = dbg_cond_nodes[0] if dbg_cond_nodes else None
            dbg_condition = dbg_first_pair[0] if isinstance(dbg_first_pair, tuple) and len(dbg_first_pair) >= 2 else None
            dbg_if_body = dbg_first_pair[1] if isinstance(dbg_first_pair, tuple) and len(dbg_first_pair) >= 2 else None
            dbg_if_body_types = (
                tuple(type(child).__name__ for child in _dynamic_sequence_8616(getattr(dbg_if_body, "statements", ())))
                if isinstance(dbg_if_body, CStatements)
                else (type(dbg_if_body).__name__,)
            )
            log.warning(
                "[conditional-continue-repair] body[%d]=%s break_cond=%s if_cond=%s if_op=%s else=%s cstyle=%r tags=%r if_body=%r",
                dbg_idx,
                type(dbg_stmt).__name__,
                type(_ifbreak_condition_8616(dbg_stmt)).__name__,
                type(_single_ifelse_condition_8616(dbg_stmt)).__name__,
                getattr(dbg_condition, "op", None),
                type(getattr(dbg_stmt, "else_node", None)).__name__,
                getattr(dbg_stmt, "cstyle_ifs", None),
                getattr(dbg_stmt, "tags", None),
                dbg_if_body_types,
            )
    local_changed = False
    idx = 0
    while idx + 1 < len(body_statements) and remaining_repairs > 0:
        current_stmt = body_statements[idx]
        if isinstance(current_stmt, CIfElse):
            current_ifelse = current_stmt
            ifelse_changed, remaining_repairs = _repair_conditional_continue_in_ifelse_node_8616(
                current_ifelse,
                remaining_repairs,
                stats,
            )
            local_changed = ifelse_changed or local_changed
            if ifelse_changed:
                idx += 1
                continue
        break_cond = _ifbreak_condition_8616(current_stmt)
        guarded_cond = _single_ifelse_condition_8616(body_statements[idx + 1])
        if (
            break_cond is not None
            and guarded_cond is not None
            and _conditions_are_complementary_8616(
                break_cond,
                guarded_cond,
            )
        ):
            del body_statements[idx]
            remaining_repairs -= 1
            stats.record(ConditionalContinueRepairDecision8616.MATERIALIZED)
            local_changed = True
            continue
        child_changed, remaining_repairs = _repair_conditional_continue_in_node_8616(
            body_statements[idx],
            remaining_repairs,
            stats,
        )
        local_changed = child_changed or local_changed
        idx += 1
    if idx < len(body_statements) and remaining_repairs > 0:
        current_stmt = body_statements[idx]
        if isinstance(current_stmt, CIfElse):
            current_ifelse = current_stmt
            ifelse_changed, remaining_repairs = _repair_conditional_continue_in_ifelse_node_8616(
                current_ifelse,
                remaining_repairs,
                stats,
            )
            local_changed = ifelse_changed or local_changed
        child_changed, remaining_repairs = _repair_conditional_continue_in_node_8616(
            current_stmt,
            remaining_repairs,
            stats,
        )
        local_changed = child_changed or local_changed
    if local_changed:
        cast(Any, body).statements = body_statements
    return local_changed, remaining_repairs


def _repair_conditional_continue_in_ifelse_node_8616(
    node: CIfElse,
    remaining_repairs: int,
    stats: ConditionalContinueRepairStats8616,
) -> tuple[bool, int]:
    if remaining_repairs <= 0 or getattr(node, "else_node", None) is not None:
        return False, remaining_repairs
    pairs: list[object] = list(_dynamic_sequence_8616(getattr(node, "condition_and_nodes", ())))
    if len(pairs) < 2:
        return False, remaining_repairs
    for break_idx, break_pair in enumerate(tuple(pairs)):
        if not isinstance(break_pair, tuple) or len(break_pair) < 2:
            continue
        break_cond, break_body = break_pair[0], break_pair[1]
        if not _body_is_single_break_8616(break_body):
            continue
        for guarded_idx, guarded_pair in enumerate(tuple(pairs)):
            if not isinstance(guarded_pair, tuple) or len(guarded_pair) < 2:
                continue
            guarded_cond, guarded_body = guarded_pair[0], guarded_pair[1]
            if guarded_idx == break_idx or _body_is_single_break_8616(guarded_body):
                continue
            if not _conditions_are_complementary_8616(break_cond, guarded_cond):
                continue
            del pairs[break_idx]
            cast(Any, node).condition_and_nodes = pairs
            remaining_repairs -= 1
            stats.record(ConditionalContinueRepairDecision8616.MATERIALIZED)
            return True, remaining_repairs
    return False, remaining_repairs


def _repair_hoisted_jcc_target_copy_in_node_8616(
    node: object,
    evidence: tuple[HoistedJccTargetCopyEvidence8616, ...],
    stats: HoistedJccTargetCopyRepairStats8616,
) -> bool:
    changed = False
    if isinstance(node, CStatements):
        raw_statements: list[object] = list(_dynamic_sequence_8616(node.statements))
        statements, _flattened_wrappers = _flatten_direct_statement_wrappers_8616(raw_statements)
        idx = 0
        while idx < len(statements):
            stmt = statements[idx]
            if isinstance(stmt, CIfElse):
                decision, removed_index = _try_repair_displaced_jcc_target_copy_8616(
                    statements,
                    idx,
                    stmt,
                    evidence,
                )
                stats.record(decision)
                if decision is HoistedJccTargetCopyRepairDecision8616.MATERIALIZED:
                    changed = True
                    if removed_index is not None and removed_index < idx:
                        idx -= 1
                    idx += 1
                    continue
            child_changed = _repair_hoisted_jcc_target_copy_in_node_8616(stmt, evidence, stats)
            changed = child_changed or changed
            idx += 1
        if changed:
            node.statements = statements
        return changed
    if isinstance(node, (CForLoop, CWhileLoop, CDoWhileLoop)):
        body = node.body
        if isinstance(body, CStatements):
            return _repair_hoisted_jcc_target_copy_in_node_8616(body, evidence, stats)
        return False
    if isinstance(node, CIfElse):
        local_changed = False
        pairs = _dynamic_sequence_8616(node.condition_and_nodes)
        for pair in pairs:
            if not isinstance(pair, tuple) or len(pair) < 2:
                continue
            body = pair[1]
            local_changed = _repair_hoisted_jcc_target_copy_in_node_8616(body, evidence, stats) or local_changed
        else_node = node.else_node
        local_changed = _repair_hoisted_jcc_target_copy_in_node_8616(else_node, evidence, stats) or local_changed
        return local_changed
    return False


def _try_repair_displaced_jcc_target_copy_8616(
    statements: list[object],
    if_index: int,
    if_stmt: CIfElse,
    evidence: tuple[HoistedJccTargetCopyEvidence8616, ...],
) -> tuple[HoistedJccTargetCopyRepairDecision8616, int | None]:
    """Move one uniquely proven sibling copy into its JCC target body."""
    condition, body = _single_ifelse_pair_8616(if_stmt)
    if condition is None or body is None:
        return HoistedJccTargetCopyRepairDecision8616.REFUSED_NO_MATCHING_IF, None
    matched_evidence = _evidence_for_if_body_8616(condition, body, evidence)
    if matched_evidence is None:
        return HoistedJccTargetCopyRepairDecision8616.REFUSED_NO_MATCHING_IF, None
    if not _node_has_ins_addr_in_window_8616(body, matched_evidence.body_target, 0x40):
        return HoistedJccTargetCopyRepairDecision8616.REFUSED_BODY_TARGET_UNPROVEN, None

    candidate_indices: list[int] = []
    for idx, stmt in enumerate(statements):
        if idx == if_index:
            continue
        if _assignment_matches_hoisted_jcc_target_copy_8616(stmt, matched_evidence):
            candidate_indices.append(idx)
            continue
        stmt = statements[idx]
        if os.environ.get("INERTIA_DEBUG_HOISTED_JCC_TARGET_COPY_REPAIR_VERBOSE") and isinstance(stmt, CAssignment):
            log.warning(
                "[hoisted-jcc-target-copy-repair] candidate idx=%d side=%s lhs_disp=%r rhs_disps=%r ins=%r target=%#x copy=%#x expr=%s",
                idx,
                "before" if idx < if_index else "after",
                _assignment_lhs_stack_offset_8616(stmt),
                sorted(_stack_offsets_read_8616(stmt.rhs)),
                sorted(_node_ins_addrs_8616(stmt)),
                matched_evidence.body_target,
                matched_evidence.copy_addr,
                _debug_c_expr_string_8616(stmt),
            )
    if not candidate_indices:
        return HoistedJccTargetCopyRepairDecision8616.REFUSED_NO_HOISTED_COPY, None
    if len(candidate_indices) != 1:
        return HoistedJccTargetCopyRepairDecision8616.REFUSED_AMBIGUOUS_COPY, None
    candidate_index = candidate_indices[0]

    candidate = statements.pop(candidate_index)
    if isinstance(body, CStatements):
        body.statements = [candidate, *list(body.statements or ())]
    else:
        cast(Any, if_stmt).condition_and_nodes = [
            (condition, CStatements([candidate, body], codegen=getattr(if_stmt, "codegen", None)))
        ]
    return HoistedJccTargetCopyRepairDecision8616.MATERIALIZED, candidate_index


def _evidence_for_if_body_8616(
    condition: object,
    body: object,
    evidence: tuple[HoistedJccTargetCopyEvidence8616, ...],
) -> HoistedJccTargetCopyEvidence8616 | None:
    branch_addr = _condition_branch_addr_8616(condition)
    if isinstance(branch_addr, int):
        for item in evidence:
            if item.branch_addr == branch_addr and _node_has_ins_addr_in_window_8616(body, item.body_target, 0x40):
                return item
        return None
    body_matches = tuple(item for item in evidence if _node_has_ins_addr_in_window_8616(body, item.body_target, 0x40))
    if len(body_matches) == 1:
        return body_matches[0]
    return None


def _single_ifelse_pair_8616(node: CIfElse) -> tuple[object | None, object | None]:
    if getattr(node, "else_node", None) is not None:
        return None, None
    pairs = _dynamic_sequence_8616(getattr(node, "condition_and_nodes", ()))
    if len(pairs) != 1:
        return None, None
    pair = pairs[0]
    if not isinstance(pair, tuple) or len(pair) < 2:
        return None, None
    return pair[0], pair[1]


def _condition_branch_addr_8616(condition: object) -> int | None:
    """Return the tagged branch instruction address for structuring evidence matching."""
    for node in _iter_node_and_children_8616(condition):
        tags = getattr(node, "tags", None)
        if not isinstance(tags, dict):
            continue
        ins_addr = tags.get("ins_addr")
        if isinstance(ins_addr, int):
            return int(ins_addr)
    return None


def _assignment_matches_hoisted_jcc_target_copy_8616(
    stmt: object,
    evidence: HoistedJccTargetCopyEvidence8616,
) -> bool:
    if not isinstance(stmt, CAssignment):
        return False
    has_exact_copy_tag = _node_has_ins_addr_8616(stmt, evidence.copy_addr)
    has_target_window_tag = _node_has_ins_addr_in_window_8616(stmt, evidence.body_target, 0x20)
    if not has_exact_copy_tag and not has_target_window_tag:
        return False
    if _node_contains_call_8616(stmt):
        return False
    if _assignment_lhs_stack_offset_8616(stmt) != evidence.dest_disp:
        return False
    return evidence.src_disp in _stack_offsets_read_8616(stmt.rhs)


def _node_has_ins_addr_8616(node: object, target_addr: int) -> bool:
    return _node_has_ins_addr_in_window_8616(node, int(target_addr), 0)


def _node_has_ins_addr_in_window_8616(node: object, start_addr: int, max_forward_bytes: int) -> bool:
    if node is None:
        return False
    for current in _iter_node_and_children_8616(node):
        tags = getattr(current, "tags", None)
        if not isinstance(tags, dict):
            continue
        ins_addr = tags.get("ins_addr")
        if not isinstance(ins_addr, int):
            continue
        if ins_addr == start_addr:
            return True
        if max_forward_bytes > 0 and int(start_addr) <= ins_addr <= int(start_addr) + int(max_forward_bytes):
            return True
    return False


def _node_ins_addrs_8616(node: object) -> frozenset[int]:
    addrs: set[int] = set()
    for current in _iter_node_and_children_8616(node):
        tags = getattr(current, "tags", None)
        if not isinstance(tags, dict):
            continue
        ins_addr = tags.get("ins_addr")
        if isinstance(ins_addr, int):
            addrs.add(int(ins_addr))
    return frozenset(addrs)


def _node_contains_call_8616(node: object) -> bool:
    return any(isinstance(current, CFunctionCall) for current in _iter_node_and_children_8616(node))


def _node_contains_effectful_call_8616(node: object) -> bool:
    for current in _iter_node_and_children_8616(node):
        if not isinstance(current, CFunctionCall):
            continue
        if _pure_memory_helper_call_name_8616(current) is not None:
            continue
        return True
    return False


def _pure_memory_helper_call_name_8616(node: CFunctionCall) -> str | None:
    callee = getattr(node, "callee", None)
    name = callee if isinstance(callee, str) else None
    if name is None:
        target = getattr(node, "target", None)
        name = target if isinstance(target, str) else None
    if name is None:
        target = getattr(node, "callee_target", None)
        name = target if isinstance(target, str) else None
    if name is None:
        func = getattr(node, "function", None) or getattr(node, "callee_func", None)
        name = getattr(func, "name", None) if func is not None else None
    if not isinstance(name, str):
        return None
    if name.startswith(("SEG_U", "MEM_U")) or name in {"MK_FP", "SEG_PTR"}:
        return name
    return None


def _body_is_single_loop_exit_8616(body: object) -> bool:
    if isinstance(body, CBreak):
        return True
    if _is_void_return_8616(body):
        return True
    if not isinstance(body, CStatements):
        return False
    statements = tuple(body.statements or ())
    return len(statements) == 1 and (isinstance(statements[0], CBreak) or _is_void_return_8616(statements[0]))


def _body_is_single_break_8616(body: object) -> bool:
    return _body_is_single_loop_exit_8616(body)


def _ifelse_body_is_single_return_8616(node: object) -> bool:
    """Return whether a single-arm if contains exactly one return statement."""
    if not isinstance(node, CIfElse):
        return False
    pairs = _dynamic_sequence_8616(node.condition_and_nodes)
    if len(pairs) != 1 or not isinstance(pairs[0], tuple) or len(pairs[0]) < 2:
        return False
    body = pairs[0][1]
    if isinstance(body, CReturn):
        return True
    if not isinstance(body, CStatements):
        return False
    statements = _dynamic_sequence_8616(body.statements)
    return len(statements) == 1 and isinstance(statements[0], CReturn)


def _is_void_return_8616(node: object) -> bool:
    return isinstance(node, CReturn) and getattr(node, "retval", None) is None


def _flatten_direct_statement_wrappers_8616(statements: list[object]) -> tuple[list[object], bool]:
    flattened: list[object] = []
    changed = False
    for stmt in statements:
        if isinstance(stmt, CStatements):
            children = list(stmt.statements or ())
            if len(children) != 1:
                flattened.append(stmt)
                continue
            flattened.extend(children)
            changed = True
            continue
        flattened.append(stmt)
    return flattened, changed


def _ifbreak_condition_8616(node: object) -> object | None:
    if isinstance(node, CIfBreak):
        return cast(object, node.condition)
    if not isinstance(node, CIfElse):
        return None
    if node.else_node is not None:
        return None
    condition_and_nodes = _dynamic_sequence_8616(node.condition_and_nodes)
    if len(condition_and_nodes) != 1:
        return None
    pair = condition_and_nodes[0]
    if not isinstance(pair, tuple) or len(pair) < 2:
        return None
    condition = pair[0]
    body = pair[1]
    if isinstance(body, CBreak) or _is_void_return_8616(body):
        return cast(object, condition)
    if not isinstance(body, CStatements):
        return None
    statements = _dynamic_sequence_8616(body.statements)
    if len(statements) == 1 and (isinstance(statements[0], CBreak) or _is_void_return_8616(statements[0])):
        return cast(object, condition)
    return None


def _single_ifelse_condition_8616(node: object) -> object | None:
    if not isinstance(node, CIfElse):
        return None
    if node.else_node is not None:
        return None
    condition_and_nodes = _dynamic_sequence_8616(node.condition_and_nodes)
    if len(condition_and_nodes) != 1:
        return None
    pair = condition_and_nodes[0]
    if not isinstance(pair, tuple) or len(pair) < 2:
        return None
    return cast(object, pair[0])


def _conditions_are_complementary_8616(left: object, right: object) -> bool:
    if not isinstance(left, CBinaryOp) or not isinstance(right, CBinaryOp):
        return False
    if (getattr(left, "op", None), getattr(right, "op", None)) not in _COMPLEMENTARY_COMPARISONS_8616:
        if os.environ.get("INERTIA_DEBUG_CONDITIONAL_CONTINUE_REPAIR_VERBOSE"):
            log.warning(
                "[conditional-continue-repair] non-complementary ops left=%s right=%s left_expr=%s right_expr=%s",
                getattr(left, "op", None),
                getattr(right, "op", None),
                _debug_c_expr_string_8616(left),
                _debug_c_expr_string_8616(right),
            )
        return False
    left_lhs = getattr(left, "lhs", None)
    left_rhs = getattr(left, "rhs", None)
    right_lhs = getattr(right, "lhs", None)
    right_rhs = getattr(right, "rhs", None)
    same_operands = _same_c_expression_8616(left_lhs, right_lhs) and _same_c_expression_8616(
        left_rhs,
        right_rhs,
    )
    if not same_operands and os.environ.get("INERTIA_DEBUG_CONDITIONAL_CONTINUE_REPAIR_VERBOSE"):
        log.warning(
            "[conditional-continue-repair] complementary op operand mismatch left=%s right=%s left_lhs=%s right_lhs=%s left_rhs=%s right_rhs=%s",
            getattr(left, "op", None),
            getattr(right, "op", None),
            _debug_c_expr_string_8616(left_lhs),
            _debug_c_expr_string_8616(right_lhs),
            _debug_c_expr_string_8616(left_rhs),
            _debug_c_expr_string_8616(right_rhs),
        )
    return bool(same_operands)


def _debug_c_expr_string_8616(expr: object) -> str:
    if expr is None:
        return "<none>"
    try:
        return str(cast(Any, expr).c_repr())
    except Exception:
        return repr(expr)


def _cfunc_roots_8616(cfunc: object) -> tuple[object, ...]:
    roots: list[object] = []
    seen: set[int] = set()
    for attr in ("body", "statements", "stmt"):
        root = getattr(cfunc, attr, None)
        if root is None or id(root) in seen:
            continue
        roots.append(root)
        seen.add(id(root))
    return tuple(roots)


def _repair_statement_list_8616(
    node: object,
    evidence: tuple[StackAccumulatorLoopEvidence8616, ...],
    stats: LoopBodyRepairStats8616,
    codegen: object,
) -> bool:
    if not isinstance(node, CStatements):
        stats.record(LoopBodyRepairDecision8616.REFUSED_NO_STATEMENTS)
        return False
    statements: list[object] = list(_dynamic_sequence_8616(node.statements))
    if os.environ.get("INERTIA_DEBUG_LOOP_BODY_REPAIR_VERBOSE"):
        log.warning(
            "[loop-body-repair] root=%s statements=%r",
            type(node).__name__,
            tuple(type(stmt).__name__ for stmt in statements),
        )
    changed = False
    idx = 0
    while idx < len(statements):
        stmt = statements[idx]
        if isinstance(stmt, CStatements):
            changed = _repair_statement_list_8616(stmt, evidence, stats, codegen) or changed
            idx += 1
            continue
        for attr in ("body", "else_node"):
            child = getattr(stmt, attr, None)
            if isinstance(child, CStatements):
                changed = _repair_statement_list_8616(child, evidence, stats, codegen) or changed
        if not isinstance(stmt, (CForLoop, CWhileLoop)):
            idx += 1
            continue
        decision, inserted = _try_repair_loop_at_8616(statements, idx, evidence, codegen)
        stats.record(decision)
        if decision is LoopBodyRepairDecision8616.MATERIALIZED:
            changed = True
            idx += 1 + int(inserted)
            continue
        idx += 1
    if changed:
        cast(Any, node).statements = statements
    return changed


def _try_repair_loop_at_8616(
    statements: list[object],
    loop_index: int,
    evidence: tuple[StackAccumulatorLoopEvidence8616, ...],
    codegen: object,
) -> tuple[LoopBodyRepairDecision8616, bool]:
    loop = statements[loop_index]
    body = getattr(loop, "body", None)
    if not _body_semantically_empty_8616(body):
        if isinstance(body, CStatements):
            init_decision = _try_insert_missing_accumulator_init_8616(statements, loop_index, body, evidence, codegen)
            if init_decision is LoopBodyRepairDecision8616.MATERIALIZED:
                return init_decision, True
        if os.environ.get("INERTIA_DEBUG_LOOP_BODY_REPAIR_VERBOSE"):
            raw_body_statements = tuple(getattr(body, "statements", ()) or ()) if isinstance(body, CStatements) else ()
            log.warning(
                "[loop-body-repair] refused nonempty body_type=%s child_types=%r",
                type(body).__name__,
                tuple(type(child).__name__ for child in raw_body_statements),
            )
        return LoopBodyRepairDecision8616.REFUSED_NONEMPTY_BODY, False
    following_update = _next_assignment_after_loop_8616(statements, loop_index)
    if following_update is None:
        return LoopBodyRepairDecision8616.REFUSED_NO_FOLLOWING_UPDATE, False
    update_container, update_index, update_stmt = following_update
    loop_induction_disp = _loop_induction_disp_8616(loop)
    update_accumulator_disp = _stack_offset_8616(getattr(update_stmt, "lhs", None))
    update_read_disps = _stack_offsets_read_8616(getattr(update_stmt, "rhs", None))
    if loop_induction_disp is None or update_accumulator_disp is None:
        return LoopBodyRepairDecision8616.REFUSED_SLOT_MISMATCH, False
    matched = None
    for item in evidence:
        if (
            item.induction_disp == loop_induction_disp
            and item.accumulator_disp == update_accumulator_disp
            and item.accumulator_disp in update_read_disps
            and item.induction_disp in update_read_disps
        ):
            matched = item
            break
    if matched is None:
        return LoopBodyRepairDecision8616.REFUSED_SLOT_MISMATCH, False

    if not isinstance(body, CStatements):
        body = CStatements([], codegen=codegen)
        cast(Any, loop).body = body
    cast(Any, body).statements = [update_stmt]
    del update_container[update_index]
    if update_container is not statements and not update_container:
        del statements[loop_index + 1]
    inserted = False
    if matched.accumulator_zero_initialized and not _preceded_by_zero_init_8616(
        statements,
        loop_index,
        matched.accumulator_disp,
    ):
        lhs = getattr(update_stmt, "lhs", None)
        zero = CConstant(0, getattr(lhs, "variable_type", None) or SimTypeShort(False), codegen=codegen)
        statements.insert(loop_index, CAssignment(lhs, zero, codegen=codegen))
        inserted = True
    return LoopBodyRepairDecision8616.MATERIALIZED, inserted


def _try_insert_missing_accumulator_init_8616(
    statements: list[object],
    loop_index: int,
    body: CStatements,
    evidence: tuple[StackAccumulatorLoopEvidence8616, ...],
    codegen: object,
) -> LoopBodyRepairDecision8616:
    body_statements = tuple(getattr(body, "statements", ()) or ())
    if not body_statements or not isinstance(body_statements[0], CAssignment):
        return LoopBodyRepairDecision8616.REFUSED_NONEMPTY_BODY
    loop = statements[loop_index]
    loop_induction_disp = _loop_induction_disp_8616(loop)
    update_stmt = body_statements[0]
    accumulator_disp = _stack_offset_8616(getattr(update_stmt, "lhs", None))
    update_read_disps = _stack_offsets_read_8616(getattr(update_stmt, "rhs", None))
    if loop_induction_disp is None or accumulator_disp is None:
        return LoopBodyRepairDecision8616.REFUSED_SLOT_MISMATCH
    matched = None
    for item in evidence:
        if (
            item.induction_disp == loop_induction_disp
            and item.accumulator_disp == accumulator_disp
            and item.accumulator_disp in update_read_disps
            and item.induction_disp in update_read_disps
        ):
            matched = item
            break
    if matched is None or not matched.accumulator_zero_initialized:
        return LoopBodyRepairDecision8616.REFUSED_SLOT_MISMATCH
    if _preceded_by_zero_init_8616(statements, loop_index, matched.accumulator_disp):
        return LoopBodyRepairDecision8616.REFUSED_NONEMPTY_BODY
    lhs = getattr(update_stmt, "lhs", None)
    zero = CConstant(0, getattr(lhs, "variable_type", None) or SimTypeShort(False), codegen=codegen)
    statements.insert(loop_index, CAssignment(lhs, zero, codegen=codegen))
    return LoopBodyRepairDecision8616.MATERIALIZED


def _next_assignment_after_loop_8616(
    statements: list[object],
    loop_index: int,
) -> tuple[list[object], int, CAssignment] | None:
    if loop_index + 1 >= len(statements):
        return None
    direct = statements[loop_index + 1]
    if isinstance(direct, CAssignment):
        return statements, loop_index + 1, direct
    if isinstance(direct, CStatements):
        children: list[object] = list(_dynamic_sequence_8616(direct.statements))
        if children and isinstance(children[0], CAssignment):
            first = children[0]
            cast(Any, direct).statements = children
            return children, 0, first
    return None


def _body_semantically_empty_8616(body: object) -> bool:
    if body is None:
        return True
    if not isinstance(body, CStatements):
        return False
    return all(_body_semantically_empty_8616(child) for child in tuple(body.statements or ()))


def _loop_induction_disp_8616(loop: object) -> int | None:
    for attr in ("initializer", "init", "iterator", "iteration"):
        assignment = getattr(loop, attr, None)
        disp = _assignment_lhs_stack_offset_8616(assignment)
        if isinstance(disp, int) and disp < 0:
            return disp
    return None


def _assignment_lhs_stack_offset_8616(node: object) -> int | None:
    return _stack_offset_8616(getattr(node, "lhs", None)) if isinstance(node, CAssignment) else None


def _stack_offset_8616(node: object) -> int | None:
    if not isinstance(node, CVariable):
        return None
    variable = node.variable
    if not isinstance(variable, SimStackVariable) or getattr(variable, "base", None) != "bp":
        return None
    offset = getattr(variable, "offset", None)
    return offset if isinstance(offset, int) else None


def _stack_offsets_read_8616(node: object) -> frozenset[int]:
    offsets: set[int] = set()
    for child in _iter_c_nodes_deep_8616(node):
        offset = _stack_offset_8616(child)
        if isinstance(offset, int):
            offsets.add(offset)
    return frozenset(offsets)


def _preceded_by_zero_init_8616(statements: list[object], loop_index: int, accumulator_disp: int) -> bool:
    if loop_index <= 0:
        return False
    previous = statements[loop_index - 1]
    if not isinstance(previous, CAssignment):
        return False
    if _assignment_lhs_stack_offset_8616(previous) != accumulator_disp:
        return False
    rhs = previous.rhs
    return isinstance(rhs, CConstant) and getattr(rhs, "value", None) == 0
