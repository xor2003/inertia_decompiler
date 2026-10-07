"""Arbitrate typed control-flow ownership for direct stack moves.

Layer: Structuring.
Responsibility: expose branch ownership already proven by ConditionIR and exact
CFG targets so broader loop placement services cannot steal the same move.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
Do not recover values, aliases, widths, types, or semantics here. Lowering owns
the assignment; this module only ranks competing structured control owners.

Conditional-arm ownership is narrower than an enclosing loop, while a loop
fully contained in the arm is narrower than that arm. A failed or overlapping
join must keep the move in place instead of silently broadening its execution.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Any, cast

from inertia.ir.condition_ir import ConditionIR
from inertia.lowering.real_mode_linear import DirectStackMoveFact8616

from .direct_stack_move_branches import (
    DirectStackMoveBranchFact8616,
    direct_stack_move_instruction_targets_8616,
    recover_direct_stack_move_branch_facts_8616,
)
from .direct_stack_move_loop_evidence import DirectStackMoveLoopEntryEdge8616


class DirectStackMoveControlOwner8616(Enum):
    """A proven structured control owner ordered from narrow to broad."""

    CONDITIONAL_BRANCH = "conditional_branch"


@dataclass(frozen=True, slots=True)
class DirectStackMoveControlClaim8616:
    """One typed claim that prevents a broader owner from taking a move."""

    move_ins_addr: int
    owner: DirectStackMoveControlOwner8616
    branch_fact: DirectStackMoveBranchFact8616


def direct_stack_move_loop_entry_supersedes_branch_claim_8616(
    claim: DirectStackMoveControlClaim8616,
    edge: DirectStackMoveLoopEntryEdge8616,
) -> bool:
    """Return whether an exact repeated loop is nested in the claimed arm."""
    fact = claim.branch_fact
    return (
        claim.move_ins_addr == edge.move_addr
        and fact.arm_start <= edge.entry_addr <= edge.move_addr
        and edge.move_addr <= edge.jump_addr < fact.merge_addr
    )


def _boundary_tuple_8616(value: object) -> tuple[Any, ...]:
    """Convert one dynamic angr collection to a stable tuple."""
    return tuple(cast(Iterable[Any], value))


def direct_stack_move_branch_claims_8616(
    project: object,
    codegen: object,
    function: object,
) -> tuple[DirectStackMoveControlClaim8616, ...]:
    """Return exact conditional-arm claims for current codegen evidence.

    Dynamic boundary: codegen and function are third-party angr surfaces with
    optional evidence fields populated by earlier Inertia pipeline stages.
    """
    conditions = tuple(
        condition
        for condition in _boundary_tuple_8616(
            getattr(codegen, "_inertia_typed_conditions", ()) or ()
        )
        if isinstance(condition, ConditionIR)
    )
    move_facts = tuple(
        fact
        for fact in _boundary_tuple_8616(
            getattr(codegen, "_inertia_direct_stack_move_facts_8616", ()) or ()
        )
        if isinstance(fact, DirectStackMoveFact8616)
    )
    if not conditions or not move_facts:
        return ()
    branch_facts = recover_direct_stack_move_branch_facts_8616(
        conditions,
        move_facts,
        direct_stack_move_instruction_targets_8616(
            project,
            function,
            conditions,
        ),
    )
    return tuple(
        DirectStackMoveControlClaim8616(
            move_ins_addr=fact.move_ins_addr,
            owner=DirectStackMoveControlOwner8616.CONDITIONAL_BRANCH,
            branch_fact=fact,
        )
        for fact in branch_facts
    )


def direct_stack_move_branch_owned_addresses_8616(
    project: object,
    codegen: object,
    function: object,
) -> frozenset[int]:
    """Return move addresses claimed by a narrower conditional branch."""
    return frozenset(
        claim.move_ins_addr
        for claim in direct_stack_move_branch_claims_8616(
            project,
            codegen,
            function,
        )
    )
