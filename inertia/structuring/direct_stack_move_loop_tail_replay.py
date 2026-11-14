# cython: language_level=3, infer_types=True
"""Replay binary-proven direct stack moves at structured loop tails.

Layer: Structuring.
Responsibility: restore unique CFG-proven loop-tail ownership after angr
regenerates the structured C AST and loses earlier placement mutations.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol, cast

from inertia.lowering.real_mode_linear import DirectStackMoveFact8616

from .direct_stack_move_loop_sites import (
    DirectStackMoveAssignmentLocation8616,
    tagged_assignment_locations_8616,
)
from .direct_stack_move_loops import (
    direct_stack_move_has_loop_tail_edge_8616,
    place_direct_stack_move_loop_tail_assignment_8616,
)
from .direct_stack_move_ownership import (
    direct_stack_move_branch_owned_addresses_8616,
)
import dataclasses
import operator


@dataclasses.dataclass(frozen=True, )
class DirectStackMoveLoopTailReplayStats8616:
    """Closed evidence census for regenerated loop-tail assignments."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong
    moved_count: cython.longlong
    already_materialized_count: cython.longlong
    refused_branch_owner_count: cython.longlong


class _StructuredFunctionBoundary8616(Protocol):
    """Third-party angr structured-function fields consumed by replay."""

    statements: object | None


class _CodegenBoundary8616(Protocol):
    """Third-party angr codegen plus Inertia-owned replay evidence fields."""

    cfunc: _StructuredFunctionBoundary8616 | None
    _inertia_direct_stack_move_facts_8616: Iterable[object]
    _inertia_direct_stack_move_loop_tail_replay_8616: DirectStackMoveLoopTailReplayStats8616


def materialize_direct_stack_move_loop_tail_ownership_8616(
    project: object,
    codegen: object,
    function: object,
) -> cython.bint:
    """Move unique regenerated assignments to their unique proven loop tail."""
    cfunc: object
    root: object
    fact: object
    codegen_boundary = cast(_CodegenBoundary8616, codegen)
    try:
        cfunc = codegen_boundary.cfunc
    except AttributeError:
        cfunc = None
    root = cfunc.statements if cfunc is not None else None
    try:
        raw_facts = codegen_boundary._inertia_direct_stack_move_facts_8616
    except AttributeError:
        raw_facts = ()
    facts = tuple(fact for fact in iter(raw_facts) if isinstance(fact, DirectStackMoveFact8616))
    normalized_count = 0
    classified_count = 0
    materialized_count = 0
    failure_count = 0
    moved_count = 0
    already_count = 0
    refused_branch_owner_count = 0
    branch_owned = direct_stack_move_branch_owned_addresses_8616(
        project,
        codegen,
        function,
    )
    for fact in facts:
        if fact.ins_addr in branch_owned:
            refused_branch_owner_count += 1
            continue
        if not direct_stack_move_has_loop_tail_edge_8616(
            project,
            function,
            fact.ins_addr,
        ):
            continue
        normalized_count += 1
        locations: object = (
            tagged_assignment_locations_8616(project, codegen, root, fact)
            if root is not None
            else ()
        )
        if len(locations) != 1:
            failure_count += int(len(locations) > 1)
            continue
        location = locations[0]
        original_owner = location.statements
        original_index = location.index
        if not place_direct_stack_move_loop_tail_assignment_8616(
            project,
            codegen,
            function,
            fact,
            location.assignment,
            branch_owned_addresses=branch_owned,
        ):
            continue
        classified_count += 1
        materialized_count += 1
        relocated = tagged_assignment_locations_8616(project, codegen, root, fact)
        moved = bool(
            len(relocated) == 1
            and (
                relocated[0].statements is not original_owner
                or operator.ne(relocated[0].index, original_index)
            )
        )
        moved_count += int(moved)
        already_count += int(not moved)
    stats = DirectStackMoveLoopTailReplayStats8616(
        raw_fact_count=len(facts),
        normalized_fact_count=normalized_count,
        classified_fact_count=classified_count,
        materialized_count=materialized_count,
        failure_count=failure_count,
        moved_count=moved_count,
        already_materialized_count=already_count,
        refused_branch_owner_count=refused_branch_owner_count,
    )
    codegen_boundary._inertia_direct_stack_move_loop_tail_replay_8616 = stats
    return moved_count > 0
