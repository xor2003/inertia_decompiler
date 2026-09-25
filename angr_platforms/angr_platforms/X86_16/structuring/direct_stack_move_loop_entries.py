"""Place binary-proven stack moves at their owning structured loop entry.

Layer: Structuring.
Responsibility: join typed direct-stack-move facts to exact machine loopback
edges and restore assignments at the unique enclosing posttest-loop entry.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
Lowering owns the assignment value and storage identity; this module owns only
structured control-flow placement. It never uses rendered C, symbols, source
text, or variable names as evidence.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c

from ..lowering.real_mode_linear import (
    DirectStackMoveFact8616,
    DirectStackMoveSourceKind8616,
)
from .direct_stack_move_immediate_loop_entries import (
    classify_immediate_loop_entry_relocation_8616,
)
from .direct_stack_move_loop_evidence import (
    DirectStackMoveLoopEntryEdge8616,
    boundary_tuple_8616,
    repeated_sequence_edges_8616,
)
from .direct_stack_move_loop_sites import (
    DirectStackMoveLoopEntrySite8616,
    loop_entry_sites_8616,
    place_assignment_8616,
    tagged_assignment_locations_8616,
)
from .direct_stack_move_ownership import (
    DirectStackMoveControlClaim8616,
    direct_stack_move_branch_claims_8616,
    direct_stack_move_loop_entry_supersedes_branch_claim_8616,
)
from .direct_stack_move_pretest_body import (
    materialize_direct_stack_move_pretest_body_ownership_8616,
    place_direct_stack_move_pretest_body_assignment_8616,
)
from .direct_stack_move_pretest_initializers import (
    materialize_direct_stack_move_pretest_initializers_8616,
    place_direct_stack_move_pretest_initializer_assignment_8616,
)

log: logging.Logger = logging.getLogger(__name__)

_LOOP_ENTRY_SOURCE_KINDS_8616 = frozenset(
    {
        DirectStackMoveSourceKind8616.IMMEDIATE,
        DirectStackMoveSourceKind8616.STACK_SLOT,
        DirectStackMoveSourceKind8616.STACK_SLOT_EXPR,
        DirectStackMoveSourceKind8616.STACK_SLOT_BINARY_EXPR,
        DirectStackMoveSourceKind8616.STACK_AGGREGATE_ELEMENT,
    }
)


@dataclass(frozen=True, slots=True)
class DirectStackMoveLoopEntryStats8616:
    """Closed evidence counters for loop-entry placement."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    already_materialized_count: int
    refused_no_edge_count: int
    refused_no_site_count: int
    refused_assignment_count: int
    refused_branch_owner_count: int
    refused_immediate_scope_count: int


def place_direct_stack_move_loop_entry_assignment_8616(
    project: object,
    codegen: object,
    function: object,
    move_fact: DirectStackMoveFact8616,
    assignment: structured_c.CAssignment,
) -> bool:
    """Place one Lowering-built assignment at its unique posttest-loop entry."""
    branch_claims = tuple(
        claim
        for claim in direct_stack_move_branch_claims_8616(project, codegen, function)
        if claim.move_ins_addr == move_fact.ins_addr
    )
    codegen_contract = cast(Any, codegen)
    root = codegen_contract.cfunc.statements
    edges = repeated_sequence_edges_8616(project, function, move_fact.ins_addr)
    if branch_claims and not (
        len(branch_claims) == 1
        and len(edges) == 1
        and direct_stack_move_loop_entry_supersedes_branch_claim_8616(
            branch_claims[0],
            edges[0],
        )
    ):
        return False
    sites: tuple[DirectStackMoveLoopEntrySite8616, ...] = (
        loop_entry_sites_8616(
            project,
            codegen,
            root,
            edges[0],
            move_fact.dst_offset,
            function=function,
        )
        if root is not None and len(edges) == 1
        else ()
    )
    locations = (
        tagged_assignment_locations_8616(project, codegen, root, move_fact)
        if root is not None
        else ()
    )
    if len(locations) > 1:
        return False
    location = locations[0] if locations else None
    owned_assignment = location.assignment if location is not None else assignment
    materialized = False
    if len(sites) == 1:
        materialized, _already = place_assignment_8616(
            project,
            codegen,
            sites[0],
            move_fact,
            owned_assignment,
            location,
        )
    if materialized:
        return True
    if place_direct_stack_move_pretest_body_assignment_8616(
        project,
        codegen,
        function,
        move_fact,
        assignment,
    ):
        return True
    return bool(
        place_direct_stack_move_pretest_initializer_assignment_8616(
            project,
            codegen,
            function,
            move_fact,
            assignment,
        )
    )


@dataclass(slots=True)
class _LoopEntryScan8616:
    """Mutable per-fact loop-entry placement scan state."""

    project: object
    codegen: object
    function: object
    root: object
    normalized: int = 0
    classified: int = 0
    materialized: int = 0
    failures: int = 0
    already_materialized: int = 0
    refused_no_edge: int = 0
    refused_no_site: int = 0
    refused_assignment: int = 0
    refused_branch_owner: int = 0
    refused_immediate_scope: int = 0
    changed: bool = False

    def process(
        self,
        move_fact: DirectStackMoveFact8616,
        move_branch_claims: tuple[DirectStackMoveControlClaim8616, ...],
    ) -> None:
        """Apply the loop-entry gate ladder to one move fact."""
        edges = repeated_sequence_edges_8616(self.project, self.function, move_fact.ins_addr)
        if move_branch_claims and not (
            len(move_branch_claims) == 1
            and len(edges) == 1
            and direct_stack_move_loop_entry_supersedes_branch_claim_8616(
                move_branch_claims[0],
                edges[0],
            )
        ):
            self.refused_branch_owner += 1
            return
        debug_loop_entry = os.environ.get("INERTIA_DEBUG_STACK_LOOP_ENTRY") == "1"
        if not edges:
            self.refused_no_edge += 1
            if debug_loop_entry:
                log.warning("[direct-stack-move-loop-entry] move=%#x no-edge", move_fact.ins_addr)
            return
        self.normalized += 1
        if len(edges) != 1 or self.root is None:
            self.failures += 1
            if debug_loop_entry:
                log.warning(
                    "[direct-stack-move-loop-entry] move=%#x edge-count=%d",
                    move_fact.ins_addr,
                    len(edges),
                )
            return
        self._resolve_and_place(move_fact, edges[0], debug_loop_entry)

    def _resolve_and_place(
        self,
        move_fact: DirectStackMoveFact8616,
        edge: DirectStackMoveLoopEntryEdge8616,
        debug_loop_entry: bool,
    ) -> None:
        """Resolve site/location/verdict gates, then place the assignment."""
        sites = loop_entry_sites_8616(
            self.project,
            self.codegen,
            self.root,
            edge,
            move_fact.dst_offset,
            function=self.function,
        )
        if len(sites) != 1:
            self.refused_no_site += 1
            self.failures += int(len(sites) > 1)
            if debug_loop_entry:
                log.warning(
                    "[direct-stack-move-loop-entry] move=%#x site-count=%d edge=%r",
                    move_fact.ins_addr,
                    len(sites),
                    edge,
                )
            return
        locations = tagged_assignment_locations_8616(self.project, self.codegen, self.root, move_fact)
        if len(locations) != 1:
            self.refused_assignment += 1
            self.failures += int(len(locations) > 1)
            if debug_loop_entry:
                log.warning(
                    "[direct-stack-move-loop-entry] move=%#x assignment-count=%d",
                    move_fact.ins_addr,
                    len(locations),
                )
            return
        immediate_verdict = classify_immediate_loop_entry_relocation_8616(
            self.root,
            sites[0],
            move_fact,
            edge,
            locations[0],
        )
        if not immediate_verdict.permits_relocation:
            self.refused_immediate_scope += 1
            if debug_loop_entry:
                log.warning(
                    "[direct-stack-move-loop-entry] move=%#x immediate-verdict=%s",
                    move_fact.ins_addr,
                    immediate_verdict.name,
                )
            return
        self.classified += 1
        placed, already = place_assignment_8616(
            self.project,
            self.codegen,
            sites[0],
            move_fact,
            locations[0].assignment,
            locations[0],
        )
        if not placed:
            self.failures += 1
            return
        self.materialized += 1
        self.already_materialized += int(already)
        self.changed = self.changed or not already


def materialize_direct_stack_move_loop_entry_ownership_8616(
    project: object,
    codegen: object,
    function: object,
) -> bool:
    """Relocate tagged stack assignments to CFG-proven posttest-loop entries."""
    codegen_contract = cast(Any, codegen)
    try:
        root = codegen_contract.cfunc.statements
        direct_move_facts = codegen_contract._inertia_direct_stack_move_facts_8616
    except AttributeError:
        return False
    move_facts = tuple(
        fact
        for fact in boundary_tuple_8616(direct_move_facts or ())
        if isinstance(fact, DirectStackMoveFact8616)
        and fact.source_kind in _LOOP_ENTRY_SOURCE_KINDS_8616
    )
    scan = _LoopEntryScan8616(project, codegen, function, root)
    branch_claims = direct_stack_move_branch_claims_8616(
        project,
        codegen,
        function,
    )
    for move_fact in sorted(move_facts, key=lambda fact: fact.ins_addr):
        move_branch_claims = tuple(
            claim
            for claim in branch_claims
            if claim.move_ins_addr == move_fact.ins_addr
        )
        scan.process(move_fact, move_branch_claims)
    stats = DirectStackMoveLoopEntryStats8616(
        raw_fact_count=len(move_facts),
        normalized_fact_count=scan.normalized,
        classified_fact_count=scan.classified,
        materialized_count=scan.materialized,
        failure_count=scan.failures,
        already_materialized_count=scan.already_materialized,
        refused_no_edge_count=scan.refused_no_edge,
        refused_no_site_count=scan.refused_no_site,
        refused_assignment_count=scan.refused_assignment,
        refused_branch_owner_count=scan.refused_branch_owner,
        refused_immediate_scope_count=scan.refused_immediate_scope,
    )
    changed = scan.changed
    cast(Any, codegen)._inertia_direct_stack_move_loop_entry_placement_8616 = stats
    if os.environ.get("INERTIA_DEBUG_STACK_NOISE") or os.environ.get(
        "INERTIA_DEBUG_STACK_LOOP_ENTRY"
    ):
        log.warning("[direct-stack-move-loop-entry] stats=%r", stats)
    return (
        materialize_direct_stack_move_pretest_body_ownership_8616(
            project,
            codegen,
            function,
        )
        or
        materialize_direct_stack_move_pretest_initializers_8616(
            project,
            codegen,
            function,
        )
        or changed
    )
