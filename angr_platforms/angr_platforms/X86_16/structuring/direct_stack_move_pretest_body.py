"""Place binary-proven stack definitions inside structured pretest loops.

Layer: Structuring.
Responsibility: join exact pretest-body CFG evidence to one structured loop and
relocate an already-lowered direct stack assignment to its machine-ordered body
position.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
Lowering owns assignment values and stack identities. This pass changes only
their structured execution scope and refuses missing or ambiguous evidence.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c

from ..lowering.real_mode_linear import (
    DirectStackMoveFact8616,
    DirectStackMoveSourceKind8616,
)
from ..pipeline.errors import PipelineHardError
from .direct_stack_move_loop_evidence import (
    boundary_tuple_8616,
    comparable_address_8616,
)
from .direct_stack_move_loop_sites import (
    DirectStackMoveAssignmentLocation8616,
    DirectStackMoveLoopEntrySite8616,
    _tree_reads_stack_offset_8616,
    _tree_tag_addresses_8616,
    place_assignment_8616,
    tagged_assignment_locations_8616,
)
from .direct_stack_move_ownership import (
    direct_stack_move_branch_owned_addresses_8616,
)
from .direct_stack_move_pretest_body_evidence import (
    DirectStackMovePretestBodyEvidence8616,
    recover_direct_stack_move_pretest_body_evidence_8616,
)
from .pretest_condition_surface import pretest_condition_surface_8616

__all__ = (
    "DirectStackMovePretestBodyStats8616",
    "materialize_direct_stack_move_pretest_body_ownership_8616",
    "place_direct_stack_move_pretest_body_assignment_8616",
)

log: logging.Logger = logging.getLogger(__name__)

_PRETEST_BODY_SOURCE_KINDS_8616 = frozenset(
    {
        DirectStackMoveSourceKind8616.SEGMENTED_MEMORY,
        DirectStackMoveSourceKind8616.STACK_SLOT,
        DirectStackMoveSourceKind8616.STACK_SLOT_EXPR,
        DirectStackMoveSourceKind8616.STACK_SLOT_BINARY_EXPR,
        DirectStackMoveSourceKind8616.STACK_AGGREGATE_ELEMENT,
    }
)


@dataclass(frozen=True, slots=True)
class _DirectStackMovePretestBodySite8616:
    """One structured loop body uniquely matched to exact CFG evidence."""

    statements: list[Any]
    depth: int


@dataclass(frozen=True, slots=True)
class DirectStackMovePretestBodyStats8616:
    """Closed evidence counters for pretest-loop body placement."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    already_materialized_count: int
    refused_no_evidence_count: int
    refused_no_site_count: int
    refused_assignment_count: int
    refused_branch_owner_count: int

    @property
    def closed(self) -> bool:
        """Return whether every raw fact materialized or refused explicitly."""
        counters = (
            self.raw_fact_count,
            self.normalized_fact_count,
            self.classified_fact_count,
            self.materialized_count,
            self.failure_count,
        )
        return (
            all(counter >= 0 for counter in counters)
            and self.raw_fact_count >= self.normalized_fact_count
            and self.normalized_fact_count >= self.classified_fact_count
            and self.classified_fact_count >= self.materialized_count
            and self.raw_fact_count == self.materialized_count + self.failure_count
        )


def _ast_field_8616(
    node: object | None,
    name: str,
    default: object | None = None,
) -> object | None:
    """Read one optional field from a heterogeneous angr structured-C node."""
    # Dynamic third-party boundary: structured-codegen node fields vary by type.
    return getattr(node, name, default)


@dataclass
class _PretestBodySiteScan8616:
    """Walk owned structured nodes and collect exact pretest-loop matches."""

    project: object
    codegen: object
    evidence: DirectStackMovePretestBodyEvidence8616
    dst_offset: int
    matches: list[_DirectStackMovePretestBodySite8616] = field(default_factory=list)
    seen: set[int] = field(default_factory=set)

    def visit(self, node: object, depth: int) -> None:
        """Walk owned structured nodes and collect exact pretest-loop matches."""
        if node is None or id(node) in self.seen:
            return
        self.seen.add(id(node))
        body = _ast_field_8616(node, "body")
        statements = _ast_field_8616(body, "statements")
        if isinstance(node, (structured_c.CForLoop, structured_c.CWhileLoop)) and isinstance(
            statements,
            list,
        ):
            self._loop_match(node, body, statements, depth)
        statements_value = _ast_field_8616(node, "statements")
        if isinstance(statements_value, list):
            for statement in tuple(statements_value):
                self.visit(statement, depth + 1)
        for attr in ("body", "else_node"):
            child = _ast_field_8616(node, attr)
            if child is not None:
                self.visit(child, depth + 1)
        pairs = _ast_field_8616(node, "condition_and_nodes")
        if pairs:
            for _condition, guarded_body in boundary_tuple_8616(pairs):
                self.visit(guarded_body, depth + 1)

    def _loop_match(
        self,
        node: object,
        body: object,
        statements: list[object],
        depth: int,
    ) -> None:
        """Record one structured loop when its exact block origins match."""
        surface = pretest_condition_surface_8616(node)
        condition_tags = frozenset(
            comparable_address_8616(self.project, address, self.evidence.move_addr)
            for condition in surface.conditions
            for address in _tree_tag_addresses_8616(condition)
        )
        body_tags = frozenset(
            comparable_address_8616(self.project, address, self.evidence.move_addr)
            for address in _tree_tag_addresses_8616(body)
        )
        if (
            condition_tags & frozenset(self.evidence.header_instruction_addrs)
            and body_tags & frozenset(self.evidence.body_entry_instruction_addrs)
            and _tree_reads_stack_offset_8616(
                self.codegen, statements, self.dst_offset,
            )
        ):
            self.matches.append(
                _DirectStackMovePretestBodySite8616(statements, depth),
            )


def _pretest_body_sites_8616(
    project: object,
    codegen: object,
    root: object,
    evidence: DirectStackMovePretestBodyEvidence8616,
    dst_offset: int,
) -> tuple[_DirectStackMovePretestBodySite8616, ...]:
    """Find the unique deepest structured loop matching exact block origins."""
    scan = _PretestBodySiteScan8616(project, codegen, evidence, dst_offset)
    scan.visit(root, 0)
    if not scan.matches:
        return ()
    deepest = max(site.depth for site in scan.matches)
    return tuple(site for site in scan.matches if site.depth == deepest)


def _place_pretest_body_assignment_8616(
    project: object,
    codegen: object,
    site: _DirectStackMovePretestBodySite8616,
    move_fact: DirectStackMoveFact8616,
    assignment: structured_c.CAssignment,
    location: DirectStackMoveAssignmentLocation8616 | None,
) -> tuple[bool, bool]:
    """Place one assignment in machine/data order within its loop body."""
    result = place_assignment_8616(
        project,
        codegen,
        DirectStackMoveLoopEntrySite8616(site.statements, site.depth),
        move_fact,
        assignment,
        location,
    )
    return bool(result[0]), bool(result[1])


def place_direct_stack_move_pretest_body_assignment_8616(
    project: object,
    codegen: object,
    function: object,
    move_fact: DirectStackMoveFact8616,
    assignment: structured_c.CAssignment,
) -> bool:
    """Place one Lowering-built assignment at its proven loop-body entry."""
    if move_fact.source_kind not in _PRETEST_BODY_SOURCE_KINDS_8616:
        return False
    if move_fact.ins_addr in direct_stack_move_branch_owned_addresses_8616(
        project,
        codegen,
        function,
    ):
        return False
    codegen_boundary = cast(Any, codegen)
    try:
        root = codegen_boundary.cfunc.statements
    except AttributeError:
        return False
    evidence = recover_direct_stack_move_pretest_body_evidence_8616(
        project,
        function,
        move_fact.ins_addr,
    )
    sites = (
        _pretest_body_sites_8616(
            project,
            codegen,
            root,
            evidence[0],
            move_fact.dst_offset,
        )
        if root is not None and len(evidence) == 1
        else ()
    )
    locations = (
        tagged_assignment_locations_8616(project, codegen, root, move_fact)
        if root is not None
        else ()
    )
    if len(evidence) != 1 or len(sites) != 1 or len(locations) > 1:
        return False
    location = locations[0] if locations else None
    owned_assignment = location.assignment if location is not None else assignment
    placed, _already = _place_pretest_body_assignment_8616(
        project,
        codegen,
        sites[0],
        move_fact,
        owned_assignment,
        location,
    )
    return placed


class _PretestBodyOutcome8616(Enum):
    """Per-fact placement outcome for the pretest-body stats contract."""

    REFUSED_BRANCH_OWNER = "refused_branch_owner"
    REFUSED_NO_EVIDENCE = "refused_no_evidence"
    REFUSED_NO_SITE = "refused_no_site"
    REFUSED_ASSIGNMENT = "refused_assignment"
    NOT_PLACED = "not_placed"
    ALREADY_MATERIALIZED = "already_materialized"
    MATERIALIZED = "materialized"


@dataclass(slots=True)
class _PretestBodyTally8616:
    """Accumulated stats for the pretest-body placement pass."""

    normalized: int = 0
    classified: int = 0
    materialized: int = 0
    already_materialized: int = 0
    refused_no_evidence: int = 0
    refused_no_site: int = 0
    refused_assignment: int = 0
    refused_branch_owner: int = 0
    changed: bool = False

    def record(self, outcome: _PretestBodyOutcome8616) -> None:
        """Fold one fact outcome into the placement stats."""
        if outcome in {
            _PretestBodyOutcome8616.REFUSED_NO_SITE,
            _PretestBodyOutcome8616.REFUSED_ASSIGNMENT,
            _PretestBodyOutcome8616.NOT_PLACED,
            _PretestBodyOutcome8616.ALREADY_MATERIALIZED,
            _PretestBodyOutcome8616.MATERIALIZED,
        }:
            self.normalized += 1
        if outcome in {
            _PretestBodyOutcome8616.NOT_PLACED,
            _PretestBodyOutcome8616.ALREADY_MATERIALIZED,
            _PretestBodyOutcome8616.MATERIALIZED,
        }:
            self.classified += 1
        if outcome is _PretestBodyOutcome8616.REFUSED_BRANCH_OWNER:
            self.refused_branch_owner += 1
        elif outcome is _PretestBodyOutcome8616.REFUSED_NO_EVIDENCE:
            self.refused_no_evidence += 1
        elif outcome is _PretestBodyOutcome8616.REFUSED_NO_SITE:
            self.refused_no_site += 1
        elif outcome is _PretestBodyOutcome8616.REFUSED_ASSIGNMENT:
            self.refused_assignment += 1
        elif outcome in {
            _PretestBodyOutcome8616.ALREADY_MATERIALIZED,
            _PretestBodyOutcome8616.MATERIALIZED,
        }:
            self.materialized += 1
            self.already_materialized += int(
                outcome is _PretestBodyOutcome8616.ALREADY_MATERIALIZED
            )
            self.changed = (
                self.changed or outcome is _PretestBodyOutcome8616.MATERIALIZED
            )


def _process_pretest_fact_8616(
    fact: DirectStackMoveFact8616,
    project: object,
    codegen: object,
    function: object,
    root: object,
    branch_owned: frozenset[int],
) -> _PretestBodyOutcome8616:
    """Place one pretest-body move fact at its unique proven site."""
    if fact.ins_addr in branch_owned:
        return _PretestBodyOutcome8616.REFUSED_BRANCH_OWNER
    evidence = recover_direct_stack_move_pretest_body_evidence_8616(
        project,
        function,
        fact.ins_addr,
    )
    if len(evidence) != 1:
        return _PretestBodyOutcome8616.REFUSED_NO_EVIDENCE
    sites = _pretest_body_sites_8616(
        project,
        codegen,
        root,
        evidence[0],
        fact.dst_offset,
    )
    if len(sites) != 1:
        return _PretestBodyOutcome8616.REFUSED_NO_SITE
    locations = tagged_assignment_locations_8616(project, codegen, root, fact)
    if len(locations) != 1:
        return _PretestBodyOutcome8616.REFUSED_ASSIGNMENT
    placed, already = _place_pretest_body_assignment_8616(
        project,
        codegen,
        sites[0],
        fact,
        locations[0].assignment,
        locations[0],
    )
    if not placed:
        return _PretestBodyOutcome8616.NOT_PLACED
    return (
        _PretestBodyOutcome8616.ALREADY_MATERIALIZED
        if already
        else _PretestBodyOutcome8616.MATERIALIZED
    )


def materialize_direct_stack_move_pretest_body_ownership_8616(
    project: object,
    codegen: object,
    function: object,
) -> bool:
    """Relocate tagged stack assignments to proven pretest-loop body entries."""
    codegen_boundary = cast(Any, codegen)
    try:
        root = codegen_boundary.cfunc.statements
        raw_facts = codegen_boundary._inertia_direct_stack_move_facts_8616
    except AttributeError:
        return False
    facts = tuple(
        fact
        for fact in boundary_tuple_8616(raw_facts or ())
        if isinstance(fact, DirectStackMoveFact8616)
        and fact.source_kind in _PRETEST_BODY_SOURCE_KINDS_8616
    )
    branch_owned = direct_stack_move_branch_owned_addresses_8616(
        project,
        codegen,
        function,
    )
    tally = _PretestBodyTally8616()
    for fact in sorted(facts, key=lambda candidate: candidate.ins_addr):
        tally.record(
            _process_pretest_fact_8616(
                fact, project, codegen, function, root, branch_owned,
            )
        )
    normalized = tally.normalized
    classified = tally.classified
    materialized = tally.materialized
    already_materialized = tally.already_materialized
    changed = tally.changed
    stats = DirectStackMovePretestBodyStats8616(
        raw_fact_count=len(facts),
        normalized_fact_count=normalized,
        classified_fact_count=classified,
        materialized_count=materialized,
        failure_count=len(facts) - materialized,
        already_materialized_count=already_materialized,
        refused_no_evidence_count=tally.refused_no_evidence,
        refused_no_site_count=tally.refused_no_site,
        refused_assignment_count=tally.refused_assignment,
        refused_branch_owner_count=tally.refused_branch_owner,
    )
    codegen_boundary._inertia_direct_stack_move_pretest_body_placement_8616 = stats
    if not stats.closed:
        raise PipelineHardError("direct-stack pretest-body evidence counters did not close")
    if classified > materialized:
        raise PipelineHardError(
            "classified direct-stack pretest-body assignments were not fully materialized"
        )
    if os.environ.get("INERTIA_DEBUG_STACK_PRETEST_BODY") or os.environ.get(
        "INERTIA_DEBUG_STACK_NOISE"
    ):
        log.warning("[direct-stack-move-pretest-body] stats=%r", stats)
    return changed
