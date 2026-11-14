# cython: language_level=3, infer_types=True
"""Place direct stack moves at CFG-proven linear structured prefixes.

Layer: Structuring.
Responsibility: join one Lowering-owned direct stack move to the deepest unique
structured statement boundary reached by the same block or its sole immediate
CFG successor. This covers one-time assignments immediately before a loop or
branch body without moving them into that repeated/conditional body.

Lowering owns assignment values and destinations. This module owns only
control-flow placement and refuses unresolved CFGs, repeated move sequences,
ambiguous AST joins, and non-linear successors. It never inspects rendered C,
source text, symbols, or sample-specific addresses.

Dynamic boundary: angr structured-C nodes, function graphs, blocks, and
Capstone instructions expose version-dependent attributes. Dynamic reads in
this module are restricted to those third-party surfaces.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence. Do not perform alias-state ownership, widening,
type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting
work here.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c

from inertia.lowering.real_mode_linear import (
    DirectStackMoveFact8616,
    DirectStackMoveSourceKind8616,
)

from .direct_stack_move_linear_prefix_cfg import (
    DirectStackMoveLinearCfgSnapshot8616,
    direct_stack_move_linear_cfg_snapshot_8616,
    linear_cfg_successor_proven_8616,
)
from .direct_stack_move_loop_evidence import (
    comparable_address_8616,
    repeated_sequence_edges_8616,
)
import dataclasses
import operator


class DirectStackMoveLinearPrefixVerdict8616(Enum):
    """Typed result of one CFG-to-structured-prefix ownership join."""

    NOT_APPLICABLE = "not_applicable"
    REFUSED_UNRESOLVED_CFG = "refused_unresolved_cfg"
    REFUSED_REPEATED_MOVE = "refused_repeated_move"
    REFUSED_NO_LINEAR_SUCCESSOR = "refused_no_linear_successor"
    REFUSED_AMBIGUOUS_SITE = "refused_ambiguous_site"
    ALREADY_MATERIALIZED = "already_materialized"
    PROVEN_LINEAR_PREFIX = "proven_linear_prefix"


@dataclasses.dataclass(frozen=True, )
class DirectStackMoveLinearPrefixStats8616:
    """Closed evidence counters and verdict for one placement attempt."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong
    candidate_count: cython.longlong
    verdict: DirectStackMoveLinearPrefixVerdict8616


@dataclasses.dataclass(frozen=True, )
class _PlacementSite8616:
    """One mutable statement boundary before a linear successor statement."""

    statements: object
    insertion_index: cython.longlong
    following_addr: cython.longlong
    depth: cython.longlong


_OWNED_SOURCE_KINDS_8616 = frozenset(
    {DirectStackMoveSourceKind8616.SEGMENTED_MEMORY}
)
_LOOP_TYPES_8616 = (
    structured_c.CForLoop,
    structured_c.CWhileLoop,
    structured_c.CDoWhileLoop,
)


def _tree_nodes_8616(root: object) -> Iterator[object]:
    """Yield dynamic structured-C descendants once."""
    node: object
    value: object
    attribute: object
    seen: set[cython.longlong] = set()
    stack = [root]
    while stack:
        node = stack.pop()
        if node is None or id(node) in seen:
            continue
        if isinstance(node, (list, tuple)):
            stack.extend(node)
            continue
        seen.add(id(node))
        yield node
        for attribute in (
            "lhs",
            "rhs",
            "operand",
            "condition",
            "body",
            "else_node",
            "statements",
            "condition_and_nodes",
        ):
            # Dynamic boundary: structured-C node shapes vary across angr releases.
            value = getattr(node, attribute, None)
            if isinstance(value, (list, tuple)):
                stack.extend(value)
            elif value is not None:
                stack.append(value)


@cython.ccall
def _following_address_8616(
    project: object,
    statement: object,
    move_addr: cython.longlong,
) -> int | None:
    """Return the first tagged instruction after a move in one statement tree."""
    address: object
    tags: object
    key: object
    node: object
    candidates: set[cython.longlong] = set()
    for node in _tree_nodes_8616(statement):
        # Dynamic boundary: tags are owned by angr structured-C nodes.
        tags = getattr(node, "tags", None)
        if not isinstance(tags, dict):
            continue
        for key in ("ins_addr", "inertia_relocated_from_ins_addr"):
            address = tags.get(key)
            if not isinstance(address, int) or isinstance(address, bool):
                continue
            comparable = comparable_address_8616(project, address, move_addr)
            if comparable > move_addr:
                candidates.add(comparable)
    return min(candidates) if candidates else None


@cython.ccall
def _placement_sites_8616(
    project: object,
    root: object,
    move_addr: cython.longlong,
    snapshot: DirectStackMoveLinearCfgSnapshot8616,
) -> tuple[_PlacementSite8616, ...]:
    """Return non-loop statement boundaries with exact linear CFG evidence."""
    scan = _PlacementSiteScan8616(project, move_addr, snapshot)
    scan.visit(root, 0, False)
    return tuple(scan.candidates)


@cython.dataclasses.dataclass()
class _PlacementSiteScan8616:
    """Mutable non-loop placement-site scan over structured containers."""

    project: object
    move_addr: cython.longlong
    snapshot: DirectStackMoveLinearCfgSnapshot8616
    candidates: object = field(default_factory=list)
    seen: object = field(default_factory=set)

    @cython.ccall
    def visit(self, node: object, depth: cython.longlong, inside_loop_body: cython.bint) -> None:
        """Walk structured statement containers without crossing loop ownership."""
        _condition: object
        body: object
        statement: object
        if node is None or (id(node), inside_loop_body) in self.seen:
            return
        self.seen.add((id(node), inside_loop_body))
        if isinstance(node, structured_c.CStatements):
            if not inside_loop_body:
                self._scan_container(node, depth)
            for statement in tuple(node.statements):
                self.visit(statement, depth + 1, inside_loop_body)
            return
        if isinstance(node, _LOOP_TYPES_8616):
            self.visit(node.body, depth + 1, True)
            return
        if isinstance(node, structured_c.CIfElse):
            for _condition, body in tuple(node.condition_and_nodes):
                self.visit(body, depth + 1, inside_loop_body)
            self.visit(node.else_node, depth + 1, inside_loop_body)

    @cython.ccall
    def _scan_container(self, node: structured_c.CStatements, depth: cython.longlong) -> None:
        """Record each proven linear successor boundary in one container."""
        following_addr: object
        index: object
        statement: object
        for index, statement in enumerate(tuple(node.statements)):
            following_addr = _following_address_8616(
                self.project,
                statement,
                self.move_addr,
            )
            if following_addr is not None and linear_cfg_successor_proven_8616(
                self.snapshot,
                self.move_addr,
                following_addr,
            ):
                self.candidates.append(
                    _PlacementSite8616(
                        node.statements,
                        index,
                        following_addr,
                        depth,
                    )
                )


@cython.ccall
def _same_tagged_assignment_8616(
    statement: object,
    assignment: structured_c.CAssignment,
    move_addr: cython.longlong,
) -> cython.bint:
    """Return whether one adjacent statement is the exact requested assignment."""
    return bool(
        isinstance(statement, structured_c.CAssignment)
        and statement.lhs is assignment.lhs
        and statement.rhs is assignment.rhs
        and operator.eq(statement.tags.get("ins_addr"), move_addr)
    )


@cython.ccall
def _record_stats_8616(
    codegen: object,
    stats: DirectStackMoveLinearPrefixStats8616,
) -> None:
    """Publish the typed placement evidence on the dynamic codegen boundary."""
    history: object
    dynamic_codegen = cast(Any, codegen)
    dynamic_codegen._inertia_direct_stack_move_linear_prefix_8616 = stats
    # Dynamic boundary: codegen extension state persists across replay rounds.
    history = getattr(
        dynamic_codegen,
        "_inertia_direct_stack_move_linear_prefix_history_8616",
        (),
    )
    dynamic_codegen._inertia_direct_stack_move_linear_prefix_history_8616 = (
        *tuple(history or ()),
        stats,
    )


def place_direct_stack_move_linear_prefix_assignment_8616(
    project: object,
    codegen: object,
    function: object,
    move_fact: DirectStackMoveFact8616,
    assignment: structured_c.CAssignment,
) -> cython.bint:
    """Place one assignment only at a unique non-repeated linear CFG prefix."""
    root: object
    selected: object
    snapshot: object
    if move_fact.source_kind not in _OWNED_SOURCE_KINDS_8616:
        _record_stats_8616(
            codegen,
            DirectStackMoveLinearPrefixStats8616(
                1,
                0,
                0,
                0,
                0,
                0,
                DirectStackMoveLinearPrefixVerdict8616.NOT_APPLICABLE,
            ),
        )
        return False
    if repeated_sequence_edges_8616(project, function, move_fact.ins_addr):
        verdict = DirectStackMoveLinearPrefixVerdict8616.REFUSED_REPEATED_MOVE
        snapshot = None
    else:
        snapshot = direct_stack_move_linear_cfg_snapshot_8616(
            project,
            function,
            move_fact.ins_addr,
        )
        verdict = DirectStackMoveLinearPrefixVerdict8616.REFUSED_UNRESOLVED_CFG
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    sites = (
        ()
        if snapshot is None or root is None
        else _placement_sites_8616(
            project,
            root,
            move_fact.ins_addr,
            snapshot,
        )
    )
    if snapshot is not None and not sites:
        verdict = DirectStackMoveLinearPrefixVerdict8616.REFUSED_NO_LINEAR_SUCCESSOR
    selected = None
    if sites:
        minimum_distance = min(site.following_addr - move_fact.ins_addr for site in iter(sites))
        nearest = tuple(
            site
            for site in iter(sites)
            if operator.eq(site.following_addr - move_fact.ins_addr, minimum_distance)
        )
        maximum_depth = max(site.depth for site in iter(nearest))
        deepest = tuple(site for site in iter(nearest) if operator.eq(site.depth, maximum_depth))
        unique = {
            (id(site.statements), site.insertion_index, site.following_addr): site
            for site in iter(deepest)
        }
        if len(unique) == 1:
            selected = next(iter(unique.values()))
            verdict = DirectStackMoveLinearPrefixVerdict8616.PROVEN_LINEAR_PREFIX
        else:
            verdict = DirectStackMoveLinearPrefixVerdict8616.REFUSED_AMBIGUOUS_SITE
    if selected is not None and selected.insertion_index > 0 and _same_tagged_assignment_8616(
        selected.statements[selected.insertion_index - 1],
        assignment,
        move_fact.ins_addr,
    ):
        verdict = DirectStackMoveLinearPrefixVerdict8616.ALREADY_MATERIALIZED
    elif selected is not None:
        selected.statements.insert(selected.insertion_index, assignment)
    materialized = verdict in {
        DirectStackMoveLinearPrefixVerdict8616.ALREADY_MATERIALIZED,
        DirectStackMoveLinearPrefixVerdict8616.PROVEN_LINEAR_PREFIX,
    }
    _record_stats_8616(
        codegen,
        DirectStackMoveLinearPrefixStats8616(
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=int(selected is not None),
            materialized_count=int(materialized),
            failure_count=int(not materialized),
            candidate_count=len(sites),
            verdict=verdict,
        ),
    )
    return materialized
