"""Place binary-proven stack moves at their owning structured loop tail.

Layer: Structuring.
Responsibility: join typed direct-stack-move facts to exact machine loopback
edges and place Lowering-built assignments in the unique matching loop body.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
This module owns control-flow placement only; it does not recover values,
aliases, types, or semantics from rendered C, source, symbols, or names.
"""

from __future__ import annotations

import contextlib
import logging
import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from capstone import CS_GRP_JUMP
from capstone.x86_const import X86_OP_IMM

from ..lowering.real_mode_linear import DirectStackMoveFact8616
from .direct_stack_move_loop_sites import tagged_assignment_locations_8616
from .direct_stack_move_ownership import (
    direct_stack_move_branch_owned_addresses_8616,
)

log: logging.Logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class DirectStackMoveLoopTailStats8616:
    """Closed evidence counters for one loop-tail placement decision."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    refused_branch_owner_count: int


@dataclass(frozen=True, slots=True)
class _LoopbackEdge8616:
    """One direct backward jump following a stack-move instruction."""

    move_addr: int
    jump_addr: int
    target_addr: int


@dataclass(frozen=True, slots=True)
class _LoopTailSite8616:
    """One structured loop body proven to own a machine loop-tail move."""

    statements: list[Any]
    gap: int
    depth: int


def _boundary_tuple_8616(value: object) -> tuple[Any, ...]:
    """Convert one dynamic angr collection to a stable tuple."""
    return tuple(cast(Iterable[Any], value))


def _candidate_addresses_8616(project: object, address: int) -> frozenset[int]:
    """Return current and original address-domain candidates.

    Dynamic boundary: angr project attributes may include original-address metadata.
    """
    candidates = {address}
    delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(delta, int) and delta:
        candidates.update((address + delta, address - delta))
    return frozenset(candidates)


def _ordered_instructions_8616(function: object) -> tuple[object, ...]:
    """Return unique function instructions in address order.

    Dynamic boundary: angr/capstone block interfaces are optional external objects.
    """
    blocks = _boundary_tuple_8616(getattr(function, "blocks", ()) or ())
    local_blocks = getattr(function, "_local_blocks", None)
    if isinstance(local_blocks, dict) and local_blocks:
        blocks = tuple(local_blocks.values())
    by_addr: dict[int, object] = {}
    for block in blocks:
        capstone = getattr(block, "capstone", None)
        for wrapper in _boundary_tuple_8616(getattr(capstone, "insns", ()) or ()):
            insn = getattr(wrapper, "insn", wrapper)
            address = getattr(insn, "address", None)
            if isinstance(address, int):
                by_addr[address] = insn
    return tuple(by_addr[address] for address in sorted(by_addr))


def _loopback_after_move_8616(
    project: object,
    function: object,
    move_addr: int,
) -> _LoopbackEdge8616 | None:
    """Return the first nearby direct loopback after one exact move.

    Dynamic boundary: project, factory, and capstone fields are third-party/angr.
    """
    move_candidates = _candidate_addresses_8616(project, move_addr)
    instruction_sets = [_ordered_instructions_8616(function)]
    factory = getattr(project, "factory", None)
    if factory is not None:
        for candidate in move_candidates:
            with contextlib.suppress(Exception):
                block = factory.block(candidate, size=32, opt_level=0)
                capstone = getattr(block, "capstone", None)
                instruction_sets.append(
                    tuple(
                        getattr(wrapper, "insn", wrapper)
                        for wrapper in _boundary_tuple_8616(
                            getattr(capstone, "insns", ()) or ()
                        )
                    )
                )
    for instructions in instruction_sets:
        move_indexes = tuple(
            index
            for index, insn in enumerate(instructions)
            if getattr(insn, "address", None) in move_candidates
        )
        if len(move_indexes) != 1:
            continue
        decoded_move_addr = getattr(instructions[move_indexes[0]], "address", None)
        if not isinstance(decoded_move_addr, int):
            continue
        following = instructions[move_indexes[0] + 1 :]
        if not following:
            continue
        insn = following[0]
        jump_addr = getattr(insn, "address", None)
        groups = _boundary_tuple_8616(getattr(insn, "groups", ()) or ())
        operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
        if (
            not isinstance(jump_addr, int)
            or CS_GRP_JUMP not in groups
            or len(operands) != 1
            or getattr(operands[0], "type", None) != X86_OP_IMM
            or not isinstance(getattr(operands[0], "imm", None), int)
        ):
            continue
        target_addr = int(operands[0].imm)
        if target_addr < jump_addr:
            return _LoopbackEdge8616(decoded_move_addr, jump_addr, target_addr)
    return None


def direct_stack_move_has_loop_tail_edge_8616(
    project: object,
    function: object,
    move_addr: int,
) -> bool:
    """Return whether CFG instructions prove this move owns a loopback tail."""
    return _loopback_after_move_8616(project, function, move_addr) is not None


def _tree_tag_addresses_8616(root: object) -> frozenset[int]:
    """Collect exact instruction-origin tags from a structured subtree.

    Dynamic boundary: structured codegen nodes use optional attributes.
    """
    addresses: set[int] = set()
    seen: set[int] = set()
    stack = [root]
    while stack:
        node = stack.pop()
        if node is None or id(node) in seen:
            continue
        if isinstance(node, (list, tuple)):
            stack.extend(node)
            continue
        seen.add(id(node))
        tags = getattr(node, "tags", None)
        if isinstance(tags, dict):
            addresses.update(
                value
                for value in (
                    tags.get("ins_addr"),
                    tags.get("inertia_relocated_from_ins_addr"),
                )
                if isinstance(value, int)
            )
        for attr in ("condition", "body", "else_node", "statements"):
            child = getattr(node, attr, None)
            if child is not None:
                stack.append(child)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for condition, body in _boundary_tuple_8616(pairs):
                stack.extend((condition, body))
    return frozenset(addresses)


@dataclass(slots=True)
class _LoopTailSiteScan8616:
    """Structured-loop tail-site scan state for one loopback edge.

    Dynamic boundary: codegen loop nodes are traversed through optional
    attributes for safety.
    """

    project: object
    edge: _LoopbackEdge8616
    sites: list[_LoopTailSite8616] = field(default_factory=list)
    seen: set[int] = field(default_factory=set)

    def _debug_site_8616(
        self,
        class_name: str,
        depth: int,
        body_addresses: set[int],
        condition_addresses: set[int],
    ) -> None:
        """Emit one loop-site debug record when the env flag is set."""
        if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            log.warning(
                "[direct-stack-move-loop-site] move=%#x target=%#x loop=%s depth=%d "
                "body_range=%r condition_range=%r",
                self.edge.move_addr,
                self.edge.target_addr,
                class_name,
                depth,
                (
                    min(body_addresses, default=None),
                    max(body_addresses, default=None),
                ),
                (
                    min(condition_addresses, default=None),
                    max(condition_addresses, default=None),
                ),
            )

    def _evaluate_loop_8616(
        self,
        node: object,
        body: object,
        statements: list[object],
        class_name: str,
        depth: int,
    ) -> None:
        """Record proven tail sites owned by one structured loop body."""
        body_addresses = {
            candidate
            for address in _tree_tag_addresses_8616(body)
            for candidate in _candidate_addresses_8616(self.project, address)
        }
        condition_addresses = {
            candidate
            for address in _tree_tag_addresses_8616(getattr(node, "condition", None))
            for candidate in _candidate_addresses_8616(self.project, address)
        }
        self._debug_site_8616(class_name, depth, body_addresses, condition_addresses)
        for move_addr in _candidate_addresses_8616(self.project, self.edge.move_addr):
            move_candidates = _candidate_addresses_8616(self.project, self.edge.move_addr)
            ordered_body_addresses = body_addresses - move_candidates
            before_move = tuple(address for address in ordered_body_addresses if address < move_addr)
            if not before_move or max(ordered_body_addresses, default=move_addr) >= move_addr:
                continue
            envelope = body_addresses | condition_addresses
            target_candidates = _candidate_addresses_8616(self.project, self.edge.target_addr)
            target_in_envelope = bool(envelope) and any(
                min(envelope) <= target <= max(envelope) for target in target_candidates
            )
            target_at_pretest = class_name in {"CWhileLoop", "CForLoop"} and any(
                0 < min(body_addresses) - target <= 32
                for target in target_candidates
            )
            if not target_in_envelope and not target_at_pretest:
                continue
            self.sites.append(
                _LoopTailSite8616(
                    statements=statements,
                    gap=move_addr - max(before_move),
                    depth=depth,
                )
            )

    def visit(self, node: object, depth: int) -> None:
        """Collect candidate loop bodies recursively."""
        if node is None or id(node) in self.seen:
            return
        self.seen.add(id(node))
        body = getattr(node, "body", None)
        statements = getattr(body, "statements", None)
        class_name = node.__class__.__name__
        if class_name in {"CWhileLoop", "CDoWhileLoop", "CForLoop"} and isinstance(statements, list):
            self._evaluate_loop_8616(node, body, statements, class_name, depth)
        statements_value = getattr(node, "statements", None)
        if isinstance(statements_value, list):
            for statement in tuple(statements_value):
                self.visit(statement, depth + 1)
        for attr in ("body", "else_node"):
            self.visit(getattr(node, attr, None), depth + 1)
        pairs = getattr(node, "condition_and_nodes", None)
        if pairs:
            for _condition, guarded_body in _boundary_tuple_8616(pairs):
                self.visit(guarded_body, depth + 1)


def _loop_tail_sites_8616(
    project: object,
    root: object,
    edge: _LoopbackEdge8616,
) -> tuple[_LoopTailSite8616, ...]:
    """Return structured loops whose body and loopback uniquely own the move.

    Dynamic boundary: this traversal reads optional codegen node fields.
    """
    scan = _LoopTailSiteScan8616(project, edge)
    scan.visit(root, 0)
    return tuple(scan.sites)


def place_direct_stack_move_loop_tail_assignment_8616(
    project: object,
    codegen: object,
    function: object,
    move_fact: DirectStackMoveFact8616,
    assignment: structured_c.CAssignment,
    *,
    branch_owned_addresses: frozenset[int] | None = None,
) -> bool:
    """Append one assignment to its unique CFG-proven structured loop body.

    Dynamic boundary: codegen exposes optional cfunc/statements fields.
    """
    branch_owned = (
        branch_owned_addresses
        if branch_owned_addresses is not None
        else direct_stack_move_branch_owned_addresses_8616(project, codegen, function)
    )
    if move_fact.ins_addr in branch_owned:
        stats = DirectStackMoveLoopTailStats8616(
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=0,
            materialized_count=0,
            failure_count=0,
            refused_branch_owner_count=1,
        )
        cast(Any, codegen)._inertia_direct_stack_move_loop_tail_placement_8616 = stats
        return False
    edge = _loopback_after_move_8616(project, function, move_fact.ins_addr)
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None)
    sites = _loop_tail_sites_8616(project, root, edge) if edge is not None and root is not None else ()
    locations = (
        tagged_assignment_locations_8616(project, codegen, root, move_fact)
        if edge is not None and root is not None
        else ()
    )
    best_sites: tuple[_LoopTailSite8616, ...] = ()
    if sites:
        best_gap = min(site.gap for site in sites)
        deepest = max(site.depth for site in sites if site.gap == best_gap)
        best_sites = tuple(site for site in sites if site.gap == best_gap and site.depth == deepest)
    materialized = len(best_sites) == 1 and len(locations) <= 1
    if materialized and best_sites:
        target = best_sites[0].statements
        if locations:
            location = locations[0]
            if location.statements is not target or location.index != len(target) - 1:
                del location.statements[location.index]
                target.append(assignment)
        else:
            target.append(assignment)
    stats = DirectStackMoveLoopTailStats8616(
        raw_fact_count=1,
        normalized_fact_count=len(sites),
        classified_fact_count=1 if len(best_sites) == 1 else 0,
        materialized_count=1 if materialized else 0,
        failure_count=1 if len(best_sites) > 1 or len(locations) > 1 else 0,
        refused_branch_owner_count=0,
    )
    cast(Any, codegen)._inertia_direct_stack_move_loop_tail_placement_8616 = stats
    if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
        log.warning(
            "[direct-stack-move-loop-tail] move=%#x edge=%r sites=%r stats=%r",
            move_fact.ins_addr,
            edge,
            sites,
            stats,
        )
    return materialized
