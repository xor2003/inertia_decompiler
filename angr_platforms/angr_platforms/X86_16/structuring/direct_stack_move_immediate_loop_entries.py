"""Classify immediate stack-store relocation into structured loop entries.

Layer: Structuring.
Responsibility: prove that a binary backedge repeats one exact immediate stack
store and that its tagged C assignment is adjacent to the matching loop body.
This module owns placement evidence only. Lowering owns the store value and
storage identity; Rewrite must not infer or repair this control-flow relation.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence. Do not perform alias-state ownership, widening,
type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting
work here.

Dynamic boundary: heterogeneous angr structured-C nodes expose optional fields;
dynamic reads are restricted to ``_ast_field_8616``.
"""

from __future__ import annotations

from enum import Enum

from angr.analyses.decompiler.structured_codegen import c as structured_c

from ..lowering.real_mode_linear import (
    DirectStackMoveFact8616,
    DirectStackMoveSourceKind8616,
)
from .direct_stack_move_loop_evidence import (
    DirectStackMoveLoopEntryEdge8616,
    boundary_tuple_8616,
)
from .direct_stack_move_loop_sites import (
    DirectStackMoveAssignmentLocation8616,
    DirectStackMoveLoopEntrySite8616,
)


class ImmediateLoopEntryRelocationVerdict8616(Enum):
    """Typed proof result for one immediate-store loop-entry relocation."""

    NOT_APPLICABLE = "not_applicable"
    ALREADY_OWNED = "already_owned"
    PROVEN_ADJACENT_PREDECESSOR = "proven_adjacent_predecessor"
    REFUSED_NONEXACT_BACKEDGE = "refused_nonexact_backedge"
    REFUSED_NONADJACENT_ASSIGNMENT = "refused_nonadjacent_assignment"

    @property
    def permits_relocation(self) -> bool:
        """Return whether Structuring may preserve or relocate the assignment."""
        return self in {
            self.NOT_APPLICABLE,
            self.ALREADY_OWNED,
            self.PROVEN_ADJACENT_PREDECESSOR,
        }


def _ast_field_8616(node: object | None, name: str) -> object | None:
    """Read one optional field from a heterogeneous third-party angr AST node."""
    return getattr(node, name, None)


def classify_immediate_loop_entry_relocation_8616(
    root: object,
    site: DirectStackMoveLoopEntrySite8616,
    move_fact: DirectStackMoveFact8616,
    edge: DirectStackMoveLoopEntryEdge8616,
    location: DirectStackMoveAssignmentLocation8616,
) -> ImmediateLoopEntryRelocationVerdict8616:
    """Prove the exact backedge and structured adjacency of an immediate store."""
    if move_fact.source_kind is not DirectStackMoveSourceKind8616.IMMEDIATE:
        return ImmediateLoopEntryRelocationVerdict8616.NOT_APPLICABLE
    if edge.entry_addr != move_fact.ins_addr:
        return ImmediateLoopEntryRelocationVerdict8616.REFUSED_NONEXACT_BACKEDGE
    if location.statements is site.statements:
        return ImmediateLoopEntryRelocationVerdict8616.ALREADY_OWNED
    return _loop_entry_predecessor_scan_8616(root, site, location)


def _loop_entry_predecessor_scan_8616(
    root: object,
    site: DirectStackMoveLoopEntrySite8616,
    location: DirectStackMoveAssignmentLocation8616,
) -> ImmediateLoopEntryRelocationVerdict8616:
    """Walk the structured tree for the loop body owning the site."""
    seen: set[int] = set()
    stack: list[object] = [root]
    while stack:
        node = stack.pop()
        if node is None or id(node) in seen:
            continue
        seen.add(id(node))
        verdict = _visit_scan_node_8616(node, site, location, stack)
        if verdict is not None:
            return verdict
    return ImmediateLoopEntryRelocationVerdict8616.REFUSED_NONADJACENT_ASSIGNMENT


def _visit_scan_node_8616(
    node: object,
    site: DirectStackMoveLoopEntrySite8616,
    location: DirectStackMoveAssignmentLocation8616,
    stack: list[object],
) -> ImmediateLoopEntryRelocationVerdict8616 | None:
    """Match loop-body ownership for one node or push its children."""
    statements = _ast_field_8616(node, "statements")
    if isinstance(statements, list):
        for index, statement in enumerate(tuple(statements)):
            if isinstance(
                statement,
                (structured_c.CDoWhileLoop, structured_c.CWhileLoop),
            ):
                body = _ast_field_8616(statement, "body")
                body_statements = _ast_field_8616(body, "statements")
                if body_statements is site.statements:
                    if (
                        location.statements is statements
                        and location.index + 1 == index
                    ):
                        return ImmediateLoopEntryRelocationVerdict8616.PROVEN_ADJACENT_PREDECESSOR
                    return ImmediateLoopEntryRelocationVerdict8616.REFUSED_NONADJACENT_ASSIGNMENT
            stack.append(statement)
    for attr in ("body", "else_node"):
        child = _ast_field_8616(node, attr)
        if child is not None:
            stack.append(child)
    for _condition, body in boundary_tuple_8616(
        _ast_field_8616(node, "condition_and_nodes") or (),
    ):
        stack.append(body)
    return None
