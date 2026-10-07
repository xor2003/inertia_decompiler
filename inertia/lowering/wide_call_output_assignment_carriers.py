"""Resolve complete C-AST ownership for one wide call-output carrier fact.

Layer: Types/Lowering.
Responsibility: find maximal mutable statement subtrees whose direct instruction
tags are wholly owned by one immutable wide call-output fact. This is the
conservative fallback when Structuring distributes linear machine carriers
across more than one nested statement group.
Consumes alias, widening, and typed facts without deriving semantics from C
shape, rendered text, symbols, source, or assembly.

Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CFunctionCall,
    CStatements,
)

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616

from .wide_call_output_assignment_ast import c_node_instruction_addrs_8616
from .wide_call_output_assignment_contracts import (
    WideCallOutputAssignmentFailure8616,
)


class _TaggedNodeBoundary8616(Protocol):
    """Dynamic instruction tags exposed by angr C-AST nodes."""

    tags: object


@dataclass(frozen=True, slots=True)
class CarrierStatementRef8616:
    """One mutable statement slot wholly owned by carrier instructions."""

    group: CStatements
    index: int
    statement: object


@dataclass(frozen=True, slots=True)
class CompleteCarrierCoverage8616:
    """Maximal exact carrier slots and their closed coverage verdict."""

    refs: tuple[CarrierStatementRef8616, ...] = ()
    observed: frozenset[int] = frozenset()
    failure: WideCallOutputAssignmentFailure8616 | None = None


def _statement_groups_8616(root: object) -> tuple[CStatements, ...]:
    """Return every mutable statement group once in tree order."""
    groups: dict[int, CStatements] = {}
    for node in _iter_c_nodes_deep_8616(root):
        if isinstance(node, CStatements):
            groups.setdefault(id(node), node)
    return tuple(groups.values())


def _has_call_8616(node: object) -> bool:
    """Return whether deleting this subtree would delete a call effect."""
    return any(
        isinstance(child, CFunctionCall)
        for child in _iter_c_nodes_deep_8616(node)
    )


def _direct_instruction_addr_8616(node: object) -> int | None:
    """Return one direct instruction tag at the dynamic angr boundary."""
    try:
        tags = cast(_TaggedNodeBoundary8616, node).tags
    except AttributeError:
        return None
    if not isinstance(tags, dict):
        return None
    address = tags.get("ins_addr")
    return address if isinstance(address, int) else None


def _maximal_refs_8616(
    candidates: tuple[CarrierStatementRef8616, ...],
) -> tuple[CarrierStatementRef8616, ...]:
    """Discard candidate slots already enclosed by a larger exact slot."""
    closures = tuple(
        {id(node) for node in _iter_c_nodes_deep_8616(candidate.statement)}
        | {id(candidate.statement)}
        for candidate in candidates
    )
    return tuple(
        candidate
        for index, candidate in enumerate(candidates)
        if not any(
            id(candidate.statement) in closure
            for other_index, closure in enumerate(closures)
            if other_index != index
        )
    )


def complete_carrier_coverage_8616(
    root: object,
    required: frozenset[int],
) -> CompleteCarrierCoverage8616:
    """Collect complete fact-owned carriers across nested Structuring groups.

    Every retained slot is call-free and contains only required instruction
    tags. Every direct required tag must belong to one retained slot; otherwise
    the surface is refused without mutation.
    """
    candidates: list[CarrierStatementRef8616] = []
    for group in _statement_groups_8616(root):
        for index, statement in enumerate(group.statements):
            addresses = c_node_instruction_addrs_8616(statement)
            if not addresses & required or not addresses <= required:
                continue
            if _has_call_8616(statement):
                continue
            candidates.append(CarrierStatementRef8616(group, index, statement))
    refs = _maximal_refs_8616(tuple(candidates))
    selected_node_ids = {
        id(node)
        for ref in refs
        for node in _iter_c_nodes_deep_8616(ref.statement)
    } | {id(ref.statement) for ref in refs}
    required_node_ids = {
        id(node)
        for node in _iter_c_nodes_deep_8616(root)
        if _direct_instruction_addr_8616(node) in required
    }
    observed = frozenset(
        address
        for ref in refs
        for address in c_node_instruction_addrs_8616(ref.statement)
    )
    if required_node_ids - selected_node_ids:
        return CompleteCarrierCoverage8616(
            failure=WideCallOutputAssignmentFailure8616.MIXED_STATEMENT_OWNERSHIP
        )
    if not required <= observed:
        return CompleteCarrierCoverage8616(
            refs=refs,
            observed=observed,
            failure=WideCallOutputAssignmentFailure8616.CARRIER_COVERAGE_MISSING,
        )
    return CompleteCarrierCoverage8616(refs=refs, observed=observed)


def delete_carrier_refs_8616(
    refs: tuple[CarrierStatementRef8616, ...],
) -> None:
    """Delete maximal exact carrier slots in descending group-index order."""
    by_group: dict[int, tuple[CStatements, list[int]]] = {}
    for ref in refs:
        entry = by_group.setdefault(id(ref.group), (ref.group, []))
        entry[1].append(ref.index)
    for group, indices in by_group.values():
        for index in sorted(set(indices), reverse=True):
            del group.statements[index]


__all__ = [
    "CarrierStatementRef8616",
    "CompleteCarrierCoverage8616",
    "complete_carrier_coverage_8616",
    "delete_carrier_refs_8616",
]
