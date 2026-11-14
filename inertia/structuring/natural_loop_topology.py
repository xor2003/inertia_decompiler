# cython: language_level=3, infer_types=True
"""Classify exact natural-loop topology from a typed CFG view.

Layer: Structuring.
Responsibility: owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence. This module classifies deterministic, fail-closed
natural-loop topology evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
Forbidden: graph mutation, region collapse, semantic inference, or C mutation.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol

import networkx as nx

from inertia.pipeline.errors import PipelineHardError
import dataclasses
import operator
import builtins

__all__ = (
    "LoopTopologyStats8616",
    "LoopTopologyVerdict8616",
    "NaturalLoopTopology8616",
    "classify_natural_loop_topology_8616",
)

LoopTopologyEdge8616 = typing.TypeAliasType("LoopTopologyEdge8616", tuple[int, int])


class LoopTopologyVerdict8616(Enum):
    """Typed verdict for one natural-loop topology candidate."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


@dataclasses.dataclass(frozen=True, )
class LoopTopologyStats8616:
    """Closed evidence counters for one topology classification."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0

    def __post_init__(self) -> None:
        """Reject open accounting and classified-but-unmaterialized evidence."""
        if self.classified_fact_count > 0 and self.materialized_count == 0:
            raise PipelineHardError("classified natural-loop topology was not materialized")
        if not self.is_closed:
            raise ValueError("natural-loop topology counters do not close")

    @property
    def is_closed(self) -> cython.bint:
        """Return whether every raw candidate ended in materialization or refusal."""
        counters = (
            self.raw_fact_count,
            self.normalized_fact_count,
            self.classified_fact_count,
            self.materialized_count,
            self.failure_count,
        )
        return (
            all(count >= 0 for count in iter(counters))
            and self.raw_fact_count >= self.normalized_fact_count
            and self.normalized_fact_count >= self.classified_fact_count
            and self.classified_fact_count >= self.materialized_count
            and operator.eq(self.raw_fact_count, self.materialized_count + self.failure_count)
        )


@dataclasses.dataclass(frozen=True, )
class NaturalLoopTopology8616:
    """Immutable exact topology, or an empty fail-closed refusal artifact."""

    header: cython.longlong
    latch: cython.longlong
    body: object
    entry_edges: object
    backedges: object
    exit_edges: object
    verdict: LoopTopologyVerdict8616
    stats: LoopTopologyStats8616
    refusal_reason: object = None

    def __post_init__(self) -> None:
        """Enforce deterministic ordering and exact proven-loop cardinalities."""
        edges: object
        if operator.ne(self.body, tuple(sorted(tuple(set(self.body))))):
            raise ValueError("natural-loop body must be sorted and unique")
        for edges in (self.entry_edges, self.backedges, self.exit_edges):
            if operator.ne(edges, tuple(sorted(tuple(set(edges))))):
                raise ValueError("natural-loop edges must be sorted and unique")
        if self.verdict is LoopTopologyVerdict8616.UNKNOWN_REFUSE:
            if self.body or self.entry_edges or self.backedges or self.exit_edges:
                raise ValueError("refused natural-loop topology cannot publish exact edges")
            return
        _validate_proven_topology_8616(self)

    @property
    def is_proven(self) -> cython.bint:
        """Return whether all narrow-slice topology requirements were proven."""
        return self.verdict is LoopTopologyVerdict8616.PROVEN


def _validate_proven_topology_8616(topology: NaturalLoopTopology8616) -> None:
    """Enforce the exact-edge invariants of one proven natural loop."""
    if topology.refusal_reason is not None:
        raise ValueError("proven natural-loop topology cannot carry a refusal reason")
    if topology.header not in topology.body or topology.latch not in topology.body:
        raise ValueError("proven natural-loop topology must contain header and latch")
    if operator.ne(topology.backedges, ((topology.latch, topology.header),)):
        raise ValueError("proven natural-loop topology requires one exact backedge")
    if any(operator.ne(target, topology.header) for _, target in iter(topology.entry_edges)):
        raise ValueError("proven natural-loop topology has a non-header entry")
    if len({target for _, target in iter(topology.exit_edges)}) != 1:
        raise ValueError("proven natural-loop topology requires one exit target")
    if operator.ne(topology.stats, LoopTopologyStats8616(1, 1, 1, 1, 0)):
        raise ValueError("proven natural-loop topology requires closed materialization counters")


class _NaturalLoopGraph8616(Protocol):
    """Minimal integer-node CFG boundary consumed by the topology owner."""

    def successors(self, node: cython.longlong) -> Iterable[cython.longlong]:
        """Return direct successor node ids."""
        ...

    def predecessors(self, node: cython.longlong) -> Iterable[cython.longlong]:
        """Return direct predecessor node ids."""
        ...


@cython.ccall
def _unknown_topology_8616(
    header: cython.longlong,
    latch: cython.longlong,
    reason: object,
    *,
    normalized: cython.bint,
) -> NaturalLoopTopology8616:
    """Build one closed refusal without publishing partial topology as exact."""
    return NaturalLoopTopology8616(
        header=header,
        latch=latch,
        body=(),
        entry_edges=(),
        backedges=(),
        exit_edges=(),
        verdict=LoopTopologyVerdict8616.UNKNOWN_REFUSE,
        stats=LoopTopologyStats8616(1, int(normalized), 0, 0, 1),
        refusal_reason=reason,
    )


def _header_dominated_nodes_8616(
    entry: cython.longlong, header: cython.longlong, successors: Callable[[int], tuple[cython.longlong, ...]],
) -> frozenset[cython.longlong]:
    """Use entry-rooted dominance to exclude enclosing-loop re-entry paths."""
    source: object
    snapshot = nx.DiGraph()
    pending = [entry]
    seen: set[cython.longlong] = set()
    while pending:
        source = pending.pop()
        if source in seen:
            continue
        seen.add(source)
        targets = successors(source)
        snapshot.add_node(source)
        snapshot.add_edges_from((source, target) for target in iter(targets))
        pending.extend(targets)
    dominators = nx.immediate_dominators(snapshot, entry)
    dominators[entry] = entry
    if header not in dominators:
        return frozenset()
    tree = nx.DiGraph()
    tree.add_nodes_from(dominators)
    tree.add_edges_from((parent, node) for node, parent in builtins.iter(dominators.items()) if parent != node)
    return frozenset({header} | nx.descendants(tree, header))


@cython.dataclasses.dataclass()
class _OrderedNeighborCache8616:
    """Validated deterministic adjacency cache for one integer-node CFG."""

    graph: _NaturalLoopGraph8616
    successor_cache: object = field(default_factory=dict)
    predecessor_cache: object = field(default_factory=dict)

    def ordered(self, node: cython.longlong, *, predecessors: cython.bint) -> object:
        """Read, validate, deduplicate, and sort one adjacency list."""
        cache = self.predecessor_cache if predecessors else self.successor_cache
        if node in cache:
            return cache[node]
        values = self.graph.predecessors(node) if predecessors else self.graph.successors(node)
        observed = tuple(values)
        if any(not isinstance(value, int) or isinstance(value, bool) for value in iter(observed)):
            raise TypeError("natural-loop topology requires integer CFG node ids")
        ordered = tuple(sorted(tuple(set(observed))))
        cache[node] = ordered
        return ordered

    def forward_without_header_return(self, header: cython.longlong) -> object:
        """Collect nodes reachable from the header before taking a backedge."""
        node: object
        visited: set[cython.longlong] = set()
        pending = [header]
        while pending:
            node = pending.pop()
            if node in visited:
                continue
            visited.add(node)
            pending.extend(
                reversed(
                    tuple(
                        target
                        for target in builtins.iter(self.ordered(node, predecessors=False))
                        if target != header
                    )
                )
            )
        return visited

    @cython.ccall
    def reverse_to_latch(self, latch: cython.longlong, header: cython.longlong) -> object:
        """Collect nodes that can reach the latch without crossing the header."""
        node: object
        visited: set[cython.longlong] = set()
        pending = [latch]
        while pending:
            node = pending.pop()
            if node in visited:
                continue
            visited.add(node)
            if operator.eq(node, header):
                continue
            pending.extend(reversed(self.ordered(node, predecessors=True)))
        return visited


def _boundary_edges_8616(
    cache: _OrderedNeighborCache8616,
    header: cython.longlong,
    latch: cython.longlong,
    body_set: object,
    latch_candidates: object,
) -> object:
    """Return ``(entry_edges, exit_edges)`` or a refusal reason string."""
    source: object
    target: object
    latches = tuple(
        source for source in builtins.iter(cache.ordered(header, predecessors=True)) if source in latch_candidates
    )
    if latches != (latch,):
        return "non-unique-latch"

    entry_edges: set[LoopTopologyEdge8616] = set()
    for target in sorted(body_set):
        for source in cache.ordered(target, predecessors=True):
            if source in body_set:
                continue
            if target != header:
                return "external-non-header-entry"
            entry_edges.add((source, target))

    exit_edges = {
        (source, target)
        for source in iter(body_set)
        for target in builtins.iter(cache.ordered(source, predecessors=False))
        if target not in body_set
    }
    return entry_edges, exit_edges


def classify_natural_loop_topology_8616(
    graph: _NaturalLoopGraph8616,
    header: cython.longlong,
    latch: cython.longlong,
    entry: int | None = None,
) -> NaturalLoopTopology8616:
    """Classify one exact single-latch, single-exit-target natural loop.

    The graph is observed through deterministic integer-node snapshots. Any
    missing edge, non-integer node, external non-header entry, extra latch, or
    non-unique exit target produces ``UNKNOWN_REFUSE``.
    When the function entry is supplied, dominance distinguishes true latches
    from enclosing-loop re-entry. Without it, retain conservative reachability.
    """
    cache = _OrderedNeighborCache8616(graph)

    try:
        if header not in cache.ordered(latch, predecessors=False):
            return _unknown_topology_8616(header, latch, "missing-latch-backedge", normalized=False)
        forward = cache.forward_without_header_return(header)
        reverse = cache.reverse_to_latch(latch, header)
    except (AttributeError, KeyError, TypeError, ValueError):
        return _unknown_topology_8616(header, latch, "incomplete-graph-evidence", normalized=False)

    body_set = forward & reverse
    if header not in body_set or latch not in body_set:
        return _unknown_topology_8616(header, latch, "incomplete-loop-body", normalized=True)

    try:
        latch_candidates = (
            _header_dominated_nodes_8616(
                entry, header, lambda node: cache.ordered(node, predecessors=False),
            )
            if entry is not None else forward
        )
        boundary = _boundary_edges_8616(cache, header, latch, body_set, latch_candidates)
    except (AttributeError, KeyError, TypeError, ValueError):
        return _unknown_topology_8616(header, latch, "incomplete-graph-evidence", normalized=True)
    if isinstance(boundary, str):
        return _unknown_topology_8616(header, latch, boundary, normalized=True)
    entry_edges, exit_edges = boundary

    if len({target for _, target in iter(exit_edges)}) != 1:
        return _unknown_topology_8616(header, latch, "non-unique-exit-target", normalized=True)

    return NaturalLoopTopology8616(
        header=header,
        latch=latch,
        body=tuple(sorted(body_set)),
        entry_edges=tuple(sorted(entry_edges)),
        backedges=((latch, header),),
        exit_edges=tuple(sorted(exit_edges)),
        verdict=LoopTopologyVerdict8616.PROVEN,
        stats=LoopTopologyStats8616(1, 1, 1, 1, 0),
    )
